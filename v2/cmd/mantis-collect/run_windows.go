//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// Item and run states of the execution screen. They describe what actually
// happened to each source, independent of what was selected.
type itemState int

const (
	stPending itemState = iota
	stRunning
	stDone
	stFailed
	stSkipped
	stCancelled
)

type outcome int

const (
	ocNone outcome = iota
	ocComplete
	ocPartial
	ocFailed
	ocCancelled
)

type runItem struct {
	id, locator string
	state       itemState
	started     time.Time
	dur         time.Duration
	result      string // one-line outcome
	detail      string // full text for the detail strip
}

type logLine struct {
	t     time.Time
	level string
	msg   string
}

func (p *picker) logf(level, format string, args ...any) {
	r := p.run
	r.log = append(r.log, logLine{t: time.Now(), level: level, msg: fmt.Sprintf(format, args...)})
	if r.logFollow {
		r.logScroll = len(r.log)
	}
}

// ---- lifecycle ----

func (p *picker) startCollection() {
	if p.phase != phSelect || p.selectedCount() == 0 {
		return
	}
	var chosen []collector.Source
	for _, r := range p.rows {
		if r.on {
			chosen = append(chosen, r.src)
		}
	}
	if sens := collector.NeedsConfirmation(chosen); len(sens) > 0 && !p.confirmSensitive(sens) {
		return
	}
	p.selected = chosen
	p.started = true
	ctx, cancel := context.WithCancel(context.Background())
	run := &runState{startedAt: time.Now(), cancel: cancel, sel: -1, logFollow: true}
	p.run, p.phase = run, phPreparing
	p.scroll, p.hover, p.tipText, p.tipShown = 0, hit{}, "", false
	p.logf("INFO", "Recolección iniciada: %d fuentes seleccionadas", len(p.selected))
	p.placeEdit()
	pSetTimer.Call(p.hwnd, 1, 120, 0)
	sources, hwnd := p.selected, p.hwnd
	go func() { // evidence collection never runs on the UI thread
		var results []collector.ItemResult
		var err error
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					err = fmt.Errorf("collector panic: %v", rec)
				}
			}()
			if guiCollect == nil {
				err = errors.New("collector is not available")
				return
			}
			results, err = guiCollect(ctx, sources, func(e collector.Event) {
				run.mu.Lock()
				run.queue = append(run.queue, e)
				run.mu.Unlock()
				pPostMessage.Call(hwnd, wmRunEvents, 0, 0)
			})
		}()
		run.mu.Lock()
		run.finished, run.fResults, run.fErr = true, results, err
		run.mu.Unlock()
		pPostMessage.Call(hwnd, wmRunDone, 0, 0)
	}()
	p.redraw()
}

func (p *picker) drainRunEvents() {
	r := p.run
	if r == nil {
		return
	}
	r.mu.Lock()
	events := r.queue
	r.queue = nil
	r.mu.Unlock()
	for _, e := range events {
		switch e.Kind {
		case collector.EventPlanReady:
			r.items = make([]runItem, len(e.Planned))
			for i, ps := range e.Planned {
				r.items[i] = runItem{id: ps.ID, locator: ps.Locator}
			}
			if p.phase == phPreparing {
				p.phase = phRunning
			}
			p.logf("INFO", "Plan listo: %d fuentes por procesar", len(e.Planned))
		case collector.EventSourceStarted:
			if e.Index < len(r.items) {
				it := &r.items[e.Index]
				it.state, it.started = stRunning, e.Time
				p.logf("INFO", "Recopilando %s", it.id)
				if !r.manualScroll {
					p.ensureVisible(e.Index)
				}
			}
		case collector.EventSourceFinished:
			if e.Index < len(r.items) {
				it := &r.items[e.Index]
				it.dur = e.Duration
				it.state, it.result, it.detail = classify(e.Item)
				switch it.state {
				case stDone:
					p.logf("INFO", "%s completada (%s)", it.id, it.result)
				case stSkipped:
					p.logf("WARN", "%s omitida: %s", it.id, it.result)
				case stCancelled:
					p.logf("WARN", "%s cancelada", it.id)
				default:
					p.logf("ERROR", "%s falló: %s", it.id, it.result)
				}
			}
		}
	}
	p.redraw()
}

// classify turns a collector result into a display state; nothing is assumed
// successful unless the artifact was actually published.
func classify(it collector.ItemResult) (itemState, string, string) {
	if errors.Is(it.Err, collector.ErrTotalBudgetExceeded) {
		// not acquired: the manifest records it as failed, and the run must not read as complete
		return stFailed, "Presupuesto total de bytes agotado: no se recolectó", "Se agotó el tope de bytes de la recolección (perfil o --max-total-bytes) antes de procesar esta fuente."
	}
	method := it.Method
	switch it.Classify() {
	case collector.Collected, collector.CollectedWarnings:
		size, sum := it.Result.Blob.SizeBytes, it.Result.Blob.SHA256
		short := sum
		if len(short) > 12 {
			short = short[:12]
		}
		lead := "Artefacto generado"
		if w := it.Notes["warnings"]; w != "" && w != "0" {
			lead = "Con advertencias (" + w + ")"
		}
		detail := fmt.Sprintf("SHA-256 %s  ·  %d bytes  ·  método %s  ·  manifiesto %s", sum, size, method, it.Result.ManifestSHA256)
		if d := it.Notes["warning_detail"]; d != "" {
			detail += "  ·  advertencias: " + d
		}
		return stDone, fmt.Sprintf("%s · %s · sha256 %s… · %s", lead, humanBytes(size), short, method), detail
	case collector.Empty:
		return stDone, "Fuente vacía (0 B) · " + method, "La fuente existe pero no contenía datos."
	case collector.DispCancelled:
		return stCancelled, "Interrumpida por el analista", "La fuente se interrumpió; no se publicó un artefacto completo."
	case collector.DispNotPresent:
		return stSkipped, "No presente en este equipo", uniqueLines(errText(it.Err))
	case collector.DispNotSupported:
		return stSkipped, "No soportado en este equipo", uniqueLines(errText(it.Err))
	case collector.DispAccessDenied:
		return stFailed, "Acceso denegado: ejecuta Mantis como administrador para esta fuente", uniqueLines(errText(it.Err))
	}
	switch {
	case errors.Is(it.Err, windows.ERROR_ACCESS_DENIED):
		return stFailed, "Acceso denegado: ejecuta Mantis como administrador para esta fuente", uniqueLines(errText(it.Err))
	case it.Err != nil:
		msg := uniqueLines(errText(it.Err))
		first, _, _ := strings.Cut(msg, "\n")
		return stFailed, first, msg
	}
	return stFailed, "El artefacto no se publicó", "El collector terminó sin publicar el artefacto ni informar un error."
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// uniqueLines drops repeated lines (joined errors often repeat the same cause).
func uniqueLines(text string) string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" && !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func (p *picker) finishRun() {
	r := p.run
	if r == nil || p.phase == phDone {
		return
	}
	p.drainRunEvents()
	r.mu.Lock()
	res, err := r.fResults, r.fErr
	r.mu.Unlock()
	r.results, r.err, r.finishedAt = res, err, time.Now()
	cancelled := errors.Is(err, context.Canceled)
	for i := range r.items {
		it := &r.items[i]
		switch it.state {
		case stPending:
			if cancelled {
				it.state, it.result = stCancelled, "No se inició"
			} else if err != nil {
				it.state, it.result, it.detail = stFailed, "No se ejecutó", err.Error()
			}
		case stRunning:
			it.state, it.result = stCancelled, "Interrumpida"
		}
	}
	counts := p.counts()
	switch {
	case cancelled:
		r.outcome = ocCancelled
	case len(r.items) == 0 && err != nil:
		r.outcome = ocFailed
	case counts.done > 0 && counts.failed == 0 && counts.cancelled == 0:
		r.outcome = ocComplete
	case counts.done > 0:
		r.outcome = ocPartial
	default:
		r.outcome = ocFailed
	}
	if r.cancelReq && !cancelled {
		p.logf("INFO", "La cancelación llegó cuando la recolección ya había terminado.")
	}
	switch r.outcome {
	case ocCancelled:
		p.logf("WARN", "Recolección cancelada. %d fuentes conservadas, %d sin completar.", counts.done, counts.cancelled)
	case ocFailed:
		if err != nil {
			p.logf("ERROR", "La recolección falló: %v", err)
		} else {
			p.logf("ERROR", "La recolección terminó sin generar artefactos.")
		}
	case ocPartial:
		p.logf("WARN", "Recolección finalizada con errores: %d completadas, %d con error.", counts.done, counts.failed)
	default:
		p.logf("INFO", "Recolección finalizada: %d fuentes completadas.", counts.done)
	}
	p.phase = phDone
	pKillTimer.Call(p.hwnd, 1)
	guiOutcome.Ran, guiOutcome.Results, guiOutcome.Err = true, res, err
	if r.closeAfter {
		pDestroyWindow.Call(p.hwnd)
		return
	}
	p.clampScroll()
	p.redraw()
}

type runCounts struct{ done, failed, skipped, cancelled, pending, running int }

func (p *picker) counts() runCounts {
	var c runCounts
	if p.run == nil {
		return c
	}
	for _, it := range p.run.items {
		switch it.state {
		case stDone:
			c.done++
		case stFailed:
			c.failed++
		case stSkipped:
			c.skipped++
		case stCancelled:
			c.cancelled++
		case stRunning:
			c.running++
		default:
			c.pending++
		}
	}
	return c
}

func (p *picker) requestCancel() {
	r := p.run
	if r == nil || r.cancelReq || (p.phase != phPreparing && p.phase != phRunning) {
		return
	}
	r.cancelReq = true
	p.phase = phCancelling
	r.cancel()
	p.logf("WARN", "Cancelación solicitada. Se detendrá al terminar la operación en curso; la evidencia ya adquirida se conserva.")
	p.redraw()
}

func (p *picker) requestClose() {
	switch p.phase {
	case phSelect:
		p.err = errors.New("collection canceled by analyst")
		pDestroyWindow.Call(p.hwnd)
	case phPreparing, phRunning:
		p.run.closeAfter = true
		p.requestCancel()
	case phCancelling:
		p.run.closeAfter = true
	default:
		pDestroyWindow.Call(p.hwnd)
	}
}

func (p *picker) activateRun(h hit) {
	r := p.run
	switch h.kind {
	case hitRunCancel:
		p.requestCancel()
	case hitRunLog:
		r.logOpen = !r.logOpen
		p.clampScroll()
	case hitRunOpen:
		dir := selectionContext.Output
		if dir == "" {
			dir = selectionContext.Store
		}
		openFolder(dir)
	case hitRunClose:
		pDestroyWindow.Call(p.hwnd)
		return
	case hitRunRow:
		r.sel = h.idx
	case hitLogCopy:
		p.copyLog()
	}
	p.redraw()
}

func (p *picker) keyDownRun(key uintptr) {
	r := p.run
	n := len(r.items)
	l := p.layout()
	page := max(1, int(l.runBody.B-l.runBody.T)/p.rowH()-1)
	move := func(to int) {
		if n == 0 {
			return
		}
		r.sel = max(0, min(n-1, to))
		r.manualScroll = true
		p.ensureVisible(r.sel)
	}
	switch key {
	case 27:
		if p.phase == phDone {
			pDestroyWindow.Call(p.hwnd)
			return
		}
	case 38:
		move(r.sel - 1)
	case 40:
		move(r.sel + 1)
	case 33:
		move(r.sel - page)
	case 34:
		move(r.sel + page)
	case 36:
		move(0)
	case 35:
		move(n - 1)
	case 0x43: // Ctrl+C
		if ctrlDown() {
			p.copyLog()
		}
	}
	p.redraw()
}

func (p *picker) hitTestRun(l layout, x, y int) hit {
	r := p.run
	if r == nil {
		return hit{}
	}
	switch {
	case in(l.bLog, x, y):
		return hit{hitRunLog, 0}
	case p.phase == phDone && in(l.bOpen, x, y):
		return hit{hitRunOpen, 0}
	case p.phase == phDone && in(l.bClose, x, y):
		return hit{hitRunClose, 0}
	case p.phase != phDone && in(l.bCancelRun, x, y):
		return hit{hitRunCancel, 0}
	case r.logOpen && in(l.logCopy, x, y):
		return hit{hitLogCopy, 0}
	case in(l.info, x, y):
		return hit{hitInfo, p.infoCell(l, x)}
	case in(l.runBody, x, y):
		i := (y - int(l.runBody.T) + p.scroll) / p.rowH()
		if i >= 0 && i < len(r.items) {
			return hit{hitRunRow, i}
		}
	}
	return hit{}
}

func (p *picker) scrollLog(delta int) {
	r := p.run
	r.logScroll += delta
	l := p.layout()
	maxScroll := p.logMax(l)
	r.logScroll = max(0, min(maxScroll, r.logScroll))
	r.logFollow = r.logScroll >= maxScroll
}

func (p *picker) logLines(l layout) (lineH, view int) {
	lineH = p.s(17)
	view = max(1, (int(l.log.B)-int(l.log.T)-p.s(48))/lineH)
	return
}

func (p *picker) logMax(l layout) int {
	_, view := p.logLines(l)
	return max(0, len(p.run.log)-view)
}

// ---- presentation helpers ----

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func clock(d time.Duration) string {
	s := int(d.Round(time.Second) / time.Second)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

func shortDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d m %02d s", int(d.Minutes()), int(d.Seconds())%60)
	}
	return clock(d)
}

func (p *picker) elapsed() time.Duration {
	r := p.run
	if r == nil {
		return 0
	}
	if !r.finishedAt.IsZero() {
		return r.finishedAt.Sub(r.startedAt)
	}
	return time.Since(r.startedAt)
}

func stateLabel(s itemState) (string, uint32) {
	switch s {
	case stRunning:
		return "En ejecución", colLime
	case stDone:
		return "Completada", colOK
	case stFailed:
		return "Error", colErr
	case stSkipped:
		return "Omitida", colMuted
	case stCancelled:
		return "Cancelada", colWarn
	}
	return "Pendiente", colDim
}

func (p *picker) runSubtitle() string {
	r := p.run
	switch p.phase {
	case phPreparing:
		return "Preparando la recolección y expandiendo los grupos de fuentes…"
	case phRunning:
		return "Recopilando evidencia. Cada artefacto se almacena con hash SHA-256 y registro de custodia."
	case phCancelling:
		return "Cancelando: se espera a que termine la operación en curso. La evidencia ya adquirida se conserva."
	}
	switch r.outcome {
	case ocComplete:
		return "Todas las fuentes procesadas se almacenaron correctamente."
	case ocPartial:
		return "Algunas fuentes fallaron o se interrumpieron; el resto de la evidencia quedó almacenada."
	case ocCancelled:
		return "La recolección se canceló. La evidencia adquirida antes de cancelar se conservó."
	}
	return "No se generó evidencia. Revisa el registro para ver la causa."
}

func (p *picker) statusChip() (string, uint32) {
	switch p.phase {
	case phPreparing:
		return "PREPARANDO", colMuted
	case phRunning:
		return "EN EJECUCIÓN", colLime
	case phCancelling:
		return "CANCELANDO", colWarn
	}
	switch p.run.outcome {
	case ocComplete:
		return "FINALIZADA", colOK
	case ocPartial:
		return "FINALIZADA CON ERRORES", colWarn
	case ocCancelled:
		return "CANCELADA", colWarn
	}
	return "FALLÓ", colErr
}

func (p *picker) drawStatusChip(c canvas, l layout) {
	s := p.s
	label, col := p.statusChip()
	w := p.textWidth(p.f.tiny, label) + s(28)
	x := l.w - s(262) - w - s(14)
	r := rc(x, s(30), x+w, s(30)+s(24))
	c.round(r, s(12), colElev, col)
	c.text(label, r, p.f.tiny, col, dtCenter|dtVCenter)
}

func lerp(a, b uint32, t int, of int) uint32 {
	ch := func(sh uint) uint32 {
		x, y := int(a>>sh&0xFF), int(b>>sh&0xFF)
		return uint32(x + (y-x)*t/of)
	}
	return ch(0) | ch(8)<<8 | ch(16)<<16
}

func (p *picker) pulse() uint32 {
	ms := int(time.Now().UnixMilli() % 1200)
	if ms > 600 {
		ms = 1200 - ms
	}
	return lerp(colLimeDark, colLime, ms, 600)
}

func (p *picker) runColumns(l layout) [4]int {
	left, right := int(l.runHdr.L), int(l.runHdr.R)
	body := right - left - p.s(32)
	var cols [4]int
	cols[0] = left + p.s(16)
	cols[1] = cols[0] + body*30/100
	cols[2] = cols[1] + body*16/100
	cols[3] = cols[2] + body*10/100
	return cols
}

func (p *picker) runTip(l layout, idx, x int) string {
	cols, s := p.runColumns(l), p.s
	right := int(l.runHdr.R) - s(16)
	it := p.run.items[idx]
	if x >= cols[0] && x < cols[1] && p.truncated(p.f.body, it.id, cols[1]-cols[0]-s(10)) {
		return it.id
	}
	if x >= cols[3] && p.truncated(p.f.body, it.result, right-cols[3]) {
		if it.detail != "" {
			return it.detail
		}
		return it.result
	}
	return ""
}

// ---- drawing ----

func (p *picker) drawRun(c canvas, l layout) {
	p.drawProgress(c, l)
	p.drawRunTable(c, l)
	if p.run.logOpen {
		p.drawLog(c, l)
	}
	p.drawRunFooter(c, l)
}

func (p *picker) drawProgress(c canvas, l layout) {
	s, r := p.s, p.run
	c.round(l.prog, s(10), colPanel, colBorder)
	cnt := p.counts()
	total := len(r.items)
	finished := cnt.done + cnt.failed + cnt.skipped // cancelled sources were never processed
	px, py, pw := int(l.prog.L)+s(18), int(l.prog.T), int(l.prog.R-l.prog.L)-s(36)

	title := "Preparando recolección…"
	switch {
	case p.phase == phDone:
		title = map[outcome]string{ocComplete: "Recolección finalizada", ocPartial: "Recolección finalizada con errores", ocCancelled: "Recolección cancelada", ocFailed: "La recolección falló"}[r.outcome]
	case p.phase == phCancelling:
		title = fmt.Sprintf("Cancelando… %d de %d fuentes procesadas", finished, total)
	case total > 0:
		title = fmt.Sprintf("%d de %d fuentes procesadas", finished, total)
	}
	c.text(title, rc(px, py+s(10), px+pw-s(220), py+s(38)), p.f.section, colText, dtLeft|dtVCenter|dtEllipsis)
	label := "Transcurrido "
	if p.phase == phDone {
		label = "Duración total "
	}
	c.text(label+clock(p.elapsed()), rc(px+pw-s(220), py+s(10), px+pw, py+s(38)), p.f.body, colMuted, dtRight|dtVCenter)

	// progress bar: terminal sources divided by the real plan size
	bar := rc(px, py+s(46), px+pw, py+s(54))
	c.round(bar, s(4), colElev, colElev)
	if total > 0 && finished > 0 {
		fillCol := colLime
		if p.phase == phDone {
			fillCol = map[outcome]uint32{ocComplete: colOK, ocPartial: colWarn, ocCancelled: colWarn, ocFailed: colErr}[r.outcome]
		} else if p.phase == phCancelling {
			fillCol = colWarn
		}
		w := max(s(8), pw*finished/total)
		c.round(rc(px, py+s(46), px+w, py+s(54)), s(4), fillCol, fillCol)
	}

	// counters
	x := px
	chip := func(col uint32, text string) {
		c.dot(x+s(4), py+s(72), s(4), col)
		w := p.textWidth(p.f.small, text)
		c.text(text, rc(x+s(14), py+s(62), x+s(14)+w+s(4), py+s(82)), p.f.small, colMuted, dtLeft|dtVCenter)
		x += s(14) + w + s(22)
	}
	chip(colOK, fmt.Sprintf("Completadas %d", cnt.done))
	chip(colErr, fmt.Sprintf("Con error %d", cnt.failed))
	chip(colMuted, fmt.Sprintf("Omitidas %d", cnt.skipped))
	if cnt.cancelled > 0 || p.phase == phDone && r.outcome == ocCancelled {
		chip(colWarn, fmt.Sprintf("Canceladas %d", cnt.cancelled))
	}
	if p.phase != phDone {
		chip(colDim, fmt.Sprintf("Restantes %d", total-finished))
	}

	// activity / destination line
	var line string
	if p.phase == phDone {
		line = packageLine()
	} else {
		line = "Actividad actual: "
		cur := ""
		for _, it := range r.items {
			if it.state == stRunning {
				cur = it.id + " · " + it.locator
			}
		}
		switch {
		case p.phase == phCancelling:
			line += "esperando que termine la operación en curso…"
		case cur != "":
			line += cur
		default:
			line += "—"
		}
		if eta := p.eta(cnt, total); eta != "" {
			line += "   ·   " + eta
		}
	}
	c.text(line, rc(px, py+s(86), px+pw, py+s(108)), p.f.small, colMuted, dtLeft|dtVCenter|dtEllipsis)
}

// eta is shown only with enough real measurements; it is an average, not a promise.
func (p *picker) eta(cnt runCounts, total int) string {
	finished := cnt.done + cnt.failed + cnt.skipped
	remaining := total - finished
	if p.phase != phRunning || finished < 5 || remaining <= 0 || p.elapsed() < 8*time.Second {
		return ""
	}
	var spent time.Duration
	for _, it := range p.run.items {
		if it.state != stPending && it.state != stRunning {
			spent += it.dur
		}
	}
	est := spent / time.Duration(finished) * time.Duration(remaining)
	return "Tiempo restante estimado ~" + clock(est) + " (promedio; puede variar)"
}

func (p *picker) drawRunTable(c canvas, l layout) {
	s, r := p.s, p.run
	c.round(l.runPanel, s(10), colPanelAlt, colBorder)
	cols := p.runColumns(l)
	left, right := int(l.runHdr.L), int(l.runHdr.R)
	c.fill(l.runHdr, rgb(0x0E, 0x18, 0x11))
	hy0, hy1 := int(l.runHdr.T), int(l.runHdr.B)
	rightEdge := right - s(16)
	for i, h := range []string{"Fuente", "Estado", "Duración", "Resultado"} {
		end := rightEdge
		if i < 3 {
			end = cols[i+1]
		}
		c.text(h, rc(cols[i], hy0, end, hy1), p.f.bold, colMuted, dtLeft|dtVCenter)
	}
	saved, _, _ := pSaveDC.Call(c.dc)
	pIntersectClipRect.Call(c.dc, uintptr(l.runBody.L), uintptr(l.runBody.T), uintptr(l.runBody.R), uintptr(l.runBody.B))
	rh := p.rowH()
	if len(r.items) == 0 {
		c.text("Expandiendo fuentes y preparando el plan…", rc(left, int(l.runBody.T)+s(20), right, int(l.runBody.T)+s(48)), p.f.body, colDim, dtCenter|dtVCenter)
	}
	for i, it := range r.items {
		y0 := int(l.runBody.T) + i*rh - p.scroll
		if y0+rh < int(l.runBody.T) || y0 > int(l.runBody.B) {
			continue
		}
		y1 := y0 + rh
		switch {
		case i == r.sel:
			c.fill(rc(left, y0, right, y1), colSelBG)
		case p.hover.kind == hitRunRow && p.hover.idx == i:
			c.fill(rc(left, y0, right, y1), colHover)
		}
		c.fill(rc(left, y1-1, right, y1), colLine)
		label, col := stateLabel(it.state)
		c.text(it.id, rc(cols[0], y0, cols[1]-s(10), y1), p.f.body, colText, dtLeft|dtVCenter|dtEllipsis)
		dotCol := col
		if it.state == stRunning {
			dotCol = p.pulse()
		}
		c.dot(cols[1]+s(4), (y0+y1)/2, s(4), dotCol)
		c.text(label, rc(cols[1]+s(16), y0, cols[2]-s(6), y1), p.f.body, col, dtLeft|dtVCenter)
		dur := "—"
		switch it.state {
		case stRunning:
			dur = shortDur(time.Since(it.started))
		case stPending:
		default:
			if it.dur > 0 {
				dur = shortDur(it.dur)
			}
		}
		c.text(dur, rc(cols[2], y0, cols[3]-s(10), y1), p.f.body, colMuted, dtLeft|dtVCenter)
		res := it.result
		resCol := colMuted
		switch it.state {
		case stRunning:
			res, resCol = "Recopilando…", colText
		case stPending:
			res = "—"
		case stFailed:
			resCol = colErr
		case stCancelled:
			resCol = colWarn
		}
		c.text(res, rc(cols[3], y0, rightEdge, y1), p.f.body, resCol, dtLeft|dtVCenter|dtEllipsis)
	}
	if total := len(r.items) * rh; total > int(l.runBody.B-l.runBody.T) {
		view := int(l.runBody.B - l.runBody.T)
		th := max(s(30), view*view/total)
		ty := int(l.runBody.T) + p.scroll*(view-th)/(total-view)
		c.round(rc(right-s(7), ty, right-s(3), ty+th), s(2), rgb(0x2E, 0x44, 0x35), rgb(0x2E, 0x44, 0x35))
	}
	pRestoreDC.Call(c.dc, saved)

	// detail strip for the selected source
	c.fill(l.detail, rgb(0x0E, 0x18, 0x11))
	c.fill(rc(left, int(l.detail.T), right, int(l.detail.T)+1), colLine)
	text, col := "Selecciona una fuente para ver su detalle completo.", colDim
	if r.sel >= 0 && r.sel < len(r.items) {
		it := r.items[r.sel]
		text, col = it.id+" — "+firstNonEmpty(strings.ReplaceAll(it.detail, "\n", "  "), it.result, "sin detalle todavía"), colMuted
		if it.state == stFailed {
			col = colErr
		}
	}
	c.text(text, rc(left+s(16), int(l.detail.T), right-s(16), int(l.detail.B)), p.f.small, col, dtLeft|dtVCenter|dtEllipsis)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (p *picker) drawLog(c canvas, l layout) {
	s, r := p.s, p.run
	c.round(l.log, s(10), colPanelAlt, colBorder)
	c.text("Registro de eventos", rc(int(l.log.L)+s(16), int(l.log.T)+s(8), int(l.log.L)+s(300), int(l.log.T)+s(36)), p.f.bold, colText, dtLeft|dtVCenter)
	hot := p.hover.kind == hitLogCopy
	c.button(l.logCopy, "Copiar registro", "secondary", hot, true)
	lineH, view := p.logLines(l)
	maxScroll := p.logMax(l)
	if r.logFollow || r.logScroll > maxScroll {
		r.logScroll = maxScroll
	}
	y := int(l.log.T) + s(42)
	saved, _, _ := pSaveDC.Call(c.dc)
	pIntersectClipRect.Call(c.dc, uintptr(l.log.L)+uintptr(s(2)), uintptr(y), uintptr(l.log.R)-uintptr(s(2)), uintptr(l.log.B)-uintptr(s(4)))
	for i := r.logScroll; i < len(r.log) && i < r.logScroll+view+1; i++ {
		ln := r.log[i]
		col := colMuted
		switch ln.level {
		case "WARN":
			col = colWarn
		case "ERROR":
			col = colErr
		}
		c.text(fmt.Sprintf("[%s] %-5s %s", ln.t.Format("15:04:05"), ln.level, ln.msg), rc(int(l.log.L)+s(16), y, int(l.log.R)-s(16), y+lineH), p.f.mono, col, dtLeft|dtVCenter|dtEllipsis)
		y += lineH
	}
	pRestoreDC.Call(c.dc, saved)
}

func (p *picker) drawRunFooter(c canvas, l layout) {
	s, r := p.s, p.run
	c.round(l.foot, s(10), colPanel, colBorder)
	fx, fy, fh := int(l.foot.L), int(l.foot.T), int(l.foot.B-l.foot.T)
	var note, noteCol = "Los datos se guardan localmente; nada sale del equipo.", colMuted
	switch p.phase {
	case phCancelling:
		note, noteCol = "Cancelando… la fuente en curso se detiene en su siguiente lectura.", colWarn
	case phDone:
		note = "Paquete de evidencia: " + selectionContext.Output
	}
	c.text("Destino", rc(fx+s(18), fy+s(14), int(l.bLog.L)-s(16), fy+s(34)), p.f.small, colDim, dtLeft|dtVCenter)
	c.text(note, rc(fx+s(18), fy+s(34), int(l.bLog.L)-s(16), fy+fh-s(12)), p.f.small, noteCol, dtLeft|dtVCenter|dtEllipsis)
	logLabel := "Ver registro"
	switch {
	case r.logOpen:
		logLabel = "Ocultar registro"
	case p.phase == phDone:
		logLabel = "Ver detalles"
	}
	c.button(l.bLog, logLabel, "secondary", p.hover.kind == hitRunLog, true)
	if p.phase == phDone {
		c.button(l.bOpen, "Abrir carpeta de evidencias", "accent", p.hover.kind == hitRunOpen, true)
		c.button(l.bClose, "Cerrar", "secondary", p.hover.kind == hitRunClose, true)
		return
	}
	label := "Cancelar recolección"
	if p.phase == phCancelling {
		label = "Cancelando…"
	}
	c.button(l.bCancelRun, label, "danger", p.hover.kind == hitRunCancel, p.phase != phCancelling)
}

// ---- shell helpers ----

func openFolder(dir string) {
	if dir == "" {
		return
	}
	verb, _ := windows.UTF16PtrFromString("open")
	path, _ := windows.UTF16PtrFromString(dir)
	pShellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), 0, 0, 1)
}

func (p *picker) copyLog() {
	var b strings.Builder
	for _, ln := range p.run.log {
		fmt.Fprintf(&b, "[%s] %-5s %s\r\n", ln.t.Format("15:04:05"), ln.level, ln.msg)
	}
	text, err := windows.UTF16FromString(b.String())
	if err != nil {
		return
	}
	if ok, _, _ := pOpenClipboard.Call(p.hwnd); ok == 0 {
		return
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	mem, _, _ := pGlobalAlloc.Call(0x2, uintptr(len(text)*2)) // GMEM_MOVEABLE
	if mem == 0 {
		return
	}
	locked, _, _ := pGlobalLock.Call(mem)
	if locked == 0 {
		return
	}
	dst := unsafe.Slice((*uint16)(*(*unsafe.Pointer)(unsafe.Pointer(&locked))), len(text))
	copy(dst, text)
	pGlobalUnlock.Call(mem)
	pSetClipboardData.Call(13, mem) // CF_UNICODETEXT; the clipboard now owns mem
	p.logf("INFO", "Registro copiado al portapapeles")
}

// packageLine describes the exported evidence package and its integrity verification.
func packageLine() string {
	switch {
	case packageOutcome.Summary != nil && packageOutcome.Summary.Verified:
		return fmt.Sprintf("Paquete: %s  ·  %d archivos, %s  ·  integridad SHA-256 verificada", packageOutcome.Dir, packageOutcome.Summary.Files, humanSize(packageOutcome.Summary.Bytes))
	case packageOutcome.Summary != nil:
		return fmt.Sprintf("Paquete: %s  ·  VERIFICACIÓN FALLIDA en %d archivo(s); revisa verification.json", packageOutcome.Dir, len(packageOutcome.Summary.VerifyErrors))
	case packageOutcome.Err != nil:
		return "Paquete no generado: " + packageOutcome.Err.Error()
	}
	return "Paquete: " + selectionContext.Output
}

// confirmSensitive asks before sources that read process memory or otherwise alter or
// expose sensitive state are collected.
func (p *picker) confirmSensitive(sens []collector.Source) bool {
	var b strings.Builder
	b.WriteString("Las siguientes fuentes son sensibles o alteran el sistema:\n\n")
	for _, s := range sens {
		fmt.Fprintf(&b, "• %s\n   %s\n", s.Meta.Name, s.Meta.SideEffects)
	}
	b.WriteString("\n¿Confirmas que estás autorizado a recopilarlas?")
	text, _ := windows.UTF16PtrFromString(b.String())
	title, _ := windows.UTF16PtrFromString("Mantis — confirmar fuentes sensibles")
	ret, _, _ := pMessageBox.Call(p.hwnd, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x4|0x30|0x100) // YESNO | WARNING | DEFBUTTON2
	return ret == 6
}
