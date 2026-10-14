//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// ---- layout ----

type layout struct {
	w, h                                          int
	header, info, side, main, search, filter      pickRect
	tableHdr, tableBody, foot, start, cancel, all pickRect
	sideTop, sideItemH                            int
	// execution screen
	prog, runPanel, runHdr, runBody, detail, log, logCopy pickRect
	bLog, bCancelRun, bOpen, bClose                       pickRect
	chips                                                 [4]pickRect
}

func rc(l, t, r, b int) pickRect { return pickRect{int32(l), int32(t), int32(r), int32(b)} }

func (p *picker) layout() layout {
	var client pickRect
	pGetClientRect.Call(p.hwnd, uintptr(unsafe.Pointer(&client)))
	W, H, s := int(client.R), int(client.B), p.s
	var l layout
	l.w, l.h = W, H
	l.header = rc(0, 0, W, s(92))
	l.info = rc(s(16), s(104), W-s(16), s(172))
	top := s(184)
	l.foot = rc(s(16), H-s(88), W-s(16), H-s(12))
	bottom := int(l.foot.T) - s(12)
	l.side = rc(s(16), top, s(236), bottom)
	l.main = rc(s(248), top, W-s(16), bottom)
	l.filter = rc(int(l.main.R)-s(12)-s(124), top+s(10), int(l.main.R)-s(12), top+s(46))
	chipW, chipGap := s(70), s(6)
	cx := int(l.filter.L) - s(10) - (4*chipW + 3*chipGap)
	for i := range l.chips {
		x0 := cx + i*(chipW+chipGap)
		l.chips[i] = rc(x0, top+s(10), x0+chipW, top+s(46))
	}
	l.search = rc(int(l.main.L)+s(12), top+s(10), cx-s(10), top+s(46))
	l.tableHdr = rc(int(l.main.L)+1, top+s(56), int(l.main.R)-1, top+s(88))
	l.tableBody = rc(int(l.main.L)+1, top+s(88), int(l.main.R)-1, int(l.main.B)-s(4))
	btnT, btnB := int(l.foot.T)+s(16), int(l.foot.B)-s(16)
	R := int(l.foot.R) - s(16)
	l.cancel = rc(R-s(112), btnT, R, btnB)
	l.start = rc(int(l.cancel.L)-s(12)-s(176), btnT, int(l.cancel.L)-s(12), btnB)
	l.all = rc(int(l.start.L)-s(12)-s(168), btnT, int(l.start.L)-s(12), btnB)
	l.sideTop, l.sideItemH = top+s(10), s(36)

	// execution screen
	l.prog = rc(s(16), top, W-s(16), top+s(116))
	panelBottom := bottom
	if p.run != nil && p.run.logOpen {
		avail := bottom - (int(l.prog.B) + s(12))
		logH := max(s(96), min(s(160), avail*40/100)) // keep room for the source table
		l.log = rc(s(16), bottom-logH, W-s(16), bottom)
		l.logCopy = rc(int(l.log.R)-s(12)-s(150), int(l.log.T)+s(8), int(l.log.R)-s(12), int(l.log.T)+s(36))
		panelBottom = int(l.log.T) - s(12)
	}
	l.runPanel = rc(s(16), int(l.prog.B)+s(12), W-s(16), panelBottom)
	l.runHdr = rc(int(l.runPanel.L)+1, int(l.runPanel.T)+1, int(l.runPanel.R)-1, int(l.runPanel.T)+s(33))
	l.detail = rc(int(l.runPanel.L)+1, int(l.runPanel.B)-s(34), int(l.runPanel.R)-1, int(l.runPanel.B)-1)
	l.runBody = rc(int(l.runPanel.L)+1, int(l.runHdr.B), int(l.runPanel.R)-1, int(l.detail.T))
	l.bClose = rc(R-s(112), btnT, R, btnB)
	l.bOpen = rc(int(l.bClose.L)-s(12)-s(236), btnT, int(l.bClose.L)-s(12), btnB)
	l.bCancelRun = rc(R-s(210), btnT, R, btnB)
	last := int(l.bOpen.L)
	if p.phase != phDone {
		last = int(l.bCancelRun.L)
	}
	l.bLog = rc(last-s(12)-s(150), btnT, last-s(12), btnB)
	return l
}

func (p *picker) rowH() int { return p.s(34) }

// bodyRect is the scrollable table body of the active screen.
func (l layout) body(ph phase) pickRect {
	if ph == phSelect {
		return l.tableBody
	}
	return l.runBody
}

func (p *picker) rowCount() int {
	if p.phase == phSelect {
		return len(p.visible)
	}
	if p.run == nil {
		return 0
	}
	return len(p.run.items)
}

func (p *picker) clampScroll() {
	l := p.layout()
	b := l.body(p.phase)
	max := p.rowCount()*p.rowH() - int(b.B-b.T)
	if max < 0 {
		max = 0
	}
	if p.scroll > max {
		p.scroll = max
	}
	if p.scroll < 0 {
		p.scroll = 0
	}
}

func (p *picker) ensureVisible(row int) {
	l := p.layout()
	b := l.body(p.phase)
	view := int(b.B - b.T)
	if top := row * p.rowH(); top < p.scroll {
		p.scroll = top
	} else if bottom := top + p.rowH(); bottom > p.scroll+view {
		rh := p.rowH() // snap to a row boundary so the first visible row is never cut
		p.scroll = (bottom - view + rh - 1) / rh * rh
	}
	p.clampScroll()
}

func (p *picker) placeEdit() {
	l := p.layout()
	s := p.s
	x, w := int(l.search.L)+s(38), int(l.search.R-l.search.L)-s(48)
	h := s(18)
	pMoveWindow.Call(p.edit, uintptr(x), uintptr(int(l.search.T)+(int(l.search.B-l.search.T)-h)/2), uintptr(w), uintptr(h), 1)
	vis := uintptr(0)
	if p.phase == phSelect {
		vis = 5
	}
	pShowWindow.Call(p.edit, vis)
}

func in(r pickRect, x, y int) bool {
	return x >= int(r.L) && x < int(r.R) && y >= int(r.T) && y < int(r.B)
}

// selColumns returns the left edge of each table column and the usable width.
func (p *picker) selColumns(l layout) ([5]int, int) {
	left, right := int(l.tableHdr.L), int(l.tableHdr.R)
	body := right - left - p.s(80) - p.s(20)
	var cols [5]int
	cols[0] = left + p.s(80)
	cols[1] = cols[0] + body*28/100
	cols[2] = cols[1] + body*31/100
	cols[3] = cols[2] + body*11/100
	cols[4] = cols[3] + body*12/100
	return cols, body
}

func (p *picker) hitTest(x, y int) hit {
	l := p.layout()
	if p.phase != phSelect {
		return p.hitTestRun(l, x, y)
	}
	switch {
	case in(l.start, x, y):
		return hit{hitStart, 0}
	case in(l.cancel, x, y):
		return hit{hitCancel, 0}
	case in(l.all, x, y):
		return hit{hitAll, 0}
	case in(l.filter, x, y):
		return hit{hitFilter, 0}
	case in(l.info, x, y):
		return hit{hitInfo, p.infoCell(l, x)}
	case in(l.tableHdr, x, y):
		if x < int(l.tableHdr.L)+p.s(48) {
			return hit{hitHeaderCheck, 0}
		}
	case in(l.tableBody, x, y):
		i := (y - int(l.tableBody.T) + p.scroll) / p.rowH()
		if i >= 0 && i < len(p.visible) {
			return hit{hitRow, i}
		}
	case in(l.side, x, y):
		i := (y - l.sideTop + p.sideScroll) / l.sideItemH
		if y >= l.sideTop && i >= 0 {
			if i == 0 {
				return hit{hitSideAll, 0}
			}
			if i-1 < len(p.cats) {
				return hit{hitSideCat, i - 1}
			}
		}
	}
	for i, c := range l.chips {
		if in(c, x, y) {
			return hit{hitProfile, i}
		}
	}
	return hit{}
}

var infoWidths = []int{18, 17, 25, 40}

func (p *picker) infoCell(l layout, x int) int {
	total, left := int(l.info.R-l.info.L), int(l.info.L)
	for i, w := range infoWidths {
		left += total * w / 100
		if x < left {
			return i
		}
	}
	return len(infoWidths) - 1
}

func (p *picker) clickable(h hit) bool {
	switch h.kind {
	case hitNone, hitInfo:
		return false
	case hitStart:
		return p.selectedCount() > 0
	case hitRunCancel:
		return p.phase == phPreparing || p.phase == phRunning
	}
	return true
}

// ---- actions ----

func (p *picker) activate(h hit) {
	switch h.kind {
	case hitSideAll:
		p.cat, p.scroll = -1, 0
		p.refilter()
	case hitSideCat:
		p.cat, p.scroll = h.idx, 0
		p.refilter()
	case hitFilter:
		p.show = (p.show + 1) % 3
		p.scroll = 0
		p.refilter()
	case hitHeaderCheck:
		p.profile = collector.ProfileCustom
		all := true
		for _, i := range p.visible {
			all = all && p.rows[i].on
		}
		for _, i := range p.visible {
			p.rows[i].on = !all
		}
		p.refilter()
	case hitRow:
		p.cur = h.idx
		p.toggleRow(h.idx)
		p.profile = collector.ProfileCustom
	case hitAll:
		on := p.selectedCount() < len(p.rows)
		for i := range p.rows {
			p.rows[i].on = on && !p.rows[i].src.Meta.Sensitive
		}
		p.profile = collector.ProfileCustom
		p.refilter()
	case hitProfile:
		p.applyProfile([]collector.Profile{collector.ProfileQuick, collector.ProfileStandard, collector.ProfileFull, collector.ProfileCustom}[h.idx])
	case hitStart:
		p.startCollection()
		return
	case hitCancel:
		p.err = errors.New("collection canceled by analyst")
		pDestroyWindow.Call(p.hwnd)
		return
	default:
		p.activateRun(h)
		return
	}
	p.redraw()
}

func (p *picker) toggleRow(visibleIdx int) {
	if visibleIdx < 0 || visibleIdx >= len(p.visible) {
		return
	}
	i := p.visible[visibleIdx]
	p.rows[i].on = !p.rows[i].on
	if p.show != 0 {
		p.refilter()
	}
}

func (p *picker) selectedCount() int {
	n := 0
	for _, r := range p.rows {
		if r.on {
			n++
		}
	}
	return n
}

func (p *picker) redraw() { pInvalidateRect.Call(p.hwnd, 0, 0) }

func (p *picker) updateQuery() {
	buf := make([]uint16, 256)
	n, _, _ := pGetWindowText.Call(p.edit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	p.query = windows.UTF16ToString(buf[:n])
	p.scroll, p.cur = 0, 0
	p.refilter()
	p.redraw()
}

func ctrlDown() bool {
	r, _, _ := pGetKeyState.Call(0x11)
	return int16(r) < 0
}

// ---- tooltips (full text of truncated cells) ----

func (p *picker) textWidth(font uintptr, text string) int {
	dc, _, _ := pGetDC.Call(p.hwnd)
	defer pReleaseDC.Call(p.hwnd, dc)
	pSelectObject.Call(dc, font)
	ptr, _ := windows.UTF16PtrFromString(text)
	var size struct{ W, H int32 }
	n := len(windows.StringToUTF16(text)) - 1
	pGetTextExtent.Call(dc, uintptr(unsafe.Pointer(ptr)), uintptr(n), uintptr(unsafe.Pointer(&size)))
	return int(size.W)
}

func (p *picker) truncated(font uintptr, text string, avail int) bool {
	return text != "" && p.textWidth(font, text) > avail
}

func (p *picker) tipAt(x, y int) string {
	l := p.layout()
	h := p.hitTest(x, y)
	s := p.s
	switch {
	case h.kind == hitInfo:
		host, _ := os.Hostname()
		vals := []string{selectionContext.Case, host, selectionContext.Profile, selectionContext.Store}
		total, left := int(l.info.R-l.info.L), int(l.info.L)
		for i := 0; i < h.idx; i++ {
			left += total * infoWidths[i] / 100
		}
		avail := total*infoWidths[h.idx]/100 - s(62) - s(14)
		if p.truncated(p.f.body, vals[h.idx], avail) {
			return vals[h.idx]
		}
	case h.kind == hitRow && p.phase == phSelect:
		row := p.rows[p.visible[h.idx]]
		cols, _ := p.selColumns(l)
		name := rowName(row)
		if x >= cols[0] && x < cols[1] && p.truncated(p.f.body, name, cols[1]-cols[0]-s(10)) {
			return name + "\n(" + row.src.ID + ")"
		}
		if x >= cols[1] && x < cols[2] && p.truncated(p.f.body, row.src.Locator, cols[2]-cols[1]-s(10)) {
			return row.src.Locator
		}
		if x >= cols[0] && x < cols[1] && row.src.Meta.Description != "" {
			return row.src.Meta.Description
		}
		if x >= cols[4] && row.avail.Reason != "" {
			return row.avail.Reason
		}
	case h.kind == hitRunRow:
		return p.runTip(l, h.idx, x)
	}
	return ""
}

func (p *picker) updateTip(x, y int) {
	text := p.tipAt(x, y)
	if text == p.tipText {
		return
	}
	p.tipText, p.tipShown, p.tipX, p.tipY = text, false, x, y
	pKillTimer.Call(p.hwnd, 2)
	if text != "" {
		pSetTimer.Call(p.hwnd, 2, 450, 0)
	}
}

func (p *picker) drawTip(c canvas, l layout) {
	if !p.tipShown || p.tipText == "" {
		return
	}
	s := p.s
	maxW := min(s(560), l.w-s(32))
	r := rc(0, 0, maxW, 0)
	ptr, _ := windows.UTF16PtrFromString(p.tipText)
	pSelectObject.Call(c.dc, p.f.small)
	pDrawText.Call(c.dc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), 0x400|0x10|0x800) // CALCRECT|WORDBREAK|NOPREFIX
	w, h := int(r.R)+s(20), int(r.B)+s(14)
	x, y := p.tipX+s(14), p.tipY+s(20)
	if x+w > l.w-s(8) {
		x = l.w - s(8) - w
	}
	if y+h > l.h-s(8) {
		y = p.tipY - h - s(8)
	}
	box := rc(x, y, x+w, y+h)
	c.round(box, s(6), colElev, rgb(0x3A, 0x55, 0x42))
	c.textWrap(p.tipText, rc(x+s(10), y+s(7), x+w-s(10), y+h-s(7)), p.f.small, colText)
}

// ---- window procedure ----

func loword(v uintptr) int { return int(uint16(v)) }
func hiword(v uintptr) int { return int(uint16(v >> 16)) }

func pickerProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	p := activePicker
	if p == nil {
		r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
		return r
	}
	switch message {
	case wmCreate:
		p.hwnd = hwnd
		p.create()
		return 0
	case wmGetMinMax:
		// MINMAXINFO.ptMinTrackSize is at offset 24 (three POINTs precede it plus the reserved one).
		info := *(*unsafe.Pointer)(unsafe.Pointer(&lParam))
		size := (*[2]int32)(unsafe.Add(info, 24))
		size[0], size[1] = int32(p.s(960)), int32(p.s(620))
		return 0
	case wmSize:
		if p.edit != 0 && wParam != 1 { // not minimized
			p.placeEdit()
			p.clampScroll()
			p.redraw()
		}
		return 0
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		p.paint()
		return 0
	case wmTimer:
		switch wParam {
		case 1:
			p.redraw()
		case 2:
			pKillTimer.Call(hwnd, 2)
			if p.tipText != "" {
				p.tipShown = true
				p.redraw()
			}
		}
		return 0
	case wmProbe:
		p.applyProbes()
		return 0
	case wmRunEvents:
		p.drainRunEvents()
		return 0
	case wmRunDone:
		p.finishRun()
		return 0
	case wmCtlColorEdit:
		if lParam == p.edit {
			c := colText
			if p.placeholder {
				c = colDim
			}
			pSetTextColor.Call(wParam, uintptr(c))
			pSetBkColor.Call(wParam, uintptr(colPanelAlt))
			return p.editBrush
		}
	case wmCommand:
		if loword(wParam) == idSearch {
			switch hiword(wParam) {
			case enSetFocus:
				if p.placeholder {
					p.placeholder = false
					p.setEditText("")
				}
			case enKillFocus:
				if p.query == "" {
					p.placeholder = true
					p.setEditText(placeholderText)
				}
			case enChange:
				if !p.settingText && !p.placeholder {
					p.updateQuery()
				}
			}
			return 0
		}
	case wmMouseMove:
		x, y := int(int16(lParam)), int(int16(lParam>>16))
		h := p.hitTest(x, y)
		if !p.tracking {
			tme := trackMouse{Size: uint32(unsafe.Sizeof(trackMouse{})), Flags: 2, Hwnd: hwnd}
			pTrackMouseEvent.Call(uintptr(unsafe.Pointer(&tme)))
			p.tracking = true
		}
		redraw := false
		if h != p.hover {
			p.hover = h
			redraw = true
		}
		wasShown := p.tipShown
		p.updateTip(x, y)
		if redraw || wasShown != p.tipShown {
			p.redraw()
		}
		return 0
	case wmMouseLeave:
		p.tracking = false
		p.hover = hit{}
		p.tipText, p.tipShown = "", false
		pKillTimer.Call(hwnd, 2)
		p.redraw()
		return 0
	case wmSetCursor:
		if loword(lParam) == 1 && p.clickable(p.hover) {
			c, _, _ := pLoadCursor.Call(0, 32649)
			pSetCursor.Call(c)
			return 1
		}
	case wmLButtonDown:
		x, y := int(int16(lParam)), int(int16(lParam>>16))
		pSetFocus.Call(hwnd)
		p.tipShown = false
		if h := p.hitTest(x, y); p.clickable(h) {
			p.activate(h)
		}
		return 0
	case wmMouseWheel:
		delta := int(int16(wParam >> 16))
		x, y := int(int16(lParam)), int(int16(lParam>>16))
		var pt pickPoint
		pt.X, pt.Y = int32(x), int32(y)
		pScreenToClient.Call(hwnd, uintptr(unsafe.Pointer(&pt)))
		l := p.layout()
		if p.phase == phSelect && in(l.side, int(pt.X), int(pt.Y)) {
			p.sideScroll = max(0, p.sideScroll-delta/120*l.sideItemH*2)
		} else if p.run != nil && p.run.logOpen && p.phase != phSelect && in(l.log, int(pt.X), int(pt.Y)) {
			p.scrollLog(-delta / 120 * 3)
		} else {
			p.scroll -= delta / 120 * p.rowH() * 3
			if p.run != nil {
				p.run.manualScroll = true
			}
			p.clampScroll()
		}
		p.redraw()
		return 0
	case wmKeyDown:
		return p.keyDown(wParam)
	case wmClose:
		p.requestClose()
		return 0
	case wmDestroy:
		pKillTimer.Call(hwnd, 1)
		pPostQuit.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func (p *picker) keyDown(key uintptr) uintptr {
	if p.phase != phSelect {
		p.keyDownRun(key)
		return 0
	}
	n := len(p.visible)
	move := func(to int) {
		if n == 0 {
			return
		}
		p.cur = max(0, min(n-1, to))
		p.ensureVisible(p.cur)
	}
	l := p.layout()
	page := max(1, int(l.tableBody.B-l.tableBody.T)/p.rowH()-1)
	switch key {
	case 27: // Esc
		p.activate(hit{hitCancel, 0})
		return 0
	case 13: // Enter
		if p.selectedCount() > 0 {
			p.startCollection()
		}
		return 0
	case 32: // Space
		p.toggleRow(p.cur)
	case 38:
		move(p.cur - 1)
	case 40:
		move(p.cur + 1)
	case 33:
		move(p.cur - page)
	case 34:
		move(p.cur + page)
	case 36:
		move(0)
	case 35:
		move(n - 1)
	case 0x41: // Ctrl+A
		if ctrlDown() {
			p.activate(hit{hitHeaderCheck, 0})
			return 0
		}
	case 0x46: // Ctrl+F
		if ctrlDown() {
			pSetFocus.Call(p.edit)
		}
	}
	p.redraw()
	return 0
}

// ---- painting primitives ----

type canvas struct {
	dc uintptr
	p  *picker
}

func (c canvas) fill(r pickRect, col uint32) {
	brush, _, _ := pGetStockObject.Call(18) // DC_BRUSH
	pSetDCBrushColor.Call(c.dc, uintptr(col))
	pFillRect.Call(c.dc, uintptr(unsafe.Pointer(&r)), brush)
}

func (c canvas) round(r pickRect, radius int, fill, border uint32) {
	brush, _, _ := pGetStockObject.Call(18)
	pen, _, _ := pGetStockObject.Call(19) // DC_PEN
	pSelectObject.Call(c.dc, brush)
	pSelectObject.Call(c.dc, pen)
	pSetDCBrushColor.Call(c.dc, uintptr(fill))
	pSetDCPenColor.Call(c.dc, uintptr(border))
	pRoundRect.Call(c.dc, uintptr(r.L), uintptr(r.T), uintptr(r.R), uintptr(r.B), uintptr(radius*2), uintptr(radius*2))
}

// ring draws a 1px outline without filling.
func (c canvas) ring(r pickRect, col uint32) {
	brush, _, _ := pGetStockObject.Call(5) // NULL_BRUSH
	pen, _, _ := pGetStockObject.Call(19)
	pSelectObject.Call(c.dc, brush)
	pSelectObject.Call(c.dc, pen)
	pSetDCPenColor.Call(c.dc, uintptr(col))
	pRoundRect.Call(c.dc, uintptr(r.L), uintptr(r.T), uintptr(r.R), uintptr(r.B), 0, 0)
}

func (c canvas) line(x1, y1, x2, y2 int, col uint32, width int) {
	pen, _, _ := pCreatePen.Call(0, uintptr(width), uintptr(col))
	old, _, _ := pSelectObject.Call(c.dc, pen)
	pMoveToEx.Call(c.dc, uintptr(x1), uintptr(y1), 0)
	pLineTo.Call(c.dc, uintptr(x2), uintptr(y2))
	pSelectObject.Call(c.dc, old)
	pDeleteObject.Call(pen)
}

func (c canvas) dot(cx, cy, rad int, col uint32) {
	brush, _, _ := pGetStockObject.Call(18)
	pen, _, _ := pGetStockObject.Call(19)
	pSelectObject.Call(c.dc, brush)
	pSelectObject.Call(c.dc, pen)
	pSetDCBrushColor.Call(c.dc, uintptr(col))
	pSetDCPenColor.Call(c.dc, uintptr(col))
	pEllipse.Call(c.dc, uintptr(cx-rad), uintptr(cy-rad), uintptr(cx+rad), uintptr(cy+rad))
}

const (
	dtLeft     = 0x0
	dtCenter   = 0x1
	dtRight    = 0x2
	dtVCenter  = 0x4
	dtSingle   = 0x20
	dtNoPrefix = 0x800
	dtEllipsis = 0x8000
)

func (c canvas) text(s string, r pickRect, font uintptr, col uint32, flags uintptr) {
	ptr, _ := windows.UTF16PtrFromString(s)
	pSelectObject.Call(c.dc, font)
	pSetTextColor.Call(c.dc, uintptr(col))
	pDrawText.Call(c.dc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags|dtSingle|dtNoPrefix)
}

// textWrap draws multi-line text (word break) inside r.
func (c canvas) textWrap(s string, r pickRect, font uintptr, col uint32) {
	ptr, _ := windows.UTF16PtrFromString(s)
	pSelectObject.Call(c.dc, font)
	pSetTextColor.Call(c.dc, uintptr(col))
	pDrawText.Call(c.dc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), 0x10|dtNoPrefix)
}

func (c canvas) check(r pickRect, on bool, hot bool) {
	if on {
		c.round(r, c.p.s(4), colLime, colLime)
		w, h := int(r.R-r.L), int(r.B-r.T)
		x, y := int(r.L), int(r.T)
		c.line(x+w*22/100, y+h*52/100, x+w*43/100, y+h*72/100, colBG, c.p.s(2))
		c.line(x+w*43/100, y+h*72/100, x+w*78/100, y+h*30/100, colBG, c.p.s(2))
		return
	}
	border := colDim
	if hot {
		border = colLime
	}
	c.round(r, c.p.s(4), colPanelAlt, border)
}

func (c canvas) button(r pickRect, label string, kind string, hot, enabled bool) {
	p := c.p
	switch kind {
	case "primary":
		fill, txt := colLime, colBG
		if !enabled {
			fill, txt = rgb(0x2A, 0x3A, 0x2C), colDim
		} else if hot {
			fill = rgb(0xC8, 0xFF, 0x6E)
		}
		c.round(r, p.s(8), fill, fill)
		mid := int(r.T) + int(r.B-r.T)/2
		tri := []pickPoint{{int32(int(r.L) + p.s(18)), int32(mid - p.s(7))}, {int32(int(r.L) + p.s(18)), int32(mid + p.s(7))}, {int32(int(r.L) + p.s(31)), int32(mid)}}
		brush, _, _ := pGetStockObject.Call(18)
		pen, _, _ := pGetStockObject.Call(19)
		pSelectObject.Call(c.dc, brush)
		pSelectObject.Call(c.dc, pen)
		pSetDCBrushColor.Call(c.dc, uintptr(txt))
		pSetDCPenColor.Call(c.dc, uintptr(txt))
		pPolygon.Call(c.dc, uintptr(unsafe.Pointer(&tri[0])), 3)
		tr := r
		tr.L += int32(p.s(36))
		c.text(label, tr, p.f.btn, txt, dtLeft|dtVCenter)
	case "accent":
		fill := colLime
		if hot {
			fill = rgb(0xC8, 0xFF, 0x6E)
		}
		c.round(r, p.s(8), fill, fill)
		c.text(label, r, p.f.btn, colBG, dtCenter|dtVCenter)
	case "danger":
		fill, border, txt := colBtn, rgb(0x6B, 0x3A, 0x3A), colErr
		if !enabled {
			border, txt = rgb(0x2E, 0x44, 0x35), colDim
		} else if hot {
			fill = rgb(0x2A, 0x1A, 0x1A)
		}
		c.round(r, p.s(8), fill, border)
		c.text(label, r, p.f.btn, txt, dtCenter|dtVCenter)
	default:
		fill := colBtn
		if hot && enabled {
			fill = colBtnHover
		}
		txt := colText
		if !enabled {
			txt = colDim
		}
		c.round(r, p.s(8), fill, rgb(0x2E, 0x44, 0x35))
		c.text(label, r, p.f.btn, txt, dtCenter|dtVCenter)
	}
}

func (p *picker) paint() {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(p.hwnd, uintptr(unsafe.Pointer(&ps)))
	defer pEndPaint.Call(p.hwnd, uintptr(unsafe.Pointer(&ps)))
	l := p.layout()
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	bmp, _, _ := pCreateCompatibleBitmap.Call(hdc, uintptr(l.w), uintptr(l.h))
	old, _, _ := pSelectObject.Call(mem, bmp)
	pSetBkMode.Call(mem, 1)
	c := canvas{dc: mem, p: p}
	p.drawAll(c, l)
	pBitBlt.Call(hdc, 0, 0, uintptr(l.w), uintptr(l.h), mem, 0, 0, 0x00CC0020)
	pSelectObject.Call(mem, old)
	pDeleteObject.Call(bmp)
	pDeleteDC.Call(mem)
}

func (p *picker) drawAll(c canvas, l layout) {
	c.fill(rc(0, 0, l.w, l.h), colBG)
	p.drawHeader(c, l)
	p.drawInfo(c, l)
	if p.phase == phSelect {
		p.drawSidebar(c, l)
		p.drawTable(c, l)
		p.drawSelectFooter(c, l)
	} else {
		p.drawRun(c, l)
	}
	p.drawTip(c, l)
}

func (p *picker) drawSelectFooter(c canvas, l layout) {
	s := p.s
	c.round(l.foot, s(10), colPanel, colBorder)
	n := p.selectedCount()
	fx, fy, fh := int(l.foot.L), int(l.foot.T), int(l.foot.B-l.foot.T)
	c.text(fmt.Sprint(n), rc(fx+s(14), fy, fx+s(70), fy+fh), p.f.big, colLime, dtCenter|dtVCenter)
	noun := "fuentes seleccionadas"
	if n == 1 {
		noun = "fuente seleccionada"
	}
	c.text(noun, rc(fx+s(80), fy+s(14), int(l.all.L)-s(24), fy+s(38)), p.f.bold, colText, dtLeft|dtVCenter|dtEllipsis)
	sub := "Listas para la recolección. No se ha recopilado nada aún."
	if n == 0 {
		sub = "Selecciona un perfil o fuentes individuales para iniciar. No se ha recopilado nada aún."
	} else if need := p.adminSelected(); need > 0 && !selectionContext.Elevated {
		sub = fmt.Sprintf("%d fuentes requieren administrador y Mantis no está elevado: se registrarán como acceso denegado.", need)
	}
	c.text(sub, rc(fx+s(80), fy+s(38), int(l.all.L)-s(24), fy+s(60)), p.f.small, colMuted, dtLeft|dtVCenter|dtEllipsis)
	c.line(int(l.all.L)-s(12), fy+s(14), int(l.all.L)-s(12), fy+fh-s(14), colBorder, 1)
	allLabel := "Seleccionar todas"
	if n == len(p.rows) {
		allLabel = "Ninguna"
	}
	c.button(l.all, allLabel, "secondary", p.hover.kind == hitAll, true)
	c.button(l.start, "Iniciar captura", "primary", p.hover.kind == hitStart, n > 0)
	c.button(l.cancel, "Cancelar", "secondary", p.hover.kind == hitCancel, true)
}

func (p *picker) drawHeader(c canvas, l layout) {
	s := p.s
	c.fill(l.header, colHeader)
	c.fill(rc(0, int(l.header.B)-1, l.w, int(l.header.B)), colLine)
	c.fill(rc(0, s(14), s(3), int(l.header.B)-s(14)), colLime)
	title, sub := "Seleccionar fuentes de evidencia", "Elige las fuentes para este caso. No se recopila nada hasta presionar Iniciar captura."
	if p.phase != phSelect {
		title, sub = "Recolección de evidencia", p.runSubtitle()
	}
	c.text(title, rc(s(28), s(10), l.w-s(380), s(48)), p.f.title, colText, dtLeft|dtVCenter)
	c.text(sub, rc(s(28), s(50), l.w-s(250), s(74)), p.f.sub, colMuted, dtLeft|dtVCenter|dtEllipsis)
	if p.phase != phSelect {
		p.drawStatusChip(c, l)
	}
	// compact brand block
	if p.mark != 0 {
		bx := l.w - s(262)
		src, _, _ := pCreateCompatibleDC.Call(c.dc)
		prev, _, _ := pSelectObject.Call(src, p.mark)
		const blend = 0x01FF0000 // AC_SRC_OVER, alpha 255, AC_SRC_ALPHA
		pAlphaBlend.Call(c.dc, uintptr(bx), uintptr(s(14)), uintptr(p.markSize), uintptr(p.markSize), src, 0, 0, uintptr(p.markSize), uintptr(p.markSize), blend)
		pSelectObject.Call(src, prev)
		pDeleteDC.Call(src)
		c.text("M A N T I S", rc(bx+p.markSize+s(10), s(24), l.w-s(12), s(50)), p.f.brand, colLime, dtLeft|dtVCenter)
		c.text("DFIR EVIDENCE COLLECTION", rc(bx+p.markSize+s(10), s(50), l.w-s(8), s(68)), p.f.tiny, colMuted, dtLeft|dtVCenter)
	}
}

func (p *picker) drawInfo(c canvas, l layout) {
	s := p.s
	c.round(l.info, s(10), colPanel, colBorder)
	host, _ := os.Hostname()
	priv := "Usuario estándar"
	if selectionContext.Elevated {
		priv = "Administrador"
	}
	cells := []struct{ glyph, label, value string }{
		{"\uE8A5", "Caso", selectionContext.Case},
		{"\uE7F4", "Host", host},
		{"\uE77B", "Perfil · privilegios", p.profileLabel() + " · " + priv},
		{"\uE838", "Paquete de evidencia", selectionContext.Output},
	}
	x := int(l.info.L)
	total := int(l.info.R - l.info.L)
	for i, cell := range cells {
		w := total * infoWidths[i] / 100
		if i > 0 {
			c.line(x, int(l.info.T)+s(12), x, int(l.info.B)-s(12), colBorder, 1)
		}
		c.text(cell.glyph, rc(x+s(12), int(l.info.T), x+s(40), int(l.info.B)), p.f.icon, colMuted, dtCenter|dtVCenter)
		c.text(cell.label, rc(x+s(50), int(l.info.T)+s(10), x+w-s(10), int(l.info.T)+s(28)), p.f.small, colMuted, dtLeft|dtVCenter)
		valCol := colText
		if i == 2 && !selectionContext.Elevated {
			valCol = colWarn
		}
		c.text(cell.value, rc(x+s(50), int(l.info.T)+s(30), x+w-s(14), int(l.info.B)-s(10)), p.f.body, valCol, dtLeft|dtVCenter|dtEllipsis)
		x += w
	}
}

func (p *picker) drawSidebar(c canvas, l layout) {
	s := p.s
	c.round(l.side, s(10), colPanelAlt, colBorder)
	type entry struct {
		cat          int
		glyph, label string
		count        int
	}
	entries := []entry{{-1, "\uE8FD", "Todas las fuentes", len(p.rows)}}
	for ci, cat := range p.cats {
		entries = append(entries, entry{ci, cat.glyph, cat.name, cat.count})
	}
	view := int(l.side.B) - l.sideTop - s(8)
	if total := len(entries) * l.sideItemH; p.sideScroll > total-view {
		p.sideScroll = max(0, total-view)
	}
	saved, _, _ := pSaveDC.Call(c.dc)
	pIntersectClipRect.Call(c.dc, uintptr(l.side.L), uintptr(l.side.T)+uintptr(s(2)), uintptr(l.side.R), uintptr(l.side.B)-uintptr(s(2)))
	for i, e := range entries {
		top := l.sideTop + i*l.sideItemH - p.sideScroll
		if top+l.sideItemH < int(l.side.T) || top > int(l.side.B) {
			continue
		}
		r := rc(int(l.side.L)+s(8), top, int(l.side.R)-s(8), top+l.sideItemH-s(4))
		active := e.cat == p.cat
		hot := p.hover.kind == hitSideAll && e.cat == -1 || p.hover.kind == hitSideCat && p.hover.idx == e.cat
		ico := colMuted
		if active {
			c.round(r, s(8), colSelBG, rgb(0x2F, 0x5E, 0x38))
			ico = colLime
		} else if hot {
			c.round(r, s(8), colHover, colHover)
		}
		c.text(e.glyph, rc(int(r.L)+s(8), int(r.T), int(r.L)+s(36), int(r.B)), p.f.icon, ico, dtCenter|dtVCenter)
		c.text(e.label, rc(int(r.L)+s(42), int(r.T), int(r.R)-s(44), int(r.B)), p.f.side, colText, dtLeft|dtVCenter|dtEllipsis)
		badge := rc(int(r.R)-s(38), int(r.T)+s(6), int(r.R)-s(8), int(r.B)-s(6))
		bf, bt := colBtn, colMuted
		if active {
			bf, bt = colLimeDark, colLime
		}
		c.round(badge, s(8), bf, bf)
		c.text(fmt.Sprint(e.count), badge, p.f.small, bt, dtCenter|dtVCenter)
	}
	pRestoreDC.Call(c.dc, saved)
}

func rowName(r pickRow) string {
	if r.src.Meta.Name != "" {
		return r.src.Meta.Name
	}
	return r.src.ID
}

func privLabel(m collector.Meta) (string, uint32) {
	switch {
	case m.Sensitive:
		return "Sensible", colWarn
	case m.Privilege == collector.PrivDebug:
		return "Admin+Debug", colWarn
	case m.Privilege == collector.PrivAdmin:
		return "Admin", colMuted
	}
	return "Usuario", colMuted
}

func availLabel(r pickRow) (string, uint32) {
	if r.src.Detect == nil && !r.probed {
		return "—", colDim
	}
	if !r.probed {
		return "Comprobando…", colDim
	}
	switch r.avail.State {
	case collector.Available:
		return "Disponible", colOK
	case collector.NotPresent:
		return "No presente", colDim
	case collector.NotSupported:
		return "No soportado", colDim
	case collector.NeedsAdmin:
		return "Requiere admin", colWarn
	}
	return "—", colDim
}

func (p *picker) drawTable(c canvas, l layout) {
	s := p.s
	c.round(l.main, s(10), colPanelAlt, colBorder)
	c.round(l.search, s(8), colPanelAlt, rgb(0x2E, 0x44, 0x35))
	c.text("\uE721", rc(int(l.search.L)+s(6), int(l.search.T), int(l.search.L)+s(34), int(l.search.B)), p.f.icon, colMuted, dtCenter|dtVCenter)
	// profile chips
	chipNames := []string{"Quick", "Standard", "Full", "Custom"}
	chipProf := []collector.Profile{collector.ProfileQuick, collector.ProfileStandard, collector.ProfileFull, collector.ProfileCustom}
	for i, r := range l.chips {
		active := p.profile == chipProf[i]
		hot := p.hover.kind == hitProfile && p.hover.idx == i
		fill, border, txt := colBtn, rgb(0x2E, 0x44, 0x35), colMuted
		if active {
			fill, border, txt = colSelBG, colLime, colLime
		} else if hot {
			fill, txt = colBtnHover, colText
		}
		c.round(r, s(8), fill, border)
		c.text(chipNames[i], r, p.f.small, txt, dtCenter|dtVCenter)
	}
	filters := []string{"Todas", "Selecc.", "No selecc."}
	fill := colBtn
	if p.hover.kind == hitFilter {
		fill = colBtnHover
	}
	c.round(l.filter, s(8), fill, rgb(0x2E, 0x44, 0x35))
	c.text(filters[p.show], rc(int(l.filter.L)+s(12), int(l.filter.T), int(l.filter.R)-s(30), int(l.filter.B)), p.f.body, colText, dtLeft|dtVCenter|dtEllipsis)
	c.text("\uE70D", rc(int(l.filter.R)-s(28), int(l.filter.T), int(l.filter.R)-s(6), int(l.filter.B)), p.f.icon, colMuted, dtCenter|dtVCenter)

	left, right := int(l.tableHdr.L), int(l.tableHdr.R)
	cols, _ := p.selColumns(l)
	c.fill(l.tableHdr, rgb(0x0E, 0x18, 0x11))
	all := len(p.visible) > 0
	for _, i := range p.visible {
		all = all && p.rows[i].on
	}
	cb := func(y0, y1 int) pickRect {
		sz := s(16)
		return rc(left+s(14), y0+(y1-y0-sz)/2, left+s(14)+sz, y0+(y1-y0-sz)/2+sz)
	}
	hy0, hy1 := int(l.tableHdr.T), int(l.tableHdr.B)
	c.check(cb(hy0, hy1), all, p.hover.kind == hitHeaderCheck)
	heads := []string{"Fuente", "Origen", "Acceso", "Tamaño est.", "Disponibilidad"}
	for i, h := range heads {
		end := right - s(8)
		if i < 4 {
			end = cols[i+1]
		}
		c.text(h, rc(cols[i], hy0, end, hy1), p.f.bold, colMuted, dtLeft|dtVCenter|dtEllipsis)
	}
	saved, _, _ := pSaveDC.Call(c.dc)
	pIntersectClipRect.Call(c.dc, uintptr(l.tableBody.L), uintptr(l.tableBody.T), uintptr(l.tableBody.R), uintptr(l.tableBody.B))
	rh := p.rowH()
	if len(p.visible) == 0 {
		c.text("Ninguna fuente coincide con el filtro.", rc(left, int(l.tableBody.T)+s(20), right, int(l.tableBody.T)+s(48)), p.f.body, colDim, dtCenter|dtVCenter)
	}
	for vi, ri := range p.visible {
		y0 := int(l.tableBody.T) + vi*rh - p.scroll
		if y0+rh < int(l.tableBody.T) || y0 > int(l.tableBody.B) {
			continue
		}
		y1 := y0 + rh
		row := p.rows[ri]
		hot := p.hover.kind == hitRow && p.hover.idx == vi
		switch {
		case row.on:
			c.fill(rc(left, y0, right, y1), rgb(0x0F, 0x1E, 0x14))
			c.fill(rc(left, y0, left+s(3), y1), colLime)
		case hot:
			c.fill(rc(left, y0, right, y1), colHover)
		}
		c.fill(rc(left, y1-1, right, y1), colLine)
		c.check(cb(y0, y1), row.on, hot)
		c.text(p.cats[row.cat].glyph, rc(left+s(40), y0, left+s(72), y1), p.f.icon, colMuted, dtCenter|dtVCenter)
		unavailable := row.probed && (row.avail.State == collector.NotPresent || row.avail.State == collector.NotSupported)
		nameCol, locCol := colText, colMuted
		if unavailable {
			nameCol, locCol = colDim, colDim
		}
		c.text(rowName(row), rc(cols[0], y0, cols[1]-s(10), y1), p.f.body, nameCol, dtLeft|dtVCenter|dtEllipsis)
		c.text(row.src.Locator, rc(cols[1], y0, cols[2]-s(10), y1), p.f.body, locCol, dtLeft|dtVCenter|dtEllipsis)
		pl, pc := privLabel(row.src.Meta)
		c.text(pl, rc(cols[2], y0, cols[3]-s(8), y1), p.f.body, pc, dtLeft|dtVCenter|dtEllipsis)
		size := "—"
		if row.sizeBytes > 0 {
			size = "~" + humanSize(row.sizeBytes)
		}
		c.text(size, rc(cols[3], y0, cols[4]-s(8), y1), p.f.body, colMuted, dtLeft|dtVCenter)
		al, ac := availLabel(row)
		c.dot(cols[4]+s(4), (y0+y1)/2, s(4), ac)
		c.text(al, rc(cols[4]+s(16), y0, right-s(8), y1), p.f.body, ac, dtLeft|dtVCenter|dtEllipsis)
		if vi == p.cur && pGetFocusIs(p.hwnd) {
			c.ring(rc(left+1, y0, right-1, y1), colLime)
		}
	}
	if total := len(p.visible) * rh; total > int(l.tableBody.B-l.tableBody.T) {
		view := int(l.tableBody.B - l.tableBody.T)
		th := max(s(30), view*view/total)
		ty := int(l.tableBody.T) + p.scroll*(view-th)/(total-view)
		c.round(rc(right-s(7), ty, right-s(3), ty+th), s(2), rgb(0x2E, 0x44, 0x35), rgb(0x2E, 0x44, 0x35))
	}
	pRestoreDC.Call(c.dc, saved)
}

func pGetFocusIs(hwnd uintptr) bool {
	f, _, _ := pGetFocus.Call()
	return f == hwnd
}

func (p *picker) profileLabel() string {
	switch p.profile {
	case collector.ProfileQuick:
		return "Quick Triage"
	case collector.ProfileStandard:
		return "Standard DFIR"
	case collector.ProfileFull:
		return "Full Forensic"
	}
	return "Custom"
}

// applyProfile selects the sources a built-in profile includes. Sensitive sources are never
// selected automatically; they must be ticked by hand and are confirmed before the run.
func (p *picker) applyProfile(profile collector.Profile) {
	p.profile = profile
	if profile != collector.ProfileCustom {
		for i := range p.rows {
			p.rows[i].on = p.rows[i].src.Meta.Profiles.Has(profile) && !p.rows[i].src.Meta.Sensitive
		}
	}
	p.refilter()
}

func (p *picker) adminSelected() int {
	n := 0
	for _, r := range p.rows {
		if r.on && (r.src.Meta.Privilege == collector.PrivAdmin || r.src.Meta.Privilege == collector.PrivDebug) {
			n++
		}
	}
	return n
}

// startProbes checks availability and estimates size in the background so the window opens
// immediately; results are applied on the UI thread.
func (p *picker) startProbes() {
	ctx, cancel := context.WithCancel(context.Background())
	p.probeCancel = cancel
	srcs := make([]collector.Source, len(p.rows))
	for i, r := range p.rows {
		srcs[i] = r.src
	}
	hwnd := p.hwnd
	go func() {
		for i, src := range srcs {
			if ctx.Err() != nil {
				return
			}
			res := probeResult{idx: i}
			func() {
				defer func() { _ = recover() }()
				if src.Detect != nil {
					res.avail = src.Detect(ctx)
				} else {
					res.avail = collector.Availability{State: collector.Available}
				}
				if src.Estimate != nil && res.avail.State != collector.NotPresent {
					res.size = src.Estimate(ctx)
				}
			}()
			p.probeMu.Lock()
			p.probeQ = append(p.probeQ, res)
			n := len(p.probeQ)
			p.probeMu.Unlock()
			if n%8 == 0 || i == len(srcs)-1 {
				pPostMessage.Call(hwnd, wmProbe, 0, 0)
			}
		}
	}()
}

func (p *picker) applyProbes() {
	p.probeMu.Lock()
	q := p.probeQ
	p.probeQ = nil
	p.probeMu.Unlock()
	for _, r := range q {
		if r.idx < len(p.rows) {
			p.rows[r.idx].avail, p.rows[r.idx].probed, p.rows[r.idx].sizeBytes = r.avail, true, r.size
		}
	}
	p.redraw()
}
