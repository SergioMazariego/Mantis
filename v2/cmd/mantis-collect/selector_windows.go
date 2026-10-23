//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

//go:embed assets/mantis-mark.png
var markPNG []byte

//go:embed assets/mantis-icon.png
var iconPNG []byte

var errGUIUnavailable = errors.New("Windows selection window unavailable")

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	msimg32  = windows.NewLazySystemDLL("msimg32.dll")
	dwmapi   = windows.NewLazySystemDLL("dwmapi.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClass      = user32.NewProc("RegisterClassW")
	pCreateWindowEx     = user32.NewProc("CreateWindowExW")
	pDefWindowProc      = user32.NewProc("DefWindowProcW")
	pShowWindow         = user32.NewProc("ShowWindow")
	pGetMessage         = user32.NewProc("GetMessageW")
	pTranslateMessage   = user32.NewProc("TranslateMessage")
	pDispatchMessage    = user32.NewProc("DispatchMessageW")
	pPostQuit           = user32.NewProc("PostQuitMessage")
	pDestroyWindow      = user32.NewProc("DestroyWindow")
	pBeginPaint         = user32.NewProc("BeginPaint")
	pEndPaint           = user32.NewProc("EndPaint")
	pGetClientRect      = user32.NewProc("GetClientRect")
	pInvalidateRect     = user32.NewProc("InvalidateRect")
	pFillRect           = user32.NewProc("FillRect")
	pDrawText           = user32.NewProc("DrawTextW")
	pLoadCursor         = user32.NewProc("LoadCursorW")
	pSetCursor          = user32.NewProc("SetCursor")
	pSetFocus           = user32.NewProc("SetFocus")
	pMoveWindow         = user32.NewProc("MoveWindow")
	pGetWindowText      = user32.NewProc("GetWindowTextW")
	pSetWindowText      = user32.NewProc("SetWindowTextW")
	pSendMessage        = user32.NewProc("SendMessageW")
	pTrackMouseEvent    = user32.NewProc("TrackMouseEvent")
	pAdjustWindowRect   = user32.NewProc("AdjustWindowRectEx")
	pGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	pSetDPIAware        = user32.NewProc("SetProcessDPIAware")
	pGetDpiForSystem    = user32.NewProc("GetDpiForSystem")
	pSystemParamsInfo   = user32.NewProc("SystemParametersInfoW")
	pCreateIconIndirect = user32.NewProc("CreateIconIndirect")
	pDestroyIcon        = user32.NewProc("DestroyIcon")
	pCreateBitmap       = gdi32.NewProc("CreateBitmap")
	pSetTimer           = user32.NewProc("SetTimer")
	pKillTimer          = user32.NewProc("KillTimer")
	pPostMessage        = user32.NewProc("PostMessageW")
	pGetDC              = user32.NewProc("GetDC")
	pReleaseDC          = user32.NewProc("ReleaseDC")
	pGetKeyState        = user32.NewProc("GetKeyState")
	pGetFocus           = user32.NewProc("GetFocus")
	pMessageBox         = user32.NewProc("MessageBoxW")
	pScreenToClient     = user32.NewProc("ScreenToClient")
	pOpenClipboard      = user32.NewProc("OpenClipboard")
	pCloseClipboard     = user32.NewProc("CloseClipboard")
	pEmptyClipboard     = user32.NewProc("EmptyClipboard")
	pSetClipboardData   = user32.NewProc("SetClipboardData")
	pGlobalAlloc        = kernel32.NewProc("GlobalAlloc")
	pGlobalLock         = kernel32.NewProc("GlobalLock")
	pGlobalUnlock       = kernel32.NewProc("GlobalUnlock")
	pShellExecute       = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")
	pGetTextExtent      = gdi32.NewProc("GetTextExtentPoint32W")

	pCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	pSelectObject           = gdi32.NewProc("SelectObject")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pDeleteDC               = gdi32.NewProc("DeleteDC")
	pBitBlt                 = gdi32.NewProc("BitBlt")
	pGetStockObject         = gdi32.NewProc("GetStockObject")
	pSetDCBrushColor        = gdi32.NewProc("SetDCBrushColor")
	pSetDCPenColor          = gdi32.NewProc("SetDCPenColor")
	pRoundRect              = gdi32.NewProc("RoundRect")
	pEllipse                = gdi32.NewProc("Ellipse")
	pPolygon                = gdi32.NewProc("Polygon")
	pCreateFont             = gdi32.NewProc("CreateFontW")
	pSetBkMode              = gdi32.NewProc("SetBkMode")
	pSetTextColor           = gdi32.NewProc("SetTextColor")
	pSetBkColor             = gdi32.NewProc("SetBkColor")
	pCreatePen              = gdi32.NewProc("CreatePen")
	pMoveToEx               = gdi32.NewProc("MoveToEx")
	pLineTo                 = gdi32.NewProc("LineTo")
	pSaveDC                 = gdi32.NewProc("SaveDC")
	pRestoreDC              = gdi32.NewProc("RestoreDC")
	pIntersectClipRect      = gdi32.NewProc("IntersectClipRect")
	pCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	pCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	pAlphaBlend             = msimg32.NewProc("AlphaBlend")
	pDwmSetWindowAttribute  = dwmapi.NewProc("DwmSetWindowAttribute")
	pGetModuleHandle        = kernel32.NewProc("GetModuleHandleW")
)

// Window messages and styles used by the picker.
const (
	wmCreate       = 0x0001
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmEraseBkgnd   = 0x0014
	wmSetCursor    = 0x0020
	wmKeyDown      = 0x0100
	wmCommand      = 0x0111
	wmCtlColorEdit = 0x0133
	wmMouseMove    = 0x0200
	wmLButtonDown  = 0x0201
	wmMouseWheel   = 0x020A
	wmMouseLeave   = 0x02A3
	wmPaint        = 0x000F
	wmSetFont      = 0x0030
	wmSize         = 0x0005
	wmGetMinMax    = 0x0024
	wmSetIcon      = 0x0080
	wmTimer        = 0x0113
	wmRunEvents    = 0x8001
	wmRunDone      = 0x8002
	wmProbe        = 0x8003

	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsMaximizeBox = 0x00010000
	wsThickFrame  = 0x00040000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	esAutoHScroll = 0x0080

	enChange    = 0x0300
	enSetFocus  = 0x0100
	enKillFocus = 0x0200
	idSearch    = 3001
)

type pickRect struct{ L, T, R, B int32 }
type pickPoint struct{ X, Y int32 }

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      pickPoint
}

type pickerClass struct {
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
}

type paintStruct struct {
	Hdc         uintptr
	Erase       int32
	Paint       pickRect
	Restore     int32
	IncUpdate   int32
	RgbReserved [32]byte
}

type trackMouse struct {
	Size  uint32
	Flags uint32
	Hwnd  uintptr
	Hover uint32
}

type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes, Bits  uint16
	Compression   uint32
	SizeImage     uint32
	XPels, YPels  int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// Palette (COLORREF is 0x00BBGGRR).
func rgb(r, g, b uint32) uint32 { return r | g<<8 | b<<16 }

var (
	colBG       = rgb(0x08, 0x0D, 0x0B)
	colHeader   = rgb(0x0B, 0x14, 0x0F)
	colPanel    = rgb(0x0F, 0x17, 0x12)
	colPanelAlt = rgb(0x0C, 0x13, 0x0E)
	colBorder   = rgb(0x23, 0x3A, 0x2A)
	colLine     = rgb(0x17, 0x25, 0x1C)
	colText     = rgb(0xE7, 0xFF, 0xE9)
	colMuted    = rgb(0xA8, 0xB9, 0xAE)
	colDim      = rgb(0x6E, 0x80, 0x75)
	colLime     = rgb(0xB5, 0xFF, 0x41)
	colLimeDark = rgb(0x1E, 0x4A, 0x28)
	colSelBG    = rgb(0x14, 0x2B, 0x1A)
	colHover    = rgb(0x15, 0x22, 0x1A)
	colBtn      = rgb(0x12, 0x1B, 0x15)
	colBtnHover = rgb(0x1A, 0x27, 0x1E)
	colElev     = rgb(0x18, 0x25, 0x1D)
	colOK       = rgb(0x78, 0xE8, 0x6B)
	colWarn     = rgb(0xF0, 0xBA, 0x62)
	colErr      = rgb(0xEF, 0x73, 0x73)
)

// catInfo is one sidebar category (package folder), built from the registered sources.
type catInfo struct {
	key, name, glyph string
	count            int
}

var categoryDisplay = map[string]struct{ name, glyph string }{
	"system": {"Sistema", "\uE7F4"}, "registry": {"Registro", "\uE8A5"}, "persistence": {"Persistencia", "\uE72E"},
	"processes": {"Procesos", "\uE713"}, "network": {"Red", "\uE774"}, "eventlogs": {"Event Logs", "\uE8A5"},
	"ntfs": {"NTFS", "\uE838"}, "execution": {"Ejecución", "\uE81C"}, "users": {"Usuarios", "\uE77B"},
	"remote-access": {"Acceso remoto", "\uE774"}, "usb": {"USB", "\uE838"}, "browsers": {"Navegadores", "\uE774"},
	"security": {"Seguridad", "\uE72E"}, "group-policy": {"Directivas (GPO)", "\uE8FD"},
	"shadow-copies": {"Shadow Copies", "\uE81C"}, "memory": {"Memoria", "\uE713"},
}

// buildCategories groups rows by Meta.Category in first-appearance order (the registry is
// already sorted by category) and stores each row's category index.
func (p *picker) buildCategories() {
	index := map[string]int{}
	for i := range p.rows {
		key := p.rows[i].src.Meta.Category
		if key == "" {
			key = "other"
		}
		ci, ok := index[key]
		if !ok {
			d, known := categoryDisplay[key]
			if !known {
				d.name, d.glyph = strings.ToUpper(key[:1])+key[1:], "\uE8FD"
			}
			ci = len(p.cats)
			index[key] = ci
			p.cats = append(p.cats, catInfo{key: key, name: d.name, glyph: d.glyph})
		}
		p.rows[i].cat = ci
		p.cats[ci].count++
	}
}

type hitKind int

const (
	hitNone hitKind = iota
	hitSideAll
	hitSideCat
	hitFilter
	hitHeaderCheck
	hitRow
	hitAll
	hitStart
	hitCancel
	hitInfo
	hitRunRow
	hitRunLog
	hitRunCancel
	hitRunOpen
	hitRunClose
	hitLogCopy
	hitProfile
)

type hit struct {
	kind hitKind
	idx  int
}

type phase int

const (
	phSelect phase = iota
	phPreparing
	phRunning
	phCancelling
	phDone
)

type iconInfo struct {
	Icon     int32
	XHotspot uint32
	YHotspot uint32
	Mask     uintptr
	Color    uintptr
}

type pickRow struct {
	src       collector.Source
	cat       int
	on        bool
	avail     collector.Availability
	probed    bool
	sizeBytes int64
}

type probeResult struct {
	idx   int
	avail collector.Availability
	size  int64
}

type fonts struct {
	title, section, sub, body, bold, side, small, tiny, btn, big, icon, brand, mono uintptr
}

type picker struct {
	hwnd, edit  uintptr
	instance    uintptr
	dpi         int
	rows        []pickRow
	cats        []catInfo
	profile     collector.Profile
	sideScroll  int
	probeMu     sync.Mutex
	probeQ      []probeResult
	probeCancel context.CancelFunc
	cat         int // -1: all
	show        int // 0 all, 1 selected, 2 not selected
	query       string
	placeholder bool
	settingText bool
	visible     []int
	scroll      int
	cur         int // keyboard cursor in visible (select phase)
	hover       hit
	tracking    bool
	f           fonts
	mark        uintptr // premultiplied DIB of the emblem
	markSize    int
	icons       []uintptr
	editBrush   uintptr
	selected    []collector.Source
	err         error

	phase   phase
	run     *runState
	started bool

	tipText  string
	tipShown bool
	tipX     int
	tipY     int
}

// runState holds the execution screen model. Items and log are touched only by
// the UI thread; the queue is the single hand-off point from the collector goroutine.
type runState struct {
	items        []runItem
	log          []logLine
	startedAt    time.Time
	finishedAt   time.Time
	cancel       context.CancelFunc
	cancelReq    bool
	closeAfter   bool
	logOpen      bool
	logScroll    int
	logFollow    bool
	manualScroll bool
	sel          int
	results      []collector.ItemResult
	err          error
	outcome      outcome

	mu       sync.Mutex
	queue    []collector.Event
	finished bool
	fResults []collector.ItemResult
	fErr     error
}

var activePicker *picker

const placeholderText = "Buscar fuentes de evidencia..."

func selectPlatformSources(sources []collector.Source, input *bufio.Reader, output *os.File) ([]collector.Source, error) {
	if forceCLISelection {
		return selectSourcesCLI(sources, input, output)
	}
	released := releaseOwnConsole() // double-click from Explorer: no console window behind the selection window
	selected, err := selectSourcesGUI(sources)
	if !errors.Is(err, errGUIUnavailable) {
		return selected, err
	}
	if released {
		restoreConsole() // the window could not start: the user needs a console to read why
	}
	if info, statErr := os.Stdin.Stat(); statErr == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "GUI not available; opening terminal selection.")
		return selectSourcesCLI(sources, input, output)
	}
	return nil, fmt.Errorf("%w; rerun with --cli or --artifacts", err)
}

func selectSourcesGUI(sources []collector.Source) ([]collector.Source, error) {
	if len(sources) == 0 {
		return nil, collector.ErrNoSources
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := &picker{cat: -1, placeholder: true}
	for _, s := range sources {
		p.rows = append(p.rows, pickRow{src: s})
	}
	p.buildCategories()
	p.profile = collector.ProfileCustom
	activePicker = p
	defer func() { activePicker = nil }()

	pSetDPIAware.Call()
	p.dpi = 96
	if pGetDpiForSystem.Find() == nil {
		if d, _, _ := pGetDpiForSystem.Call(); d >= 96 {
			p.dpi = int(d)
		}
	}
	instance, _, _ := pGetModuleHandle.Call(0)
	p.instance = instance
	className, _ := windows.UTF16PtrFromString("MantisEvidencePickerV2")
	cursor, _, _ := pLoadCursor.Call(0, 32512)
	class := pickerClass{WndProc: syscall.NewCallback(pickerProc), Instance: instance, Cursor: cursor, ClassName: className}
	if atom, _, callErr := pRegisterClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return nil, fmt.Errorf("%w: register window: %v", errGUIUnavailable, callErr)
	}
	const style = wsCaption | wsSysMenu | wsMinimizeBox | wsMaximizeBox | wsThickFrame
	// Open centered in the work area (taskbar excluded) with breathing room on every side.
	var work pickRect
	if ok, _, _ := pSystemParamsInfo.Call(0x30, 0, uintptr(unsafe.Pointer(&work)), 0); ok == 0 {
		sw, _, _ := pGetSystemMetrics.Call(0)
		sh, _, _ := pGetSystemMetrics.Call(1)
		work = pickRect{0, 0, int32(sw), int32(sh)}
	}
	workW, workH := int(work.R-work.L), int(work.B-work.T)
	w, h := min(p.s(1180), workW*86/100), min(p.s(900), workH*90/100)
	w, h = max(w, min(p.s(960), workW*96/100)), max(h, min(p.s(620), workH*96/100))
	x, y := int(work.L)+(workW-w)/2, int(work.T)+(workH-h)/2
	title, _ := windows.UTF16PtrFromString("Mantis — Recolección de evidencia")
	hwnd, _, callErr := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)), style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0, 0, instance, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("%w: create window: %v", errGUIUnavailable, callErr)
	}
	p.hwnd = hwnd
	darkTitleBar(hwnd)
	p.setIcons()
	pShowWindow.Call(hwnd, 5)
	pSetFocus.Call(hwnd)

	var msg winMsg
	for {
		ret, _, getErr := pGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) == -1 {
			return nil, fmt.Errorf("%w: read message: %v", errGUIUnavailable, getErr)
		}
		if ret == 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	p.release()
	if p.started { // the collection ran inside this window; main reports its outcome
		return p.selected, nil
	}
	if p.err != nil {
		return nil, p.err
	}
	if len(p.selected) == 0 {
		return nil, collector.ErrNoSources
	}
	return p.selected, nil
}

func darkTitleBar(hwnd uintptr) {
	on := int32(1)
	for _, attr := range []uintptr{20, 19} { // DWMWA_USE_IMMERSIVE_DARK_MODE (build-dependent id)
		if r, _, _ := pDwmSetWindowAttribute.Call(hwnd, attr, uintptr(unsafe.Pointer(&on)), 4); r == 0 {
			break
		}
	}
	caption, text := rgb(0x0B, 0x14, 0x0F), colText // DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR (Windows 11)
	pDwmSetWindowAttribute.Call(hwnd, 35, uintptr(unsafe.Pointer(&caption)), 4)
	pDwmSetWindowAttribute.Call(hwnd, 36, uintptr(unsafe.Pointer(&text)), 4)
}

func (p *picker) s(v int) int { return v * p.dpi / 96 }

// setIcons gives the window and taskbar the Mantis emblem.
func (p *picker) setIcons() {
	for kind, metric := range []uintptr{49, 11} { // ICON_SMALL: SM_CXSMICON, ICON_BIG: SM_CXICON
		px, _, _ := pGetSystemMetrics.Call(metric)
		dib, _ := p.premultipliedDIB(iconPNG, int(px))
		if dib == 0 {
			continue
		}
		mask, _, _ := pCreateBitmap.Call(px, px, 1, 1, 0)
		info := iconInfo{Icon: 1, Mask: mask, Color: dib}
		icon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
		pDeleteObject.Call(mask)
		pDeleteObject.Call(dib)
		if icon != 0 {
			p.icons = append(p.icons, icon)
			pSendMessage.Call(p.hwnd, wmSetIcon, uintptr(kind), icon)
		}
	}
}

func (p *picker) release() {
	if p.probeCancel != nil {
		p.probeCancel()
	}
	for _, ic := range p.icons {
		pDestroyIcon.Call(ic)
	}
	for _, f := range []uintptr{p.f.title, p.f.section, p.f.sub, p.f.body, p.f.bold, p.f.side, p.f.small, p.f.tiny, p.f.btn, p.f.big, p.f.icon, p.f.brand, p.f.mono, p.mark, p.editBrush} {
		if f != 0 {
			pDeleteObject.Call(f)
		}
	}
}

func (p *picker) makeFont(px, weight int, face string) uintptr {
	name, _ := windows.UTF16PtrFromString(face)
	f, _, _ := pCreateFont.Call(uintptr(int32(-p.s(px))), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(name)))
	return f
}

func (p *picker) create() {
	p.f = fonts{
		title: p.makeFont(26, 600, "Segoe UI Semibold"), section: p.makeFont(17, 600, "Segoe UI Semibold"),
		sub: p.makeFont(13, 400, "Segoe UI"), body: p.makeFont(13, 400, "Segoe UI"),
		bold: p.makeFont(13, 600, "Segoe UI Semibold"), side: p.makeFont(14, 400, "Segoe UI"),
		small: p.makeFont(12, 400, "Segoe UI"), tiny: p.makeFont(11, 600, "Segoe UI Semibold"),
		btn: p.makeFont(14, 600, "Segoe UI Semibold"), big: p.makeFont(28, 600, "Segoe UI Semibold"),
		icon: p.makeFont(16, 400, "Segoe MDL2 Assets"), brand: p.makeFont(20, 300, "Segoe UI Light"),
		mono: p.makeFont(12, 400, "Consolas"),
	}
	p.editBrush, _, _ = pCreateSolidBrush.Call(uintptr(colPanelAlt))
	p.loadMark()
	cls, _ := windows.UTF16PtrFromString("EDIT")
	empty, _ := windows.UTF16PtrFromString("")
	p.edit, _, _ = pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(empty)), wsChild|wsVisible|esAutoHScroll,
		0, 0, 10, 10, p.hwnd, idSearch, p.instance, 0)
	pSendMessage.Call(p.edit, wmSetFont, p.f.body, 1)
	p.setEditText(placeholderText)
	p.refilter()
	p.placeEdit()
	p.startProbes()
}

func (p *picker) setEditText(text string) {
	ptr, _ := windows.UTF16PtrFromString(text)
	p.settingText = true
	pSetWindowText.Call(p.edit, uintptr(unsafe.Pointer(ptr)))
	p.settingText = false
}

// loadMark prepares the header emblem.
func (p *picker) loadMark() {
	p.markSize = p.s(84)
	p.mark, _ = p.premultipliedDIB(markPNG, p.markSize)
}

// premultipliedDIB decodes a PNG and scales it into a top-down premultiplied BGRA DIB section.
func (p *picker) premultipliedDIB(data []byte, size int) (uintptr, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	b := img.Bounds()
	src := image.NewNRGBA(b)
	draw.Draw(src, b, img, b.Min, draw.Src)
	info := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(size), Height: int32(-size), Planes: 1, Bits: 32}
	var bits unsafe.Pointer
	dib, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if dib == 0 || bits == nil {
		return 0, errors.New("CreateDIBSection failed")
	}
	out := unsafe.Slice((*byte)(bits), size*size*4)
	sw, sh := b.Dx(), b.Dy()
	for y := 0; y < size; y++ {
		y0, y1 := y*sh/size, (y+1)*sh/size
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < size; x++ {
			x0, x1 := x*sw/size, (x+1)*sw/size
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var ar, ag, ab, aa, n uint32
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					o := src.PixOffset(b.Min.X+xx, b.Min.Y+yy)
					a := uint32(src.Pix[o+3])
					ar += uint32(src.Pix[o]) * a / 255
					ag += uint32(src.Pix[o+1]) * a / 255
					ab += uint32(src.Pix[o+2]) * a / 255
					aa += a
					n++
				}
			}
			o := (y*size + x) * 4
			out[o], out[o+1], out[o+2], out[o+3] = byte(ab/n), byte(ag/n), byte(ar/n), byte(aa/n)
		}
	}
	return dib, nil
}

func (p *picker) refilter() {
	p.visible = p.visible[:0]
	q := strings.ToLower(strings.TrimSpace(p.query))
	for i, r := range p.rows {
		if p.cat >= 0 && r.cat != p.cat {
			continue
		}
		if (p.show == 1 && !r.on) || (p.show == 2 && r.on) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r.src.ID+" "+r.src.Meta.Name+" "+r.src.Locator+" "+p.cats[r.cat].name), q) {
			continue
		}
		p.visible = append(p.visible, i)
	}
	p.clampScroll()
}
