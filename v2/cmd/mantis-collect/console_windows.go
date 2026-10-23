//go:build windows

package main

import (
	"os"
	"unsafe"
)

// The executable is a console program so that --profile, --list-artifacts and pipelines keep working. When Windows
// starts it from Explorer it creates a console only for it, and that window would stay behind the selection window.
// The console is released just before the window opens, and only when no other process (a shell) shares it.

var (
	pGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	pFreeConsole           = kernel32.NewProc("FreeConsole")
	pAllocConsole          = kernel32.NewProc("AllocConsole")
)

// ownsConsole reports whether the console was created for this process alone: the number of processes attached
// to it is 1. A process started from cmd, PowerShell or Windows Terminal shares its console with the shell.
func ownsConsole(attached uint32) bool { return attached == 1 }

func consoleProcessCount() uint32 {
	var ids [2]uint32
	n, _, _ := pGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return uint32(n)
}

// releaseOwnConsole closes the console window when this process is its only user. It reports whether it did.
func releaseOwnConsole() bool {
	if !ownsConsole(consoleProcessCount()) {
		return false
	}
	r, _, _ := pFreeConsole.Call()
	return r != 0
}

// restoreConsole opens a console again (for example to show why the window could not start) and points the
// standard streams at it, because the handles Go captured at start-up referred to the console that was released.
func restoreConsole() {
	if r, _, _ := pAllocConsole.Call(); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}
