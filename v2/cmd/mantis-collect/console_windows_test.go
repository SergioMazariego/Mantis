//go:build windows

package main

import "testing"

func TestOwnsConsoleOnlyWhenNoShellSharesIt(t *testing.T) {
	for attached, want := range map[uint32]bool{0: false, 1: true, 2: false, 5: false} {
		if got := ownsConsole(attached); got != want {
			t.Errorf("ownsConsole(%d) = %v, want %v", attached, got, want)
		}
	}
}
