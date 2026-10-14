// Package browserpolicy decides which browser files may be acquired. It is deliberately tiny and
// dependency-free so the policy that excludes credentials, cookies and tokens is easy to audit and test.
package browserpolicy

import "strings"

// Browser acquisition policy. Only history, downloads, bookmarks, extension and
// configuration artifacts are collected. Credentials, cookies, session tokens, saved
// payment/autofill data and the key material that protects them are never collected
// by default; any future acquisition of such data needs its own authorization design.

// browserNeverCollect lists file names (lower case) that must not be collected from any
// browser profile, even when a directory rule would otherwise match.
var browserNeverCollect = map[string]bool{
	"login data": true, "login data-journal": true, "login data for account": true, "login data for account-journal": true,
	"cookies": true, "cookies-journal": true, "web data": true, "web data-journal": true, "local state": true,
	"extension cookies": true, "extension cookies-journal": true, "trust tokens": true, "trust tokens-journal": true,
	"affiliation database": true, "key3.db": true, "key4.db": true, "logins.json": true, "logins-backup.json": true,
	"signons.sqlite": true, "cert8.db": true, "cert9.db": true, "cookies.sqlite": true, "cookies.sqlite-wal": true,
	"cookies.sqlite-shm": true, "formhistory.sqlite": true, "formhistory.sqlite-wal": true, "webappsstore.sqlite": true,
	"pkcs11.txt": true, "autofill": true, "passwords.sqlite": true,
}

// browserSkipDirs are directory names (lower case) never descended into: caches, storage
// areas and anything that may hold tokens or large non-evidentiary data.
var browserSkipDirs = map[string]bool{
	"cache": true, "code cache": true, "gpucache": true, "grshadercache": true, "shadercache": true, "service worker": true,
	"indexeddb": true, "local storage": true, "session storage": true, "file system": true, "blob_storage": true,
	"crashpad": true, "component_crx_cache": true, "dawncache": true, "storage": true, "sync data": true,
	"network": true, "safe browsing": true, "optimizationguidemodeldownloads": true, "certificaterevocation": true,
	"extension state": true, "extension rules": true, "extension scripts": true, "local extension settings": true, "sync extension settings": true,
	"jumplisticonscache": true, "videodecodestats": true, "webrtc logs": true, "datareductionproxysettings": true,
}

func normRel(rel string) []string {
	rel = strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	var parts []string
	for _, p := range strings.Split(rel, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	return parts
}

// SkipDir reports whether a directory (relative path) must not be descended into.
func SkipDir(rel string) bool {
	parts := normRel(rel)
	if len(parts) == 0 {
		return false
	}
	return browserSkipDirs[parts[len(parts)-1]]
}

func chromiumProfileDir(name string) bool {
	return name == "default" || name == "guest profile" || name == "system profile" || strings.HasPrefix(name, "profile ")
}

var chromiumFiles = map[string]bool{
	"history": true, "history-journal": true, "bookmarks": true, "bookmarks.bak": true, "preferences": true, "secure preferences": true,
	"top sites": true, "top sites-journal": true, "shortcuts": true, "shortcuts-journal": true, "favicons": true, "favicons-journal": true,
	"network action predictor": true, "network action predictor-journal": true, "media history": true, "media history-journal": true,
	"current session": true, "current tabs": true, "last session": true, "last tabs": true, "visited links": true,
}

// ChromiumAllowed decides whether a path relative to a Chromium "User Data" directory
// (Chrome, Edge) is collected.
func ChromiumAllowed(rel string) (bool, string) {
	parts := normRel(rel)
	if len(parts) == 0 {
		return false, "empty path"
	}
	name := parts[len(parts)-1]
	if browserNeverCollect[name] {
		return false, "credential/secret store: never collected"
	}
	if len(parts) < 2 || !chromiumProfileDir(parts[0]) {
		return false, "not inside a browser profile directory"
	}
	for _, p := range parts[1 : len(parts)-1] {
		if browserSkipDirs[p] {
			return false, "cache or storage directory"
		}
	}
	switch {
	case len(parts) == 2 && chromiumFiles[name]:
		return true, "history/bookmarks/configuration"
	case len(parts) >= 3 && parts[1] == "sessions":
		return true, "session metadata (URLs, tab state)"
	case len(parts) == 5 && parts[1] == "extensions" && name == "manifest.json":
		return true, "extension inventory (manifest)"
	}
	return false, "not an allowlisted artifact"
}

var firefoxProfileFiles = map[string]bool{
	"places.sqlite": true, "places.sqlite-wal": true, "places.sqlite-shm": true, "favicons.sqlite": true, "favicons.sqlite-wal": true, "favicons.sqlite-shm": true,
	"extensions.json": true, "prefs.js": true, "user.js": true, "containers.json": true, "handlers.json": true, "addons.json": true,
}

// FirefoxAllowed decides for a path relative to the "...\Mozilla\Firefox" directory.
// Session store files are excluded: they embed session cookies and form data.
func FirefoxAllowed(rel string) (bool, string) {
	parts := normRel(rel)
	if len(parts) == 0 {
		return false, "empty path"
	}
	name := parts[len(parts)-1]
	if browserNeverCollect[name] {
		return false, "credential/secret store: never collected"
	}
	if len(parts) == 1 && (name == "profiles.ini" || name == "installs.ini") {
		return true, "profile registry"
	}
	if len(parts) == 3 && parts[0] == "profiles" && firefoxProfileFiles[name] {
		return true, "history/extensions/configuration"
	}
	return false, "not an allowlisted artifact"
}
