//go:build windows

package windows

import (
	"os"
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/browserpolicy"
	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(extended(dir))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// browserSources collects browsing history, downloads, bookmarks, session metadata,
// extension inventories and configuration. Credential stores, cookies, tokens and the
// keys protecting them are excluded by policy (see browser_rules.go and its tests).
// Locked SQLite databases are acquired through the raw NTFS fallback, with their
// -journal/-wal/-shm companions, so uncommitted pages are preserved.
func browserSources() []collector.Source {
	bm := func(name, desc string, p collector.ProfileMask, art ...string) collector.Meta {
		m := baseMeta(name, desc, "browsers", collector.PrivUser, p, art...)
		m.SideEffects = readSideEffect + "; credential, cookie, token and session stores are excluded by policy"
		return m
	}
	chromium := func(id, name, sub string) collector.Source {
		rootsFn := perUserRoots(sub)
		g := walkGroup(id, bm(name+" history, bookmarks, sessions and extension inventory", "Raw browser databases (History with journal), bookmarks, preferences, top sites, session metadata and extension manifests for every profile",
			collector.InStdFull), `%LOCALAPPDATA%\`+sub, walkSpec{
			Roots: rootsFn, MaxDepth: 6, MaxFiles: 6000, FileMax: 1 << 30, SkipDir: browserpolicy.SkipDir,
			Match: func(rel, _ string) bool {
				ok, _ := browserpolicy.ChromiumAllowed(rel)
				return ok
			}})
		return g
	}
	firefox := walkGroup("browser-firefox", bm("Mozilla Firefox history and configuration", "places.sqlite (history, bookmarks, downloads) with WAL, favicons, extensions.json, prefs and profiles.ini. Session store, cookies and logins are excluded",
		collector.InStdFull, "browser/firefox-places-sqlite.md"), `%APPDATA%\Mozilla\Firefox`, walkSpec{
		Roots: perUserRoots(`AppData\Roaming\Mozilla\Firefox`), MaxDepth: 4, MaxFiles: 2000, FileMax: 1 << 30, SkipDir: browserpolicy.FirefoxSkipDir,
		Match: func(rel, _ string) bool {
			ok, _ := browserpolicy.FirefoxAllowed(rel)
			return ok
		}})
	webcache := walkGroup("browser-ie-edge-legacy-webcache", bm("Internet Explorer / legacy Edge WebCache", "WebCacheV01.dat (ESE) with logs: legacy browser history and downloads, also used by Windows components", collector.InStdFull),
		`%LOCALAPPDATA%\Microsoft\Windows\WebCache`, walkSpec{Roots: perUserRoots(`AppData\Local\Microsoft\Windows\WebCache`), MaxDepth: -1, MaxFiles: 100, FileMax: 2 << 30,
			Match: func(_, n string) bool {
				l := strings.ToLower(n)
				return strings.HasPrefix(l, "webcachev") || strings.HasSuffix(l, ".log") || strings.HasSuffix(l, ".jfm") || strings.HasSuffix(l, ".chk")
			}})
	return []collector.Source{
		chromium("browser-edge", "Edge", `AppData\Local\Microsoft\Edge\User Data`),
		chromium("browser-chrome", "Google Chrome", `AppData\Local\Google\Chrome\User Data`),
		firefox, webcache,
	}
}
