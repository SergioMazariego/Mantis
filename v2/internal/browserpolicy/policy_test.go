package browserpolicy

import "testing"

func TestChromiumPolicyNeverCollectsSecrets(t *testing.T) {
	never := []string{
		`Default\Login Data`, `Default\Login Data-journal`, `Default\Cookies`, `Default\Network\Cookies`, `Default\Web Data`, `Local State`,
		`Profile 1\Login Data For Account`, `Default\Extension Cookies`, `Default\Trust Tokens`, `Default\Affiliation Database`,
		`Default\Sync Data\LevelDB\000003.log`, `Default\Local Storage\leveldb\x.ldb`, `Default\IndexedDB\foo`, `Default\Cache\Cache_Data\data_1`,
		`Default\Session Storage\000003.log`, `Default\Service Worker\Database\x`,
		// session stores keep page state with typed form values and POST bodies, like Firefox's sessionstore
		`Default\Sessions\Session_13300000000000000`, `Default\Sessions\Tabs_13300000000000000`, `Default\Current Session`, `Default\Last Tabs`,
	}
	for _, rel := range never {
		if ok, why := ChromiumAllowed(rel); ok {
			t.Errorf("%s must never be collected (%s)", rel, why)
		}
	}
	allowed := []string{
		`Default\History`, `Default\History-journal`, `Default\Bookmarks`, `Profile 3\Preferences`, `Default\Top Sites`,
		`Default\Extensions\abcdefgh\1.0_0\manifest.json`, `Default\Shortcuts`,
	}
	for _, rel := range allowed {
		if ok, why := ChromiumAllowed(rel); !ok {
			t.Errorf("%s should be collected (%s)", rel, why)
		}
	}
	if ok, _ := ChromiumAllowed(`Default\Extensions\abcdefgh\1.0_0\_locales\en\messages.json`); ok {
		t.Error("extension payload files must not be collected, only manifests")
	}
}

func TestFirefoxPolicyExcludesCredentialsAndSessionStore(t *testing.T) {
	for _, rel := range []string{`Profiles\abc.default\logins.json`, `Profiles\abc.default\key4.db`, `Profiles\abc.default\cookies.sqlite`,
		`Profiles\abc.default\cookies.sqlite-wal`, `Profiles\abc.default\formhistory.sqlite`, `Profiles\abc.default\cert9.db`,
		`Profiles\abc.default\sessionstore.jsonlz4`, `Profiles\abc.default\sessionstore-backups\recovery.jsonlz4`, `Profiles\abc.default\storage\default\x`} {
		if ok, why := FirefoxAllowed(rel); ok {
			t.Errorf("%s must not be collected (%s)", rel, why)
		}
	}
	for _, rel := range []string{`Profiles\abc.default\places.sqlite`, `Profiles\abc.default\places.sqlite-wal`, `Profiles\abc.default\extensions.json`, `profiles.ini`} {
		if ok, why := FirefoxAllowed(rel); !ok {
			t.Errorf("%s should be collected (%s)", rel, why)
		}
	}
}

func TestBrowserSkipDirs(t *testing.T) {
	for _, d := range []string{`Default\Cache`, `Default\Local Storage`, `Default\IndexedDB`, `Default\Network`} {
		if !SkipDir(d) {
			t.Errorf("%s should be skipped", d)
		}
	}
	if SkipDir(`Default\Extensions`) {
		t.Error("Extensions must be traversed")
	}
}

func TestFirefoxSkipDirKeepsTheWalkInsideProfiles(t *testing.T) {
	for _, d := range []string{`Background Tasks Profiles`, `Background Tasks Profiles\x.MozillaBackgroundTask\datareporting`, `Crash Reports`, `Profiles\abc.default\storage`, `Profiles\abc.default\sessionstore-backups`} {
		if !FirefoxSkipDir(d) {
			t.Errorf("%s should be skipped", d)
		}
	}
	for _, d := range []string{`Profiles`, `Profiles\abc.default`} {
		if FirefoxSkipDir(d) {
			t.Errorf("%s must be traversed", d)
		}
	}
}
