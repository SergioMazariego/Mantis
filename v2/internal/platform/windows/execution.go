//go:build windows

package windows

import (
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// executionSources covers application-execution history: Prefetch, Amcache, ShimCache,
// BAM/DAM, UserAssist, Program Compatibility Assistant, SRUM and Windows Error Reporting.
// The raw artifacts are preserved; parsing belongs to the analysis stage.
func executionSources() []collector.Source {
	em := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "execution", priv, p, art...)
	}
	win := windowsDir()
	var out []collector.Source

	out = append(out, requiresAdmin(walkGroup("execution-prefetch",
		em("Prefetch files", "Application prefetch (.pf) files and SysMain layout/database files: executable name, run count, last run times, referenced files", collector.InAll, collector.PrivAdmin,
			"execution/prefetch.md"), win+`\Prefetch`, walkSpec{
			Roots: staticRoots(win + `\Prefetch`), MaxDepth: -1, MaxFiles: 5000, FileMax: 64 << 20})))

	out = append(out, requiresAdmin(walkGroup("execution-amcache",
		em("Amcache hive", "Amcache.hve with transaction logs: program inventory with file SHA-1, paths, first-execution/install evidence", collector.InStdFull, collector.PrivAdmin,
			"execution/amcache.md"), win+`\appcompat\Programs\Amcache.hve*`, walkSpec{
			Roots: staticRoots(win + `\appcompat\Programs`), MaxDepth: -1, MaxFiles: 50, FileMax: 2 << 30,
			Match: func(_, name string) bool {
				n := strings.ToLower(name)
				return strings.HasPrefix(n, "amcache.hve") || n == "recentfilecache.bcf"
			}})))

	out = append(out, regSnapshotSource("execution-shimcache-live",
		em("ShimCache / AppCompatCache (live value)", "AppCompatCache raw value as currently stored. The cache is flushed to the registry at shutdown, so the live value may lag; the SYSTEM hive copy is the authoritative on-disk source",
			collector.InAll, collector.PrivUser, "execution/shimcache.md"), `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, false, 0), hklm(`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility`, true, 2)}
		}))

	out = append(out, regSnapshotSource("execution-bam-dam",
		em("BAM/DAM (Background/Desktop Activity Moderator)", "Per-user last execution times of executables (bam\\State\\UserSettings, dam)", collector.InAll, collector.PrivUser, "execution/bam-dam.md"),
		`HKLM\SYSTEM\CurrentControlSet\Services\{bam,dam}`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, true, 2), hklm(`SYSTEM\CurrentControlSet\Services\bam\UserSettings`, true, 2),
				hklm(`SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`, true, 2), hklm(`SYSTEM\CurrentControlSet\Services\dam\UserSettings`, true, 2)}
		}))

	out = append(out, regSnapshotSource("execution-userassist",
		em("UserAssist (all loaded users)", "GUI program launch counts and last-run times, ROT13-encoded names preserved raw, for every loaded user hive", collector.InAll, collector.PrivUser),
		`HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, func() []regTarget {
			return perLoadedUser(`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, true, 3)
		}))

	out = append(out, regSnapshotSource("execution-compat-assistant",
		em("Program Compatibility Assistant and AppCompatFlags (registry)", "Compatibility Assistant Store/Persisted (executed programs), layers and flags for the machine and loaded users", collector.InStdFull, collector.PrivUser,
			"execution/program-compatibility-assistant.md"), `...\AppCompatFlags`, func() []regTarget {
			t := []regTarget{hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`, true, 4), hklm(`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`, true, 4)}
			return append(t, perLoadedUser(`Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`, true, 4)...)
		}))

	out = append(out, walkGroup("execution-pca-files",
		em("Program Compatibility Assistant log files (Windows 11 22H2+)", "PcaAppLaunchDic.txt and PcaGeneralDb*.txt: executed GUI programs with last-run times", collector.InStdFull, collector.PrivAdmin,
			"execution/program-compatibility-assistant.md"), win+`\appcompat\pca`, walkSpec{
			Roots: staticRoots(win + `\appcompat\pca`), MaxDepth: -1, MaxFiles: 50, FileMax: 256 << 20}))

	out = append(out, requiresAdmin(walkGroup("execution-srum",
		em("SRUM database", "System Resource Usage Monitor ESE database (SRUDB.dat) with its logs/checkpoint: per-app network and CPU usage over time", collector.InStdFull, collector.PrivAdmin,
			"execution/srum-db.md"), win+`\System32\sru`, walkSpec{
			Roots: staticRoots(win + `\System32\sru`), MaxDepth: -1, MaxFiles: 50, FileMax: 2 << 30})))
	out = append(out, regSnapshotSource("execution-srum-registry",
		em("SRUM registry configuration", "SRUM extensions and parameters (needed to interpret the database)", collector.InStdFull, collector.PrivUser, "execution/srum-db.md"),
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM`, func() []regTarget {
			return []regTarget{hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM`, true, 3)}
		}))

	out = append(out, walkGroup("execution-wer",
		em("Windows Error Reporting reports", "WER report metadata (.wer, small XML/text): application crashes with module versions and timestamps. Memory dump files are deliberately excluded",
			collector.InStdFull, collector.PrivUser, "execution/wer-files.md"), expandEnv(`%ProgramData%`)+`\Microsoft\Windows\WER | %LOCALAPPDATA%\Microsoft\Windows\WER`, walkSpec{
			Roots: func() []string {
				r := []string{expandEnv(`%ProgramData%`) + `\Microsoft\Windows\WER`}
				return append(r, perUser(`AppData\Local\Microsoft\Windows\WER`)...)
			}, MaxDepth: 4, MaxFiles: 4000, FileMax: 16 << 20,
			Match: func(_, name string) bool {
				n := strings.ToLower(name)
				return strings.HasSuffix(n, ".wer") || strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".xml") || strings.HasSuffix(n, ".ini")
			}}))
	return out
}
