//go:build windows

package windows

import (
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// persistenceSources covers the Autoruns-equivalent persistence surfaces: registry
// autostart locations (machine and loaded users), startup folders, scheduled tasks,
// services (see system-services), WMI repository, BITS jobs and COM registration.
func persistenceSources() []collector.Source {
	pm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "persistence", priv, p, art...)
	}
	// both 64-bit and WOW6432Node views of a machine key
	both := func(path string, recursive bool, depth int) []regTarget {
		parts := strings.SplitN(path, `\`, 3)
		t := []regTarget{hklm(path, recursive, depth)}
		if len(parts) == 3 && strings.EqualFold(parts[0], "SOFTWARE") {
			t = append(t, hklm(parts[0]+`\WOW6432Node\`+strings.Join(parts[1:], `\`), recursive, depth))
		}
		return t
	}
	var out []collector.Source

	out = append(out, regSnapshotSource("persistence-autorun-registry",
		pm("Autorun registry keys (Run, RunOnce, StartupApproved)", "Run/RunOnce/RunServices/Policies Run and StartupApproved (enabled/disabled state) for the machine and every loaded user hive", collector.InAll, collector.PrivUser,
			"persistence/reg-run-runonce.md"), `HKLM|HKU\...\Run*`, func() []regTarget {
			var t []regTarget
			for _, k := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved`} {
				t = append(t, both(k, true, 2)...)
			}
			for _, k := range []string{`Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`,
				`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved`,
				`Software\Microsoft\Windows NT\CurrentVersion\Windows`, `Software\Microsoft\Command Processor`} {
				t = append(t, perLoadedUser(k, true, 2)...)
			}
			// user environment variables often carry tokens set with setx: names, types and sizes only, except
			// UserInitMprLogonScript, a logon script that is persistence (its command is the evidence)
			for _, et := range perLoadedUser("Environment", false, 0) {
				et.NamesOnly = true
				et.KeepData = []string{"UserInitMprLogonScript"}
				t = append(t, et)
			}
			return t
		}))

	out = append(out, regSnapshotSource("persistence-logon-boot",
		pm("Logon, boot and authentication persistence keys", "Winlogon (Userinit/Shell/Notify), Session Manager (BootExecute, SetupExecute, PendingFileRenameOperations), KnownDLLs, AppInit_DLLs, AppCertDLLs, LSA packages, security/time/network/print providers, Netsh helpers, Command Processor AutoRun",
			collector.InAll, collector.PrivUser),
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | Session Manager | Lsa | ...`, func() []regTarget {
			var t []regTarget
			for _, k := range []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
				`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32`, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`,
				`SOFTWARE\Microsoft\Command Processor`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`} {
				t = append(t, both(k, true, 2)...)
			}
			for _, k := range []string{`SYSTEM\CurrentControlSet\Control\Session Manager`, `SYSTEM\CurrentControlSet\Control\Lsa`, `SYSTEM\CurrentControlSet\Control\SecurityProviders`,
				`SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, `SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder`,
				`SYSTEM\CurrentControlSet\Control\Print\Monitors`, `SYSTEM\CurrentControlSet\Control\Print\Providers`,
				`SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders`, `SYSTEM\CurrentControlSet\Control\Terminal Server\Wds`,
				`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations`, `SYSTEM\CurrentControlSet\Control\SafeBoot`, `SOFTWARE\Microsoft\NetSh`,
				`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`} {
				t = append(t, hklm(k, true, 2))
			}
			t = append(t, hklm(`SYSTEM\CurrentControlSet\Control\Lsa\OSConfig`, true, 2))
			return t
		}))

	out = append(out, regSnapshotSource("persistence-ifeo",
		pm("Image File Execution Options and SilentProcessExit", "Debugger / GlobalFlag hijacks and monitoring hooks per executable (64-bit and 32-bit views)", collector.InAll, collector.PrivUser,
			"persistence/image-file-execution-options.md"), `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, func() []regTarget {
			t := both(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, true, 2)
			return append(t, both(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`, true, 2)...)
		}))

	out = append(out, regSnapshotSource("persistence-shell-extensions",
		pm("Explorer and shell extension persistence", "Approved shell extensions, context-menu/property/icon-overlay handlers, ShellExecuteHooks, Browser Helper Objects, ShellServiceObjects, SharedTaskScheduler", collector.InStdFull, collector.PrivUser),
		`HKLM\...\Explorer | Shell Extensions | shellex`, func() []regTarget {
			var t []regTarget
			for _, k := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, `SOFTWARE\Classes\*\shellex\ContextMenuHandlers`,
				`SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers`, `SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`,
				`SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers`, `SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers`,
				`SOFTWARE\Classes\*\shellex\PropertySheetHandlers`, `SOFTWARE\Classes\Folder\ShellEx\ExtShellFolderViews`} {
				t = append(t, both(k, true, 2)...)
			}
			t = append(t, perLoadedUser(`Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, true, 2)...)
			return t
		}))

	out = append(out, regSnapshotSource("persistence-active-setup",
		pm("Active Setup installed components", "Per-user logon-time execution via Active Setup StubPath", collector.InStdFull, collector.PrivUser),
		`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`, func() []regTarget {
			t := both(`SOFTWARE\Microsoft\Active Setup\Installed Components`, true, 2)
			return append(t, perLoadedUser(`Software\Microsoft\Active Setup\Installed Components`, true, 2)...)
		}))

	// Autostart extensibility points that a live Autoruns scan inspects and the sources above do not:
	// credential providers, protocol handlers, shell handlers, DirectShow filter instances and image hijacks.
	out = append(out, regSnapshotSource("persistence-extensibility-points",
		pm("Credential providers, protocol/shell handlers and codec filters", "Credential Providers/Filters and PLAP, URL protocol handlers, Directory/Folder/AllFileSystemObjects shell handlers, DirectShow filter categories, executable file-association commands and IE UrlSearchHooks (64-bit and 32-bit views, loaded users)",
			collector.InAll, collector.PrivUser),
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication | HKLM\SOFTWARE\Classes\{Protocols,*,Directory,Folder,CLSID} | HKU\<SID>\...\UrlSearchHooks`, func() []regTarget {
			var t []regTarget
			for _, k := range []string{
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters`,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers`,
				`SOFTWARE\Classes\Protocols\Handler`,
				`SOFTWARE\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers`,
				`SOFTWARE\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers`,
				`SOFTWARE\Classes\Directory\ShellEx\CopyHookHandlers`,
				`SOFTWARE\Classes\Directory\ShellEx\PropertySheetHandlers`,
				`SOFTWARE\Classes\Directory\ShellEx\DragDropHandlers`,
				`SOFTWARE\Classes\Folder\ShellEx\DragDropHandlers`,
				`SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers`,
				`SOFTWARE\Classes\Drive\ShellEx\ContextMenuHandlers`,
				// DirectShow filter categories (video/audio compressors and decompressors)
				`SOFTWARE\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance`,
				`SOFTWARE\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance`,
				`SOFTWARE\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance`,
				`SOFTWARE\Classes\CLSID\{DA4E3DA0-D07D-11d0-BD50-00A0C911CE86}\Instance`,
				`SOFTWARE\Classes\CLSID\{33D9A760-90C8-11d0-BD43-00A0C911CE86}\Instance`,
				`SOFTWARE\Classes\CLSID\{33D9A761-90C8-11d0-BD43-00A0C911CE86}\Instance`,
				// commands run when an executable or script type is opened (Image Hijacks)
				`SOFTWARE\Classes\exefile\Shell\Open\Command`, `SOFTWARE\Classes\cmdfile\Shell\Open\Command`,
				`SOFTWARE\Classes\batfile\Shell\Open\Command`, `SOFTWARE\Classes\comfile\Shell\Open\Command`,
				`SOFTWARE\Classes\piffile\Shell\Open\Command`, `SOFTWARE\Classes\scrfile\Shell\Open\Command`,
				`SOFTWARE\Classes\htmlfile\Shell\Open\Command`, `SOFTWARE\Classes\.exe`, `SOFTWARE\Classes\.cmd`,
				`SOFTWARE\Classes\.bat`, `SOFTWARE\Classes\.com`, `SOFTWARE\Classes\.scr`,
			} {
				t = append(t, both(k, true, 2)...)
			}
			t = append(t, perLoadedUser(`Software\Microsoft\Internet Explorer\UrlSearchHooks`, true, 1)...)
			t = append(t, perLoadedUser(`Software\Classes\exefile\Shell\Open\Command`, true, 1)...)
			return t
		}))

	out = append(out, regSnapshotSource("persistence-winsock-providers",
		pm("Winsock LSP and namespace providers", "Layered service provider and namespace provider catalogs (network-stack persistence)", collector.InStdFull, collector.PrivUser),
		`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`, true, 3)}
		}))

	out = append(out, regSnapshotSource("persistence-taskcache-registry",
		pm("Task Scheduler registry cache", "TaskCache Tree/Tasks/Boot/Logon/Plain/Maintenance: task IDs, paths, SDs, triggers metadata and hashes", collector.InAll, collector.PrivUser,
			"persistence/task-scheduler-files.md"), `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`, func() []regTarget {
			return []regTarget{hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`, true, 0)}
		}))

	out = append(out, regSnapshotSource("persistence-com-hkcu",
		pm("COM registration per user (HKCU CLSID)", "User-level COM class registrations that override machine registrations (hijack surface)", collector.InStdFull, collector.PrivUser),
		`HKU\<SID>\Software\Classes\CLSID`, func() []regTarget { return perLoadedUser(`Software\Classes\CLSID`, true, 3) }))
	comMachine := regSnapshotSource("persistence-com-hklm",
		pm("COM registration (machine CLSID, depth-limited)", "Machine COM class registrations (InprocServer32/LocalServer32/TreatAs); large", collector.InFullOnly, collector.PrivUser),
		`HKLM\SOFTWARE\Classes\CLSID`, func() []regTarget {
			t := both(`SOFTWARE\Classes\CLSID`, true, 2)
			return append(t, hklm(`SOFTWARE\Classes\AppID`, true, 2))
		})
	out = append(out, comMachine)

	// files
	out = append(out, walkGroup("persistence-startup-folders",
		pm("Startup folders (machine and users)", "Shortcuts and executables launched at logon from the Startup folders", collector.InAll, collector.PrivUser),
		`%ProgramData%\...\Startup | %APPDATA%\...\Startup`, walkSpec{
			Roots: func() []string {
				r := []string{expandEnv(`%ProgramData%`) + `\Microsoft\Windows\Start Menu\Programs\StartUp`}
				return append(r, perUser(`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)...)
			}, MaxFiles: 2000}))

	tasks := walkGroup("persistence-scheduled-tasks",
		pm("Scheduled task definitions (XML and .job)", "Task XML under System32\\Tasks (and legacy .job under Windows\\Tasks): actions, triggers, principals, dates", collector.InAll, collector.PrivUser,
			"persistence/task-scheduler-files.md"), windowsDir()+`\System32\Tasks | `+windowsDir()+`\Tasks`, walkSpec{
			Roots: staticRoots(windowsDir()+`\System32\Tasks`, windowsDir()+`\SysWOW64\Tasks`, windowsDir()+`\Tasks`), MaxFiles: 8000, FileMax: 16 << 20})
	out = append(out, tasks)

	out = append(out, requiresAdmin(walkGroup("persistence-wmi-repository",
		pm("WMI repository", "WMI CIM repository (permanent event subscriptions: filters, consumers, bindings) and its index/mapping files", collector.InStdFull, collector.PrivAdmin,
			"persistence/evtx-5861-event-consumer-created.md"), windowsDir()+`\System32\wbem\Repository`, walkSpec{
			Roots: staticRoots(windowsDir() + `\System32\wbem\Repository`), MaxDepth: 2, MaxFiles: 200, FileMax: 2 << 30})))

	out = append(out, walkGroup("persistence-bits-jobs",
		pm("BITS transfer job database", "Background Intelligent Transfer Service queue (qmgr*.dat / qmgr.db and logs): URLs, destinations, notification commands", collector.InStdFull, collector.PrivAdmin),
		expandEnv(`%ProgramData%`)+`\Microsoft\Network\Downloader`, walkSpec{
			Roots: staticRoots(expandEnv(`%ProgramData%`) + `\Microsoft\Network\Downloader`), MaxDepth: -1, MaxFiles: 50, FileMax: 1 << 30}))
	out = append(out, persistenceEnrichedSource())
	return out
}
