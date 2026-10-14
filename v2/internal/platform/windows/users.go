//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

var (
	pNetUserEnum            = netapi32.NewProc("NetUserEnum")
	pNetLocalGroupEnum      = netapi32.NewProc("NetLocalGroupEnum")
	pNetLocalGroupGetMember = netapi32.NewProc("NetLocalGroupGetMembers")
	pNetShareEnum           = netapi32.NewProc("NetShareEnum")
	pNetSessionEnum         = netapi32.NewProc("NetSessionEnum")
)

type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

type localGroupInfo1 struct{ Name, Comment *uint16 }
type localGroupMember0 struct{ Sid *windows.SID }

var (
	machineSIDOnce sync.Once
	machineSID     string
)

// isLocalSID reports whether name resolution for sid stays on this machine (well-known and
// local-account SIDs). Domain SIDs are left unresolved so the endpoint does not generate
// domain controller traffic during acquisition.
func isLocalSID(sid string) bool {
	machineSIDOnce.Do(func() { machineSID = computerSID(&warnings{}) })
	if strings.HasPrefix(sid, "S-1-5-21-") {
		return machineSID != "" && strings.HasPrefix(sid, machineSID+"-")
	}
	return strings.HasPrefix(sid, "S-1-5-") || strings.HasPrefix(sid, "S-1-1-") || strings.HasPrefix(sid, "S-1-2-")
}

func epoch(sec uint32) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
}

// netEnum runs a NetXxxEnum style call, invoking fn for every record of size recSize.
func netEnum(call func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr, recSize uintptr, fn func(unsafe.Pointer)) error {
	var resume uintptr
	for {
		var buf uintptr
		var read, total uint32
		r := call(&buf, &read, &total, &resume)
		if r != 0 && r != uintptr(windows.ERROR_MORE_DATA) {
			if buf != 0 {
				pNetBufferFree.Call(buf)
			}
			return syscall.Errno(r)
		}
		base := *(*unsafe.Pointer)(unsafe.Pointer(&buf))
		for i := uint32(0); i < read; i++ {
			fn(unsafe.Add(base, uintptr(i)*recSize))
		}
		if buf != 0 {
			pNetBufferFree.Call(buf)
		}
		if r == 0 {
			return nil
		}
	}
}

func accountInventory(w *warnings) map[string]any {
	out := map[string]any{}
	var users []map[string]any
	err := netEnum(func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr {
		r, _, _ := pNetUserEnum.Call(0, 2, 2 /*FILTER_NORMAL_ACCOUNT*/, uintptr(unsafe.Pointer(buf)), ^uintptr(0), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(total)), uintptr(unsafe.Pointer(resume)))
		return r
	}, unsafe.Sizeof(userInfo2{}), func(p unsafe.Pointer) {
		u := (*userInfo2)(p)
		users = append(users, map[string]any{
			"name": windows.UTF16PtrToString(u.Name), "full_name": windows.UTF16PtrToString(u.FullName), "comment": windows.UTF16PtrToString(u.Comment),
			"flags": u.Flags, "disabled": u.Flags&0x2 != 0, "locked_out": u.Flags&0x10 != 0, "password_age_seconds": u.PasswordAge, "privilege": u.Priv,
			"last_logon_utc": epoch(u.LastLogon), "last_logoff_utc": epoch(u.LastLogoff), "account_expires_utc": epoch(u.AcctExpires),
			"bad_password_count": u.BadPwCount, "logon_count": u.NumLogons, "home_dir": windows.UTF16PtrToString(u.HomeDir), "script_path": windows.UTF16PtrToString(u.ScriptPath),
		})
	})
	if err != nil {
		w.add("NetUserEnum: %v", err)
	}
	out["local_users"] = users

	var groups []map[string]any
	var names []string
	err = netEnum(func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr {
		r, _, _ := pNetLocalGroupEnum.Call(0, 1, uintptr(unsafe.Pointer(buf)), ^uintptr(0), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(total)), uintptr(unsafe.Pointer(resume)))
		return r
	}, unsafe.Sizeof(localGroupInfo1{}), func(p unsafe.Pointer) {
		g := (*localGroupInfo1)(p)
		names = append(names, windows.UTF16PtrToString(g.Name))
	})
	if err != nil {
		w.add("NetLocalGroupEnum: %v", err)
	}
	for _, name := range names {
		g := map[string]any{"name": name}
		var members []map[string]any
		np, _ := windows.UTF16PtrFromString(name)
		// level 0 returns SIDs only; names are resolved offline for local SIDs so that no domain
		// controller is contacted from the endpoint
		merr := netEnum(func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr {
			r, _, _ := pNetLocalGroupGetMember.Call(0, uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(buf)), ^uintptr(0), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(total)), uintptr(unsafe.Pointer(resume)))
			return r
		}, unsafe.Sizeof(localGroupMember0{}), func(p unsafe.Pointer) {
			m := (*localGroupMember0)(p)
			rec := map[string]any{}
			if m.Sid != nil {
				sid := m.Sid.String()
				rec["sid"] = sid
				if isLocalSID(sid) {
					if acct, dom, _, err := m.Sid.LookupAccount(""); err == nil {
						rec["name"] = dom + "\\" + acct
					}
				} else {
					rec["name_note"] = "domain SID not resolved on purpose (avoids contacting a domain controller)"
				}
			}
			members = append(members, rec)
		})
		if merr != nil {
			g["members_error"] = merr.Error()
			w.add("members of %s: %v", name, merr)
		}
		g["members"] = members
		groups = append(groups, g)
	}
	out["local_groups"] = groups
	profs := []map[string]any{}
	for _, up := range userProfiles() {
		profs = append(profs, map[string]any{"name": up.Name, "path": up.Path, "sid": up.SID, "registry_hive_loaded": up.Loaded})
	}
	out["profiles"] = profs
	return out
}

func usersSources() []collector.Source {
	um := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "users", priv, p, art...)
	}
	out := []collector.Source{
		withDetect(jsonSource("users-accounts", um("Local accounts, groups and profiles", "Local users (flags, last logon, logon counts), local groups with members, and discovered profiles", collector.InAll, collector.PrivUser,
			"account/profile-list-key.md", "account/group-membership-key.md", "account/sam-hive.md"), "netapi32-enumeration", "netapi32://users-groups",
			func(ctx context.Context, w *warnings) (any, error) { return accountInventory(w), nil }), available),
		regSnapshotSource("users-profilelist", um("ProfileList registry key", "Profile SIDs, paths, load/unload times (account/profile-list-key)", collector.InAll, collector.PrivUser, "account/profile-list-key.md"),
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, func() []regTarget {
				return []regTarget{hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, true, 2), hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid`, true, 2),
					hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, true, 2)}
			}),
		regSnapshotSource("users-explorer-activity", um("Explorer activity keys (loaded users)", "RecentDocs, ComDlg32 (OpenSave/LastVisited PIDL MRU), TypedPaths, WordWheelQuery, RunMRU, MountPoints2, StreamMRU, Search RecentApps, Windows Search history, Office MRU/TrustRecords",
			collector.InAll, collector.PrivUser, "user-activity/wordwheelquery.md", "file-activity/trustrecords-registry-key.md"), `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer`, func() []regTarget {
			var t []regTarget
			for _, k := range []string{`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`, `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`,
				`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`, `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`,
				`Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`,
				`Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU`, `Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU`,
				`Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`, `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage`,
				`Software\Microsoft\Windows\CurrentVersion\Applets`, `Software\Microsoft\Windows\Shell\BagMRU`, `Software\Microsoft\Windows\Shell\Bags`,
				`Software\Microsoft\Windows\ShellNoRoam\BagMRU`, `Software\Microsoft\Windows\ShellNoRoam\Bags`, `Software\Microsoft\Internet Explorer\TypedURLs`,
				`Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo`, `Software\Microsoft\Windows\CurrentVersion\Explorer\Discardable`} {
				t = append(t, perLoadedUser(k, true, 0)...)
			}
			// Office MRU and Trusted Documents under any Office version/app
			office := perLoadedUser(`Software\Microsoft\Office`, true, 7)
			for i := range office {
				office[i].Include = func(path string) bool {
					l := strings.ToLower(path)
					return strings.Contains(l, `\file mru`) || strings.Contains(l, `\place mru`) || strings.Contains(l, `\user mru`) || strings.Contains(l, `trusted documents`)
				}
			}
			t = append(t, office...)
			// UsrClass.dat part of the user registry (ShellBags live in both locations)
			t = append(t, perLoadedUserClasses(`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`, true, 0)...)
			t = append(t, perLoadedUserClasses(`Local Settings\Software\Microsoft\Windows\Shell\Bags`, true, 0)...)
			t = append(t, perLoadedUserClasses(`Local Settings\Software\Microsoft\Windows\Shell\MuiCache`, false, 0)...)
			return t
		}),
		perUserFileGroup("users-psreadline-history", um("PowerShell PSReadLine history (all profiles)", "Interactive PowerShell command history for every profile", collector.InAll, collector.PrivUser),
			[]string{`AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt`}),
		walkGroup("users-recent-lnk", um("Recent items (LNK files)", "Shortcut files for recently opened files and folders: target path, MAC times, volume serial, machine ID", collector.InAll, collector.PrivUser),
			`%APPDATA%\Microsoft\Windows\Recent`, walkSpec{Roots: perUserRoots(`AppData\Roaming\Microsoft\Windows\Recent`), MaxDepth: -1, MaxFiles: 20000, FileMax: 16 << 20,
				Match: func(_, n string) bool { return strings.HasSuffix(strings.ToLower(n), ".lnk") }}),
		walkGroup("users-jump-lists", um("Jump Lists (Automatic/Custom Destinations)", "Per-application recent/pinned items (OLE compound files with embedded LNK)", collector.InStdFull, collector.PrivUser,
			"file-activity/automatic-destinations.md"), `%APPDATA%\Microsoft\Windows\Recent\{Automatic,Custom}Destinations`, walkSpec{
			Roots: func() []string {
				return append(perUser(`AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`), perUser(`AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`)...)
			}, MaxDepth: -1, MaxFiles: 20000, FileMax: 64 << 20}),
		walkGroup("users-timeline-activities", um("Windows Timeline (ActivitiesCache.db)", "Windows 10 Timeline activity database per user (app/file activity)", collector.InStdFull, collector.PrivUser),
			`%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db`, walkSpec{Roots: perUserRoots(`AppData\Local\ConnectedDevicesPlatform`), MaxDepth: 3, MaxFiles: 200, FileMax: 1 << 30,
				Match: func(_, n string) bool {
					l := strings.ToLower(n)
					return strings.HasPrefix(l, "activitiescache.db")
				}}),
		walkGroup("users-winget", um("Winget activity logs", "Windows Package Manager diagnostic logs: installed/removed packages and sources", collector.InStdFull, collector.PrivUser, "user-activity/winget.md"),
			`%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_*\LocalState\DiagOutputDir`, walkSpec{
				Roots: func() []string {
					var r []string
					for _, pk := range perUser(`AppData\Local\Packages`) {
						r = append(r, walkGlobDirs(pk, "Microsoft.DesktopAppInstaller_", `LocalState\DiagOutputDir`)...)
					}
					return r
				}, MaxDepth: 2, MaxFiles: 2000, FileMax: 32 << 20}),
	}
	return out
}

// ---- remote access ----

type lsaUnicode struct {
	Length, Max uint16
	Buffer      *uint16
}

type logonSessionData struct {
	Size        uint32
	LogonID     windows.LUID
	UserName    lsaUnicode
	LogonDomain lsaUnicode
	AuthPackage lsaUnicode
	LogonType   uint32
	Session     uint32
	Sid         *windows.SID
	LogonTime   int64
	LogonServer lsaUnicode
	DNSDomain   lsaUnicode
	UPN         lsaUnicode
}

var (
	secur32                 = windows.NewLazySystemDLL("secur32.dll")
	pLsaEnumLogonSessions   = secur32.NewProc("LsaEnumerateLogonSessions")
	pLsaGetLogonSessionData = secur32.NewProc("LsaGetLogonSessionData")
	pLsaFreeReturnBuffer    = secur32.NewProc("LsaFreeReturnBuffer")
)

func (u lsaUnicode) String() string {
	if u.Buffer == nil || u.Length == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(u.Buffer, int(u.Length)/2))
}

var logonTypes = map[uint32]string{2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive", 12: "CachedRemoteInteractive", 13: "CachedUnlock"}

func logonSessions(w *warnings) []map[string]any {
	var count uint32
	var luids uintptr
	if r, _, _ := pLsaEnumLogonSessions.Call(uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&luids))); r != 0 {
		w.add("LsaEnumerateLogonSessions: NTSTATUS 0x%08x", uint32(r))
		return nil
	}
	defer pLsaFreeReturnBuffer.Call(luids)
	base := *(*unsafe.Pointer)(unsafe.Pointer(&luids))
	var out []map[string]any
	for i := uint32(0); i < count; i++ {
		luid := (*windows.LUID)(unsafe.Add(base, uintptr(i)*unsafe.Sizeof(windows.LUID{})))
		var data uintptr
		if r, _, _ := pLsaGetLogonSessionData.Call(uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(&data))); r != 0 {
			w.add("LsaGetLogonSessionData(%x): NTSTATUS 0x%08x", luid.LowPart, uint32(r))
			continue
		}
		d := (*logonSessionData)(*(*unsafe.Pointer)(unsafe.Pointer(&data)))
		sid := ""
		if d.Sid != nil {
			sid = d.Sid.String()
		}
		out = append(out, map[string]any{
			"logon_id": fmt.Sprintf("0x%x", uint64(luid.HighPart)<<32|uint64(luid.LowPart)), "user": d.UserName.String(), "domain": d.LogonDomain.String(),
			"auth_package": d.AuthPackage.String(), "logon_type": logonTypes[d.LogonType], "logon_type_code": d.LogonType, "session_id": d.Session, "sid": sid,
			"logon_time_utc": time.Unix(0, (d.LogonTime-116444736000000000)*100).UTC().Format(time.RFC3339Nano), "logon_server": d.LogonServer.String(),
			"dns_domain": d.DNSDomain.String(), "upn": d.UPN.String(),
		})
		pLsaFreeReturnBuffer.Call(data)
	}
	return out
}

var (
	wtsapi32               = windows.NewLazySystemDLL("wtsapi32.dll")
	pWTSEnumerateSessionsW = wtsapi32.NewProc("WTSEnumerateSessionsW")
	pWTSQuerySessionInfoW  = wtsapi32.NewProc("WTSQuerySessionInformationW")
	pWTSFreeMemory         = wtsapi32.NewProc("WTSFreeMemory")
)

type wtsSessionInfo struct {
	SessionID uint32
	Name      *uint16
	State     uint32
}

func wtsString(session uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	if r, _, _ := pWTSQuerySessionInfoW.Call(0, uintptr(session), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	defer pWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

func terminalSessions(w *warnings) []map[string]any {
	var p *wtsSessionInfo
	var n uint32
	if r, _, err := pWTSEnumerateSessionsW.Call(0, 0, 1, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n))); r == 0 {
		w.add("WTSEnumerateSessions: %v", err)
		return nil
	}
	defer pWTSFreeMemory.Call(uintptr(unsafe.Pointer(p)))
	states := map[uint32]string{0: "Active", 1: "Connected", 2: "ConnectQuery", 3: "Shadow", 4: "Disconnected", 5: "Idle", 6: "Listen", 7: "Reset", 8: "Down", 9: "Init"}
	var out []map[string]any
	for _, s := range unsafe.Slice(p, n) {
		rec := map[string]any{"session_id": s.SessionID, "window_station": windows.UTF16PtrToString(s.Name), "state": states[s.State],
			"user": wtsString(s.SessionID, 5), "domain": wtsString(s.SessionID, 7), "client_name": wtsString(s.SessionID, 10)}
		// WTSClientAddress (14) returns a binary WTS_CLIENT_ADDRESS: report family and the raw bytes
		var addr uintptr
		var an uint32
		if r, _, _ := pWTSQuerySessionInfoW.Call(0, uintptr(s.SessionID), 14, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&an))); r != 0 && an >= 4 {
			b := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), an)
			rec["client_address_family"] = *(*uint32)(unsafe.Pointer(&b[0]))
			if an >= 24 {
				rec["client_address_bytes"] = fmt.Sprintf("%x", b[4:24])
			}
			pWTSFreeMemory.Call(addr)
		}
		out = append(out, rec)
	}
	return out
}

func shares(w *warnings) []map[string]any {
	type shareInfo2 struct {
		Name        *uint16
		Type        uint32
		Remark      *uint16
		Permissions uint32
		MaxUses     uint32
		CurrentUses uint32
		Path        *uint16
		Passwd      *uint16
	}
	var out []map[string]any
	err := netEnum(func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr {
		r, _, _ := pNetShareEnum.Call(0, 2, uintptr(unsafe.Pointer(buf)), ^uintptr(0), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(total)), uintptr(unsafe.Pointer(resume)))
		return r
	}, unsafe.Sizeof(shareInfo2{}), func(p unsafe.Pointer) {
		s := (*shareInfo2)(p)
		out = append(out, map[string]any{"name": windows.UTF16PtrToString(s.Name), "type": s.Type, "remark": windows.UTF16PtrToString(s.Remark),
			"path": windows.UTF16PtrToString(s.Path), "current_uses": s.CurrentUses, "max_uses": s.MaxUses})
	})
	if err != nil {
		w.add("NetShareEnum: %v", err)
	}
	return out
}

func smbSessions(w *warnings) []map[string]any {
	type sessionInfo10 struct {
		Client   *uint16
		User     *uint16
		Time     uint32
		IdleTime uint32
	}
	var out []map[string]any
	err := netEnum(func(buf *uintptr, read, total *uint32, resume *uintptr) uintptr {
		r, _, _ := pNetSessionEnum.Call(0, 0, 0, 10, uintptr(unsafe.Pointer(buf)), ^uintptr(0), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(total)), uintptr(unsafe.Pointer(resume)))
		return r
	}, unsafe.Sizeof(sessionInfo10{}), func(p unsafe.Pointer) {
		s := (*sessionInfo10)(p)
		out = append(out, map[string]any{"client": windows.UTF16PtrToString(s.Client), "user": windows.UTF16PtrToString(s.User), "active_seconds": s.Time, "idle_seconds": s.IdleTime})
	})
	if err != nil {
		w.add("NetSessionEnum (inbound SMB sessions): %v", err)
	}
	return out
}

func remoteSources() []collector.Source {
	rm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "remote-access", priv, p, art...)
	}
	return []collector.Source{
		withDetect(jsonSource("remote-logon-sessions", rm("Logon sessions (LSA) and terminal sessions", "Live logon sessions (user, logon type, time, server, auth package) and Remote Desktop/console sessions with client name and address. Live state only; history is in the Security and TerminalServices logs",
			collector.InAll, collector.PrivAdmin, "network/evtx-4778-session-reconnected.md"), "lsa+wts-enumeration", "lsa://logon-sessions", func(ctx context.Context, w *warnings) (any, error) {
			return map[string]any{"logon_sessions": logonSessions(w), "terminal_sessions": terminalSessions(w),
				"note": "a logon session or RDP session listed here is authenticated state now; connection attempts and failed logons are only in the event logs"}, nil
		}), available),
		withDetect(jsonSource("remote-smb-shares-sessions", rm("SMB shares and inbound sessions", "Shares exported by this host and currently connected SMB client sessions", collector.InStdFull, collector.PrivAdmin),
			"netapi32-share-session", "netapi32://shares-sessions", func(ctx context.Context, w *warnings) (any, error) {
				return map[string]any{"shares": shares(w), "inbound_sessions": smbSessions(w)}, nil
			}), available),
		regSnapshotSource("remote-rdp-server-config", rm("Remote Desktop server and RemoteApp configuration", "Terminal Server settings: fDenyTSConnections, RDP-Tcp port/security layer/NLA, policies, and licensing; server-side RDP evidence (distinct from client history)",
			collector.InAll, collector.PrivUser, "network/terminal-services-remote-1149.md"), `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Control\Terminal Server`, true, 4), hklm(`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, true, 3),
				hklm(`SOFTWARE\Microsoft\Terminal Server Client`, true, 3), hklm(`SYSTEM\CurrentControlSet\Services\TermService`, true, 2),
				hklm(`SYSTEM\CurrentControlSet\Control\Remote Assistance`, true, 2)}
		}),
		regSnapshotSource("remote-rdp-client-history", rm("RDP client history (loaded users)", "Terminal Server Client: MRU of servers connected to, saved usernames and per-server settings (client-side evidence)",
			collector.InAll, collector.PrivUser, "network/terminal-server-client-keys.md"), `HKU\<SID>\Software\Microsoft\Terminal Server Client`, func() []regTarget {
			return perLoadedUser(`Software\Microsoft\Terminal Server Client`, true, 0)
		}),
		sensitiveFullOnly(walkGroup("remote-rdp-bitmap-cache", rm("RDP persistent bitmap cache", "Bitmap cache tiles of past RDP client sessions (screen fragments); can be large", collector.InStdFull, collector.PrivUser, "network/rdp-bitmap-cache.md"),
			`%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache`, walkSpec{Roots: perUserRoots(`AppData\Local\Microsoft\Terminal Server Client\Cache`), MaxDepth: -1, MaxFiles: 500, FileMax: 512 << 20}), "RDP bitmap cache tiles are screen fragments and may contain on-screen secrets"),
		perUserFileGroup("remote-rdp-default-file", rm("Default.rdp connection files", "Default.rdp / .rdp files in Documents: last RDP target and settings", collector.InStdFull, collector.PrivUser),
			[]string{`Documents\Default.rdp`}),
		regSnapshotSource("remote-smb-winrm-config", rm("SMB and WinRM configuration", "LanmanServer/LanmanWorkstation parameters and shares, SMB client/server policy, WinRM policy and listeners", collector.InStdFull, collector.PrivUser),
			`HKLM\SYSTEM\CurrentControlSet\Services\{LanmanServer,LanmanWorkstation}`, func() []regTarget {
				return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, true, 2), hklm(`SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`, true, 2),
					hklm(`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, true, 2), hklm(`SOFTWARE\Policies\Microsoft\Windows\WinRM`, true, 3),
					hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN`, true, 3)}
			}),
	}
}

// walkGlobDirs returns "<base>\<dirPrefix>*\<tail>" directories that exist.
func walkGlobDirs(base, dirPrefix, tail string) []string {
	var out []string
	entries, err := readDirNames(base)
	if err != nil {
		return nil
	}
	for _, n := range entries {
		if strings.HasPrefix(strings.ToLower(n), strings.ToLower(dirPrefix)) {
			p := base + `\` + n + `\` + tail
			if dirExists(p) {
				out = append(out, p)
			}
		}
	}
	return out
}
