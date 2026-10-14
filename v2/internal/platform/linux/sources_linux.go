//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

const defaultSourceBytes int64 = 512 << 20

// Sources returns an opt-in catalog. Source data is not read or enumerated
// until the analyst selects a source or group.
func Sources() []collector.Source {
	candidates := []struct{ id, kind, locator, path string }{
		{"auth-log", "linux.authentication_log", "/var/log/auth.log", "/var/log/auth.log"},
		{"secure-log", "linux.authentication_log", "/var/log/secure", "/var/log/secure"},
		{"syslog", "linux.system_log", "/var/log/syslog", "/var/log/syslog"},
		{"messages", "linux.system_log", "/var/log/messages", "/var/log/messages"},
		{"audit-log", "linux.audit_log", "/var/log/audit/audit.log", "/var/log/audit/audit.log"},
		{"kernel-log", "linux.kernel_log", "/var/log/kern.log", "/var/log/kern.log"},
		{"package-logs-dpkg", "linux.package_log", "/var/log/dpkg.log", "/var/log/dpkg.log"},
		{"package-logs-dnf", "linux.package_log", "/var/log/dnf.log", "/var/log/dnf.log"},
		{"package-logs-yum", "linux.package_log", "/var/log/yum.log", "/var/log/yum.log"},
		{"package-logs-pacman", "linux.package_log", "/var/log/pacman.log", "/var/log/pacman.log"},
		{"package-logs-emerge", "linux.package_log", "/var/log/emerge.log", "/var/log/emerge.log"},
		{"system-hosts", "linux.host_configuration", "/etc/hosts", "/etc/hosts"},
		{"system-resolver", "linux.host_configuration", "/etc/resolv.conf", "/etc/resolv.conf"},
		{"system-fstab", "linux.mount_configuration", "/etc/fstab", "/etc/fstab"},
		{"system-mounts", "linux.mount_state", "/proc/self/mountinfo", "/proc/self/mountinfo"},
		{"zimbra-audit", "linux.zimbra_audit_log", "/opt/zimbra/log/audit.log", "/opt/zimbra/log/audit.log"},
		{"zimbra-mailbox", "linux.zimbra_mailbox_log", "/opt/zimbra/log/mailbox.log", "/opt/zimbra/log/mailbox.log"},
		{"zimbra-nginx", "linux.zimbra_proxy_log", "/opt/zimbra/log/nginx.log", "/opt/zimbra/log/nginx.log"},
	}
	var out []collector.Source
	out = append(out,
		generatedSource("system-info", "linux.system_info", "procfs-and-etc://system", 4<<20, systemInfo),
		generatedSource("network-interfaces", "linux.network_interfaces", "netlink-readonly://interfaces", 4<<20, networkInterfaces),
	)
	out = append(out, collector.Source{ID: "process-snapshot", Kind: "linux.process_snapshot", Locator: "procfs://processes", Method: "procfs-snapshot/v1", MaxBytes: 16 << 20,
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			data, err := processSnapshot(ctx)
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}})
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := "/proc/net/" + name
		out = append(out, collector.Source{ID: "network-" + name, Kind: "linux.network_table", Locator: "procfs://net/" + name, Method: "procfs-snapshot/v1", MaxBytes: 4 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) { return openRegular(ctx, path) }})
	}
	for _, candidate := range candidates {
		candidate := candidate
		path := candidate.path
		method := "bounded-file-copy/v1"
		if candidate.id == "system-resolver" {
			method = "bounded-file-or-symlink-metadata/v1"
		}
		out = append(out, collector.Source{ID: candidate.id, Kind: candidate.kind, Locator: candidate.locator, Method: method, MaxBytes: defaultSourceBytes,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				if candidate.id == "system-resolver" {
					return openResolverConfig(ctx, path)
				}
				return openRegular(ctx, path)
			}})
	}
	for _, candidate := range []struct{ id, kind, path string }{
		{"account-passwd", "linux.account_database", "/etc/passwd"},
		{"account-group", "linux.account_database", "/etc/group"},
		{"account-shadow", "linux.sensitive_account_database", "/etc/shadow"},
		{"account-gshadow", "linux.sensitive_account_database", "/etc/gshadow"},
		{"ssh-sshd-config", "linux.ssh_configuration", "/etc/ssh/sshd_config"},
		{"ssh-client-config", "linux.ssh_configuration", "/etc/ssh/ssh_config"},
		{"session-wtmp", "linux.login_history", "/var/log/wtmp"},
		{"session-btmp", "linux.login_history", "/var/log/btmp"},
		{"session-lastlog", "linux.login_history", "/var/log/lastlog"},
		{"session-utmp", "linux.login_state", "/run/utmp"},
		{"cron-system-table", "linux.scheduled_task", "/etc/crontab"},
		{"package-dpkg-status", "linux.package_inventory", "/var/lib/dpkg/status"},
		{"package-rpm-database", "linux.package_inventory", "/var/lib/rpm/rpmdb.sqlite"},
		{"package-apk-database", "linux.package_inventory", "/lib/apk/db/installed"},
	} {
		candidate := candidate
		out = append(out, collector.Source{ID: candidate.id, Kind: candidate.kind, Locator: candidate.path, Method: "bounded-file-copy/v1", MaxBytes: defaultSourceBytes,
			Open: func(ctx context.Context) (io.ReadCloser, error) { return openRegular(ctx, candidate.path) }})
	}
	out = append(out,
		fileTreeGroup("shell-history-root", "linux.shell_history", "/root", 32, func(rel string, _ os.DirEntry) bool {
			return isShellHistory(rel)
		}),
		fileTreeGroup("shell-history-home", "linux.shell_history", "/home", 128, func(rel string, _ os.DirEntry) bool {
			parts := strings.Split(filepath.ToSlash(rel), "/")
			return len(parts) >= 2 && isShellHistory(strings.Join(parts[1:], "/"))
		}),
		fileTreeGroup("ssh-public-material", "linux.ssh_public_material", "/etc/ssh", 128, func(rel string, _ os.DirEntry) bool {
			base := filepath.Base(rel)
			return base == "authorized_keys" || base == "authorized_keys2" || base == "known_hosts" || base == "known_hosts2" ||
				base == "ssh_config" || base == "sshd_config" || strings.HasSuffix(base, ".conf")
		}),
	)
	for _, group := range []struct {
		id, kind, path, locator string
		max                     int
		match                   func(string, os.DirEntry) bool
	}{
		{"cron-config", "linux.scheduled_task", "/etc/cron.d", "/etc/cron.d", 256, allRegularFiles},
		{"cron-daily", "linux.scheduled_task", "/etc/cron.daily", "/etc/cron.daily", 256, allRegularFiles},
		{"cron-hourly", "linux.scheduled_task", "/etc/cron.hourly", "/etc/cron.hourly", 256, allRegularFiles},
		{"cron-weekly", "linux.scheduled_task", "/etc/cron.weekly", "/etc/cron.weekly", 256, allRegularFiles},
		{"cron-monthly", "linux.scheduled_task", "/etc/cron.monthly", "/etc/cron.monthly", 256, allRegularFiles},
		{"cron-user-spool", "linux.scheduled_task", "/var/spool/cron", "/var/spool/cron", 256, allRegularFiles},
		{"cron-user-spool-debian", "linux.scheduled_task", "/var/spool/cron/crontabs", "/var/spool/cron/crontabs", 256, allRegularFiles},
		{"temp-tmp", "linux.temporary_files", "/tmp", "/tmp", 128, allRegularFiles},
		{"temp-var-tmp", "linux.temporary_files", "/var/tmp", "/var/tmp", 128, allRegularFiles},
		{"journal-persistent", "linux.journald_binary", "/var/log/journal", "/var/log/journal", 512, allRegularFiles},
		{"journal-runtime", "linux.journald_binary", "/run/log/journal", "/run/log/journal", 512, allRegularFiles},
		{"web-logs-apache", "linux.web_server_log", "/var/log/apache2", "/var/log/apache2", 256, allRegularFiles},
		{"web-logs-httpd", "linux.web_server_log", "/var/log/httpd", "/var/log/httpd", 256, allRegularFiles},
		{"web-logs-nginx", "linux.web_server_log", "/var/log/nginx", "/var/log/nginx", 256, allRegularFiles},
		{"package-logs-apt", "linux.package_log", "/var/log/apt", "/var/log/apt", 128, allRegularFiles},
		{"package-logs-zypp", "linux.package_log", "/var/log/zypp", "/var/log/zypp", 128, allRegularFiles},
		{"cron-at-queue", "linux.scheduled_task", "/var/spool/at", "/var/spool/at", 256, allRegularFiles},
		{"package-pacman-database", "linux.package_inventory", "/var/lib/pacman/local", "/var/lib/pacman/local", 512, allRegularFiles},
		{"package-rpm-database-files", "linux.package_inventory", "/var/lib/rpm", "/var/lib/rpm", 32, allRegularFiles},
		{"services-systemd-etc", "linux.service_definition", "/etc/systemd/system", "/etc/systemd/system", 512, serviceUnitFiles},
		{"services-systemd-lib", "linux.service_definition", "/usr/lib/systemd/system", "/usr/lib/systemd/system", 512, serviceUnitFiles},
		{"services-systemd-lib-compat", "linux.service_definition", "/lib/systemd/system", "/lib/systemd/system", 512, serviceUnitFiles},
		{"services-init-d", "linux.service_definition", "/etc/init.d", "/etc/init.d", 256, allRegularFiles},
	} {
		out = append(out, fileTreeGroup(group.id, group.kind, group.path, group.max, group.match))
	}
	return out
}

func allRegularFiles(_ string, entry os.DirEntry) bool { return !entry.IsDir() }

func serviceUnitFiles(rel string, entry os.DirEntry) bool {
	return !entry.IsDir() && (strings.HasSuffix(rel, ".service") || strings.HasSuffix(rel, ".timer") || strings.HasSuffix(rel, ".socket"))
}

func isShellHistory(rel string) bool {
	return rel == ".bash_history" || rel == ".zsh_history" || rel == ".python_history" || rel == ".history" || rel == ".local/share/fish/fish_history"
}

func generatedSource(id, kind, locator string, limit int64, generate func(context.Context) ([]byte, error)) collector.Source {
	return collector.Source{ID: id, Kind: kind, Locator: locator, Method: "native-readonly-snapshot/v1", MaxBytes: limit,
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			data, err := generate(ctx)
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}}
}

func fileTreeGroup(id, kind, root string, maxFiles int, match func(string, os.DirEntry) bool) collector.Source {
	return collector.Source{ID: id, Kind: kind, Locator: "optional-path-group://" + id, Method: "bounded-no-follow-walk/v1", MaxBytes: defaultSourceBytes,
		Expand: func(ctx context.Context) ([]collector.Source, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			info, err := os.Lstat(root)
			if err != nil {
				return nil, err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("source group root is not a real directory")
			}
			var paths []string
			visited := 0
			truncated := false
			enumerationErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if walkErr != nil {
					return walkErr
				}
				visited++
				if visited > 8192 {
					truncated = true
					return filepath.SkipAll
				}
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				if entry.IsDir() {
					if rel != "." && strings.Count(filepath.Clean(rel), string(os.PathSeparator)) >= 3 {
						truncated = true
						return filepath.SkipDir
					}
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return nil
				}
				fileInfo, err := entry.Info()
				if err != nil || !fileInfo.Mode().IsRegular() || !match(rel, entry) {
					return nil
				}
				paths = append(paths, path)
				if len(paths) >= maxFiles {
					truncated = true
					return filepath.SkipAll
				}
				return nil
			})
			if enumerationErr != nil {
				return nil, enumerationErr
			}
			sort.Strings(paths)
			children := make([]collector.Source, 0, len(paths))
			for i, path := range paths {
				filePath := path
				rel, _ := filepath.Rel(root, path)
				rel = filepath.ToSlash(rel)
				relDigest := sha256.Sum256([]byte(rel))
				childID := fmt.Sprintf("%s-%03d-%s-%s", id, i+1, safeComponent(rel), hex.EncodeToString(relDigest[:4]))
				children = append(children, collector.Source{ID: childID, Kind: kind, Locator: "path-relative://" + filepath.ToSlash(rel), Method: "bounded-file-copy/v1", MaxBytes: defaultSourceBytes,
					Open: func(ctx context.Context) (io.ReadCloser, error) { return openRegular(ctx, filePath) }})
			}
			if truncated {
				children = append(children, collector.Source{ID: id + "-enumeration-gap", Kind: "linux.collection_gap", Locator: "optional-path-group://" + id,
					Method: "bounded-no-follow-walk/v1", MaxBytes: 1,
					Open: func(context.Context) (io.ReadCloser, error) {
						return nil, errors.New("source group enumeration reached a safety limit")
					}})
			}
			if len(children) == 0 {
				return nil, collector.ErrNoSources
			}
			return children, nil
		}}
}

func safeComponent(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

func systemInfo(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	osRelease, _ := readProcValue("/etc/os-release", 64<<10)
	kernel, _ := readProcValue("/proc/sys/kernel/osrelease", 4096)
	host, _ := os.Hostname()
	return json.Marshal(struct {
		CapturedAt   string `json:"captured_at_utc"`
		Hostname     string `json:"hostname,omitempty"`
		OSRelease    string `json:"os_release,omitempty"`
		Kernel       string `json:"kernel_release,omitempty"`
		Architecture string `json:"architecture"`
	}{time.Now().UTC().Format(time.RFC3339Nano), host, string(osRelease), strings.TrimSpace(string(kernel)), runtime.GOARCH})
}

func networkInterfaces(ctx context.Context) ([]byte, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	type networkInterface struct {
		Index        int      `json:"index"`
		Name         string   `json:"name"`
		MTU          int      `json:"mtu"`
		Flags        string   `json:"flags"`
		HardwareAddr string   `json:"hardware_address,omitempty"`
		Addresses    []string `json:"addresses,omitempty"`
		Status       string   `json:"status"`
	}
	rows := make([]networkInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := networkInterface{Index: iface.Index, Name: iface.Name, MTU: iface.MTU, Flags: iface.Flags.String(), HardwareAddr: iface.HardwareAddr.String(), Status: "OK"}
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			row.Status = "ADDRESS_QUERY_ERROR"
		} else {
			for _, addr := range addresses {
				row.Addresses = append(row.Addresses, addr.String())
			}
		}
		rows = append(rows, row)
	}
	return json.Marshal(struct {
		CapturedAt string             `json:"captured_at_utc"`
		Interfaces []networkInterface `json:"interfaces"`
	}{time.Now().UTC().Format(time.RFC3339Nano), rows})
}

type processRecord struct {
	PID         int    `json:"pid"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	Name        string `json:"name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Executable  string `json:"executable,omitempty"`
	State       string `json:"state,omitempty"`
	UIDs        string `json:"uids,omitempty"`
	GIDs        string `json:"gids,omitempty"`
	ResidentKB  uint64 `json:"resident_kb,omitempty"`
}

func processSnapshot(ctx context.Context) ([]byte, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	processes := make([]processRecord, 0, 256)
	unreadableFields := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		base := "/proc/" + entry.Name()
		comm, commErr := readProcValue(base+"/comm", 4096)
		cmd, cmdErr := readProcValue(base+"/cmdline", 16<<10)
		status, statusErr := readProcValue(base+"/status", 64<<10)
		if commErr != nil {
			unreadableFields++
		}
		if cmdErr != nil {
			unreadableFields++
		}
		if statusErr != nil {
			unreadableFields++
		}
		record := processRecord{PID: pid, Name: strings.TrimSpace(string(comm)), CommandLine: strings.ReplaceAll(strings.TrimRight(string(cmd), "\x00"), "\x00", " ")}
		record.Executable, _ = os.Readlink(base + "/exe")
		for _, line := range bytes.Split(status, []byte("\n")) {
			key, value, ok := bytes.Cut(line, []byte(":"))
			if !ok {
				continue
			}
			switch string(key) {
			case "PPid":
				record.ParentPID, _ = strconv.Atoi(strings.TrimSpace(string(value)))
			case "State":
				record.State = strings.TrimSpace(string(value))
			case "Uid":
				record.UIDs = strings.TrimSpace(string(value))
			case "Gid":
				record.GIDs = strings.TrimSpace(string(value))
			case "VmRSS":
				fields := strings.Fields(string(value))
				if len(fields) > 0 {
					record.ResidentKB, _ = strconv.ParseUint(fields[0], 10, 64)
				}
			}
		}
		processes = append(processes, record)
		if len(processes) > 8192 {
			return nil, errors.New("process count exceeds collection limit")
		}
	}
	data, err := json.Marshal(struct {
		CapturedAt       string          `json:"captured_at_utc"`
		Processes        []processRecord `json:"processes"`
		UnreadableFields int             `json:"unreadable_process_fields"`
	}{time.Now().UTC().Format(time.RFC3339Nano), processes, unreadableFields})
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("process snapshot exceeds collection limit")
	}
	return data, nil
}

func readProcValue(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("proc value exceeds collection limit")
	}
	return data, nil
}

func openRegular(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("source is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, errors.New("source changed during open")
	}
	return f, nil
}

func openResolverConfig(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return openRegular(ctx, path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(struct {
		Path   string `json:"path"`
		Type   string `json:"type"`
		Target string `json:"symlink_target"`
	}{path, "symlink", target})
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
