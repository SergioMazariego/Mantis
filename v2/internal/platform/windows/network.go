//go:build windows

package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	pGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	pGetExtendedUdpTable  = iphlpapi.NewProc("GetExtendedUdpTable")
	pGetIpNetTable2       = iphlpapi.NewProc("GetIpNetTable2")
	pGetIpForwardTable2   = iphlpapi.NewProc("GetIpForwardTable2")
	pFreeMibTable         = iphlpapi.NewProc("FreeMibTable")
	dnsapi                = windows.NewLazySystemDLL("dnsapi.dll")
	pDnsGetCacheDataTable = dnsapi.NewProc("DnsGetCacheDataTable")
)

const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

type socketRecord struct {
	Protocol      string `json:"protocol"`
	Family        string `json:"family"`
	State         string `json:"state,omitempty"`
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
	PID           uint32 `json:"pid"`
	Process       string `json:"process,omitempty"`
}

var tcpStates = map[uint32]string{1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}

func ntohs(v uint32) uint16 { return uint16(v>>8&0xff) | uint16(v&0xff)<<8 }

// extendedTable calls GetExtendedTcpTable/UdpTable, growing the buffer until it fits.
func extendedTable(tcp bool, family uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		var r uintptr
		if tcp {
			r, _, _ = pGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(family), tcpTableOwnerPidAll, 0)
		} else {
			r, _, _ = pGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(family), udpTableOwnerPid, 0)
		}
		switch syscall.Errno(r) {
		case 0:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, fmt.Errorf("connection table kept growing")
}

// socketTables returns the live TCP and UDP endpoint tables (IPv4 and IPv6) with owning PIDs.
// These are the connections present now; a current table says nothing about history.
func socketTables(w *warnings) []socketRecord {
	var out []socketRecord
	for _, fam := range []uint32{afInet, afInet6} {
		fname := map[uint32]string{afInet: "IPv4", afInet6: "IPv6"}[fam]
		if buf, err := extendedTable(true, fam); err != nil {
			w.add("TCP %s table: %v", fname, err)
		} else {
			n := int(binary.LittleEndian.Uint32(buf))
			rowSize := 24
			if fam == afInet6 {
				rowSize = 56
			}
			for i := 0; i < n && 4+rowSize*(i+1) <= len(buf); i++ {
				r := buf[4+rowSize*i:]
				rec := socketRecord{Protocol: "TCP", Family: fname}
				if fam == afInet {
					rec.State = tcpStates[binary.LittleEndian.Uint32(r[0:])]
					rec.LocalAddress, rec.LocalPort = net.IP(r[4:8]).String(), ntohs(binary.LittleEndian.Uint32(r[8:]))
					rec.RemoteAddress, rec.RemotePort = net.IP(r[12:16]).String(), ntohs(binary.LittleEndian.Uint32(r[16:]))
					rec.PID = binary.LittleEndian.Uint32(r[20:])
				} else {
					rec.LocalAddress, rec.LocalPort = net.IP(r[0:16]).String(), ntohs(binary.LittleEndian.Uint32(r[20:]))
					rec.RemoteAddress, rec.RemotePort = net.IP(r[24:40]).String(), ntohs(binary.LittleEndian.Uint32(r[44:]))
					rec.State = tcpStates[binary.LittleEndian.Uint32(r[48:])]
					rec.PID = binary.LittleEndian.Uint32(r[52:])
				}
				out = append(out, rec)
			}
		}
		if buf, err := extendedTable(false, fam); err != nil {
			w.add("UDP %s table: %v", fname, err)
		} else {
			n := int(binary.LittleEndian.Uint32(buf))
			rowSize := 12
			if fam == afInet6 {
				rowSize = 28
			}
			for i := 0; i < n && 4+rowSize*(i+1) <= len(buf); i++ {
				r := buf[4+rowSize*i:]
				rec := socketRecord{Protocol: "UDP", Family: fname}
				if fam == afInet {
					rec.LocalAddress, rec.LocalPort, rec.PID = net.IP(r[0:4]).String(), ntohs(binary.LittleEndian.Uint32(r[4:])), binary.LittleEndian.Uint32(r[8:])
				} else {
					rec.LocalAddress, rec.LocalPort, rec.PID = net.IP(r[0:16]).String(), ntohs(binary.LittleEndian.Uint32(r[20:])), binary.LittleEndian.Uint32(r[24:])
				}
				out = append(out, rec)
			}
		}
	}
	names := processNames()
	for i := range out {
		out[i].Process = names[out[i].PID]
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].LocalPort < out[j].LocalPort
	})
	return out
}

func processNames() map[uint32]string {
	out := map[uint32]string{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
	}
	return out
}

// ---- neighbors and routes (raw table kept alongside the parsed view) ----

func sockaddrInet(b []byte) string {
	if len(b) < 28 {
		return ""
	}
	switch binary.LittleEndian.Uint16(b) {
	case afInet:
		return net.IP(b[4:8]).String()
	case afInet6:
		return net.IP(b[8:24]).String()
	}
	return ""
}

func neighborsAndRoutes(w *warnings) map[string]any {
	out := map[string]any{}

	// ARP / neighbor cache: MIB_IPNET_TABLE2 { ULONG NumEntries; (pad) MIB_IPNET_ROW2 Table[] }, row = 88 bytes.
	var tbl uintptr
	if r, _, _ := pGetIpNetTable2.Call(0, uintptr(unsafe.Pointer(&tbl))); r != 0 {
		w.add("GetIpNetTable2: %v", syscall.Errno(r))
	} else {
		defer pFreeMibTable.Call(tbl)
		base := *(*unsafe.Pointer)(unsafe.Pointer(&tbl))
		n := int(*(*uint32)(base))
		const rowSize = 88
		raw := unsafe.Slice((*byte)(base), 8+rowSize*n)
		var rows []map[string]any
		for i := 0; i < n; i++ {
			r := raw[8+rowSize*i:]
			plen := binary.LittleEndian.Uint32(r[72:])
			if plen > 32 {
				plen = 32
			}
			rows = append(rows, map[string]any{
				"address": sockaddrInet(r[0:28]), "interface_index": binary.LittleEndian.Uint32(r[28:]),
				"physical_address": fmt.Sprintf("%x", r[40:40+plen]),
				"state":            map[uint32]string{0: "unreachable", 1: "incomplete", 2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "permanent"}[binary.LittleEndian.Uint32(r[76:])],
			})
		}
		out["neighbors"] = rows
		out["neighbors_raw_base64"] = base64.StdEncoding.EncodeToString(append([]byte(nil), raw...))
	}

	// routes: MIB_IPFORWARD_TABLE2 { ULONG NumEntries; (pad) MIB_IPFORWARD_ROW2 Table[] }, row = 104 bytes.
	var rt uintptr
	if r, _, _ := pGetIpForwardTable2.Call(0, uintptr(unsafe.Pointer(&rt))); r != 0 {
		w.add("GetIpForwardTable2: %v", syscall.Errno(r))
	} else {
		defer pFreeMibTable.Call(rt)
		base := *(*unsafe.Pointer)(unsafe.Pointer(&rt))
		n := int(*(*uint32)(base))
		const rowSize = 104
		raw := unsafe.Slice((*byte)(base), 8+rowSize*n)
		var rows []map[string]any
		for i := 0; i < n; i++ {
			r := raw[8+rowSize*i:]
			rows = append(rows, map[string]any{
				"interface_index": binary.LittleEndian.Uint32(r[8:]),
				"destination":     fmt.Sprintf("%s/%d", sockaddrInet(r[12:40]), r[40]),
				"next_hop":        sockaddrInet(r[44:72]),
				"metric":          binary.LittleEndian.Uint32(r[84:]),
				"protocol":        binary.LittleEndian.Uint32(r[88:]),
				"age_seconds":     binary.LittleEndian.Uint32(r[96:]),
			})
		}
		out["routes"] = rows
		out["routes_raw_base64"] = base64.StdEncoding.EncodeToString(append([]byte(nil), raw...))
	}
	out["note"] = "live neighbor cache and routing table; raw table bytes are preserved in *_raw_base64 in case the parsed view is imperfect"
	return out
}

// ---- DNS client cache ----

type dnsCacheEntry struct {
	Next    uintptr
	Name    *uint16
	Type    uint16
	DataLen uint16
	Flags   uint32
}

func dnsCache(w *warnings) []map[string]any {
	if err := dnsapi.Load(); err != nil || pDnsGetCacheDataTable.Find() != nil {
		w.add("DnsGetCacheDataTable is not available on this host")
		return nil
	}
	var head *dnsCacheEntry
	if r, _, err := pDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head))); r == 0 {
		w.add("DnsGetCacheDataTable failed or cache is empty: %v", err)
		return nil
	}
	var out []map[string]any
	for e := head; e != nil && len(out) < 100000; e = (*dnsCacheEntry)(*(*unsafe.Pointer)(unsafe.Pointer(&e.Next))) {
		out = append(out, map[string]any{"name": windows.UTF16PtrToString(e.Name), "type": e.Type, "data_length": e.DataLen, "flags": e.Flags})
	}
	return out
}

// ---- interfaces ----

func interfaceConfig(w *warnings) map[string]any {
	type adapter struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Index       uint32   `json:"index"`
		MAC         string   `json:"mac,omitempty"`
		MTU         uint32   `json:"mtu"`
		Type        uint32   `json:"if_type"`
		Oper        uint32   `json:"oper_status"`
		DNSSuffix   string   `json:"dns_suffix,omitempty"`
		Addresses   []string `json:"unicast_addresses"`
		DNSServers  []string `json:"dns_servers,omitempty"`
		Gateways    []string `json:"gateways,omitempty"`
		DHCPv4      string   `json:"dhcpv4_enabled,omitempty"`
	}
	var out []adapter
	size := uint32(32 << 10)
	var buf []byte
	const flags = 0x80 | 0x10 // GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX
	for i := 0; i < 8; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			w.add("GetAdaptersAddresses: %v", err)
			return map[string]any{"adapters": out}
		}
	}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		ad := adapter{Name: windows.UTF16PtrToString(a.FriendlyName), Description: windows.UTF16PtrToString(a.Description), Index: a.IfIndex,
			MTU: a.Mtu, Type: a.IfType, Oper: a.OperStatus, DNSSuffix: windows.UTF16PtrToString(a.DnsSuffix)}
		if a.PhysicalAddressLength > 0 {
			ad.MAC = fmt.Sprintf("%x", a.PhysicalAddress[:a.PhysicalAddressLength])
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := sockaddrIP(u.Address); ip != "" {
				ad.Addresses = append(ad.Addresses, ip)
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := sockaddrIP(d.Address); ip != "" {
				ad.DNSServers = append(ad.DNSServers, ip)
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := sockaddrIP(g.Address); ip != "" {
				ad.Gateways = append(ad.Gateways, ip)
			}
		}
		out = append(out, ad)
	}
	return map[string]any{"adapters": out}
}

func sockaddrIP(sa windows.SocketAddress) string {
	if sa.Sockaddr == nil {
		return ""
	}
	any, err := sa.Sockaddr.Sockaddr()
	if err != nil {
		return ""
	}
	switch v := any.(type) {
	case *syscall.SockaddrInet4:
		return net.IP(v.Addr[:]).String()
	case *syscall.SockaddrInet6:
		return net.IP(v.Addr[:]).String()
	}
	return ""
}

// ---- sources ----

func networkSources() []collector.Source {
	m := func(name, desc string, p collector.ProfileMask, art ...string) collector.Meta {
		x := baseMeta(name, desc, "network", collector.PrivUser, p, art...)
		return x
	}
	regDump := func(id, name, desc string, p collector.ProfileMask, locator string, targets func() []regTarget, art ...string) collector.Source {
		return regSnapshotSource(id, m(name, desc, p, art...), locator, targets)
	}
	return []collector.Source{
		withDetect(jsonSource("network-connections", m("Live TCP/UDP endpoints with owning process", "Current TCP connections/listeners and UDP endpoints (IPv4 and IPv6) with owning PID and process name. This is a live snapshot, not history", collector.InAll),
			"GetExtendedTcpTable/GetExtendedUdpTable", "iphlpapi://extended-tables", func(ctx context.Context, w *warnings) (any, error) {
				return map[string]any{"sockets": socketTables(w), "note": "live snapshot at collection time; historical connections are not derivable from this table"}, nil
			}), available),
		withDetect(jsonSource("network-dns-cache", m("DNS client cache", "Name-resolution cache entries present now (undocumented dnsapi export; absent on some builds)", collector.InAll),
			"DnsGetCacheDataTable", "dnsapi://cache", func(ctx context.Context, w *warnings) (any, error) {
				return map[string]any{"entries": dnsCache(w)}, nil
			}), available),
		withDetect(jsonSource("network-neighbors-routes", m("ARP/neighbor cache and routing table", "Live IPv4/IPv6 neighbor cache and routing table", collector.InAll),
			"GetIpNetTable2/GetIpForwardTable2", "iphlpapi://neighbors-routes", func(ctx context.Context, w *warnings) (any, error) { return neighborsAndRoutes(w), nil }), available),
		withDetect(jsonSource("network-interfaces", m("Network adapters and IP configuration", "Adapters, MACs, addresses, DNS servers, gateways and DNS suffixes", collector.InAll, "enumeration/interfaces.md", "enumeration/network-cards.md"),
			"GetAdaptersAddresses", "iphlpapi://adapters", func(ctx context.Context, w *warnings) (any, error) { return interfaceConfig(w), nil }), available),
		regDump("network-registry-interfaces", "TCP/IP interface registry configuration", "Per-interface IP, DHCP, DNS and NetBIOS configuration as stored in the registry", collector.InStdFull,
			`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip*\Parameters`, func() []regTarget {
				return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, true, 3), hklm(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, true, 3),
					hklm(`SYSTEM\CurrentControlSet\Services\NetBT\Parameters`, true, 3), hklm(`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, true, 2),
					hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`, true, 2)}
			}, "enumeration/interfaces.md"),
		regDump("network-proxy", "Proxy configuration", "WinINet and WinHTTP proxy settings (machine and loaded users)", collector.InStdFull, `registry://Internet Settings`, func() []regTarget {
			t := []regTarget{hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, true, 3), hklm(`SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`, true, 3)}
			return append(t, perLoadedUser(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, true, 3)...)
		}),
		regDump("network-firewall-config", "Windows Firewall configuration and rules", "Firewall profile settings and the complete rule set stored in the registry (FirewallRules), plus GPO-delivered rules", collector.InStdFull,
			`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`, func() []regTarget {
				return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`, true, 4), hklm(`SOFTWARE\Policies\Microsoft\WindowsFirewall`, true, 4),
					hklm(`SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy`, true, 4)}
			}, "network/evtx-2004-firewall.md", "network/evtx-2005-firewall.md", "network/evtx-2006-firewall.md"),
		regDump("network-profiles", "Network profiles and signatures", "Known networks (NetworkList), first/last connect times, gateways and DNS suffixes; WLAN history is in the WLAN-AutoConfig channel", collector.InStdFull,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`, func() []regTarget {
				return []regTarget{hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`, true, 5), hklm(`SOFTWARE\Microsoft\WlanSvc\Interfaces`, true, 3)}
			}, "network/evtx-8001-wlan-connect.md", "network/evtx-8003-wlan-disconnect.md"),
		regDump("network-tracing-keys", "Network tracing registry keys", "Tracing keys under HKLM\\SOFTWARE\\Microsoft\\Tracing (application network-activity traces)", collector.InStdFull,
			`HKLM\SOFTWARE\Microsoft\Tracing`, func() []regTarget {
				return []regTarget{hklm(`SOFTWARE\Microsoft\Tracing`, true, 3), hklm(`SOFTWARE\WOW6432Node\Microsoft\Tracing`, true, 3)}
			}, "network/tracing-keys.md"),
	}
}
