package ntfs

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"
)

// VolumeInfo describes the volume geometry read from $Boot and $Volume.
type VolumeInfo struct {
	SerialNumber      uint64
	BytesPerSector    uint32
	SectorsPerCluster uint32
	BytesPerCluster   uint32
	MFTRecordSize     uint32
	TotalSectors      uint64
	MFTStartCluster   uint64
	MFTMirrorCluster  uint64
	VolumeSerialHex   string
	NTFSMajor         uint8
	NTFSMinor         uint8
}

// Volume is a read-only view of an NTFS volume. It is not safe for concurrent
// use; serialize all calls (and use the underlying reader from one goroutine
// at a time, particularly when it is an AlignedReaderAt).
type Volume struct {
	r             io.ReaderAt
	info          VolumeInfo
	bps           int64
	bpc           int64
	recSize       int64
	totalClusters int64
	mft           *stream
	upcase        []uint16 // nil => fallback folding
}

// Info returns the volume geometry.
func (v *Volume) Info() VolumeInfo { return v.info }

// UpcaseLoaded reports whether the volume's real $UpCase table is in use
// (otherwise a simple Unicode simple-uppercase fallback is used).
func (v *Volume) UpcaseLoaded() bool { return v.upcase != nil }

func notNTFS(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNotNTFS, fmt.Sprintf(format, a...))
}

// OpenVolume parses the boot sector and the $MFT record and prepares the
// volume for reading. r must be positioned at the start of the volume. For raw
// device handles, wrap them with NewAlignedReaderAt first.
func OpenVolume(r io.ReaderAt) (*Volume, error) {
	boot := make([]byte, 512)
	n, err := r.ReadAt(boot, 0)
	if n < 512 {
		if err == nil || err == io.EOF {
			return nil, notNTFS("image shorter than one sector")
		}
		return nil, err
	}
	if string(boot[3:11]) != "NTFS    " {
		return nil, notNTFS("missing NTFS OEM ID")
	}
	bps := int64(le.Uint16(boot[0x0B:]))
	if bps < 256 || bps > 4096 || bps&(bps-1) != 0 {
		return nil, notNTFS("bad bytes per sector %d", bps)
	}
	spc := int64(boot[0x0D])
	if spc > 0x80 {
		spc = 1 << (256 - spc)
	}
	if spc == 0 || spc&(spc-1) != 0 || bps*spc > maxClusterSize {
		return nil, notNTFS("bad sectors per cluster")
	}
	bpc := bps * spc
	totalSectors := le.Uint64(boot[0x28:])
	if totalSectors == 0 || totalSectors > (1<<62)/uint64(bps) {
		return nil, notNTFS("bad total sector count")
	}
	totalClusters := int64(totalSectors) / spc
	mftLCN, mirrLCN := le.Uint64(boot[0x30:]), le.Uint64(boot[0x38:])
	if mftLCN >= uint64(totalClusters) {
		return nil, notNTFS("$MFT cluster beyond volume")
	}
	var recSize int64
	switch cpr := int8(boot[0x40]); {
	case cpr > 0:
		recSize = int64(cpr) * bpc
	case cpr < 0 && cpr >= -16:
		recSize = 1 << uint(-cpr)
	}
	if recSize < 512 || recSize > maxRecordSize || recSize%fixupStride != 0 {
		return nil, notNTFS("bad MFT record size")
	}
	v := &Volume{r: r, bps: bps, bpc: bpc, recSize: recSize, totalClusters: totalClusters}
	serial := le.Uint64(boot[0x48:])
	v.info = VolumeInfo{
		SerialNumber:      serial,
		BytesPerSector:    uint32(bps),
		SectorsPerCluster: uint32(spc),
		BytesPerCluster:   uint32(bpc),
		MFTRecordSize:     uint32(recSize),
		TotalSectors:      totalSectors,
		MFTStartCluster:   mftLCN,
		MFTMirrorCluster:  mirrLCN,
		VolumeSerialHex:   fmt.Sprintf("%016X", serial),
	}

	// Bootstrap: read record 0 directly from the boot sector's MFT location.
	raw := make([]byte, recSize)
	if err := readFullAt(r, raw, int64(mftLCN)*bpc); err != nil {
		return nil, err
	}
	rec0, err := parseRecord(raw, 0)
	if err != nil {
		return nil, fmt.Errorf("$MFT record: %w", err)
	}
	boots, err := v.findStream(rec0.attrs, attrData, "")
	if err != nil {
		return nil, err
	}
	if boots == nil || boots.resident || boots.real < recSize {
		return nil, corrupt("$MFT has no usable non-resident $DATA")
	}
	v.mft = boots // partial view: only extents stored in record 0
	attrs, err := v.gather(rec0)
	if err != nil {
		return nil, err
	}
	full, err := v.findStream(attrs, attrData, "")
	if err != nil {
		return nil, err
	}
	if full == nil || full.resident || full.real < recSize {
		return nil, corrupt("$MFT has no usable non-resident $DATA")
	}
	v.mft = full

	// Best-effort extras: NTFS version ($Volume) and $UpCase table.
	if rec, err := v.readRecord(3); err == nil {
		if as, err := v.gather(rec); err == nil {
			for _, a := range as {
				if a.typ == attrVolumeInfo && !a.nonRes && len(a.value) >= 10 {
					v.info.NTFSMajor, v.info.NTFSMinor = a.value[8], a.value[9]
				}
			}
		}
	}
	v.loadUpcase()
	return v, nil
}

func (v *Volume) loadUpcase() {
	f, err := v.loadFile(10)
	if err != nil || f.selectStream("") != nil || f.sel == nil || f.sel.real != 65536*2 {
		return
	}
	b, err := v.readAll(f.sel, 65536*2)
	if err != nil {
		return
	}
	t := u16s(b)
	if t['a'] != 'A' || t['z'] != 'Z' || t['A'] != 'A' || t['0'] != '0' {
		return // implausible table
	}
	v.upcase = t
}

func (v *Volume) upper(u uint16) uint16 {
	if v.upcase != nil {
		return v.upcase[u]
	}
	if u < 0x80 {
		if u >= 'a' && u <= 'z' {
			return u - 32
		}
		return u
	}
	if u >= 0xD800 && u <= 0xDFFF {
		return u
	}
	if r := unicode.ToUpper(rune(u)); r <= 0xFFFF {
		return uint16(r)
	}
	return u
}

// compareUnits orders two UTF-16 names like NTFS COLLATION_FILE_NAME: by
// upcased code unit value, shorter first on a common prefix.
func (v *Volume) compareUnits(a, b []uint16) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := v.upper(a[i]), v.upper(b[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func (v *Volume) fold(s string) string {
	u := utf16.Encode([]rune(s))
	for i := range u {
		u[i] = v.upper(u[i])
	}
	return string(utf16.Decode(u))
}

// splitPath normalizes p into components and an optional stream name.
func splitPath(p string, allowStream bool) (comps []string, stream string, err error) {
	p = strings.ReplaceAll(p, "/", "\\")
	if len(p) >= 2 && p[1] == ':' && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z') && (len(p) == 2 || p[2] == '\\') {
		p = p[2:]
	}
	for _, c := range strings.Split(p, "\\") {
		switch c {
		case "", ".":
		case "..":
			return nil, "", fmt.Errorf("%w: '..' is not supported in paths", ErrNotFound)
		default:
			comps = append(comps, c)
		}
	}
	if len(comps) > maxPathComponents {
		return nil, "", fmt.Errorf("%w: path too long", ErrNotFound)
	}
	if allowStream && len(comps) > 0 {
		last := comps[len(comps)-1]
		if i := strings.IndexByte(last, ':'); i >= 0 {
			stream = last[i+1:]
			comps[len(comps)-1] = last[:i]
			if len(stream) >= 6 && strings.EqualFold(stream[len(stream)-6:], ":$DATA") {
				stream = stream[:len(stream)-6]
			} else if strings.EqualFold(stream, "$DATA") {
				stream = ""
			}
			if strings.IndexByte(stream, ':') >= 0 {
				return nil, "", fmt.Errorf("%w: only $DATA streams are addressable", ErrUnsupported)
			}
			if comps[len(comps)-1] == "" {
				return nil, "", fmt.Errorf("%w: empty file name", ErrNotFound)
			}
		}
	}
	return comps, stream, nil
}

func (v *Volume) resolve(p string, allowStream bool) (*File, error) {
	comps, stream, err := splitPath(p, allowStream)
	if err != nil {
		return nil, err
	}
	cur, err := v.loadFile(5)
	if err != nil {
		return nil, err
	}
	for _, c := range comps {
		if !cur.isDir {
			return nil, fmt.Errorf("%w: %q", ErrNotDirectory, cur.name)
		}
		num, err := v.lookup(cur, c)
		if err != nil {
			return nil, fmt.Errorf("%w (component %q)", err, c)
		}
		if cur, err = v.loadFile(num); err != nil {
			return nil, err
		}
	}
	if err := cur.selectStream(stream); err != nil {
		return nil, err
	}
	return cur, nil
}

// OpenPath opens a file or directory. p uses '\' or '/' separators and no
// drive letter (a leading "C:" is tolerated and ignored). Matching is case
// insensitive using the volume's $UpCase table when available (see doc.go).
// The last component may carry an alternate data stream suffix
// ("file:Zone.Identifier", "$Extend\$UsnJrnl:$J"); ":$DATA" suffixes are
// accepted. Reparse points are not followed.
func (v *Volume) OpenPath(p string) (*File, error) { return v.resolve(p, true) }

// OpenRecord opens an MFT record by number (the default stream is selected).
func (v *Volume) OpenRecord(recordNumber uint64) (*File, error) {
	f, err := v.loadFile(recordNumber)
	if err != nil {
		return nil, err
	}
	if err := f.selectStream(""); err != nil {
		return nil, err
	}
	return f, nil
}
