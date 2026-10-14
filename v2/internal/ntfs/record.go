package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf16"
)

const (
	attrStandardInfo  = 0x10
	attrAttributeList = 0x20
	attrFileName      = 0x30
	attrVolumeInfo    = 0x70
	attrData          = 0x80
	attrIndexRoot     = 0x90
	attrIndexAlloc    = 0xA0
	attrEnd           = 0xFFFFFFFF

	refMask = 1<<48 - 1

	maxRecordSize     = 65536
	maxClusterSize    = 1 << 21
	maxAttrListSize   = 4 << 20
	maxRuns           = 1 << 20
	maxVCN            = 1 << 40
	maxExtRecords     = 8192
	maxAttrsPerRecord = 4096
	maxDirDepth       = 256
	maxIndexDepth     = 64
	maxIndexBlocks    = 1 << 20
	maxDirEntries     = 1 << 23
	maxIndexBlockSize = 1 << 20
	maxPathComponents = 1024

	fixupStride = 512
)

var le = binary.LittleEndian

type attr struct {
	typ      uint32
	name     string
	flags    uint16
	id       uint16
	nonRes   bool
	value    []byte // resident
	startVCN int64
	runs     []byte
	alloc    int64
	real     int64
	init     int64
}

type record struct {
	num   uint64
	seq   uint16
	flags uint16
	base  uint64
	attrs []*attr
}

type run struct {
	vcn int64
	n   int64
	lcn int64 // -1 => sparse
}

type stream struct {
	resident bool
	value    []byte
	runs     []run
	alloc    int64
	real     int64
	init     int64
	flags    uint16
}

func u16s(b []byte) []uint16 {
	out := make([]uint16, len(b)/2)
	for i := range out {
		out[i] = le.Uint16(b[2*i:])
	}
	return out
}

func utf16ToString(u []uint16) string { return string(utf16.Decode(u)) }

func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ft/10000000)-11644473600, int64(ft%10000000)*100).UTC()
}

// applyFixups verifies and removes the update sequence array from buf in place.
func applyFixups(buf []byte, usaOff, usaCnt int) error {
	if usaCnt < 2 || len(buf)%fixupStride != 0 || (usaCnt-1)*fixupStride != len(buf) ||
		usaOff < 8 || usaOff+2*usaCnt > len(buf) {
		return corrupt("bad update sequence array (offset %d count %d size %d)", usaOff, usaCnt, len(buf))
	}
	for i := 1; i < usaCnt; i++ {
		end := i*fixupStride - 2
		if buf[end] != buf[usaOff] || buf[end+1] != buf[usaOff+1] {
			return corrupt("update sequence mismatch in sector %d", i-1)
		}
		buf[end] = buf[usaOff+2*i]
		buf[end+1] = buf[usaOff+2*i+1]
	}
	return nil
}

func parseRecord(buf []byte, num uint64) (*record, error) {
	if len(buf) < 0x30 {
		return nil, corrupt("record %d too short", num)
	}
	if buf[0]|buf[1]|buf[2]|buf[3] == 0 {
		return nil, fmt.Errorf("%w: MFT record %d is unused", ErrNotFound, num)
	}
	if string(buf[:4]) != "FILE" {
		return nil, corrupt("record %d: bad signature %q", num, buf[:4])
	}
	if err := applyFixups(buf, int(le.Uint16(buf[4:])), int(le.Uint16(buf[6:]))); err != nil {
		return nil, fmt.Errorf("record %d: %w", num, err)
	}
	rec := &record{
		num:   num,
		seq:   le.Uint16(buf[0x10:]),
		flags: le.Uint16(buf[0x16:]),
		base:  le.Uint64(buf[0x20:]) & refMask,
	}
	attrOff := int(le.Uint16(buf[0x14:]))
	used := int(le.Uint32(buf[0x18:]))
	if attrOff < 0x30 || attrOff%8 != 0 || used > len(buf) || used < attrOff {
		return nil, corrupt("record %d: bad attribute/used offsets", num)
	}
	off := attrOff
	for {
		if off+4 > used {
			return nil, corrupt("record %d: attributes not terminated", num)
		}
		typ := le.Uint32(buf[off:])
		if typ == attrEnd {
			break
		}
		if len(rec.attrs) >= maxAttrsPerRecord {
			return nil, corrupt("record %d: too many attributes", num)
		}
		if off+16 > used {
			return nil, corrupt("record %d: truncated attribute header", num)
		}
		alen := int(le.Uint32(buf[off+4:]))
		nonRes := buf[off+8] != 0
		hdr := 0x18
		if nonRes {
			hdr = 0x40
		}
		if alen < hdr || alen%8 != 0 || off+alen > used {
			return nil, corrupt("record %d: bad attribute length %d", num, alen)
		}
		a := &attr{typ: typ, nonRes: nonRes, flags: le.Uint16(buf[off+12:]), id: le.Uint16(buf[off+14:])}
		if nl := int(buf[off+9]); nl > 0 {
			no := int(le.Uint16(buf[off+10:]))
			if no < hdr || no+nl*2 > alen {
				return nil, corrupt("record %d: bad attribute name", num)
			}
			a.name = utf16ToString(u16s(buf[off+no : off+no+nl*2]))
		}
		if !nonRes {
			vl := int(le.Uint32(buf[off+0x10:]))
			vo := int(le.Uint16(buf[off+0x14:]))
			if vo < hdr || vo > alen || vl < 0 || vl > alen-vo {
				return nil, corrupt("record %d: bad resident value", num)
			}
			a.value = buf[off+vo : off+vo+vl]
		} else {
			ro := int(le.Uint16(buf[off+0x20:]))
			if ro < hdr || ro > alen {
				return nil, corrupt("record %d: bad runlist offset", num)
			}
			a.runs = buf[off+ro : off+alen]
			sv, al, rl, in := le.Uint64(buf[off+0x10:]), le.Uint64(buf[off+0x28:]), le.Uint64(buf[off+0x30:]), le.Uint64(buf[off+0x38:])
			if sv > maxVCN || al > 1<<62 || rl > 1<<62 || in > 1<<62 {
				return nil, corrupt("record %d: absurd attribute sizes", num)
			}
			a.startVCN, a.alloc, a.real, a.init = int64(sv), int64(al), int64(rl), int64(in)
		}
		rec.attrs = append(rec.attrs, a)
		off += alen
	}
	return rec, nil
}

// decodeRuns decodes a mapping-pairs array starting at vcn. It returns the
// extended run slice and the VCN following the last run.
func decodeRuns(b []byte, vcn, totalClusters int64, dst []run) ([]run, int64, error) {
	var lcn int64
	i := 0
	for i < len(b) {
		h := b[i]
		if h == 0 {
			break
		}
		i++
		ls, os := int(h&0xF), int(h>>4)
		if ls == 0 || ls > 8 || os > 8 || i+ls+os > len(b) {
			return nil, 0, corrupt("bad runlist header")
		}
		var length uint64
		for k := 0; k < ls; k++ {
			length |= uint64(b[i+k]) << (8 * uint(k))
		}
		i += ls
		if length == 0 || length > maxVCN {
			return nil, 0, corrupt("bad run length")
		}
		r := run{vcn: vcn, n: int64(length), lcn: -1}
		if os > 0 {
			var u uint64
			for k := 0; k < os; k++ {
				u |= uint64(b[i+k]) << (8 * uint(k))
			}
			if os < 8 && b[i+os-1]&0x80 != 0 {
				u |= ^uint64(0) << (8 * uint(os))
			}
			delta := int64(u)
			nl := lcn + delta
			if (delta > 0 && nl < lcn) || (delta < 0 && nl > lcn) || nl < 0 {
				return nil, 0, corrupt("bad run offset")
			}
			lcn = nl
			if totalClusters > 0 && (lcn >= totalClusters || int64(length) > totalClusters-lcn) {
				return nil, 0, corrupt("run beyond end of volume")
			}
			r.lcn = lcn
		}
		i += os
		vcn += int64(length)
		if vcn > maxVCN || len(dst) >= maxRuns {
			return nil, 0, corrupt("runlist too large")
		}
		dst = append(dst, r)
	}
	return dst, vcn, nil
}

func (v *Volume) buildStream(parts []*attr) (*stream, error) {
	for _, p := range parts {
		if !p.nonRes {
			if len(parts) != 1 {
				return nil, corrupt("resident attribute with multiple parts")
			}
			n := int64(len(p.value))
			return &stream{resident: true, value: p.value, alloc: n, real: n, init: n, flags: p.flags}, nil
		}
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].startVCN < parts[j].startVCN })
	first := parts[0]
	if first.startVCN != 0 {
		return nil, corrupt("attribute does not start at VCN 0")
	}
	s := &stream{alloc: first.alloc, real: first.real, init: first.init, flags: first.flags}
	if s.init > s.real {
		s.init = s.real
	}
	var next int64
	for _, p := range parts {
		if p.startVCN != next {
			return nil, corrupt("discontinuous attribute extents")
		}
		var err error
		s.runs, next, err = decodeRuns(p.runs, next, v.totalClusters, s.runs)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (v *Volume) findStream(attrs []*attr, typ uint32, name string) (*stream, error) {
	var want string
	if name != "" {
		want = v.fold(name)
	}
	var parts []*attr
	for _, a := range attrs {
		if a.typ != typ {
			continue
		}
		if a.name == name || (name != "" && a.name != "" && v.fold(a.name) == want) {
			parts = append(parts, a)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return v.buildStream(parts)
}

func (v *Volume) streamNames(attrs []*attr, typ uint32) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range attrs {
		if a.typ != typ || a.name == "" {
			continue
		}
		k := v.fold(a.name)
		if !seen[k] {
			seen[k] = true
			out = append(out, a.name)
		}
	}
	return out
}

func readFullAt(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		return corrupt("short read at device offset %d (%d of %d bytes)", off, n, len(p))
	}
	return err
}

// streamReadAt reads logical bytes of s. Bytes in [initialized, real) and
// sparse holes read as zeros. It returns io.EOF when it reaches the real size.
func (v *Volume) streamReadAt(s *stream, p []byte, off int64) (int, error) {
	if s.flags&0x4000 != 0 {
		return 0, ErrEncrypted
	}
	if s.flags&0x0001 != 0 {
		return 0, ErrCompressed
	}
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative offset")
	}
	if off >= s.real {
		return 0, io.EOF
	}
	want := len(p)
	eof := false
	if int64(want) > s.real-off {
		want = int(s.real - off)
		eof = true
	}
	p = p[:want]
	if s.resident {
		n := copy(p, s.value[min(off, int64(len(s.value))):])
		clear(p[n:])
	} else {
		bpc := v.bpc
		n := 0
		for n < want {
			pos := off + int64(n)
			if pos >= s.init {
				clear(p[n:])
				break
			}
			vcn := pos / bpc
			idx := sort.Search(len(s.runs), func(i int) bool { return s.runs[i].vcn+s.runs[i].n > vcn })
			if idx == len(s.runs) || s.runs[idx].vcn > vcn {
				return n, corrupt("logical offset %d is not mapped by the runlist", pos)
			}
			r := s.runs[idx]
			chunk := min(int64(want-n), (r.vcn+r.n)*bpc-pos, s.init-pos)
			dst := p[n : n+int(chunk)]
			if r.lcn < 0 {
				clear(dst)
			} else if err := readFullAt(v.r, dst, r.lcn*bpc+(pos-r.vcn*bpc)); err != nil {
				return n, err
			}
			n += int(chunk)
		}
	}
	if eof {
		return want, io.EOF
	}
	return want, nil
}

func (v *Volume) readAll(s *stream, limit int64) ([]byte, error) {
	if s.real > limit {
		return nil, corrupt("stream too large (%d bytes)", s.real)
	}
	buf := make([]byte, s.real)
	n, err := v.streamReadAt(s, buf, 0)
	if n == len(buf) {
		return buf, nil
	}
	if err == nil || err == io.EOF {
		err = corrupt("short stream read")
	}
	return nil, err
}

func (v *Volume) readRecordRaw(num uint64) ([]byte, error) {
	if num > refMask || num > uint64(v.mft.real)/uint64(v.recSize) {
		return nil, fmt.Errorf("%w: record %d is beyond the end of the MFT", ErrNotFound, num)
	}
	off := int64(num) * v.recSize
	if off+v.recSize > v.mft.real {
		return nil, fmt.Errorf("%w: record %d is beyond the end of the MFT", ErrNotFound, num)
	}
	buf := make([]byte, v.recSize)
	n, err := v.streamReadAt(v.mft, buf, off)
	if n == len(buf) {
		return buf, nil
	}
	if err == nil || err == io.EOF {
		err = corrupt("short MFT record read")
	}
	return nil, err
}

func (v *Volume) readRecord(num uint64) (*record, error) {
	raw, err := v.readRecordRaw(num)
	if err != nil {
		return nil, err
	}
	return parseRecord(raw, num)
}

// gather returns all attributes of the base record, including those that live
// in extension records referenced through $ATTRIBUTE_LIST.
func (v *Volume) gather(rec *record) ([]*attr, error) {
	all := append([]*attr(nil), rec.attrs...)
	var list *attr
	for _, a := range rec.attrs {
		if a.typ == attrAttributeList && a.name == "" {
			list = a
			break
		}
	}
	if list == nil {
		return all, nil
	}
	var content []byte
	if !list.nonRes {
		content = list.value
	} else {
		s, err := v.buildStream([]*attr{list})
		if err != nil {
			return nil, err
		}
		if content, err = v.readAll(s, maxAttrListSize); err != nil {
			return nil, err
		}
	}
	var exts []uint64
	seen := map[uint64]bool{}
	for off := 0; off+0x1A <= len(content); {
		rl := int(le.Uint16(content[off+4:]))
		if rl < 0x1A || off+rl > len(content) {
			return nil, corrupt("record %d: bad attribute list entry", rec.num)
		}
		ref := le.Uint64(content[off+0x10:]) & refMask
		if ref != rec.num && !seen[ref] {
			if len(exts) >= maxExtRecords {
				return nil, corrupt("record %d: too many extension records", rec.num)
			}
			seen[ref] = true
			exts = append(exts, ref)
		}
		off += rl
	}
	for _, ref := range exts {
		er, err := v.readRecord(ref)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				err = corrupt("record %d: extension record %d missing: %v", rec.num, ref, err)
			}
			return nil, err
		}
		if er.flags&1 == 0 || er.base != rec.num {
			continue // stale or foreign entry
		}
		for _, a := range er.attrs {
			if a.typ != attrAttributeList {
				all = append(all, a)
			}
		}
	}
	return all, nil
}
