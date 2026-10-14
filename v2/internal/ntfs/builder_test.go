package ntfs

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Synthetic image geometry: 512-byte sectors, 2 sectors/cluster (1 KiB
// clusters), 4 KiB MFT records, 4 KiB index blocks, 400 clusters.
const (
	tBPS      = 512
	tSPC      = 2
	tBPC      = 1024
	tRec      = 4096
	tClusters = 400
	tIdxBlk   = 4096
	tMFTRecs  = 40
)

// Record numbers of the synthetic files.
const (
	rMFT      = 0
	rVolume   = 3
	rRoot     = 5
	rUpcase   = 10
	rExtend   = 11
	rUsn      = 12
	rExtMFT   = 15 // extension record of $MFT (mftExt variant)
	rWindows  = 24
	rHello    = 25
	rFrag     = 26
	rADS      = 27
	rBig      = 28
	rAttrList = 29
	rSys32    = 30
	rConfig   = 31
	rSystem   = 32
	rAttrExt  = 33
	rComp     = 34
	rEnc      = 35
	rJunction = 36
	rLong     = 37
)

var tTime = time.Date(2024, 1, 2, 3, 4, 5, 123456700, time.UTC)

func toFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100)
}

type opts struct{ upcase, mftExt bool }

var (
	helloData = []byte("Hello, NTFS!\n")
	zoneData  = []byte("[ZoneTransfer]\r\nZoneId=3\r\n")
	adsMain   = []byte("MZ-fake-exe")
)

func pat(seed, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7+seed)%251 + 1)
	}
	return b
}

// expectations for non-resident files.
func fragLogical() []byte { // what the file must read as (9000 bytes)
	b := pat(11, 9000)
	for i := 3072; i < 5120; i++ {
		b[i] = 0
	}
	for i := 8000; i < 9000; i++ {
		b[i] = 0
	}
	return b
}
func attrListData() []byte { return pat(23, 8000) }
func systemData() []byte   { return pat(37, 1500) }
func usnJ() []byte {
	b := make([]byte, 6144)
	copy(b[4096:], pat(41, 2048))
	return b
}

func put16(b []byte, o int, v uint16) { binary.LittleEndian.PutUint16(b[o:], v) }
func put32(b []byte, o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
func put64(b []byte, o int, v uint64) { binary.LittleEndian.PutUint64(b[o:], v) }
func align8(n int) int                { return (n + 7) &^ 7 }
func ref(n, seq uint64) uint64        { return n | seq<<48 }

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}

func resAttr(typ uint32, name string, id uint16, value []byte) []byte {
	nb := utf16le(name)
	vo := align8(0x18 + len(nb))
	total := align8(vo + len(value))
	a := make([]byte, total)
	put32(a, 0, typ)
	put32(a, 4, uint32(total))
	a[9] = byte(len(nb) / 2)
	put16(a, 10, 0x18)
	put16(a, 14, id)
	put32(a, 0x10, uint32(len(value)))
	put16(a, 0x14, uint16(vo))
	copy(a[0x18:], nb)
	copy(a[vo:], value)
	return a
}

func nonResAttr(typ uint32, name string, id, flags uint16, startVCN, endVCN int64, runs []byte, alloc, real, init int64) []byte {
	nb := utf16le(name)
	hdr := 0x40
	if flags&1 != 0 {
		hdr = 0x48
	}
	ro := align8(hdr + len(nb))
	total := align8(ro + len(runs))
	a := make([]byte, total)
	put32(a, 0, typ)
	put32(a, 4, uint32(total))
	a[8] = 1
	a[9] = byte(len(nb) / 2)
	put16(a, 10, uint16(hdr))
	put16(a, 12, flags)
	put16(a, 14, id)
	put64(a, 0x10, uint64(startVCN))
	put64(a, 0x18, uint64(endVCN))
	put16(a, 0x20, uint16(ro))
	if flags&1 != 0 {
		put16(a, 0x22, 4)
	}
	put64(a, 0x28, uint64(alloc))
	put64(a, 0x30, uint64(real))
	put64(a, 0x38, uint64(init))
	copy(a[hdr:], nb)
	copy(a[ro:], runs)
	return a
}

type rs struct{ lcn, n int64 } // lcn < 0 => sparse

func minU(v uint64) int {
	for k := 1; k < 8; k++ {
		if v < 1<<(8*uint(k)) {
			return k
		}
	}
	return 8
}
func minS(d int64) int {
	for k := 1; k < 8; k++ {
		lim := int64(1) << (8*uint(k) - 1)
		if d >= -lim && d < lim {
			return k
		}
	}
	return 8
}
func encRuns(runs []rs) []byte {
	var out []byte
	prev := int64(0)
	le8 := func(v uint64, k int) {
		for i := 0; i < k; i++ {
			out = append(out, byte(v>>(8*uint(i))))
		}
	}
	for _, r := range runs {
		lb := minU(uint64(r.n))
		if r.lcn < 0 {
			out = append(out, byte(lb))
			le8(uint64(r.n), lb)
			continue
		}
		d := r.lcn - prev
		prev = r.lcn
		ob := minS(d)
		out = append(out, byte(ob<<4|lb))
		le8(uint64(r.n), lb)
		le8(uint64(d), ob)
	}
	return append(out, 0)
}

func mkRecord(num uint32, seq, flags uint16, base uint64, attrs ...[]byte) []byte {
	r := make([]byte, tRec)
	copy(r, "FILE")
	put16(r, 4, 0x30)
	put16(r, 6, uint16(tRec/512+1))
	put16(r, 0x10, seq)
	put16(r, 0x12, 1)
	put16(r, 0x14, 0x48)
	put16(r, 0x16, flags)
	put32(r, 0x1C, tRec)
	put64(r, 0x20, base)
	put32(r, 0x2C, num)
	off := 0x48
	for _, a := range attrs {
		if off+len(a)+8 > tRec {
			panic(fmt.Sprintf("record %d overflow", num))
		}
		copy(r[off:], a)
		off += len(a)
	}
	put32(r, off, 0xFFFFFFFF)
	off += 8
	put32(r, 0x18, uint32(off))
	const usn = 0x7E7E
	put16(r, 0x30, usn)
	for i := 0; i < tRec/512; i++ {
		end := i*512 + 510
		copy(r[0x32+2*i:], r[end:end+2])
		put16(r, end, usn)
	}
	return r
}

func siVal(flags uint32) []byte {
	v := make([]byte, 0x48)
	for i := 0; i < 4; i++ {
		put64(v, 8*i, toFiletime(tTime))
	}
	put32(v, 0x20, flags)
	return v
}

func fnVal(parent uint64, name string, ns byte, flags uint32, real int64) []byte {
	nb := utf16le(name)
	v := make([]byte, 0x42+len(nb))
	put64(v, 0, parent)
	for i := 0; i < 4; i++ {
		put64(v, 8+8*i, toFiletime(tTime))
	}
	put64(v, 0x28, uint64((real+1023)/1024*1024))
	put64(v, 0x30, uint64(real))
	put32(v, 0x38, flags)
	v[0x40] = byte(len(nb) / 2)
	v[0x41] = ns
	copy(v[0x42:], nb)
	return v
}

func idxEnt(refv uint64, key []byte, child int64) []byte {
	elen := align8(16 + len(key))
	if child >= 0 {
		elen += 8
	}
	e := make([]byte, elen)
	put64(e, 0, refv)
	put16(e, 8, uint16(elen))
	put16(e, 10, uint16(len(key)))
	if child >= 0 {
		put16(e, 12, 1)
		put64(e, elen-8, uint64(child))
	}
	copy(e[16:], key)
	return e
}

func idxLast(child int64) []byte {
	elen := 16
	if child >= 0 {
		elen = 24
	}
	e := make([]byte, elen)
	put16(e, 8, uint16(elen))
	fl := uint16(2)
	if child >= 0 {
		fl |= 1
		put64(e, 16, uint64(child))
	}
	put16(e, 12, fl)
	return e
}

func idxRoot(entries []byte, hasChild bool) []byte {
	v := make([]byte, 0x20+len(entries))
	put32(v, 0, 0x30)
	put32(v, 4, 1)
	put32(v, 8, tIdxBlk)
	v[0xC] = tIdxBlk / tBPC
	put32(v, 0x10, 0x10)
	put32(v, 0x14, uint32(0x10+len(entries)))
	put32(v, 0x18, uint32(0x10+len(entries)))
	if hasChild {
		v[0x1C] = 1
	}
	copy(v[0x20:], entries)
	return v
}

func indxBlock(vcn int64, entries []byte, hasChild bool) []byte {
	b := make([]byte, tIdxBlk)
	copy(b, "INDX")
	put16(b, 4, 0x28)
	put16(b, 6, tIdxBlk/512+1)
	put64(b, 0x10, uint64(vcn))
	put32(b, 0x18, 0x28)
	put32(b, 0x1C, uint32(0x28+len(entries)))
	put32(b, 0x20, tIdxBlk-0x18)
	if hasChild {
		b[0x24] = 1
	}
	if 0x40+len(entries) > tIdxBlk {
		panic("index block overflow")
	}
	copy(b[0x40:], entries)
	const usn = 0x5A5A
	put16(b, 0x28, usn)
	for i := 0; i < tIdxBlk/512; i++ {
		end := i*512 + 510
		copy(b[0x2A+2*i:], b[end:end+2])
		put16(b, end, usn)
	}
	return b
}

type dent struct {
	name  string
	rec   uint64
	ns    byte
	flags uint32
	real  int64
}

func sortEnts(es []dent) {
	sort.SliceStable(es, func(i, j int) bool {
		return strings.ToUpper(es[i].name) < strings.ToUpper(es[j].name)
	})
}

func entBytes(parent uint64, es []dent) []byte {
	sortEnts(es)
	var out []byte
	for _, e := range es {
		out = append(out, idxEnt(ref(e.rec, 1), fnVal(ref(parent, 1), e.name, e.ns, e.flags, e.real), -1)...)
	}
	return out
}

func smallDir(num uint32, parent uint64, name string, es []dent) []byte {
	body := append(entBytes(uint64(num), es), idxLast(-1)...)
	return mkRecord(num, 1, 3, 0,
		resAttr(attrStandardInfo, "", 0, siVal(0)),
		resAttr(attrFileName, "", 1, fnVal(ref(parent, 1), name, 3, 0x10000000, 0)),
		resAttr(attrIndexRoot, "$I30", 2, idxRoot(body, false)))
}

func fileRec(num uint32, parent uint64, name string, flags uint32, real int64, extra ...[]byte) []byte {
	attrs := [][]byte{
		resAttr(attrStandardInfo, "", 0, siVal(flags)),
		resAttr(attrFileName, "", 1, fnVal(ref(parent, 1), name, 3, flags, real)),
	}
	return mkRecord(num, 1, 1, 0, append(attrs, extra...)...)
}

func alEntry(typ uint32, name string, startVCN int64, recNum uint64, id uint16) []byte {
	nb := utf16le(name)
	e := make([]byte, align8(0x1A+len(nb)))
	put32(e, 0, typ)
	put16(e, 4, uint16(len(e)))
	e[6] = byte(len(nb) / 2)
	e[7] = 0x1A
	put64(e, 8, uint64(startVCN))
	put64(e, 0x10, ref(recNum, 1))
	put16(e, 0x18, id)
	copy(e[0x1A:], nb)
	return e
}

func mftRecLoc(n int) int { // byte offset of MFT record n in the image
	if n < 16 {
		return (4 + 4*n) * tBPC
	}
	return (80 + 4*(n-16)) * tBPC
}

func bigNames() []string {
	var out []string
	for i := 0; i < 200; i++ {
		out = append(out, fmt.Sprintf("file%03d", i))
	}
	return out
}

// buildImage creates the synthetic NTFS image described in the tests.
func buildImage(o opts) []byte {
	img := make([]byte, tClusters*tBPC)
	boot := img[:512]
	boot[0], boot[1], boot[2] = 0xEB, 0x52, 0x90
	copy(boot[3:], "NTFS    ")
	put16(boot, 0x0B, tBPS)
	boot[0x0D] = tSPC
	put64(boot, 0x28, tClusters*tSPC)
	put64(boot, 0x30, 4)
	put64(boot, 0x38, 2)
	boot[0x40] = 0xF4 // -12 => 4096
	boot[0x44] = 4
	put64(boot, 0x48, 0x1122334455667788)
	boot[510], boot[511] = 0x55, 0xAA

	put := func(lcn int, data []byte) { copy(img[lcn*tBPC:], data) }
	recs := map[int][]byte{}

	// $MFT
	mftAlloc := int64(tMFTRecs * tRec)
	if o.mftExt {
		first := encRuns([]rs{{4, 64}})
		second := encRuns([]rs{{80, 96}})
		al := append(alEntry(attrStandardInfo, "", 0, rMFT, 0), alEntry(attrAttributeList, "", 0, rMFT, 1)...)
		al = append(al, alEntry(attrFileName, "", 0, rMFT, 2)...)
		al = append(al, alEntry(attrData, "", 0, rMFT, 3)...)
		al = append(al, alEntry(attrData, "", 64, rExtMFT, 0)...)
		recs[0] = mkRecord(0, 1, 1, 0,
			resAttr(attrStandardInfo, "", 0, siVal(6)),
			resAttr(attrAttributeList, "", 1, al),
			resAttr(attrFileName, "", 2, fnVal(ref(5, 5), "$MFT", 3, 6, mftAlloc)),
			nonResAttr(attrData, "", 3, 0, 0, 63, first, mftAlloc, mftAlloc, mftAlloc))
		recs[rExtMFT] = mkRecord(rExtMFT, 1, 1, ref(0, 1),
			nonResAttr(attrData, "", 0, 0, 64, 159, second, 0, 0, 0))
	} else {
		runs := encRuns([]rs{{4, 64}, {80, 96}})
		recs[0] = mkRecord(0, 1, 1, 0,
			resAttr(attrStandardInfo, "", 0, siVal(6)),
			resAttr(attrFileName, "", 1, fnVal(ref(5, 5), "$MFT", 3, 6, mftAlloc)),
			nonResAttr(attrData, "", 2, 0, 0, 159, runs, mftAlloc, mftAlloc, mftAlloc))
	}
	// $Volume
	vi := make([]byte, 12)
	vi[8], vi[9] = 3, 1
	recs[rVolume] = fileRec(rVolume, 5, "$Volume", 6, 0, resAttr(attrVolumeInfo, "", 2, vi))

	// $UpCase
	if o.upcase {
		tbl := make([]byte, 131072)
		for i := 0; i < 65536; i++ {
			c := uint16(i)
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			put16(tbl, 2*i, c)
		}
		put(180, tbl)
		recs[rUpcase] = fileRec(rUpcase, 5, "$UpCase", 6, 131072,
			nonResAttr(attrData, "", 2, 0, 0, 127, encRuns([]rs{{180, 128}}), 131072, 131072, 131072))
	}

	// $Extend\$UsnJrnl:$J
	recs[rExtend] = smallDir(rExtend, 5, "$Extend", []dent{{"$UsnJrnl", rUsn, 3, 0, 0}})
	put(374, usnJ()[4096:])
	recs[rUsn] = fileRec(rUsn, rExtend, "$UsnJrnl", 0, 0,
		resAttr(attrData, "", 2, nil),
		nonResAttr(attrData, "$J", 3, 0x8000, 0, 5, encRuns([]rs{{-1, 4}, {374, 2}}), 6144, 6144, 6144))

	// hello.txt
	recs[rHello] = fileRec(rHello, 5, "hello.txt", 0x20, int64(len(helloData)), resAttr(attrData, "", 2, helloData))

	// frag.bin: runs 3@340, hole 2, 3@332 (negative delta), 2@350; init 8000, real 9000.
	logical := pat(11, 10240)
	put(340, logical[0:3072])
	put(332, logical[5120:8192])
	put(350, logical[8192:10240])
	recs[rFrag] = fileRec(rFrag, 5, "frag.bin", 0x20, 9000,
		nonResAttr(attrData, "", 2, 0, 0, 9, encRuns([]rs{{340, 3}, {-1, 2}, {332, 3}, {350, 2}}), 10240, 9000, 8000))

	// ads.exe with Zone.Identifier
	recs[rADS] = fileRec(rADS, 5, "ads.exe", 0x20, int64(len(adsMain)),
		resAttr(attrData, "", 2, adsMain), resAttr(attrData, "Zone.Identifier", 3, zoneData))

	// Big directory with INDEX_ALLOCATION
	names := bigNames()
	mk := func(n string) []byte {
		return idxEnt(ref(rHello, 1), fnVal(ref(rBig, 1), n, 3, 0x20, 13), -1)
	}
	var rootEnts []byte
	var blocks [][]byte
	idx := 0
	for leaf := 0; leaf < 5; leaf++ {
		cnt := 39
		if leaf == 4 {
			cnt = 40
		}
		var le []byte
		for i := 0; i < cnt; i++ {
			le = append(le, mk(names[idx])...)
			idx++
		}
		le = append(le, idxLast(-1)...)
		blocks = append(blocks, indxBlock(int64(leaf*4), le, false))
		if leaf < 4 {
			sep := names[idx]
			idx++
			rootEnts = append(rootEnts, idxEnt(ref(rHello, 1), fnVal(ref(rBig, 1), sep, 3, 0x20, 13), int64(leaf*4))...)
		} else {
			rootEnts = append(rootEnts, idxLast(int64(leaf*4))...)
		}
	}
	for i, b := range blocks {
		put(310+4*i, b)
	}
	recs[rBig] = mkRecord(rBig, 1, 3, 0,
		resAttr(attrStandardInfo, "", 0, siVal(0)),
		resAttr(attrFileName, "", 1, fnVal(ref(5, 5), "Big", 3, 0x10000000, 0)),
		resAttr(attrIndexRoot, "$I30", 2, idxRoot(rootEnts, true)),
		nonResAttr(attrIndexAlloc, "$I30", 3, 0, 0, 19, encRuns([]rs{{310, 20}}), 20480, 20480, 20480),
		resAttr(0xB0, "$I30", 4, []byte{0x1F, 0, 0, 0, 0, 0, 0, 0}))

	// attrlist.dat: $DATA split between base record and extension record.
	ad := attrListData()
	buf8 := make([]byte, 8192)
	copy(buf8, ad)
	put(360, buf8[:4096])
	put(366, buf8[4096:])
	al := append(alEntry(attrStandardInfo, "", 0, rAttrList, 0), alEntry(attrAttributeList, "", 0, rAttrList, 1)...)
	al = append(al, alEntry(attrFileName, "", 0, rAttrList, 2)...)
	al = append(al, alEntry(attrData, "", 0, rAttrList, 3)...)
	al = append(al, alEntry(attrData, "", 4, rAttrExt, 0)...)
	recs[rAttrList] = mkRecord(rAttrList, 1, 1, 0,
		resAttr(attrStandardInfo, "", 0, siVal(0x20)),
		resAttr(attrAttributeList, "", 1, al),
		resAttr(attrFileName, "", 2, fnVal(ref(5, 5), "attrlist.dat", 3, 0x20, 8000)),
		nonResAttr(attrData, "", 3, 0, 0, 3, encRuns([]rs{{360, 4}}), 8192, 8000, 8000))
	recs[rAttrExt] = mkRecord(rAttrExt, 1, 1, ref(rAttrList, 1),
		nonResAttr(attrData, "", 0, 0, 4, 7, encRuns([]rs{{366, 4}}), 0, 0, 0))

	// Windows\System32\config\SYSTEM
	recs[rWindows] = smallDir(rWindows, 5, "Windows", []dent{{"System32", rSys32, 3, 0x10000000, 0}})
	recs[rSys32] = smallDir(rSys32, rWindows, "System32", []dent{{"config", rConfig, 3, 0x10000000, 0}})
	recs[rConfig] = smallDir(rConfig, rSys32, "config", []dent{{"SYSTEM", rSystem, 3, 0x20, 1500}})
	sd := make([]byte, 2048)
	copy(sd, systemData())
	put(380, sd)
	recs[rSystem] = fileRec(rSystem, rConfig, "SYSTEM", 0x20, 1500,
		nonResAttr(attrData, "", 2, 0, 0, 1, encRuns([]rs{{380, 2}}), 2048, 1500, 1500))

	// compressed / encrypted files
	recs[rComp] = fileRec(rComp, 5, "comp.bin", 0x820, 100,
		nonResAttr(attrData, "", 2, 0x0001, 0, 0, encRuns([]rs{{372, 1}}), 1024, 100, 100))
	recs[rEnc] = fileRec(rEnc, 5, "enc.bin", 0x4020, 100,
		nonResAttr(attrData, "", 2, 0x4000, 0, 0, encRuns([]rs{{373, 1}}), 1024, 100, 100))

	// reparse-point directory with content that must not be walked
	recs[rJunction] = smallDir(rJunction, 5, "Junction", []dent{{"inside.txt", rHello, 3, 0x20, 13}})

	// long file name with DOS alias
	recs[rLong] = mkRecord(rLong, 1, 1, 0,
		resAttr(attrStandardInfo, "", 0, siVal(0x20)),
		resAttr(attrFileName, "", 1, fnVal(ref(5, 5), "LONGFI~1.TXT", 2, 0x20, 5)),
		resAttr(attrFileName, "", 2, fnVal(ref(5, 5), "LongFileName.txt", 1, 0x20, 5)),
		resAttr(attrData, "", 3, []byte("long!")))

	// root directory
	rootList := []dent{
		{"$Extend", rExtend, 3, 0x10000000, 0},
		{"$MFT", rMFT, 3, 0x6, mftAlloc},
		{"$Volume", rVolume, 3, 0x6, 0},
		{"Big", rBig, 3, 0x10000000, 0},
		{"attrlist.dat", rAttrList, 3, 0x20, 8000},
		{"comp.bin", rComp, 3, 0x820, 100},
		{"enc.bin", rEnc, 3, 0x4020, 100},
		{"frag.bin", rFrag, 3, 0x20, 9000},
		{"hello.txt", rHello, 3, 0x20, int64(len(helloData))},
		{"Junction", rJunction, 3, 0x10000000 | 0x400, 0},
		{"LongFileName.txt", rLong, 1, 0x20, 5},
		{"LONGFI~1.TXT", rLong, 2, 0x20, 5},
		{"ads.exe", rADS, 3, 0x20, int64(len(adsMain))},
		{"Windows", rWindows, 3, 0x10000000, 0},
	}
	if o.upcase {
		rootList = append(rootList, dent{"$UpCase", rUpcase, 3, 0x6, 131072})
	}
	body := append(entBytes(5, rootList), idxLast(-1)...)
	recs[rRoot] = mkRecord(rRoot, 5, 3, 0,
		resAttr(attrStandardInfo, "", 0, siVal(0x6)),
		resAttr(attrFileName, "", 1, fnVal(ref(5, 5), ".", 3, 0x10000000, 0)),
		resAttr(attrIndexRoot, "$I30", 2, idxRoot(body, false)))

	for n, r := range recs {
		copy(img[mftRecLoc(n):], r)
	}
	return img
}
