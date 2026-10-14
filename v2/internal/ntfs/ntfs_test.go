package ntfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

var variants = []struct {
	name string
	o    opts
}{
	{"plain", opts{}},
	{"upcase", opts{upcase: true}},
	{"mftext", opts{upcase: true, mftExt: true}},
	{"mftext-noupcase", opts{mftExt: true}},
}

func forVariants(t *testing.T, fn func(t *testing.T, v *Volume, img []byte, o opts)) {
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			img := buildImage(tc.o)
			v, err := OpenVolume(bytes.NewReader(img))
			if err != nil {
				t.Fatalf("OpenVolume: %v", err)
			}
			fn(t, v, img, tc.o)
		})
	}
}

func readAllFile(t *testing.T, v *Volume, path string) []byte {
	t.Helper()
	f, err := v.OpenPath(path)
	if err != nil {
		t.Fatalf("OpenPath(%q): %v", path, err)
	}
	b, err := io.ReadAll(f.NewReader())
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if int64(len(b)) != f.Size() {
		t.Fatalf("%q: read %d bytes, Size %d", path, len(b), f.Size())
	}
	return b
}

func TestVolumeInfo(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, o opts) {
		want := VolumeInfo{
			SerialNumber: 0x1122334455667788, BytesPerSector: 512, SectorsPerCluster: 2,
			BytesPerCluster: 1024, MFTRecordSize: 4096, TotalSectors: 800,
			MFTStartCluster: 4, MFTMirrorCluster: 2, VolumeSerialHex: "1122334455667788",
			NTFSMajor: 3, NTFSMinor: 1,
		}
		if got := v.Info(); got != want {
			t.Errorf("Info = %+v, want %+v", got, want)
		}
		if v.UpcaseLoaded() != o.upcase {
			t.Errorf("UpcaseLoaded = %v, want %v", v.UpcaseLoaded(), o.upcase)
		}
	})
}

func TestFilesData(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		checks := map[string][]byte{
			"hello.txt":                         helloData,
			"HELLO.TXT":                         helloData,
			"/hello.txt":                        helloData,
			`C:\hello.txt`:                      helloData,
			"frag.bin":                          fragLogical(),
			"attrlist.dat":                      attrListData(),
			"windows\\SYSTEM32\\Config\\system": systemData(),
			"Windows/System32/config/SYSTEM":    systemData(),
			"ads.exe":                           adsMain,
			"ads.exe:Zone.Identifier":           zoneData,
			"ADS.EXE:zone.identifier:$DATA":     zoneData,
			"ads.exe::$DATA":                    adsMain,
			"$Extend\\$UsnJrnl:$J":              usnJ(),
			"longfilename.TXT":                  []byte("long!"),
			"LONGFI~1.TXT":                      []byte("long!"),
			"Big\\file123":                      helloData,
			"Big\\file000":                      helloData,
			"Big\\file039":                      helloData, // separator in root node
			"Big\\file040":                      helloData,
			"Big\\file079":                      helloData,
			"Big\\file199":                      helloData,
			"Big\\FILE100":                      helloData,
			"$UnknownIsFine":                    nil,
		}
		for p, want := range checks {
			if want == nil {
				if _, err := v.OpenPath(p); !errors.Is(err, ErrNotFound) {
					t.Errorf("OpenPath(%q) = %v, want ErrNotFound", p, err)
				}
				continue
			}
			if got := readAllFile(t, v, p); !bytes.Equal(got, want) {
				t.Errorf("%q: data mismatch (got %d bytes, want %d)", p, len(got), len(want))
			}
		}
		// $MFT itself.
		f, err := v.OpenPath("$MFT")
		if err != nil {
			t.Fatal(err)
		}
		if f.Size() != tMFTRecs*tRec || f.RecordNumber() != 0 || f.Name() != "$MFT" {
			t.Errorf("$MFT: size %d rec %d name %q", f.Size(), f.RecordNumber(), f.Name())
		}
		b, _ := io.ReadAll(f.NewReader())
		if len(b) != tMFTRecs*tRec || string(b[:4]) != "FILE" {
			t.Errorf("$MFT read wrong: %d bytes", len(b))
		}
		if string(b[24*tRec:24*tRec+4]) != "FILE" || string(b[25*tRec:25*tRec+4]) != "FILE" {
			t.Error("$MFT second extent not readable")
		}
	})
}

func TestMetadata(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		f, err := v.OpenPath("hello.txt")
		if err != nil {
			t.Fatal(err)
		}
		if f.Name() != "hello.txt" || f.RecordNumber() != rHello || f.IsDir() || f.Size() != int64(len(helloData)) ||
			f.Flags() != 0x20 || f.ParentRecord() != rRoot {
			t.Errorf("metadata wrong: %q %d %v %d %#x", f.Name(), f.RecordNumber(), f.IsDir(), f.Size(), f.Flags())
		}
		if !f.Timestamps().Created.Equal(tTime) || !f.Timestamps().Accessed.Equal(tTime) ||
			f.Timestamps().Modified.Location().String() != "UTC" {
			t.Errorf("timestamps wrong: %+v", f.Timestamps())
		}
		fr, _ := v.OpenPath("frag.bin")
		if fr.Size() != 9000 || fr.AllocatedSize() != 10240 {
			t.Errorf("frag sizes %d/%d", fr.Size(), fr.AllocatedSize())
		}
		l, _ := v.OpenPath("LONGFI~1.TXT")
		if l.Name() != "LongFileName.txt" {
			t.Errorf("preferred name = %q", l.Name())
		}
		d, err := v.OpenPath("Windows")
		if err != nil || !d.IsDir() || d.Size() != 0 {
			t.Errorf("Windows: %v dir=%v", err, d != nil && d.IsDir())
		}
		root, err := v.OpenPath("")
		if err != nil || root.RecordNumber() != 5 || !root.IsDir() {
			t.Errorf("root: %v", err)
		}
		r2, err := v.OpenRecord(rFrag)
		if err != nil || r2.Name() != "frag.bin" {
			t.Errorf("OpenRecord: %v", err)
		}
		if _, err := v.OpenRecord(1); !errors.Is(err, ErrNotFound) {
			t.Errorf("OpenRecord(unused) = %v", err)
		}
		if _, err := v.OpenRecord(rAttrExt); !errors.Is(err, ErrNotFound) {
			t.Errorf("OpenRecord(extension) = %v", err)
		}
		if _, err := v.OpenRecord(100000); !errors.Is(err, ErrNotFound) {
			t.Errorf("OpenRecord(huge) = %v", err)
		}
	})
}

func TestStreams(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		f, _ := v.OpenPath("ads.exe")
		if got := f.Streams(); !reflect.DeepEqual(got, []string{"Zone.Identifier"}) {
			t.Errorf("Streams = %v", got)
		}
		z, _ := v.OpenPath("ads.exe:Zone.Identifier")
		if z.StreamName() != "Zone.Identifier" || z.Size() != int64(len(zoneData)) {
			t.Errorf("zone stream %q size %d", z.StreamName(), z.Size())
		}
		if _, err := v.OpenPath("ads.exe:nope"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing stream: %v", err)
		}
		if _, err := v.OpenPath("ads.exe:x:$INDEX_ALLOCATION"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("other attr type: %v", err)
		}
		h, _ := v.OpenPath("hello.txt")
		if len(h.Streams()) != 0 {
			t.Errorf("hello has streams %v", h.Streams())
		}
		u, _ := v.OpenPath("$Extend\\$UsnJrnl")
		if !reflect.DeepEqual(u.Streams(), []string{"$J"}) {
			t.Errorf("usn streams %v", u.Streams())
		}
	})
}

func TestExtents(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		f, _ := v.OpenPath("frag.bin")
		got, err := f.Extents()
		if err != nil {
			t.Fatal(err)
		}
		want := []Extent{
			{0, 3072, false, 340 * 1024},
			{3072, 2048, true, -1},
			{5120, 3072, false, 332 * 1024},
			{8192, 808, false, 350 * 1024},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("extents = %+v\nwant %+v", got, want)
		}
		a, _ := v.OpenPath("attrlist.dat")
		ex, _ := a.Extents()
		if len(ex) != 2 || ex[0].Length != 4096 || ex[1].LogicalOffset != 4096 || ex[1].Length != 3904 {
			t.Errorf("attrlist extents = %+v", ex)
		}
		h, _ := v.OpenPath("hello.txt")
		ex, _ = h.Extents()
		if len(ex) != 1 || ex[0].Length != int64(len(helloData)) || ex[0].PhysicalOffset != -1 {
			t.Errorf("resident extents = %+v", ex)
		}
		d, _ := v.OpenPath("Windows")
		if _, err := d.Extents(); !errors.Is(err, ErrIsDirectory) {
			t.Errorf("dir extents: %v", err)
		}
	})
}

func TestReadAtAndSections(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		f, _ := v.OpenPath("frag.bin")
		want := fragLogical()
		for _, c := range []struct{ off, n int }{{0, 1}, {1023, 3}, {3000, 200}, {5119, 2}, {7990, 40}, {8999, 1}, {9000, 5}, {8500, 1000}} {
			buf := make([]byte, c.n)
			n, err := f.ReadAt(buf, int64(c.off))
			end := min(c.off+c.n, 9000)
			exp := 0
			if end > c.off {
				exp = end - c.off
			}
			if n != exp {
				t.Errorf("ReadAt(%d,%d) n=%d want %d", c.off, c.n, n, exp)
			}
			if exp < c.n && err != io.EOF {
				t.Errorf("ReadAt(%d,%d) err=%v want EOF", c.off, c.n, err)
			}
			if exp > 0 && !bytes.Equal(buf[:n], want[c.off:c.off+exp]) {
				t.Errorf("ReadAt(%d,%d) data mismatch", c.off, c.n)
			}
		}
		sr, _ := io.ReadAll(f.NewSectionReader(3000, 2500))
		if !bytes.Equal(sr, want[3000:5500]) {
			t.Error("section reader mismatch")
		}
		d, _ := v.OpenPath("Windows")
		if _, err := d.ReadAt(make([]byte, 4), 0); !errors.Is(err, ErrIsDirectory) {
			t.Errorf("dir ReadAt: %v", err)
		}
	})
}

func names(es []DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func TestReadDir(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, o opts) {
		for _, p := range []string{"", "\\", "/"} {
			es, err := v.ReadDir(p)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"$Extend", "$MFT", "$Volume", "ads.exe", "attrlist.dat", "Big", "comp.bin", "enc.bin",
				"frag.bin", "hello.txt", "Junction", "LongFileName.txt", "Windows"}
			if o.upcase {
				want = []string{"$Extend", "$MFT", "$UpCase", "$Volume", "ads.exe", "attrlist.dat", "Big", "comp.bin", "enc.bin",
					"frag.bin", "hello.txt", "Junction", "LongFileName.txt", "Windows"}
			}
			if !reflect.DeepEqual(names(es), want) {
				t.Errorf("root(%q) = %v\nwant %v", p, names(es), want)
			}
		}
		es, _ := v.ReadDir("")
		for _, e := range es {
			switch e.Name {
			case "hello.txt":
				if e.RecordNumber != rHello || e.IsDir || e.Size != int64(len(helloData)) || e.ParentRecord != 5 || !e.Timestamps.Created.Equal(tTime) {
					t.Errorf("hello entry %+v", e)
				}
			case "Windows", "Big":
				if !e.IsDir {
					t.Errorf("%s not dir", e.Name)
				}
			}
		}
		big, err := v.ReadDir("BIG")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(names(big), bigNames()) {
			t.Errorf("Big listing wrong: %d entries", len(big))
		}
		cfg, err := v.ReadDir("windows/system32/config")
		if err != nil || !reflect.DeepEqual(names(cfg), []string{"SYSTEM"}) {
			t.Errorf("config = %v %v", names(cfg), err)
		}
		if _, err := v.ReadDir("hello.txt"); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("ReadDir(file) = %v", err)
		}
		if _, err := v.ReadDir("nope"); !errors.Is(err, ErrNotFound) {
			t.Errorf("ReadDir(missing) = %v", err)
		}
	})
}

func TestErrors(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		for _, p := range []string{"nothing", "Windows\\nothing", "Big\\file200", "Big\\", "..\\x"} {
			_, err := v.OpenPath(p)
			if p == "Big\\" {
				if err != nil {
					t.Errorf("OpenPath(%q) = %v", p, err)
				}
				continue
			}
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("OpenPath(%q) = %v, want ErrNotFound", p, err)
			}
		}
		if _, err := v.OpenPath("hello.txt\\x"); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("through file: %v", err)
		}
		c, err := v.OpenPath("comp.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ReadAt(make([]byte, 10), 0); !errors.Is(err, ErrCompressed) {
			t.Errorf("compressed read: %v", err)
		}
		if _, err := io.ReadAll(c.NewReader()); !errors.Is(err, ErrCompressed) {
			t.Errorf("compressed reader: %v", err)
		}
		e, _ := v.OpenPath("enc.bin")
		if _, err := io.ReadAll(e.NewReader()); !errors.Is(err, ErrEncrypted) {
			t.Errorf("encrypted reader: %v", err)
		}
	})
}

func TestCorruption(t *testing.T) {
	forVariants(t, func(t *testing.T, _ *Volume, img []byte, _ opts) {
		bad := bytes.Clone(img)
		bad[mftRecLoc(rHello)+510] ^= 0xFF // break fixup check value of sector 0
		v, err := OpenVolume(bytes.NewReader(bad))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.OpenPath("hello.txt"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("record fixup mismatch: %v", err)
		}
		if _, err := v.OpenPath("frag.bin"); err != nil {
			t.Errorf("unrelated file affected: %v", err)
		}

		bad = bytes.Clone(img)
		bad[(310+4)*tBPC+1022] ^= 0xFF // second INDX block, sector 1
		v, _ = OpenVolume(bytes.NewReader(bad))
		if _, err := v.ReadDir("Big"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("INDX fixup mismatch: %v", err)
		}

		bad = bytes.Clone(img)
		bad[mftRecLoc(0)+510] ^= 0xFF
		if _, err := OpenVolume(bytes.NewReader(bad)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("$MFT fixup mismatch: %v", err)
		}

		bad = bytes.Clone(img)
		copy(bad[3:], "NTFX    ")
		if _, err := OpenVolume(bytes.NewReader(bad)); !errors.Is(err, ErrNotNTFS) {
			t.Errorf("bad OEM ID: %v", err)
		}
		if _, err := OpenVolume(bytes.NewReader(img[:100])); !errors.Is(err, ErrNotNTFS) {
			t.Errorf("short image: %v", err)
		}
		if _, err := OpenVolume(bytes.NewReader(nil)); !errors.Is(err, ErrNotNTFS) {
			t.Errorf("empty image: %v", err)
		}
	})
}

func TestWalk(t *testing.T) {
	forVariants(t, func(t *testing.T, v *Volume, _ []byte, _ opts) {
		var paths []string
		err := v.Walk("", func(p string, e DirEntry) error {
			paths = append(paths, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		joined := "\n" + strings.Join(paths, "\n") + "\n"
		for _, want := range []string{"Windows\\System32\\config\\SYSTEM", "Big\\file199", "$Extend\\$UsnJrnl", "Junction", "hello.txt"} {
			if !strings.Contains(joined, "\n"+want+"\n") {
				t.Errorf("Walk missed %q", want)
			}
		}
		if strings.Contains(joined, "Junction\\") {
			t.Error("Walk descended into a reparse point")
		}
		if strings.Contains(joined, "LONGFI~1") {
			t.Error("Walk reported DOS-only name")
		}
		// Windows\... comes after Big\...: lexical order.
		if strings.Index(joined, "\nBig\\file000\n") > strings.Index(joined, "\nWindows\\System32\n") {
			t.Error("order is not lexical")
		}

		paths = nil
		_ = v.Walk("", func(p string, e DirEntry) error {
			paths = append(paths, p)
			if e.Name == "Windows" || e.Name == "Big" {
				return ErrSkipDir
			}
			return nil
		})
		for _, p := range paths {
			if strings.HasPrefix(p, "Windows\\") || strings.HasPrefix(p, "Big\\") {
				t.Errorf("ErrSkipDir not honoured: %q", p)
			}
		}

		paths = nil
		if err := v.Walk("windows/system32", func(p string, e DirEntry) error { paths = append(paths, p); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(paths, []string{"windows\\system32\\config", "windows\\system32\\config\\SYSTEM"}) {
			t.Errorf("subtree walk = %v", paths)
		}
		sentinel := errors.New("boom")
		if err := v.Walk("", func(string, DirEntry) error { return sentinel }); err != sentinel {
			t.Errorf("callback error not propagated: %v", err)
		}
		if err := v.Walk("hello.txt", func(string, DirEntry) error { return nil }); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("Walk(file) = %v", err)
		}
	})
}

// A directory index whose child pointer points at its own block must not loop.
func TestIndexCycleGuard(t *testing.T) {
	img := buildImage(opts{upcase: true})
	// Make block 0's last entry point to VCN 0 (itself): patch the leaf.
	blk := (310) * tBPC
	// Re-fixup is required; easier: rebuild block with child pointers.
	var ents []byte
	for i := 0; i < 3; i++ {
		ents = append(ents, idxEnt(ref(rHello, 1), fnVal(ref(rBig, 1), fmt.Sprintf("file%03d", i), 3, 0x20, 13), 0)...)
	}
	ents = append(ents, idxLast(0)...)
	copy(img[blk:], indxBlock(0, ents, true))
	v, err := OpenVolume(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadDir("Big"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("cycle: %v", err)
	}
	if err := v.Walk("", func(string, DirEntry) error { return nil }); !errors.Is(err, ErrCorrupt) {
		t.Errorf("walk cycle: %v", err)
	}
}

func TestRunlistDecode(t *testing.T) {
	runs, next, err := decodeRuns(encRuns([]rs{{100, 5}, {-1, 3}, {50, 1}, {70000, 300}}), 10, 0, nil)
	if err != nil || next != 10+5+3+1+300 {
		t.Fatalf("decode: %v next=%d", err, next)
	}
	want := []run{{10, 5, 100}, {15, 3, -1}, {18, 1, 50}, {19, 300, 70000}}
	if !reflect.DeepEqual(runs, want) {
		t.Errorf("runs = %+v", runs)
	}
	for _, bad := range [][]byte{{0x01}, {0x11, 0x05}, {0x01, 0x00, 0x00}, {0x91, 1, 1, 0}, {0x21, 1, 0}} {
		if _, _, err := decodeRuns(bad, 0, 0, nil); err == nil {
			t.Errorf("decodeRuns(% x) accepted", bad)
		}
	}
	if _, _, err := decodeRuns(encRuns([]rs{{500, 5}}), 0, 400, nil); !errors.Is(err, ErrCorrupt) {
		t.Errorf("run past volume end: %v", err)
	}
	if _, _, err := decodeRuns([]byte{0x11, 5, 0x80, 0}, 0, 0, nil); !errors.Is(err, ErrCorrupt) { // lcn -128
		t.Errorf("negative lcn: %v", err)
	}
}

// ---- AlignedReaderAt ----

type strictReader struct {
	data []byte
	sec  int
	n    int
}

func (s *strictReader) ReadAt(p []byte, off int64) (int, error) {
	s.n++
	if off%int64(s.sec) != 0 || len(p)%s.sec != 0 {
		return 0, fmt.Errorf("unaligned read off=%d len=%d", off, len(p))
	}
	if off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestAlignedReaderAt(t *testing.T) {
	data := make([]byte, 300*1024+512)
	rand.New(rand.NewSource(1)).Read(data)
	for _, ss := range []int{512, 4096} {
		sr := &strictReader{data: data, sec: ss}
		a := NewAlignedReaderAt(sr, ss)
		rng := rand.New(rand.NewSource(2))
		for i := 0; i < 500; i++ {
			off := rng.Intn(len(data) + 100)
			n := rng.Intn(150000)
			if i%7 == 0 {
				n = rng.Intn(100)
			}
			buf := make([]byte, n)
			got, err := a.ReadAt(buf, int64(off))
			exp := max(0, min(n, len(data)-off))
			if got != exp {
				t.Fatalf("ss=%d ReadAt(%d,%d) = %d, want %d (err %v)", ss, off, n, got, exp, err)
			}
			if exp < n && err != io.EOF {
				t.Fatalf("expected EOF, got %v", err)
			}
			if exp == n && err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if !bytes.Equal(buf[:got], data[off:off+got]) {
				t.Fatalf("ss=%d data mismatch at %d,%d", ss, off, n)
			}
		}
		// Cache: repeated small reads in one chunk hit the device once.
		sr.n = 0
		small := make([]byte, 10)
		for i := 0; i < 20; i++ {
			a.ReadAt(small, 1000+int64(i))
		}
		if sr.n > 1 {
			t.Errorf("ss=%d cache ineffective: %d device reads", ss, sr.n)
		}
	}
	if _, err := NewAlignedReaderAt(&strictReader{data: data, sec: 512}, 512).ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("negative offset accepted")
	}
}

func TestVolumeOverStrictDevice(t *testing.T) {
	img := buildImage(opts{upcase: true})
	for _, ss := range []int{512, 4096} {
		v, err := OpenVolume(NewAlignedReaderAt(&strictReader{data: img, sec: ss}, ss))
		if err != nil {
			t.Fatalf("ss=%d: %v", ss, err)
		}
		if got := readAllFile(t, v, "frag.bin"); !bytes.Equal(got, fragLogical()) {
			t.Errorf("ss=%d frag mismatch", ss)
		}
	}
	// Without the adapter, a strict device cannot even read the boot sector at 4K.
	if _, err := OpenVolume(&strictReader{data: img, sec: 4096}); err == nil {
		t.Error("expected failure on unaligned device")
	}
}

// ---- robustness ----

func exercise(r io.ReaderAt) {
	v, err := OpenVolume(r)
	if err != nil {
		return
	}
	_ = v.Info()
	for _, p := range []string{"", "hello.txt", "frag.bin", "attrlist.dat", "Windows\\System32\\config\\SYSTEM", "ads.exe:Zone.Identifier",
		"$Extend\\$UsnJrnl:$J", "$MFT", "Big\\file123", "Big\\file039", "comp.bin", "nothing\\here", "Junction", "LongFileName.txt"} {
		f, err := v.OpenPath(p)
		if err != nil {
			continue
		}
		_ = f.Name()
		_ = f.Timestamps()
		_ = f.Streams()
		_, _ = f.Extents()
		_, _ = io.CopyN(io.Discard, f.NewReader(), 1<<20)
		_, _ = f.ReadAt(make([]byte, 100), 5000)
	}
	_, _ = v.ReadDir("")
	_, _ = v.ReadDir("Big")
	_ = v.Walk("", func(string, DirEntry) error { return nil })
	for n := uint64(0); n < 48; n++ {
		if f, err := v.OpenRecord(n); err == nil {
			_, _ = io.CopyN(io.Discard, f.NewReader(), 1<<16)
		}
	}
}

func TestTruncatedImagesNeverPanic(t *testing.T) {
	for _, o := range []opts{{upcase: true}, {mftExt: true}} {
		img := buildImage(o)
		cuts := []int{0, 1, 100, 511, 512, 513, 2048, 4096, 4608, 5000, 20000, 70000, 80000, 100000, 163840, 200000,
			300 * 1024, 310 * 1024, 320 * 1024, 340 * 1024, 380 * 1024, len(img) - 1}
		for _, c := range cuts {
			exercise(bytes.NewReader(img[:c]))
		}
	}
}

func TestRandomBytesNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50; i++ {
		b := make([]byte, 1<<16)
		rng.Read(b)
		exercise(bytes.NewReader(b))
		// plausible boot sector over random data
		copy(b[3:], "NTFS    ")
		put16(b, 0x0B, 512)
		b[0x0D] = 2
		put64(b, 0x28, 128)
		put64(b, 0x30, 4)
		b[0x40] = 0xF6
		exercise(bytes.NewReader(b))
	}
}

func TestMutatedImagesNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, o := range []opts{{upcase: true}, {mftExt: true}} {
		base := buildImage(o)
		for i := 0; i < 400; i++ {
			img := bytes.Clone(base)
			for k := 0; k <= rng.Intn(10); k++ {
				var pos int
				switch rng.Intn(3) {
				case 0:
					pos = rng.Intn(len(img))
				case 1: // MFT area
					pos = mftRecLoc(rng.Intn(tMFTRecs)) + rng.Intn(1200)
				default: // index blocks / boot
					pos = rng.Intn(512)
					if rng.Intn(2) == 0 {
						pos = 310*tBPC + rng.Intn(5*tIdxBlk)
					}
				}
				switch rng.Intn(3) {
				case 0:
					img[pos] = byte(rng.Intn(256))
				case 1:
					img[pos] ^= 1 << uint(rng.Intn(8))
				default:
					img[pos] = 0xFF
				}
			}
			exercise(bytes.NewReader(img))
		}
	}
}
