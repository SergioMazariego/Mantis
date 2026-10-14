package ntfs

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

// DirEntry is one directory entry as stored in the $I30 index. Size, Flags and
// Timestamps come from the (possibly stale) copy of $FILE_NAME in the index.
type DirEntry struct {
	Name         string
	RecordNumber uint64
	IsDir        bool
	Size         int64
	Flags        uint32
	Timestamps   Timestamps
	ParentRecord uint64
}

type fnAttr struct {
	parent uint64
	ts     Timestamps
	real   int64
	flags  uint32
	ns     uint8
	name   []uint16
}

func parseFN(b []byte) (fnAttr, error) {
	if len(b) < 0x42 {
		return fnAttr{}, corrupt("short $FILE_NAME")
	}
	nl := int(b[0x40])
	if 0x42+nl*2 > len(b) {
		return fnAttr{}, corrupt("$FILE_NAME name overflows")
	}
	return fnAttr{
		parent: le.Uint64(b[0:]) & refMask,
		ts: Timestamps{
			Created:     filetime(le.Uint64(b[0x08:])),
			Modified:    filetime(le.Uint64(b[0x10:])),
			MFTModified: filetime(le.Uint64(b[0x18:])),
			Accessed:    filetime(le.Uint64(b[0x20:])),
		},
		real:  int64(min(le.Uint64(b[0x30:]), 1<<62)),
		flags: le.Uint32(b[0x38:]),
		ns:    b[0x41],
		name:  u16s(b[0x42 : 0x42+nl*2]),
	}, nil
}

type indexEntry struct {
	ref   uint64
	last  bool
	child int64 // -1 when none
	key   []byte
}

func parseNode(node []byte, hdr int) ([]indexEntry, error) {
	if hdr < 0 || hdr+16 > len(node) {
		return nil, corrupt("index node header out of range")
	}
	entOff, total := int(le.Uint32(node[hdr:])), int(le.Uint32(node[hdr+4:]))
	if entOff < 16 || total < entOff || total > len(node)-hdr {
		return nil, corrupt("bad index node header")
	}
	off, end := hdr+entOff, hdr+total
	var out []indexEntry
	for {
		if off+16 > end {
			return nil, corrupt("index node has no terminating entry")
		}
		elen := int(le.Uint16(node[off+8:]))
		klen := int(le.Uint16(node[off+10:]))
		fl := le.Uint16(node[off+12:])
		if elen < 16 || off+elen > end {
			return nil, corrupt("bad index entry length")
		}
		e := indexEntry{ref: le.Uint64(node[off:]), last: fl&2 != 0, child: -1}
		limit := off + elen
		if fl&1 != 0 {
			if elen < 24 {
				return nil, corrupt("index entry too short for sub-node pointer")
			}
			limit -= 8
			c := le.Uint64(node[off+elen-8:])
			if c > maxVCN {
				return nil, corrupt("absurd index sub-node VCN")
			}
			e.child = int64(c)
		}
		if klen > 0 {
			if off+16+klen > limit {
				return nil, corrupt("index key overflows entry")
			}
			e.key = node[off+16 : off+16+klen]
		}
		out = append(out, e)
		if e.last {
			return out, nil
		}
		off += elen
	}
}

type dirIndex struct {
	v         *Volume
	root      []byte // $INDEX_ROOT value
	alloc     *stream
	blockSize int
	unit      int64
}

func (v *Volume) openIndex(f *File) (*dirIndex, error) {
	if !f.isDir {
		return nil, fmt.Errorf("%w: %q", ErrNotDirectory, f.name)
	}
	var root *attr
	for _, a := range f.attrs {
		if a.typ == attrIndexRoot && a.name == "$I30" && !a.nonRes {
			root = a
			break
		}
	}
	if root == nil || len(root.value) < 0x20 {
		return nil, corrupt("directory record %d has no $INDEX_ROOT", f.num)
	}
	if le.Uint32(root.value[0:]) != attrFileName {
		return nil, fmt.Errorf("%w: index of attribute type %#x", ErrUnsupported, le.Uint32(root.value[0:]))
	}
	bs := int(le.Uint32(root.value[8:]))
	if bs < fixupStride || bs > maxIndexBlockSize || bs%fixupStride != 0 {
		return nil, corrupt("bad index block size %d", bs)
	}
	ix := &dirIndex{v: v, root: root.value, blockSize: bs, unit: v.bpc}
	if int64(bs) < v.bpc {
		ix.unit = 512
	}
	s, err := v.findStream(f.attrs, attrIndexAlloc, "$I30")
	if err != nil {
		return nil, err
	}
	ix.alloc = s
	return ix, nil
}

func (ix *dirIndex) readBlock(vcn int64) ([]byte, int, error) {
	if ix.alloc == nil {
		return nil, 0, corrupt("index references sub-node but has no $INDEX_ALLOCATION")
	}
	if vcn < 0 || vcn > maxVCN {
		return nil, 0, corrupt("bad index VCN")
	}
	buf := make([]byte, ix.blockSize)
	n, err := ix.v.streamReadAt(ix.alloc, buf, vcn*ix.unit)
	if n != len(buf) {
		if err == nil || err == io.EOF {
			err = corrupt("index block %d beyond $INDEX_ALLOCATION", vcn)
		}
		return nil, 0, err
	}
	if string(buf[:4]) != "INDX" {
		return nil, 0, corrupt("index block %d: bad signature", vcn)
	}
	if err := applyFixups(buf, int(le.Uint16(buf[4:])), int(le.Uint16(buf[6:]))); err != nil {
		return nil, 0, fmt.Errorf("index block %d: %w", vcn, err)
	}
	return buf, 0x18, nil
}

// find does a B-tree descent for name.
func (ix *dirIndex) find(target []uint16) (uint64, bool, error) {
	node, hdr := ix.root, 0x10
	for depth := 0; depth < maxIndexDepth; depth++ {
		ents, err := parseNode(node, hdr)
		if err != nil {
			return 0, false, err
		}
		next := int64(-1)
		for i := range ents {
			e := &ents[i]
			if e.last {
				next = e.child
				break
			}
			fn, err := parseFN(e.key)
			if err != nil {
				return 0, false, err
			}
			c := ix.v.compareUnits(target, fn.name)
			if c == 0 {
				return e.ref & refMask, true, nil
			}
			if c < 0 {
				next = e.child
				break
			}
		}
		if next < 0 {
			return 0, false, nil
		}
		if node, hdr, err = ix.readBlock(next); err != nil {
			return 0, false, err
		}
	}
	return 0, false, corrupt("index tree too deep")
}

// each visits every real entry in tree (collation) order.
func (ix *dirIndex) each(fn func(ref uint64, f fnAttr) error) error {
	visited := map[int64]bool{}
	count := 0
	var rec func(node []byte, hdr, depth int) error
	rec = func(node []byte, hdr, depth int) error {
		if depth > maxIndexDepth {
			return corrupt("index tree too deep")
		}
		ents, err := parseNode(node, hdr)
		if err != nil {
			return err
		}
		for i := range ents {
			e := &ents[i]
			if e.child >= 0 {
				if visited[e.child] || len(visited) >= maxIndexBlocks {
					return corrupt("index block cycle or excessive size")
				}
				visited[e.child] = true
				blk, h, err := ix.readBlock(e.child)
				if err != nil {
					return err
				}
				if err := rec(blk, h, depth+1); err != nil {
					return err
				}
			}
			if e.last {
				break
			}
			if count++; count > maxDirEntries {
				return corrupt("directory has too many entries")
			}
			f, err := parseFN(e.key)
			if err != nil {
				return err
			}
			if err := fn(e.ref&refMask, f); err != nil {
				return err
			}
		}
		return nil
	}
	return rec(ix.root, 0x10, 0)
}

var errStop = fmt.Errorf("stop")

func (v *Volume) lookup(dir *File, name string) (uint64, error) {
	ix, err := v.openIndex(dir)
	if err != nil {
		return 0, err
	}
	target := utf16.Encode([]rune(name))
	ref, ok, err := ix.find(target)
	if err != nil {
		return 0, err
	}
	if !ok && v.upcase == nil {
		// Without the real $UpCase table our ordering may differ from the
		// volume's, so a tree miss is not conclusive: scan linearly.
		err = ix.each(func(r uint64, f fnAttr) error {
			if v.compareUnits(target, f.name) == 0 {
				ref, ok = r, true
				return errStop
			}
			return nil
		})
		if err != nil && err != errStop {
			return 0, err
		}
	}
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return ref, nil
}

func (v *Volume) readDirFile(f *File) ([]DirEntry, error) {
	ix, err := v.openIndex(f)
	if err != nil {
		return nil, err
	}
	var out []DirEntry
	err = ix.each(func(ref uint64, a fnAttr) error {
		if a.ns == 2 { // DOS-only 8.3 duplicate
			return nil
		}
		out = append(out, DirEntry{
			Name:         utf16ToString(a.name),
			RecordNumber: ref,
			IsDir:        a.flags&0x10000000 != 0,
			Size:         a.real,
			Flags:        a.flags,
			Timestamps:   a.ts,
			ParentRecord: a.parent,
		})
		return nil
	})
	return out, err
}

// ReadDir lists a directory (""/"\" = root). Entries are returned in index
// (NTFS collation) order; DOS-only 8.3 duplicates are skipped.
func (v *Volume) ReadDir(p string) ([]DirEntry, error) {
	f, err := v.resolve(p, false)
	if err != nil {
		return nil, err
	}
	return v.readDirFile(f)
}

// Walk traverses root depth-first in lexical (case-folded) order, calling fn
// for every entry below root (not root itself). Paths are '\'-joined relative
// to the volume root. Reparse points are reported but never descended, and
// each directory record is visited at most once (cycle guard). fn may return
// ErrSkipDir: for a directory it skips that directory; for a non-directory it
// skips the remaining entries of the parent directory.
func (v *Volume) Walk(root string, fn func(path string, e DirEntry) error) error {
	f, err := v.resolve(root, false)
	if err != nil {
		return err
	}
	if !f.isDir {
		return fmt.Errorf("%w: %q", ErrNotDirectory, root)
	}
	comps, _, _ := splitPath(root, false)
	err = v.walkDir(f, strings.Join(comps, "\\"), map[uint64]bool{}, 0, fn)
	if err == ErrSkipDir {
		return nil
	}
	return err
}

func (v *Volume) walkDir(f *File, prefix string, visited map[uint64]bool, depth int, fn func(string, DirEntry) error) error {
	if depth > maxDirDepth {
		return corrupt("directory nesting too deep")
	}
	if visited[f.num] {
		return nil
	}
	visited[f.num] = true
	ents, err := v.readDirFile(f)
	if err != nil {
		return fmt.Errorf("%q: %w", prefix, err)
	}
	keys := make([]string, len(ents))
	for i := range ents {
		keys[i] = v.fold(ents[i].Name)
	}
	idx := make([]int, len(ents))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	for _, i := range idx {
		e := ents[i]
		p := e.Name
		if prefix != "" {
			p = prefix + "\\" + e.Name
		}
		if err := fn(p, e); err != nil {
			if err == ErrSkipDir {
				if e.IsDir {
					continue
				}
				return nil
			}
			return err
		}
		if !e.IsDir || e.Flags&0x400 != 0 {
			continue
		}
		child, err := v.loadFile(e.RecordNumber)
		if err != nil {
			return fmt.Errorf("%q: %w", p, err)
		}
		if !child.isDir {
			continue
		}
		if err := v.walkDir(child, p, visited, depth+1, fn); err != nil {
			return err
		}
	}
	return nil
}
