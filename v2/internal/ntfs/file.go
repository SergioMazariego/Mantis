package ntfs

import (
	"fmt"
	"io"
	"time"
)

// Timestamps holds the four NTFS times (UTC). Zero time means unset.
type Timestamps struct {
	Created, Modified, MFTModified, Accessed time.Time
}

// Extent is a contiguous piece of a stream in logical (file offset) space.
type Extent struct {
	LogicalOffset int64
	Length        int64
	Sparse        bool
	// PhysicalOffset is the byte offset on the volume, or -1 for sparse holes
	// and resident data (which lives inside the MFT record).
	PhysicalOffset int64
}

// File is an opened MFT record with one selected $DATA stream. Not safe for
// concurrent use.
type File struct {
	v       *Volume
	num     uint64
	name    string
	parent  uint64
	isDir   bool
	ts      Timestamps
	flags   uint32
	attrs   []*attr
	sel     *stream
	selName string
}

func (v *Volume) loadFile(num uint64) (*File, error) {
	rec, err := v.readRecord(num)
	if err != nil {
		return nil, err
	}
	if rec.flags&1 == 0 {
		return nil, fmt.Errorf("%w: MFT record %d is not in use", ErrNotFound, num)
	}
	if rec.base != 0 {
		return nil, fmt.Errorf("%w: MFT record %d is an extension record", ErrNotFound, num)
	}
	attrs, err := v.gather(rec)
	if err != nil {
		return nil, err
	}
	f := &File{v: v, num: num, attrs: attrs, isDir: rec.flags&2 != 0}
	bestRank := -1
	var haveSI bool
	for _, a := range attrs {
		if a.nonRes || a.name != "" {
			continue
		}
		switch a.typ {
		case attrStandardInfo:
			if len(a.value) >= 0x24 && !haveSI {
				haveSI = true
				f.ts = Timestamps{
					Created:     filetime(le.Uint64(a.value[0:])),
					Modified:    filetime(le.Uint64(a.value[8:])),
					MFTModified: filetime(le.Uint64(a.value[16:])),
					Accessed:    filetime(le.Uint64(a.value[24:])),
				}
				f.flags = le.Uint32(a.value[0x20:])
			}
		case attrFileName:
			fn, err := parseFN(a.value)
			if err != nil {
				continue
			}
			rank := map[uint8]int{1: 3, 3: 3, 0: 2, 2: 1}[fn.ns]
			if rank > bestRank {
				bestRank = rank
				f.name = utf16ToString(fn.name)
				f.parent = fn.parent
				if !haveSI {
					f.ts, f.flags = fn.ts, fn.flags
				}
			}
		}
	}
	return f, nil
}

func (f *File) selectStream(name string) error {
	s, err := f.v.findStream(f.attrs, attrData, name)
	if err != nil {
		return err
	}
	if s == nil {
		if name != "" {
			return fmt.Errorf("%w: stream %q", ErrNotFound, name)
		}
		if f.isDir {
			f.sel, f.selName = nil, ""
			return nil
		}
		s = &stream{resident: true}
	}
	f.sel, f.selName = s, name
	return nil
}

// Name returns the preferred (Win32/POSIX) file name from $FILE_NAME.
func (f *File) Name() string { return f.name }

// RecordNumber returns the MFT record number.
func (f *File) RecordNumber() uint64 { return f.num }

// IsDir reports whether the record is a directory.
func (f *File) IsDir() bool { return f.isDir }

// IsReparsePoint reports whether FILE_ATTRIBUTE_REPARSE_POINT is set.
func (f *File) IsReparsePoint() bool { return f.flags&0x400 != 0 }

// ParentRecord returns the parent directory record number from $FILE_NAME.
func (f *File) ParentRecord() uint64 { return f.parent }

// StreamName returns the selected stream ("" = unnamed $DATA).
func (f *File) StreamName() string { return f.selName }

// Size returns the real (logical) size of the selected stream.
func (f *File) Size() int64 {
	if f.sel == nil {
		return 0
	}
	return f.sel.real
}

// AllocatedSize returns the allocated size of the selected stream.
func (f *File) AllocatedSize() int64 {
	if f.sel == nil {
		return 0
	}
	return f.sel.alloc
}

// Timestamps returns the $STANDARD_INFORMATION times (falling back to
// $FILE_NAME times when absent).
func (f *File) Timestamps() Timestamps { return f.ts }

// Flags returns FILE_ATTRIBUTE_* bits from $STANDARD_INFORMATION.
func (f *File) Flags() uint32 { return f.flags }

// Streams lists the named $DATA streams (excluding the unnamed one).
func (f *File) Streams() []string { return f.v.streamNames(f.attrs, attrData) }

// Extents returns the selected stream as logical extents, with the end clipped
// to Size(). Resident data yields one extent with PhysicalOffset -1.
func (f *File) Extents() ([]Extent, error) {
	if f.sel == nil {
		return nil, ErrIsDirectory
	}
	s := f.sel
	if s.resident {
		if len(s.value) == 0 {
			return nil, nil
		}
		return []Extent{{Length: int64(len(s.value)), PhysicalOffset: -1}}, nil
	}
	bpc := f.v.bpc
	var out []Extent
	for _, r := range s.runs {
		lo := r.vcn * bpc
		if lo >= s.real {
			break
		}
		ln := min(r.n*bpc, s.real-lo)
		e := Extent{LogicalOffset: lo, Length: ln, Sparse: r.lcn < 0, PhysicalOffset: -1}
		if r.lcn >= 0 {
			e.PhysicalOffset = r.lcn * bpc
		}
		out = append(out, e)
	}
	return out, nil
}

// ReadAt implements io.ReaderAt on the selected stream. Sparse holes and the
// region beyond the initialized size read as zeros. Compressed and encrypted
// streams return ErrCompressed / ErrEncrypted.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if f.sel == nil {
		return 0, ErrIsDirectory
	}
	return f.v.streamReadAt(f.sel, p, off)
}

// NewReader returns a sequential reader over the whole selected stream.
func (f *File) NewReader() io.Reader { return io.NewSectionReader(f, 0, f.Size()) }

// NewSectionReader returns a reader over [off, off+n) of the selected stream.
func (f *File) NewSectionReader(off, n int64) io.Reader { return io.NewSectionReader(f, off, n) }
