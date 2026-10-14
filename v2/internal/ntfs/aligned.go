package ntfs

import (
	"errors"
	"io"
)

const alignedChunkSize = 64 * 1024

// AlignedReaderAt adapts a device that only accepts sector-aligned offsets and
// sector-multiple lengths (such as a raw Windows volume handle) to arbitrary
// (offset, length) reads. It caches the most recently read chunk.
//
// It only ever reads from the underlying reader. It is NOT safe for concurrent
// use: use it from a single goroutine.
type AlignedReaderAt struct {
	r      io.ReaderAt
	sector int64
	chunk  int64
	buf    []byte
	bufOff int64
	bufLen int
	valid  bool
}

// NewAlignedReaderAt wraps r. sectorSize <= 0 defaults to 512. Use 4096 when
// the physical sector size is unknown; larger alignment is always safe.
func NewAlignedReaderAt(r io.ReaderAt, sectorSize int) *AlignedReaderAt {
	if sectorSize <= 0 {
		sectorSize = 512
	}
	chunk := (alignedChunkSize / sectorSize) * sectorSize
	if chunk == 0 {
		chunk = sectorSize
	}
	return &AlignedReaderAt{r: r, sector: int64(sectorSize), chunk: int64(chunk), buf: make([]byte, chunk)}
}

// ReadAt implements io.ReaderAt.
func (a *AlignedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("ntfs: negative offset")
	}
	n := 0
	for n < len(p) {
		cur := off + int64(n)
		rem := int64(len(p) - n)
		// Direct path for large aligned reads.
		if cur%a.sector == 0 {
			want := rem / a.sector * a.sector
			if want >= a.chunk {
				m, err := a.r.ReadAt(p[n:n+int(want)], cur)
				n += m
				if int64(m) < want {
					if err == nil || err == io.EOF {
						err = io.EOF
					}
					return n, err
				}
				continue
			}
		}
		base := cur - cur%a.chunk
		if !a.valid || a.bufOff != base {
			if err := a.load(base); err != nil {
				return n, err
			}
		}
		idx := int(cur - base)
		if idx >= a.bufLen {
			return n, io.EOF
		}
		n += copy(p[n:], a.buf[idx:a.bufLen])
	}
	return n, nil
}

func (a *AlignedReaderAt) load(base int64) error {
	a.valid = false
	m, err := a.r.ReadAt(a.buf, base)
	if int64(m) < a.chunk {
		// Fall back to sector-by-sector reads (device tail, partial failures).
		i := int64(m) / a.sector * a.sector
		for i < a.chunk {
			m2, _ := a.r.ReadAt(a.buf[i:i+a.sector], base+i)
			i += int64(m2)
			if int64(m2) < a.sector {
				break
			}
		}
		m = int(i)
	}
	if m == 0 {
		if err == nil {
			err = io.EOF
		}
		return err
	}
	a.bufOff, a.bufLen, a.valid = base, m, true
	return nil
}
