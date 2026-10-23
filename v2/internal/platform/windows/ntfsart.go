//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/ntfs"
	"golang.org/x/sys/windows"
)

var (
	pFindFirstStream = kernel32.NewProc("FindFirstStreamW")
	pFindNextStream  = kernel32.NewProc("FindNextStreamW")
	pFindClose       = kernel32.NewProc("FindClose")
)

const (
	fsctlGetNTFSVolumeData = 0x00090064
	fsctlQueryUSNJournal   = 0x000900F4
)

type fixedVolume struct {
	Drive string // "C"
	FS    string // "NTFS", "ReFS", "FAT32", ...
}

// fixedVolumes lists local fixed drives and their filesystem.
func fixedVolumes() []fixedVolume {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []fixedVolume
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var fs [64]uint16
		var serial, maxc, flags uint32
		if err := windows.GetVolumeInformation(p, nil, 0, &serial, &maxc, &flags, &fs[0], uint32(len(fs))); err != nil {
			continue
		}
		out = append(out, fixedVolume{Drive: string(rune('A' + i)), FS: windows.UTF16ToString(fs[:])})
	}
	return out
}

// rawNTFSSource acquires an NTFS system file (or stream) with the raw NTFS reader. There is
// no Win32 equivalent for $MFT/$LogFile/$UsnJrnl, so this source never falls back to a
// directory listing or a different artifact: if raw access fails it fails and says why.
func rawNTFSSource(id string, m collector.Meta, vol fixedVolume, ntfsPath string, annotate func(f *ntfs.File) (start int64, notes map[string]string)) collector.Source {
	locator := vol.Drive + `:\` + ntfsPath
	m.SourceType, m.SourcePath = "ntfs-metadata", locator
	if m.DestPath == "" {
		m.DestPath = "ntfs/" + vol.Drive + "/" + strings.NewReplacer(`\`, "/", ":", "~").Replace(ntfsPath)
	}
	return requiresAdmin(collector.Source{
		ID: id, Kind: "windows.ntfs_metadata", Locator: locator, Method: "ntfs-raw-read", MaxBytes: 256 << 30, Meta: m,
		Detect: func(context.Context) collector.Availability {
			if vol.FS != "NTFS" {
				return collector.Availability{State: collector.NotSupported, Reason: vol.FS + " volume: NTFS system files do not exist"}
			}
			return collector.Availability{State: collector.Available}
		},
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			if vol.FS != "NTFS" {
				return nil, fmt.Errorf("%w: %s is %s, not NTFS", collector.ErrNotSupported, vol.Drive, vol.FS)
			}
			enablePrivilege("SeBackupPrivilege")
			v, err := rawVolumeFor(vol.Drive)
			if err != nil {
				return nil, err
			}
			f, err := v.OpenPath(ntfsPath)
			if err != nil {
				if errors.Is(err, ntfs.ErrNotFound) {
					return nil, fmt.Errorf("%w: %s", collector.ErrNotPresent, locator)
				}
				return nil, fmt.Errorf("raw NTFS open %s: %w", locator, err)
			}
			notes := map[string]string{"read_mode": "raw volume read via NTFS parser", "consistency": "live raw read, not point-in-time consistent",
				"volume_serial": v.Info().VolumeSerialHex, "logical_size": fmt.Sprint(f.Size())}
			// the metadata file's own $STANDARD_INFORMATION times, read from its MFT record (same notes as every copied file)
			ts := f.Timestamps()
			for k, t := range map[string]time.Time{"source_created_utc": ts.Created, "source_accessed_utc": ts.Accessed, "source_modified_utc": ts.Modified} {
				if !t.IsZero() {
					notes[k] = t.UTC().Format(time.RFC3339Nano)
				}
			}
			r := &reopeningReader{ctx: ctx, f: f, end: f.Size(), notes: notes,
				open: func() (*ntfs.File, error) { return v.OpenPath(ntfsPath) }}
			if annotate != nil {
				start, extra := annotate(f)
				for k, v := range extra {
					notes[k] = v
				}
				if start > 0 && start < f.Size() {
					r.pos = start
				}
			}
			return &acqReader{r: r, method: "ntfs-raw-read", notes: notes}, nil
		},
	})
}

// reopeningReader reads [pos, end) of a live NTFS system file. $UsnJrnl:$J and $LogFile change while they are
// read: the journal frees its oldest clusters and grows at the end, so the runlist read at open can stop covering
// an offset ("not mapped by the runlist"). The file is then reopened from its MFT record (a fresh runlist) and the
// read continues at the same offset; how often that happened is recorded in the notes.
type reopeningReader struct {
	ctx      context.Context
	f        *ntfs.File
	open     func() (*ntfs.File, error)
	pos, end int64
	reopens  int
	notes    map[string]string
}

const maxNTFSReopens = 5

func (r *reopeningReader) Read(p []byte) (int, error) {
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.pos >= r.end {
			return 0, io.EOF
		}
		if rest := r.end - r.pos; int64(len(p)) > rest {
			p = p[:rest]
		}
		n, err := r.f.ReadAt(p, r.pos)
		r.pos += int64(n)
		switch {
		case n > 0:
			return n, nil // a following error is met again, and handled, by the next call
		case err == nil:
			continue
		case errors.Is(err, io.EOF):
			return 0, io.EOF
		case errors.Is(err, ntfs.ErrCorrupt) && r.reopens < maxNTFSReopens:
			nf, oerr := r.open()
			if oerr != nil {
				return 0, fmt.Errorf("%w (reopening after a moving runlist failed: %v)", err, oerr)
			}
			r.f = nf
			r.reopens++
			r.notes["reopened_during_read"] = fmt.Sprint(r.reopens)
		default:
			return 0, err
		}
	}
}

// firstAllocated returns the logical offset of the first allocated (non-sparse) byte of f.
func firstAllocated(f *ntfs.File) (int64, map[string]string) {
	ext, err := f.Extents()
	if err != nil {
		return 0, map[string]string{"warnings": "1", "warning_detail": "extents unavailable: " + err.Error()}
	}
	for _, e := range ext {
		if !e.Sparse {
			notes := map[string]string{"logical_offset_start": fmt.Sprint(e.LogicalOffset),
				"logical_size": fmt.Sprint(f.Size()),
				"sparse_note":  "the leading sparse (deallocated) region is not stored; add logical_offset_start to record offsets"}
			return e.LogicalOffset, notes
		}
	}
	return 0, nil
}

func ntfsSources() []collector.Source {
	nm := func(name, desc string, p collector.ProfileMask, art ...string) collector.Meta {
		return baseMeta(name, desc, "ntfs", collector.PrivAdmin, p, art...)
	}
	var out []collector.Source
	vols := fixedVolumes()
	for _, v := range vols {
		d := v.Drive
		out = append(out,
			rawNTFSSource("ntfs-mft-"+d, nm("$MFT ("+d+":)", "Master File Table: every file/directory record with $STANDARD_INFORMATION and $FILE_NAME timestamps, names, resident data", collector.InStdFull, "file-activity/mft.md"), v, "$MFT", nil),
			rawNTFSSource("ntfs-logfile-"+d, nm("$LogFile ("+d+":)", "NTFS metadata transaction log", collector.InStdFull), v, "$LogFile", nil),
			rawNTFSSource("ntfs-usnjrnl-j-"+d, nm("$UsnJrnl:$J ("+d+":)", "Change journal records (file create/modify/delete/rename), stored from the first allocated offset", collector.InStdFull, "file-activity/usn-journal.md"), v, `$Extend\$UsnJrnl:$J`,
				func(f *ntfs.File) (int64, map[string]string) { return firstAllocated(f) }),
			rawNTFSSource("ntfs-usnjrnl-max-"+d, nm("$UsnJrnl:$Max ("+d+":)", "Change journal parameters", collector.InStdFull, "file-activity/usn-journal.md"), v, `$Extend\$UsnJrnl:$Max`, nil),
			rawNTFSSource("ntfs-boot-"+d, nm("$Boot ("+d+":)", "Volume boot record and BPB", collector.InStdFull), v, "$Boot", nil),
			rawNTFSSource("ntfs-volume-"+d, nm("$Volume ("+d+":)", "Volume name and NTFS version flags", collector.InStdFull), v, "$Volume", nil),
		)
		out = append(out, withDetect(jsonSource("ntfs-volume-info-"+d, func() collector.Meta {
			mm := nm("NTFS volume metadata ("+d+":)", "Volume serial, cluster size, MFT geometry, USN journal identity and range (FSCTL), plus raw boot-sector parameters", collector.InAll)
			mm.Privilege = collector.PrivAdmin
			return mm
		}(), "fsctl+ntfs-boot", `\\.\`+d+`:`, func(ctx context.Context, w *warnings) (any, error) { return ntfsVolumeInfo(v, w) }), available))
	}
	if len(vols) == 0 {
		out = append(out, collector.Source{ID: "ntfs-no-fixed-volumes", Kind: "windows.ntfs_metadata", Locator: "(fixed volumes)", Method: "ntfs-raw-read", MaxBytes: 1,
			Meta: nm("NTFS metadata", "No fixed volume could be enumerated", collector.InStdFull),
			Open: func(context.Context) (io.ReadCloser, error) {
				return nil, fmt.Errorf("%w: no fixed volumes enumerated", collector.ErrNotPresent)
			}})
	}

	// Zone.Identifier streams of files in user-controlled download/work areas.
	zm := baseMeta("Zone.Identifier streams (Mark-of-the-Web)", "Alternate data streams recording the download zone, referrer and host URL for files in Downloads, Desktop, Documents and Temp", "ntfs", collector.PrivUser, collector.InStdFull,
		"file-activity/zone-identifier.md")
	out = append(out, zoneIdentifierGroup("ntfs-zone-identifier", zm))

	// Alternate data stream inventory (not only Zone.Identifier).
	am := baseMeta("Alternate data stream inventory", "Files under user profiles that carry named data streams (name and size), found with FindFirstStreamW", "ntfs", collector.PrivUser, collector.InStdFull)
	out = append(out, withDetect(jsonSource("ntfs-ads-inventory", am, "FindFirstStreamW", `%USERPROFILE%\**`, func(ctx context.Context, w *warnings) (any, error) {
		return adsInventory(ctx, w), nil
	}), available))

	// Recycle Bin: $I metadata (Standard/Full) and $R content (separate, sensitive, Full only).
	recycleRoots := func() []string {
		var r []string
		for _, v := range fixedVolumes() {
			r = append(r, v.Drive+":"+string(rune(92))+"$Recycle.Bin")
		}
		return r
	}
	rm := baseMeta("Recycle Bin metadata ($I)", "Deleted-file metadata ($I: original path, size, deletion time)", "ntfs", collector.PrivAdmin, collector.InStdFull,
		"file-activity/recycle-bin-files.md")
	out = append(out, requiresAdmin(walkGroup("ntfs-recycle-bin", rm, "X:"+string(rune(92))+"$Recycle.Bin", walkSpec{
		Roots: recycleRoots, MaxDepth: 3, MaxFiles: 20000, FileMax: 1 << 20,
		Match: func(_, name string) bool { return strings.HasPrefix(name, "$I") }})))
	rc := baseMeta("Recycle Bin content ($R)", "The deleted files themselves (bounded to 64 MiB each). Only files directly inside the bin are collected, not deleted folder trees", "ntfs", collector.PrivAdmin, collector.InFullOnly,
		"file-activity/recycle-bin-files.md")
	out = append(out, sensitiveFullOnly(requiresAdmin(walkGroup("ntfs-recycle-bin-content", rc, "X:"+string(rune(92))+"$Recycle.Bin", walkSpec{
		Roots: recycleRoots, MaxDepth: 3, MaxFiles: 20000, FileMax: 64 << 20,
		Match: func(_, name string) bool { return strings.HasPrefix(name, "$R") }})), "deleted documents are collected in full and may contain personal or confidential data"))
	return out
}

func ntfsVolumeInfo(v fixedVolume, w *warnings) (any, error) {
	out := map[string]any{"drive": v.Drive, "filesystem": v.FS}
	if v.FS != "NTFS" {
		return nil, fmt.Errorf("%w: %s volume", collector.ErrNotSupported, v.FS)
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(`\\.\`+v.Drive+`:`), windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		w.add("open volume for FSCTL: %v", classifyErr(err))
	} else {
		defer windows.CloseHandle(h)
		if b, err := deviceIoctl(h, fsctlGetNTFSVolumeData, nil, 128); err == nil && len(b) >= 96 {
			out["fsctl_volume_data"] = map[string]any{
				"volume_serial": fmt.Sprintf("%016X", binary.LittleEndian.Uint64(b[0:])), "number_sectors": binary.LittleEndian.Uint64(b[8:]),
				"total_clusters": binary.LittleEndian.Uint64(b[16:]), "free_clusters": binary.LittleEndian.Uint64(b[24:]),
				"bytes_per_sector": binary.LittleEndian.Uint32(b[40:]), "bytes_per_cluster": binary.LittleEndian.Uint32(b[44:]),
				"bytes_per_file_record": binary.LittleEndian.Uint32(b[48:]), "mft_valid_data_length": binary.LittleEndian.Uint64(b[56:]),
				"mft_start_lcn": binary.LittleEndian.Uint64(b[64:]), "mft2_start_lcn": binary.LittleEndian.Uint64(b[72:]),
			}
		} else if err != nil {
			w.add("FSCTL_GET_NTFS_VOLUME_DATA: %v", err)
		}
		if b, err := deviceIoctl(h, fsctlQueryUSNJournal, nil, 128); err == nil && len(b) >= 56 {
			out["usn_journal"] = map[string]any{"journal_id": binary.LittleEndian.Uint64(b[0:]), "first_usn": int64(binary.LittleEndian.Uint64(b[8:])),
				"next_usn": int64(binary.LittleEndian.Uint64(b[16:])), "lowest_valid_usn": int64(binary.LittleEndian.Uint64(b[24:])),
				"max_usn": int64(binary.LittleEndian.Uint64(b[32:])), "maximum_size": binary.LittleEndian.Uint64(b[40:]), "allocation_delta": binary.LittleEndian.Uint64(b[48:])}
		} else if err != nil {
			w.add("FSCTL_QUERY_USN_JOURNAL: %v (the journal may be disabled on this volume)", err)
		}
	}
	if vol, err := rawVolumeFor(v.Drive); err == nil {
		out["boot_sector"] = vol.Info()
	} else {
		w.add("raw boot sector parse: %v", err)
	}
	return out, nil
}

func zoneIdentifierGroup(id string, m collector.Meta) collector.Source {
	roots := func() []string {
		var r []string
		for _, sub := range []string{"Downloads", "Desktop", "Documents", `AppData\Local\Temp`} {
			r = append(r, perUser(sub)...)
		}
		return r
	}
	g := collector.Source{
		ID: id, Kind: "windows.file_group", Locator: `%USERPROFILE%\{Downloads,Desktop,Documents} :Zone.Identifier`, Method: "directory-walk+ads-read", MaxBytes: 1 << 20, Meta: m,
		Detect: func(context.Context) collector.Availability {
			if len(roots()) == 0 {
				return collector.Availability{State: collector.NotPresent, Reason: "no user work folders"}
			}
			return collector.Availability{State: collector.Available}
		},
	}
	g.Meta.SourceType = "file"
	g.Expand = func(ctx context.Context) ([]collector.Source, error) {
		var out []collector.Source
		visited := 0
		var incomplete string
		for _, root := range roots() {
			inc := walkFiles(ctx, root, walkSpec{MaxDepth: 8}, func(path string, _ int64) bool {
				visited++
				if visited > 60000 {
					incomplete = "stopped after 60000 files"
					return false
				}
				zone := path + ":Zone.Identifier"
				if ok, _, _ := fileInfo(zone); ok {
					cm := collector.Meta{Name: filepath.Base(path) + ":Zone.Identifier", Category: "ntfs", DestPath: "ntfs/zone-identifier/" + destFor("", path)[1:] + ".Zone.Identifier"}
					out = append(out, fileSource(id+"-"+short(path), cm, zone, 1<<20))
				}
				return true
			})
			if inc != "" {
				incomplete = inc
			}
		}
		if incomplete != "" {
			out = append(out, collector.Source{ID: id + "-enumeration-gap", Kind: "windows.collection_gap", Locator: g.Locator, Method: "directory-walk", MaxBytes: 1,
				Meta: collector.Meta{Name: "Zone.Identifier enumeration gap", Category: "ntfs", DestPath: "ntfs/gaps/zone-identifier.txt"},
				Open: func(context.Context) (io.ReadCloser, error) {
					return nil, errors.New("enumeration incomplete: " + incomplete)
				}})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: no Zone.Identifier streams found", collector.ErrNotPresent)
		}
		return out, nil
	}
	return g
}

type streamData struct {
	Size int64
	Name [296]uint16
}

func adsInventory(ctx context.Context, w *warnings) map[string]any {
	type entry struct {
		Path    string `json:"path"`
		Stream  string `json:"stream"`
		Size    int64  `json:"size"`
		ModTime string `json:"main_file_modified_utc,omitempty"`
	}
	var out []entry
	visited := 0
	for _, up := range userProfiles() {
		incomplete := walkFiles(ctx, up.Path, walkSpec{MaxDepth: 10, SkipDir: func(rel string) bool {
			l := strings.ToLower(rel)
			return strings.HasPrefix(l, `appdata\local\packages`) || strings.HasPrefix(l, `appdata\local\microsoft\windows\inetcache`)
		}}, func(path string, _ int64) bool {
			visited++
			if visited > 100000 {
				w.add("ADS inventory stopped after 100000 files")
				return false
			}
			p, err := windows.UTF16PtrFromString(extended(path))
			if err != nil {
				return true
			}
			var sd streamData
			h, _, _ := pFindFirstStream.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&sd)), 0)
			if h == uintptr(^uintptr(0)) {
				return true
			}
			defer pFindClose.Call(h)
			for {
				name := windows.UTF16ToString(sd.Name[:])
				if name != "::$DATA" {
					e := entry{Path: path, Stream: name, Size: sd.Size}
					if st, err := os.Stat(path); err == nil {
						e.ModTime = st.ModTime().UTC().Format(time.RFC3339)
					}
					out = append(out, e)
				}
				if r, _, _ := pFindNextStream.Call(h, uintptr(unsafe.Pointer(&sd))); r == 0 {
					break
				}
			}
			return true
		})
		if incomplete != "" {
			w.add("%s: %s", up.Path, incomplete)
		}
	}
	return map[string]any{"files_visited": visited, "streams": out,
		"note": "Zone.Identifier contents are collected by ntfs-zone-identifier. Not walked by design: AppData\\Local\\Packages and INetCache under each profile"}
}
