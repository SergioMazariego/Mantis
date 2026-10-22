//go:build windows

package windows

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PE image details that Autoruns reports next to every autostart image: the signer name, the Authenticode
// ("PE") hashes and the import hash.

var (
	pWTHelperProvDataFromStateData  = wintrust.NewProc("WTHelperProvDataFromStateData")
	pWTHelperGetProvSignerFromChain = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	pWTHelperGetProvCertFromChain   = wintrust.NewProc("WTHelperGetProvCertFromChain")
	crypt32DLL                      = windows.NewLazySystemDLL("crypt32.dll")
	pCertGetNameStringW             = crypt32DLL.NewProc("CertGetNameStringW")
)

const certNameSimpleDisplayType = 4

// signerFromState returns the display name of the certificate that signed the object whose WinVerifyTrust
// state is open (embedded signer, or the catalog signer for catalog-signed files).
func signerFromState(state windows.Handle) string {
	if state == 0 {
		return ""
	}
	prov, _, _ := pWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := pWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	pc, _, _ := pWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if pc == 0 {
		return ""
	}
	// CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... }: the pointer follows the size field
	cert := readPointerAt(pc, unsafe.Sizeof(uintptr(0)))
	if cert == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := pCertGetNameStringW.Call(cert, certNameSimpleDisplayType, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// readPointerAt reads one pointer-sized value from memory owned by a Windows API (a provider structure).
func readPointerAt(base, off uintptr) uintptr {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&base))
	return *(*uintptr)(unsafe.Add(p, off))
}

// peHashes returns the Authenticode image hashes (SHA-1 and SHA-256) of a file: the hash of the PE image
// without the checksum, the certificate table entry and the certificate data, which is what catalogs list.
func peHashes(path string) (sha1hex, sha256hex string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", ""
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	return catalogHashHex(h, "SHA1"), catalogHashHex(h, "SHA256")
}

func catalogHashHex(h windows.Handle, alg string) string {
	if pCryptCATAdminAcquireContext2.Find() != nil {
		return ""
	}
	algW, _ := windows.UTF16PtrFromString(alg)
	var admin uintptr
	if r, _, _ := pCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algW)), 0, 0); r == 0 || admin == 0 {
		return ""
	}
	defer pCryptCATAdminReleaseContext.Call(admin, 0)
	var n uint32
	pCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), 0, 0)
	if n == 0 || n > 128 {
		return ""
	}
	hash := make([]byte, n)
	if r, _, _ := pCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(hash))
}

const maxImpHashFileBytes = 256 << 20

// importHash computes the import hash ("imphash") of a PE file: MD5 of the comma-joined list of
// "<dll without extension>.<function>" (lower case) in import-table order. Imports by ordinal use "ord<N>".
func importHash(path string) string {
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxImpHashFileBytes || st.Size() < 64 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	defer f.Close()
	var dir pe.DataDirectory
	var is64 bool
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) <= 1 {
			return ""
		}
		dir = oh.DataDirectory[1]
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) <= 1 {
			return ""
		}
		dir, is64 = oh.DataDirectory[1], true
	default:
		return ""
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return ""
	}
	rvaToOff := func(rva uint32) (int, bool) {
		for _, s := range f.Sections {
			span := max(s.VirtualSize, s.Size)
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+span {
				off := int(rva-s.VirtualAddress) + int(s.Offset)
				return off, off >= 0 && off < len(data)
			}
		}
		return 0, false
	}
	cstring := func(rva uint32) string {
		off, ok := rvaToOff(rva)
		if !ok {
			return ""
		}
		end := bytes.IndexByte(data[off:], 0)
		if end < 0 {
			return ""
		}
		return string(data[off : off+end])
	}
	var parts []string
	descOff, ok := rvaToOff(dir.VirtualAddress)
	if !ok {
		return ""
	}
	for i := 0; i < 4096; i++ { // IMAGE_IMPORT_DESCRIPTOR is 20 bytes
		o := descOff + i*20
		if o+20 > len(data) {
			break
		}
		origFirst := binary.LittleEndian.Uint32(data[o:])
		nameRVA := binary.LittleEndian.Uint32(data[o+12:])
		first := binary.LittleEndian.Uint32(data[o+16:])
		if origFirst == 0 && nameRVA == 0 && first == 0 {
			break
		}
		dll := strings.ToLower(cstring(nameRVA))
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			dll = strings.TrimSuffix(dll, ext)
		}
		thunk := origFirst
		if thunk == 0 {
			thunk = first
		}
		toff, ok := rvaToOff(thunk)
		if !ok {
			continue
		}
		step := 4
		if is64 {
			step = 8
		}
		for k := 0; k < 100000; k++ {
			p := toff + k*step
			if p+step > len(data) {
				break
			}
			var v uint64
			if is64 {
				v = binary.LittleEndian.Uint64(data[p:])
			} else {
				v = uint64(binary.LittleEndian.Uint32(data[p:]))
			}
			if v == 0 {
				break
			}
			ordinalFlag := uint64(1) << 31
			if is64 {
				ordinalFlag = uint64(1) << 63
			}
			if v&ordinalFlag != 0 {
				parts = append(parts, fmt.Sprintf("%s.ord%d", dll, v&0xFFFF))
				continue
			}
			// hint/name entry: 2-byte hint then the NUL-terminated name
			parts = append(parts, dll+"."+strings.ToLower(cstring(uint32(v)+2)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
