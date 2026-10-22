//go:build windows

package windows

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Catalog signatures: most Windows binaries carry no embedded Authenticode signature. Their hash is listed in
// a signed security catalog (.cat). Looking the file hash up in the catalog database and validating the match
// with WinVerifyTrust is what Autoruns reports as "(Verified)". Nothing is written, no UI is shown and
// revocation retrieval is cache-only.

var (
	pCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	pCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	pCryptCATAdminEnumCatalogFromHash     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	pCryptCATCatalogInfoFromContext       = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	pCryptCATAdminReleaseCatalogContext   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	pCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
)

type catalogInfoRec struct {
	Size        uint32
	CatalogFile [260]uint16
}

type wintrustCatalogInfo struct {
	Size             uint32
	CatalogVersion   uint32
	CatalogFilePath  *uint16
	MemberTag        *uint16
	MemberFilePath   *uint16
	MemberFile       windows.Handle
	CalculatedHash   *byte
	CalculatedHashSz uint32
	CatalogContext   uintptr
	CatAdmin         uintptr
}

// wintrustDataCatalog is wintrustData with the union slot holding a catalog descriptor.
type wintrustDataCatalog struct {
	Size           uint32
	PolicyCB       uintptr
	SIPClientData  uintptr
	UIChoice       uint32
	RevocationChk  uint32
	UnionChoice    uint32
	Catalog        *wintrustCatalogInfo
	StateAction    uint32
	StateData      windows.Handle
	URLReference   *uint16
	ProvFlags      uint32
	UIContext      uint32
	SignatureSetts uintptr
}

// verifyCatalogSignature looks the file up in the catalog database (SHA-256 first, then SHA-1) and validates
// the catalog membership. found is false when no catalog lists the file.
func verifyCatalogSignature(path string) (status, code string, found bool) {
	status, code, _, found = verifyCatalogSignatureDetail(path)
	return
}

// verifyCatalogSignatureDetail also returns the name of the catalog signer.
func verifyCatalogSignatureDetail(path string) (status, code, signer string, found bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", "", "", false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", "", "", false
	}
	defer windows.CloseHandle(h)
	for _, alg := range []string{"SHA256", "SHA1"} {
		if st, c, sg, ok := catalogLookup(h, p, alg); ok {
			return st, c, sg, true
		}
	}
	return "", "", "", false
}

func catalogLookup(h windows.Handle, path *uint16, alg string) (string, string, string, bool) {
	if pCryptCATAdminAcquireContext2.Find() != nil {
		return "", "", "", false
	}
	algW, _ := windows.UTF16PtrFromString(alg)
	var admin uintptr
	if r, _, _ := pCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algW)), 0, 0); r == 0 || admin == 0 {
		return "", "", "", false
	}
	defer pCryptCATAdminReleaseContext.Call(admin, 0)

	var n uint32
	pCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), 0, 0)
	if n == 0 || n > 128 {
		return "", "", "", false
	}
	hash := make([]byte, n)
	if r, _, _ := pCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return "", "", "", false
	}
	cat, _, _ := pCryptCATAdminEnumCatalogFromHash.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(n), 0, 0)
	if cat == 0 {
		return "", "", "", false
	}
	defer pCryptCATAdminReleaseCatalogContext.Call(admin, cat, 0)

	var ci catalogInfoRec
	ci.Size = uint32(unsafe.Sizeof(ci))
	if r, _, _ := pCryptCATCatalogInfoFromContext.Call(cat, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
		return "", "", "", false
	}
	tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	wci := wintrustCatalogInfo{CatalogFilePath: &ci.CatalogFile[0], MemberTag: tag, MemberFilePath: path, MemberFile: h,
		CalculatedHash: &hash[0], CalculatedHashSz: n, CatAdmin: admin}
	wci.Size = uint32(unsafe.Sizeof(wci))
	data := wintrustDataCatalog{UIChoice: 2 /*WTD_UI_NONE*/, UnionChoice: 2 /*WTD_CHOICE_CATALOG*/, Catalog: &wci, StateAction: 1, /*VERIFY*/
		ProvFlags: 0x1000 /*WTD_CACHE_ONLY_URL_RETRIEVAL*/}
	data.Size = uint32(unsafe.Sizeof(data))
	invalidHwnd := ^uintptr(0)
	r, _, _ := pWinVerifyTrust.Call(invalidHwnd, uintptr(unsafe.Pointer(&wvtGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	signer := ""
	if uint32(r) == 0 {
		signer = signerFromState(data.StateData)
	}
	data.StateAction = 2 // WTD_STATEACTION_CLOSE
	pWinVerifyTrust.Call(invalidHwnd, uintptr(unsafe.Pointer(&wvtGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	runtime.KeepAlive(&ci)
	runtime.KeepAlive(hash)
	runtime.KeepAlive(&wci)
	code := fmt.Sprintf("0x%08X", uint32(r))
	if uint32(r) == 0 {
		return "valid (catalog-signed)", code, signer, true
	}
	return "catalog entry found but the signature is not valid", code, "", true
}
