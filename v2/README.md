# Mantis v2 — `mantis-collect`

Evidence collector for Windows and Linux. Each run stores the selected artifacts in a case-scoped, content-addressed store (SHA-256) with custody records and a tamper-evident audit chain, then exports a **portable, self-describing evidence package** (manifest, per-source status, checksums) that is re-verified from disk. It is a single static binary with no runtime dependencies and no external tools to download.

> **Status:** the expanded Windows acquisition (profiles, evidence package, registry hives, NTFS metadata, event-log discovery, browsers, and the other modules) is implemented and statically checked but **has not yet been validated on a Windows host**. Treat its output as unverified until the validation run described in the project documentation is complete.

## Download

Pre-built binaries are attached to each [release](../../releases) once published (Windows amd64/arm64, Linux amd64/arm64/386/armv7). Verify against `SHA256SUMS`. Releases also carry a per-binary SBOM and a build-provenance attestation (`gh attestation verify <file> --repo SergioMazariego/Mantis`).

## Usage

```
mantis-collect --list-artifacts                  # sources: category, privilege, profiles, availability
mantis-collect                                   # choose a profile or sources (GUI on Windows, menu on Linux)
mantis-collect --profile quick|standard|full     # built-in acquisition profiles
mantis-collect --artifacts id,id                 # specific sources
mantis-collect --all                             # every registered source (sensitive ones need --confirm-sensitive)
mantis-collect --output D:\evidence              # package location (default: next to the executable; must be NTFS)
mantis-collect --confirm-sensitive --memory-pids 1234   # opt-in sensitive sources (memory dumps need the memdump build)
mantis-collect --version
```

**Profiles.** *Quick Triage* (system, processes, network, persistence, core event logs, key execution artifacts, Defender), *Standard DFIR* (adds registry hives, all event channels, NTFS metadata, user activity, RDP/USB, browsers, security), *Full Forensic* (adds the rest, subject to size limits), and *Custom* (individual sources). Nothing is collected unless you select it.

**Run as administrator** for a complete acquisition: hives, raw NTFS artifacts, the Security log and process details need elevation. Without it, those sources are reported as `access_denied` instead of being skipped silently.

On Windows the default is a dark-themed window: profile chips, search, category sidebar, availability/privilege/size columns, a live execution screen with per-source status, an event log you can copy, safe cancellation (evidence already acquired is kept) and an accurate final summary.

## Evidence package

```
Mantis-<case>-<host>-<UTC>/
  manifest.json  acquisition-report.json  acquisition-errors.json  checksums.sha256  verification.json
  system/ registry/ persistence/ processes/ network/ eventlogs/ ntfs/ execution/ users/ remote-access/
  usb/ browsers/ security/ group-policy/ shadow-copies/ memory/
```

Every source has one of these statuses: `collected`, `collected_with_warnings`, `empty`, `not_present`, `not_supported`, `access_denied`, `failed`, `cancelled`. A finished run never implies a complete endpoint collection. Raw artifacts keep their original path; the manifest records original path, size, SHA-256 and the method actually used (direct shared read, raw NTFS read, `RegSaveKeyEx`, `EvtExportLog`, API snapshot).

## What is not collected by design

Browser passwords, cookies, session tokens and the keys that protect them; Wi-Fi profile key material; `lsass` memory; physical RAM (needs a signed kernel driver). Process memory dumps are compiled out of the default binary: build with `-tags memdump` for authorized use. Volume Shadow Copies are only read, never created or deleted.

## Build from source

```
cd v2
go test -p 1 ./...
CGO_ENABLED=0 go build -trimpath -o mantis-collect ./cmd/mantis-collect
```

The Go version is pinned in `go.mod` and `.go-version`. SQLite is a pure-Go driver, so no C toolchain is needed and cross-compiling works with `GOOS`/`GOARCH`. Because the collector uses techniques common to forensic and attack tooling (raw volume reads, hive export, backup privileges), endpoint security products may flag or block unsigned builds: sign the binaries and allowlist them for authorized use.
