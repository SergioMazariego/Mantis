#!/usr/bin/env python3
"""Allowlist gate for the public tree.

Every tracked path must match ALLOW, and file contents are scanned for local
paths, private addresses and credentials. Run against the index/worktree, or
against a commit with --ref (used by the pre-push hook and CI).
"""
import argparse, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Only paths matching one of these are allowed in the public repository.
ALLOW = [re.compile(p) for p in (
    r'^(LICENSE\.txt|README\.md|mantis\.go|\.gitignore|\.goreleaser\.yaml)$',
    r'^(assets|v2/cmd/mantis-collect/assets)/mantis-[\w-]+\.png$',
    r'^\.githooks/pre-push$',
    r'^\.github/(workflows/[\w.-]+\.ya?ml|dependabot\.yml)$',
    r'^tools/check_public_tree\.py$',
    r'^v2/(go\.mod|go\.sum|\.go-version|README\.md)$',
    r'^v2/(cmd|internal)/[\w./-]+\.go$',
)]
BLOCK_NAME = re.compile(r'(?i)(^|/)\.env|\.(pem|key|p12|pfx|exe|zip|7z|rar|pdf|docx|evtx|e01|raw|dd|vhdx|mantis|sqlite3?|db)(-wal|-shm|-journal)?$')
BINARY_OK = re.compile(r'^(assets|v2/cmd/mantis-collect/assets)/mantis-[\w-]+\.png$')
PATTERNS = {
    'local home path': re.compile(r'(?i)(?:[a-z]:[\\/]+users[\\/]+(?!public\b|default\b)[^\\/\s]+|/' + r'home/[^/\s]+)'),
    'private network address': re.compile(r'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'credential token': re.compile(r'\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b'),
    'internal planning reference': re.compile(r'(?i)blueprint|ADR-\d{3}|docs/(adr|planning|engineering)'),
}

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def inspect(name, data):
    bad = []
    if not any(p.match(name) for p in ALLOW):
        bad.append('not in public allowlist')
    if BLOCK_NAME.search(name):
        bad.append('private file type')
    if BINARY_OK.match(name):
        return bad
    if b'\x00' in data:
        return bad + ['unreviewed binary']
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return bad + ['non-UTF-8 file']
    if name != 'tools/check_public_tree.py':
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                bad.append(label)
    return bad

def files(ref):
    if ref:
        for line in filter(None, git('ls-tree', '-r', '-z', ref).split(b'\x00')):
            meta, raw = line.split(b'\t', 1)
            mode, kind, oid = meta.decode().split(' ')
            name = raw.decode('utf-8', 'surrogateescape').replace('\\', '/')
            yield name, (git('cat-file', 'blob', oid) if kind == 'blob' else b''), mode == '120000'
    else:  # what would be committed: the index
        for line in filter(None, git('ls-files', '--stage', '-z').split(b'\x00')):
            meta, raw = line.split(b'\t', 1)
            mode, oid, _ = meta.decode().split(' ')
            name = raw.decode('utf-8', 'surrogateescape').replace('\\', '/')
            yield name, git('cat-file', 'blob', oid), mode == '120000'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', help='check this commit instead of the index')
    args = ap.parse_args()
    bad = []
    for name, data, link in files(args.ref):
        reasons = inspect(name, data) + (['symbolic link'] if link else [])
        if reasons:
            bad.append((name, reasons))
    for name, reasons in bad:
        print('BLOCK', name, ':', ', '.join(reasons), file=sys.stderr)
    if bad:
        return 1
    print('Public tree check passed')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
