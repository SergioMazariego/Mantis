<#
  Verifies a Mantis evidence package against the fixtures from Fixtures.ps1.
  Usage:  .\Verify.ps1 -Package D:\out-standard [-Profile standard] [-ReportPath report.md]
  Prints PASS/FAIL per check and a summary; does not modify the package. Exit code 1 if any check fails.
  -Profile quick only runs the integrity checks; the fixture checks need standard or full.
#>
param([Parameter(Mandatory)][string]$Package, [ValidateSet('quick', 'standard', 'full')][string]$Profile = 'full', [string]$ReportPath)
$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]
function Check($name, [scriptblock]$test) {
  $msg = $null
  try { $ok = [bool](& $test) } catch { $ok = $false; $msg = $_.Exception.Message }
  $results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Note = $msg })
}
function Art($id) { $script:man.artifacts | Where-Object { $_.id -like $id } }
function Text($relPath) { Get-Content -LiteralPath (Join-Path $Package $relPath) -Raw -ErrorAction Stop }
function AnyFileContains($pattern, $needle) {
  Get-ChildItem -Path $Package -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
    Where-Object { (Select-String -Path $_.FullName -SimpleMatch $needle -Quiet) } | Select-Object -First 1
}

$manPath = Join-Path $Package 'manifest.json'
Check 'manifest.json exists and has the expected schema' { $script:man = Get-Content $manPath -Raw | ConvertFrom-Json; $man.schema -eq 'mantis.evidence-package/1' }
Check 'verification.json reports ok' { (Get-Content (Join-Path $Package 'verification.json') -Raw | ConvertFrom-Json).ok -eq $true }

Check 'checksums.sha256: every file re-hashes to its recorded digest' {
  $bad = 0
  Get-Content (Join-Path $Package 'checksums.sha256') | ForEach-Object {
    $h, $p = $_ -split ' \*', 2
    $f = Join-Path $Package $p
    if (-not (Test-Path -LiteralPath $f) -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $h.ToUpper()) { $bad++ }
  }
  $bad -eq 0
}
Check 'every collected artifact in the manifest has a destination, size and a 64-hex SHA-256' {
  $c = $man.artifacts | Where-Object { $_.status -in 'collected', 'collected_with_warnings', 'empty' }
  ($c | Where-Object { -not $_.destination -or $_.sha256 -notmatch '^[0-9a-f]{64}$' }).Count -eq 0
}
Check 'gaps carry no hash or destination (no fabricated evidence)' {
  ($man.artifacts | Where-Object { $_.status -notin 'collected', 'collected_with_warnings', 'empty' -and ($_.sha256 -or $_.destination) }).Count -eq 0
}
Check 'on-disk SHA-256 of each artifact equals the manifest' {
  $bad = 0
  $man.artifacts | Where-Object { $_.destination } | ForEach-Object {
    $f = Join-Path $Package ($_.destination -replace '/', '\')
    if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -ne $_.sha256) { $bad++ }
  }
  $bad -eq 0
}

if ($Profile -ne 'quick') {
# fixtures
Check 'V-PERSIST: HKCU Run fixture in the autorun dump' { (Text 'persistence\persistence-autorun-registry.json') -match 'MantisFixture' }
Check 'V-PERSIST: scheduled task XML preserved' { AnyFileContains 'MantisFixture*' 'notepad' }
Check 'V-PERSIST: task cache registry dump mentions the task' { (Text 'persistence\persistence-taskcache-registry.json') -match 'MantisFixture' }
Check 'V-PERSIST: startup folder entry preserved' { Get-ChildItem $Package -Recurse -File -Filter 'MantisFixture.cmd' -ErrorAction SilentlyContinue }
Check 'V-PROC: ping fixture process with command line, parent and image hash' {
  $p = (Text 'processes\processes-detailed.json' | ConvertFrom-Json).data.processes | Where-Object { $_.name -eq 'PING.EXE' -and $_.command_line -match '127.0.0.1' } | Select-Object -First 1
  $p -and $p.parent_pid -and $p.image.sha256
}
Check 'V-NETWORK: TCP listener on 50555 with an owning PID' {
  (Text 'network\network-connections.json' | ConvertFrom-Json).data.sockets | Where-Object { $_.local_port -eq 50555 -and $_.state -eq 'LISTEN' -and $_.pid -gt 0 }
}
Check 'V-NTFS: Zone.Identifier stream of the fixture preserved' { AnyFileContains '*.Zone.Identifier' 'example.invalid' }
Check 'V-NTFS: Recycle Bin $I record preserved' { Get-ChildItem $Package -Recurse -File | Where-Object { $_.Name -like '$I*' } | Select-Object -First 1 }
Check 'V-NTFS: $MFT of the system drive acquired, or reported not_supported when the host refuses raw volume reads' {
  $d = $env:SystemDrive.TrimEnd(':')
  $a = Art "ntfs-mft-$d"
  if ($a.status -eq 'collected') { return $true }
  if ($a.status -eq 'not_supported') { return $true } # e.g. Windows Sandbox: the request is not supported on the volume
  throw ("ntfs-mft-{0} status: {1}; {2}" -f $d, $a.status, $a.error)
}
Check 'V-USERS: PSReadLine history line preserved' { AnyFileContains 'ConsoleHost_history.txt' 'MantisFixture history line' }
Check 'V-USERS: fixture account listed' {
  $t = Text 'users\users-accounts.json'
  if ($t -match 'MantisFixtureUser') { return $true }
  $names = [regex]::Matches($t, '"(?:name|user_name)"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -First 15
  throw ("not found; {0} bytes; names seen: {1}" -f $t.Length, ($names -join ','))
}
Check 'V-REMOTE: Default.rdp and RDP client history key preserved' { (AnyFileContains 'Default.rdp' 'fixture.invalid') -and ((Text 'remote-access\remote-rdp-client-history.json') -match 'fixture.invalid') }
Check 'V-EVT: Application log exported and contains event 999 from MantisFixture' {
  $f = Get-ChildItem (Join-Path $Package 'eventlogs') -Filter 'Application.evtx' | Select-Object -First 1
  $e = Get-WinEvent -Path $f.FullName -FilterXPath "*[System[EventID=999]]" -MaxEvents 1 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -eq 'MantisFixture' }
  if ($e) { return $true }
  $latest = Get-WinEvent -Path $f.FullName -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { '{0}/{1}' -f $_.Id, $_.ProviderName }
  throw ("event not found in {0} ({1} bytes); latest events: {2}" -f $f.Name, $f.Length, ($latest -join ','))
}
Check 'V-EVT: all discovered channels were attempted (more than 100 evtx items)' { ($man.artifacts | Where-Object { $_.id -like 'evtx-*' }).Count -gt 100 }
Check 'V-REG: SYSTEM and SOFTWARE hives acquired with a reported method' {
  ($man.artifacts | Where-Object { $_.id -in 'hive-system', 'hive-software' -and $_.status -eq 'collected' -and $_.method }).Count -eq 2
}
if ($Profile -eq 'full') {
  Check 'V-REG: SAM and SECURITY hives (sensitive, Full only) acquired' {
    ($man.artifacts | Where-Object { $_.id -in 'hive-sam', 'hive-security' -and $_.status -eq 'collected' -and $_.method }).Count -eq 2
  }
} else {
  Check 'V-REG: SAM and SECURITY are NOT collected outside the Full profile' {
    -not ($man.artifacts | Where-Object { $_.id -in 'hive-sam', 'hive-security' })
  }
}
Check 'V-REG: hive starts with the regf signature' {
  $f = Join-Path $Package 'registry\C\Windows\System32\config\SYSTEM'
  [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($f)[0..3]) -eq 'regf'
}
Check 'V-EXEC: Prefetch files present (or the host has none and the gap is reported)' {
  $collected = (Get-ChildItem (Join-Path $Package 'execution') -Recurse -Filter '*.pf' -ErrorAction SilentlyContinue).Count
  if ($collected -gt 0) { return $true }
  # Windows Server and some images run with Prefetch disabled: then not_present is the truthful outcome
  $onHost = (Get-ChildItem (Join-Path $env:SystemRoot 'Prefetch') -Filter '*.pf' -ErrorAction SilentlyContinue).Count
  if ($onHost -eq 0) { return [bool](Art 'execution-prefetch' | Where-Object { $_.status -eq 'not_present' }) }
  throw "$onHost .pf files exist on the host but none were collected"
}
Check 'V-SYSTEM: physical disks and partitions inventoried' { ((Text 'system\system-disks.json' | ConvertFrom-Json).data.physical_disks).Count -ge 1 }
Check 'V-SEC: Defender configuration dump present' { Art 'security-defender-config' | Where-Object { $_.status -like 'collected*' } }
Check 'V-BROWSER: no credential/cookie stores in the package' {
  -not (Get-ChildItem $Package -Recurse -File | Where-Object { $_.Name -in 'Login Data', 'Cookies', 'Web Data', 'Local State', 'key4.db', 'logins.json', 'cookies.sqlite' })
}
Check 'V-PERSIST: extensibility points (credential providers, protocol handlers, DirectShow filters) are dumped' {
  $t = Text 'persistence\persistence-extensibility-points.json'
  ($t -match 'Credential Providers') -and ($t -match 'Protocols') -and ($t -match 'Instance')
}
Check 'V-PERSIST: autostart entries are enriched with hash, signature, company and version' {
  $d = (Text 'persistence\persistence-enriched.json' | ConvertFrom-Json).data
  $withHash = @($d.images | Where-Object { $_.sha256 -match '^[0-9a-f]{64}$' -and $_.md5 -and $_.sha1 }).Count
  $withCompany = @($d.images | Where-Object { $_.company }).Count
  $signed = @($d.images | Where-Object { $_.authenticode }).Count
  $fixture = $d.entries | Where-Object { $_.entry -eq 'MantisFixture' } | Select-Object -First 1
  if ($d.entry_count -lt 100) { throw "only $($d.entry_count) entries" }
  $cats = @($d.entries | ForEach-Object { $_.category } | Sort-Object -Unique)
  foreach ($c in 'logon', 'services', 'drivers', 'scheduled_tasks', 'explorer', 'winlogon', 'winsock', 'codecs') {
    if ($cats -notcontains $c) { throw "no autostart entries resolved for category '$c' (seen: $($cats -join ', '))" }
  }
  if (@($d.images | Where-Object { $_.file_version_numeric -match '^\d+\.\d+\.\d+\.\d+$' }).Count -lt 20) { throw 'numeric file versions are missing' }
  $catalog = @($d.images | Where-Object { $_.authenticode -eq 'valid (catalog-signed)' }).Count
  if ($catalog -lt 100) { throw "only $catalog images verified through a security catalog" }
  $withSigner = @($d.images | Where-Object { $_.signer }).Count
  if ($withSigner -lt 100) { throw "only $withSigner images with a signer name" }
  $withPE = @($d.images | Where-Object { $_.pe_sha1 -match '^[0-9A-F]{40}$' -and $_.pe_sha256 -match '^[0-9A-F]{64}$' }).Count
  if ($withPE -lt 100) { throw "only $withPE images with Authenticode image hashes" }
  $withImp = @($d.images | Where-Object { $_.imphash -match '^[0-9A-F]{32}$' }).Count
  if ($withImp -lt 100) { throw "only $withImp images with an import hash" }
  $withTime = @($d.entries | Where-Object { $_.time_utc }).Count
  if ($withTime -lt 100) { throw "only $withTime entries with a time" }
  $states = @($d.entries | ForEach-Object { $_.enabled } | Sort-Object -Unique)
  if ($states -notcontains 'enabled') { throw "entries carry no enabled state (seen: $($states -join ', '))" }
  if (@($d.entries | Where-Object { $_.entry_description }).Count -lt 20) { throw 'service and task descriptions are missing' }
  $svcDll = @($d.entries | Where-Object { $_.entry -like '*(ServiceDll)' }).Count
  if ($svcDll -lt 50) { throw "only $svcDll service DLL entries" }
  $builtin = $d.entries | Where-Object { $_.category -eq 'drivers' -and $_.entry -eq 'Ntfs' } | Select-Object -First 1
  if (-not $builtin -or $builtin.image_path -notmatch 'drivers\\ntfs\.sys$') { throw 'built-in driver without ImagePath (Ntfs) was not resolved to System32\drivers' }
  # the image set differs by architecture: only require the DLL when rundll32 entries exist
  $rundll = @($d.entries | Where-Object { $_.image_path -like '*\rundll32.exe' -and $_.launch_string -match '(?i)rundll32(\.exe)?"?\s+\S' })
  if ($rundll.Count -gt 0 -and @($d.entries | Where-Object { $_.launch_target }).Count -lt 1) { throw "$($rundll.Count) rundll32 entries exist but none was resolved to its DLL" }
  if (-not ($d.entries | Where-Object { $_.entry -eq 'MantisFixture.cmd' })) { throw 'the Startup folder fixture was not listed' }
  if ($withHash -lt 50) { throw "only $withHash images hashed" }
  if ($withCompany -lt 20) { throw "only $withCompany images with a company" }
  if ($signed -lt 20) { throw "only $signed images with an Authenticode result" }
  if (-not $fixture -or $fixture.image_path -notmatch 'notepad\.exe') { throw 'the HKCU Run fixture was not resolved to notepad.exe' }
  $true
}
Check 'V-PROC: performance counters (priority, CPU times, virtual size, pools, threads) for every process' {
  $d = (Text 'processes\processes-performance.json' | ConvertFrom-Json).data
  if ($d.process_count -lt 20 -or $d.thread_count -le $d.process_count) { throw "processes=$($d.process_count) threads=$($d.thread_count)" }
  $ping = $d.processes | Where-Object { $_.name -like 'ping.exe' } | Select-Object -First 1
  if (-not $ping) { throw 'ping fixture process not found' }
  # the fixture process may still be running: its live base priority must equal what was recorded (it is inherited, so it varies by host)
  $live = Get-Process -Id $ping.pid -ErrorAction SilentlyContinue
  if ($live -and $live.BasePriority -ne $ping.base_priority) { throw "base priority $($ping.base_priority) recorded but $($live.BasePriority) live" }
  if ($ping.base_priority -lt 1 -or $ping.virtual_bytes -le 0 -or $ping.private_bytes -le 0 -or @($ping.thread_detail).Count -lt 1) { throw ('ping counters look wrong: ' + ($ping | Select-Object name, base_priority, virtual_bytes, private_bytes, threads | ConvertTo-Json -Compress)) }
  $detailed = (Text 'processes\processes-detailed.json' | ConvertFrom-Json).data.processes
  $pids = @{}; foreach ($p in $d.processes) { $pids[[string]$p.pid] = $p }
  $common = @($detailed | Where-Object { $pids.ContainsKey([string]$_.pid) }).Count
  if ($common -lt 0.8 * $detailed.Count) { throw "only $common of $($detailed.Count) detailed processes appear in the performance snapshot" }
  $true
}
Check 'V-ACTIONS: the manifest carries an action type apart from the source type' {
  $with = @($man.artifacts | Where-Object { $_.action_types })
  if ($with.Count -lt 20) { throw "only $($with.Count) artifacts carry action_types" }
  if (@($with | Where-Object { -not $_.source_type }).Count -gt 0) { throw 'an artifact with action_types has no source_type' }
  $sys = $man.artifacts | Where-Object { $_.id -eq 'evtx-System' } | Select-Object -First 1
  if (-not $sys -or $sys.action_types -notcontains 'System Shutdown') { throw 'the System event log does not list System Shutdown' }
  $lnk = $man.artifacts | Where-Object { $_.id -like 'users-recent-lnk*' -and $_.status -like 'collected*' } | Select-Object -First 1
  if ($lnk -and $lnk.action_types -notcontains 'Open file or folder') { throw 'recent shortcuts do not list Open file or folder' }
  $true
}
Check 'V-SYSTEM: disks report offline, read_only and dynamic state' {
  $disk = ((Text 'system\system-disks.json' | ConvertFrom-Json).data.physical_disks) | Select-Object -First 1
  $disk -and ($disk.PSObject.Properties.Name -contains 'offline') -and ($disk.PSObject.Properties.Name -contains 'read_only')
}
if ($Profile -eq 'full') {
  Check 'V-EVT: byte copies of the .evtx files keep the ElfFile signature' {
    $f = Get-ChildItem (Join-Path $Package 'eventlogs') -Recurse -File -Filter 'Application.evtx' | Where-Object { $_.FullName -match 'winevt' } | Select-Object -First 1
    if (-not $f) { throw 'no byte copy of Application.evtx in the package' }
    [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($f.FullName)[0..6]) -eq 'ElfFile'
  }
  Check 'V-EVT: archived and crash-dump sources report an honest outcome (never failed)' {
    $bad = $man.artifacts | Where-Object { $_.id -like 'evtx-archive-files*' -or $_.id -like 'execution-crash-dumps*' } | Where-Object { $_.status -eq 'failed' }
    -not $bad
  }
}
foreach ($br in @(
    # Headless Chromium on CI images does not record the visit (and Chrome creates no profile at all), so for
    # Chromium browsers the check is structural: the profile exists and its History database was collected.
    @{ Name = 'Chrome'; Id = 'browser-chrome'; Profile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"; File = 'History'; Content = $false },
    @{ Name = 'Edge'; Id = 'browser-edge'; Profile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"; File = 'History'; Content = $false },
    @{ Name = 'Firefox'; Id = 'browser-firefox'; Profile = "$env:APPDATA\Mozilla\Firefox\Profiles"; File = 'places.sqlite*'; Content = $true })) {
  if (-not (Test-Path $br.Profile)) { continue }
  $b = $br
  Check ("V-BROWSER: {0} history collected{1}" -f $b.Name, $(if ($b.Content) { ' and holds the fixture URL' } else { '' })) {
    $a = Art ($b.Id + '*')
    if (-not $a -or ($a | Where-Object { $_.status -like 'collected*' }).Count -eq 0) {
      throw ("{0}: {1}" -f $b.Id, (($a | ForEach-Object { '{0} {1}' -f $_.status, $_.error }) -join '; '))
    }
    $files = Get-ChildItem (Join-Path $Package 'browsers') -Recurse -File -Filter $b.File -ErrorAction SilentlyContinue
    if (-not $files) { throw 'artifact reported collected but no history file is in the package' }
    if (-not $b.Content) { return $true }
    $hit = $files | Where-Object { Select-String -LiteralPath $_.FullName -SimpleMatch 'MantisFixture-browser' -Quiet } | Select-Object -First 1
    if (-not $hit) { throw 'history file(s) collected but the fixture URL is not inside' }
    $true
  }
}
Check 'V-NOT-FULL: the report states that completeness is not implied' { (Get-Content (Join-Path $Package 'acquisition-report.json') -Raw) -match 'does not imply' }
}

$results | Format-Table -AutoSize -Wrap
$fail = ($results | Where-Object Result -eq 'FAIL').Count
Write-Host ("{0} checks, {1} failed" -f $results.Count, $fail)
'Status counts:'; $man.artifacts | Group-Object status | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize
if ($ReportPath) {
  $md = New-Object System.Collections.Generic.List[string]
  $md.Add("### Verification ($Profile): $($results.Count) checks, $fail failed")
  $md.Add('')
  $md.Add('| Check | Result | Note |'); $md.Add('|---|---|---|')
  foreach ($r in $results) { $md.Add(('| {0} | {1} | {2} |' -f $r.Check, $r.Result, ($r.Note -replace '\|', '/'))) }
  $md.Add(''); $md.Add('Artifact status counts: ' + (($man.artifacts | Group-Object status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '))
  $gaps = $man.artifacts | Where-Object { $_.status -notin 'collected', 'collected_with_warnings', 'empty' }
  $clip = { param($s) $s = [string]$s; if ($s.Length -gt 240) { $s.Substring(0, 240) + '...' } else { $s } }
  if ($gaps) { $md.Add(''); $md.Add('Gaps and failures (id: status - reason):'); $gaps | ForEach-Object { $md.Add(('- {0}: {1} - {2}' -f $_.id, $_.status, (& $clip $_.error))) } }
  $warn = $man.artifacts | Where-Object { $_.status -eq 'collected_with_warnings' }
  if ($warn) {
    $md.Add(''); $md.Add('Collected with warnings (id - notes):')
    $warn | ForEach-Object { $n = if ($_.notes) { ($_.notes.PSObject.Properties | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ' } else { '' }; $md.Add(('- {0} - {1}' -f $_.id, (& $clip $n))) }
  }
  $md | Set-Content -Path $ReportPath -Encoding utf8
}
if ($fail -gt 0) { exit 1 }
