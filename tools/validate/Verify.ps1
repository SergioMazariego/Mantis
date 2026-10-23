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
  # a svchost-hosted service is one row: the DLL is the image and the ImagePath command line is the launch string
  $svcDll = @($d.entries | Where-Object { $_.category -eq 'services' -and $_.image_path -like '*.dll' -and $_.launch_string -match 'svchost' }).Count
  if ($svcDll -lt 50) { throw "only $svcDll service rows resolved to their service DLL" }
  $builtin = $d.entries | Where-Object { $_.category -eq 'drivers' -and $_.entry -eq 'Ntfs' } | Select-Object -First 1
  if (-not $builtin -or $builtin.image_path -notmatch 'drivers\\ntfs\.sys$') { throw 'built-in driver without ImagePath (Ntfs) was not resolved to System32\drivers' }
  # the image set differs by architecture: only require the DLL when rundll32 entries exist
  $rundll = @($d.entries | Where-Object { $_.launch_string -match '(?i)rundll32(\.exe)?"?\s+\S' })
  if ($rundll.Count -gt 0 -and @($d.entries | Where-Object { $_.launcher_path -like '*rundll32.exe' -and $_.image_path -like '*.dll' }).Count -lt 1) { throw "$($rundll.Count) rundll32 entries exist but none has the DLL as its image" }
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
Check 'V-PROC: threads carry the Win32 start address, stack bounds and TEB' {
  $threads = @((Text 'processes\processes-performance.json' | ConvertFrom-Json).data.processes | ForEach-Object { $_.thread_detail } | Where-Object { $_ })
  if ($threads.Count -lt 100) { throw "only $($threads.Count) threads" }
  $with = @($threads | Where-Object { $_.win32_start_address -and $_.win32_start_address -ne '0x0' -and $_.teb_base -and $_.stack_base })
  if ($with.Count -lt 0.8 * $threads.Count) { throw "only $($with.Count) of $($threads.Count) threads have a Win32 start address, stack and TEB" }
  $true
}
Check 'V-PROC: processes carry token, protection, architecture, PEB, parent validity, signer and user fields' {
  $d = (Text 'processes\processes-detailed.json' | ConvertFrom-Json).data.processes
  $n = $d.Count
  $tok = @($d | Where-Object { $_.privileges_enabled -or $_.privileges_disabled }).Count
  $arch = @($d | Where-Object { $_.architecture }).Count
  $peb = @($d | Where-Object { $_.peb_image_path -and $_.current_directory }).Count
  $par = @($d | Where-Object { $_.parent_state }).Count
  $when = @($d | Where-Object { $_.collected_utc }).Count
  $logon = @($d | Where-Object { $_.logon_session_id -and $_.token_type }).Count
  $signer = @($d | Where-Object { $_.image.signer }).Count
  $company = @($d | Where-Object { $_.image.company }).Count
  if ($tok -lt 0.5 * $n -or $arch -lt 0.5 * $n -or $par -lt 0.9 * $n -or $when -lt 0.9 * $n -or $logon -lt 0.5 * $n) { throw "fields too sparse of $n processes: privileges=$tok architecture=$arch parent_state=$par collected=$when logon=$logon" }
  if ($peb -lt 0.3 * $n) { throw "only $peb of $n processes have the PEB image path and current directory" }
  if ($signer -lt 20 -or $company -lt 20) { throw "only $signer signers and $company companies in process images" }
  $mismatch = @($d | Where-Object { $_.peb_image_matches -eq $false }).Count
  if ($mismatch -gt 0.1 * $n) { throw "$mismatch processes have a PEB image path different from the kernel's" }
  $ping = $d | Where-Object { $_.name -eq 'PING.EXE' -and $_.command_line -match '127.0.0.1' } | Select-Object -First 1
  if ($ping -and ($ping.parent_state -notin 'running', 'exited' -or -not $ping.current_directory)) { throw "ping fixture detail wrong: $($ping | Select-Object parent_state, current_directory | ConvertTo-Json -Compress)" }
  $true
}
Check 'V-PROC: loaded module images carry hashes, signatures and the processes that loaded them' {
  $d = (Text 'processes\processes-module-images.json' | ConvertFrom-Json).data
  if ($d.image_count -lt 100) { throw "only $($d.image_count) module images" }
  $hashed = @($d.images | Where-Object { $_.sha256 }).Count
  $signed = @($d.images | Where-Object { $_.signer }).Count
  $loaded = @($d.images | Where-Object { $_.loaded_by_count -ge 1 -and $_.loaded_by }).Count
  if ($hashed -lt 0.8 * $d.image_count -or $signed -lt 0.4 * $d.image_count -or $loaded -lt $d.image_count) { throw "images=$($d.image_count) hashed=$hashed signed=$signed loaded_by=$loaded" }
  $true
}
Check 'V-PROC: memory map lists executable regions with protection and backing file' {
  $d = (Text 'processes\processes-memory-map.json' | ConvertFrom-Json).data
  if ($d.process_count -lt 20) { throw "only $($d.process_count) processes" }
  $regions = @($d.processes | ForEach-Object { $_.executable } | Where-Object { $_ })
  if ($regions.Count -lt 100) { throw "only $($regions.Count) executable regions" }
  $image = @($regions | Where-Object { $_.type -eq 'image' -and $_.file -and $_.protect }).Count
  if ($image -lt 50) { throw "only $image image regions with a file and protection" }
  $true
}
Check 'V-PROC: the handle table names its object types' {
  if ($Profile -ne 'full') { return $true }  # handle sources are Full-only
  $d = (Text 'processes\processes-handle-table.json' | ConvertFrom-Json).data
  $names = @($d.object_types | ForEach-Object { $_.name })
  foreach ($t in 'Process', 'Thread', 'File', 'Key') { if ($names -notcontains $t) { throw "object type $t missing from the type table" } }
  $named = @($d.processes | Where-Object { $_.by_type -and $_.by_type.File }).Count
  if ($named -lt 10) { throw "only $named processes with handles counted by type name" }
  $true
}
Check 'V-PROC: named handles list processes, keys, files and mutexes' {
  if ($Profile -ne 'full') { return $true }
  $d = (Text 'processes\processes-handles.json' | ConvertFrom-Json).data
  if ($d.listed -lt 100) { throw "only $($d.listed) handles listed of $($d.total_handles)" }
  $types = @($d.handles | ForEach-Object { $_.type } | Select-Object -Unique)
  foreach ($t in 'Key', 'File') { if ($types -notcontains $t) { throw "no $t handles listed (types: $($types -join ','))" } }
  if (@($d.handles | Where-Object { $_.name }).Count -lt 50) { throw 'too few handles carry a resolved name' }
  $true
}
Check 'V-PROC: process environment is collected only with explicit confirmation' {
  $a = Art 'processes-environment'
  if (-not $a) { return $true }  # sensitive: absent unless --confirm-sensitive was given
  $d = (Text 'processes\processes-environment.json' | ConvertFrom-Json).data
  @($d.processes | Where-Object { $_.variables -and ($_.variables | Where-Object { $_ -like 'PATH=*' }) }).Count -ge 10
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
Check 'V-TIMES: exported event logs and copied files keep the source creation, access and modification times' {
  $sys = $man.artifacts | Where-Object { $_.id -eq 'evtx-System' } | Select-Object -First 1
  if (-not $sys -or -not $sys.notes.source_created_utc -or -not $sys.notes.source_accessed_utc -or -not $sys.notes.source_modified_utc) { throw 'the exported System log carries no source file times' }
  $files = @($man.artifacts | Where-Object { $_.method -like 'win32-shared-read' -and $_.status -like 'collected*' })
  if ($files.Count -eq 0) { throw 'no copied file to check' }
  $without = @($files | Where-Object { -not $_.notes.source_created_utc -or -not $_.notes.source_modified_utc })
  if ($without.Count -gt 0.1 * $files.Count) { throw "$($without.Count) of $($files.Count) copied files lack source times" }
  $true
}
Check 'V-FIX: execution values whose name is a path keep their data (never redacted)' {
  $keys = (Text 'execution\execution-compat-assistant.json' | ConvertFrom-Json).data.keys
  $v = @($keys | ForEach-Object { $_.values } | Where-Object { $_.name -like '*MantisFixture\tokenizer.exe' }) | Select-Object -First 1
  if (-not $v) { throw 'the fixture value was not dumped' }
  if ($v.redacted -or -not $v.data_base64) { throw 'an execution value named after a path was redacted' }
  $true
}
Check 'V-FIX: the DNS cache records cached answers (address) without querying the network' {
  $e = (Text 'network\network-dns-cache.json' | ConvertFrom-Json).data.entries | Where-Object { $_.name -eq 'mantis-fixture.test' } | Select-Object -First 1
  if (-not $e) { throw 'the fixture name is not in the DNS cache dump' }
  if (-not ($e.records | Where-Object { $_.address -eq '127.0.0.42' })) { throw "no cached answer 127.0.0.42: $($e | ConvertTo-Json -Compress -Depth 4)" }
  $true
}
Check 'V-FIX: persistence keeps the logon script, the 32-bit Run view and the Startup folder state' {
  $entries = (Text 'persistence\persistence-enriched.json' | ConvertFrom-Json).data.entries
  $script = $entries | Where-Object { $_.entry -eq 'UserInitMprLogonScript' -and $_.launch_string -match 'MantisFixtureLogonScript' }
  if (-not $script) { throw 'UserInitMprLogonScript was not listed with its command' }
  $wow = $entries | Where-Object { $_.entry -eq 'MantisFixture32' } | Select-Object -First 1
  if (-not $wow -or $wow.location -notmatch 'WOW6432Node') { throw "32-bit Run entry location: $($wow.location)" }
  $startup = $entries | Where-Object { $_.entry -eq 'MantisFixture.cmd' } | Select-Object -First 1
  if (-not $startup -or $startup.enabled -ne 'disabled') { throw "Startup folder entry state: $($startup.enabled)" }
  $dump = (Text 'persistence\persistence-autorun-registry.json' | ConvertFrom-Json).data.keys | Where-Object { $_.path -like '*\Environment' }
  $val = @($dump | ForEach-Object { $_.values } | Where-Object { $_.name -eq 'UserInitMprLogonScript' }) | Select-Object -First 1
  if (-not $val -or -not $val.text) { throw 'the Environment dump hides the logon script command' }
  $true
}
Check 'V-FIX: SAM and SECURITY logs and RegBack copies only with explicit confirmation' {
  $secret = @($man.artifacts | Where-Object { $_.destination -match '(?i)/config/(RegBack/)?(SAM|SECURITY)(\.|\{|$)' -and $_.id -notlike 'hive-secret-logs*' -and $_.id -notin 'hive-sam', 'hive-security' })
  if ($secret.Count -gt 0) { throw "secret hive files outside the sensitive sources: $(($secret | ForEach-Object id) -join ', ')" }
  if ($Profile -ne 'full' -and @($man.artifacts | Where-Object { $_.id -like 'hive-secret-logs*' -and $_.destination }).Count -gt 0) { throw 'hive-secret-logs collected without confirmation' }
  $true
}
Check 'V-FIX: interfaces report DHCP state, snapshots carry their data version, $MFT carries source times' {
  $ad = (Text 'network\network-interfaces.json' | ConvertFrom-Json).data.adapters
  if (@($ad | Where-Object { $_.dhcpv4_enabled -notin 'true', 'false' }).Count -gt 0) { throw 'an adapter has no DHCP state' }
  $doc = Text 'processes\processes-detailed.json' | ConvertFrom-Json
  $art = Art 'processes-detailed' | Select-Object -First 1
  if ($doc.data_version -ne 2 -or $art.data_version -ne 2) { throw "data_version envelope=$($doc.data_version) manifest=$($art.data_version)" }
  $mft = @(Art 'ntfs-mft-*' | Where-Object { $_.status -like 'collected*' })
  if ($mft.Count -gt 0 -and @($mft | Where-Object { -not $_.notes.source_created_utc }).Count -gt 0) { throw '$MFT copied without its source times' }
  $true
}
Check 'V-FIX: administrative templates (PolicyDefinitions) collected for the policy viewer' {
  @(Art 'gpo-policy-definitions*' | Where-Object { $_.status -like 'collected*' -and $_.destination -match '(?i)\.adm[xl]$' }).Count -ge 50
}
Check 'V-CSV: derived CSV views match their JSON and are covered by the checksums' {
  if ($Profile -ne 'standard') { return $true }  # the CI asks for --csv on the standard run only
  $derived = @($man.derived)
  if ($derived.Count -lt 5) { throw "only $($derived.Count) CSV views" }
  $sums = Get-Content (Join-Path $Package 'checksums.sha256')
  foreach ($d in $derived) {
    $f = Join-Path $Package ($d.path -replace '/', '\')
    if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -ne $d.sha256) { throw "$($d.path) hash differs from the manifest" }
    if (-not ($sums | Where-Object { $_ -like "*$($d.path)" })) { throw "$($d.path) is not in checksums.sha256" }
  }
  $procs = (Text 'processes\processes-detailed.json' | ConvertFrom-Json).data.processes
  $csv = Import-Csv (Join-Path $Package 'csv\processes.csv')
  if ($csv.Count -ne $procs.Count) { throw "processes.csv has $($csv.Count) rows, the JSON $($procs.Count)" }
  if (@($csv | Where-Object { $_.source_artifact_id -ne 'processes-detailed' -or -not $_.source_pointer }).Count -gt 0) { throw 'rows without provenance' }
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
