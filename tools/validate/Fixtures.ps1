<#
  Mantis VM validation fixtures. Run ONLY inside a disposable test machine (VM or CI runner), elevated.
  Creates small, benign, clearly named artifacts so the collectors can be checked at evidence level.
  Undo everything with:  .\Fixtures.ps1 -Remove
  -Background keeps the TCP listener in a hidden helper process (unattended runs, e.g. CI).
#>
param([switch]$Remove, [switch]$Background)
$ErrorActionPreference = 'Continue'
$marker = 'MantisFixture'
$dl = Join-Path $env:USERPROFILE 'Downloads'
$doc = Join-Path $env:USERPROFILE 'Documents'

if ($Remove) {
  Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $marker -ErrorAction SilentlyContinue
  Remove-Item "HKCU:\Software\$marker" -Recurse -ErrorAction SilentlyContinue
  schtasks /Delete /TN $marker /F 2>$null | Out-Null
  Remove-Item (Join-Path $dl "$marker.txt") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $dl "$marker-deleted.txt") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $doc 'Default.rdp') -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) "$marker.cmd") -Force -ErrorAction SilentlyContinue
  Get-Process ping -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*$marker*" } | Stop-Process -Force -ErrorAction SilentlyContinue
  net user "${marker}User" /delete 2>$null | Out-Null
  Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' -Name "C:\$marker\tokenizer.exe" -ErrorAction SilentlyContinue
  Remove-ItemProperty 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -ErrorAction SilentlyContinue
  Remove-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -Name "${marker}32" -ErrorAction SilentlyContinue
  Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' -Name "$marker.cmd" -ErrorAction SilentlyContinue
  $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
  (Get-Content $hosts) | Where-Object { $_ -notmatch 'mantis-fixture\.test' } | Set-Content $hosts
  $pidFile = Join-Path $env:TEMP "$marker.listener.pid"
  if (Test-Path $pidFile) { Stop-Process -Id ([int](Get-Content $pidFile)) -Force -ErrorAction SilentlyContinue; Remove-Item $pidFile -Force }
  Write-Host 'fixtures removed'; $global:LASTEXITCODE = 0; return
}

# 1. registry persistence (HKCU Run) and a user key
New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $marker -Value 'C:\Windows\System32\notepad.exe /MantisFixture'
New-Item "HKCU:\Software\$marker" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\$marker" -Name 'Value' -Value 'fixture-registry-value'

# 2. scheduled task (never runs: one-time in the past would be rejected, so use a far-future start)
schtasks /Create /TN $marker /TR 'C:\Windows\System32\notepad.exe' /SC ONCE /ST 23:59 /SD 01/01/2099 /F | Out-Null

# 3. startup folder entry
Set-Content -Path (Join-Path ([Environment]::GetFolderPath('Startup')) "$marker.cmd") -Value "@echo $marker"

# 4. downloaded file with a Mark-of-the-Web stream
Set-Content -Path (Join-Path $dl "$marker.txt") -Value 'fixture file'
Set-Content -Path (Join-Path $dl "$marker.txt") -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://example.invalid/$marker"

# 5. file deleted into the Recycle Bin
Set-Content -Path (Join-Path $dl "$marker-deleted.txt") -Value 'to be recycled'
Add-Type -AssemblyName Microsoft.VisualBasic
[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile((Join-Path $dl "$marker-deleted.txt"), 'OnlyErrorDialogs', 'SendToRecycleBin')

# 6. PowerShell history line (PSReadLine)
$histDir = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine'
New-Item -ItemType Directory -Force -Path $histDir | Out-Null
Add-Content -Path (Join-Path $histDir 'ConsoleHost_history.txt') -Value "Write-Output '$marker history line'"

# 7. Application event
eventcreate /T INFORMATION /ID 999 /L APPLICATION /SO $marker /D "$marker event for evtx validation" | Out-Null

# 8. RDP client file and connection history key
Set-Content -Path (Join-Path $doc 'Default.rdp') -Value "full address:s:fixture.invalid`r`nusername:s:$marker"
New-Item "HKCU:\Software\Microsoft\Terminal Server Client\Servers\fixture.invalid" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Servers\fixture.invalid" -Name UsernameHint -Value $marker

# 9. a local account (removed with -Remove)
net user "${marker}User" 'Fx-Pa55w0rd!' /add 2>&1 | Write-Host
if (-not (Get-LocalUser -Name "${marker}User" -ErrorAction SilentlyContinue)) { Write-Host "WARNING: fixture account was not created" }
$null = Get-WinEvent -LogName Application -FilterXPath "*[System[EventID=999]]" -MaxEvents 1 -ErrorAction SilentlyContinue -OutVariable liveEvt
Write-Host ("Application event 999 present in the live log: {0}" -f [bool]$liveEvt)

# 9b. real browser profiles: start each installed browser headless once on a marker URL so a profile with
#     history exists (CI images ship Chrome, Edge and Firefox; machines without them are skipped)
$browserUrl = "https://example.com/$marker-browser"
$browsers = @(
  @{ Name = 'chrome'; Exe = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"; Args = @('--headless=new', '--disable-gpu', '--no-first-run', "--user-data-dir=$env:LOCALAPPDATA\Google\Chrome\User Data", '--no-sandbox', '--virtual-time-budget=8000', "--screenshot=$env:TEMP\$marker-shot.png", $browserUrl) },
  @{ Name = 'edge'; Exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"; Args = @('--headless=new', '--disable-gpu', '--no-first-run', "--user-data-dir=$env:LOCALAPPDATA\Microsoft\Edge\User Data", '--no-sandbox', '--virtual-time-budget=8000', "--screenshot=$env:TEMP\$marker-shot.png", $browserUrl) },
  @{ Name = 'firefox'; Exe = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"; Args = @('-headless', '-screenshot', (Join-Path $env:TEMP "$marker-firefox.png"), $browserUrl) }
)
foreach ($b in $browsers) {
  if (-not (Test-Path $b.Exe)) { Write-Host "browser fixture: $($b.Name) not installed, skipped"; continue }
  $proc = Start-Process -FilePath $b.Exe -ArgumentList $b.Args -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $env:TEMP "$marker-$($b.Name).out") -RedirectStandardError (Join-Path $env:TEMP "$marker-$($b.Name).err")
  if (-not $proc.WaitForExit(60000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; Write-Host "browser fixture: $($b.Name) timed out" } else { Write-Host "browser fixture: $($b.Name) exit $($proc.ExitCode)" }
}
foreach ($root in "$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:APPDATA\Mozilla\Firefox") {
  $names = if (Test-Path $root) { (Get-ChildItem $root -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object Name) -join ', ' } else { '(missing)' }
  Write-Host "browser profile root ${root}: $names"
}
Start-Sleep -Seconds 2

# 9c. cases that once lost evidence (each is checked in Verify.ps1)
#  - an execution value whose name (a path) contains "token": its data must not be redacted
$store = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
New-Item $store -Force | Out-Null
New-ItemProperty $store -Name "C:\$marker\tokenizer.exe" -PropertyType Binary -Value ([byte[]](0x53, 0x41, 0x43, 0x50, 1, 0, 0, 0)) -Force | Out-Null
#  - a logon script stored among the user's environment variables
Set-ItemProperty 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -Value "C:\Windows\System32\notepad.exe /${marker}LogonScript"
#  - a 32-bit Run entry (WOW6432Node view)
New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -Name "${marker}32" -Value "C:\Windows\SysWOW64\notepad.exe /${marker}32"
#  - the Startup folder entry switched off in Task Manager (StartupApproved first byte 03 = disabled)
$approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
New-Item $approved -Force | Out-Null
New-ItemProperty $approved -Name "$marker.cmd" -PropertyType Binary -Value ([byte[]](3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -Force | Out-Null
#  - a name in the DNS client cache with a known answer (hosts entries are loaded into the cache)
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Select-String -Path $hosts -Pattern 'mantis-fixture\.test' -Quiet)) { Add-Content -Path $hosts -Value "127.0.0.42 mantis-fixture.test" }
Clear-DnsClientCache -ErrorAction SilentlyContinue
$null = Resolve-DnsName mantis-fixture.test -ErrorAction SilentlyContinue

# 10. a running process with a recognizable command line and a TCP listener
Start-Process -FilePath ping.exe -ArgumentList '-t', '127.0.0.1', "-l", '32' -WindowStyle Hidden
if ($Background) {
  $holder = '$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,50555);$l.Start();Start-Sleep -Seconds 3600'
  $p = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-Command', $holder -PassThru
  Set-Content -Path (Join-Path $env:TEMP "$marker.listener.pid") -Value $p.Id
  Start-Sleep -Seconds 3
  Write-Host "Fixtures created. Hidden TCP listener on 127.0.0.1:50555 (pid $($p.Id))."
  $global:LASTEXITCODE = 0
  return
}
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 50555)
$listener.Start()
Write-Host "Fixtures created. A TCP listener is open on 127.0.0.1:50555 in THIS PowerShell session: keep this window open while collecting."
Write-Host 'Also do manually: open a page in Edge, Chrome and Firefox; run calc.exe once; attach a USB stick if the VM supports it.'
Read-Host 'Press Enter when the collection has finished to close the listener'
$listener.Stop()
