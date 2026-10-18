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
net user "${marker}User" 'Fixture-Pa55w0rd!' /add 2>$null | Out-Null

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
