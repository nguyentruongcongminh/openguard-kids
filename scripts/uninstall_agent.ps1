# OpenGuard Kids - go Windows Service OpenGuardKidsAgent khoi may tre.
# Chay PowerShell voi quyen Administrator tren MAY CUA TRE.
# Chi go service; du lieu trong C:\ProgramData\OpenGuardKids (config + nhat
# ky su dung) DUOC GIU LAI - phu huynh tu xoa thu muc do neu muon go sach.
# FILE NAY CHI DUOC CHUA KY TU ASCII (ly do ghi trong install_agent.ps1).

$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$hostExe = Join-Path $root "tools\ogk-service-host.exe"
$svc = Get-Service -Name "OpenGuardKidsAgent" -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Khong co service OpenGuardKidsAgent tren may nay."
    exit 0
}
if ($svc.Status -eq "Running") { Stop-Service OpenGuardKidsAgent -Force }
if (Test-Path $hostExe) { & $hostExe uninstall | Out-Null }
$svc = Get-Service -Name "OpenGuardKidsAgent" -ErrorAction SilentlyContinue
if ($svc) {
    sc.exe delete OpenGuardKidsAgent | Out-Null
    Write-Host "Da go service OpenGuardKidsAgent (sc.exe delete)."
} else {
    Write-Host "Da go service OpenGuardKidsAgent."
}
Write-Host "Du lieu tai C:\ProgramData\OpenGuardKids van duoc giu lai."
