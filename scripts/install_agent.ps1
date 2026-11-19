# OpenGuard Kids - cai dat Agent tren may tre (Windows 10/11 x64).
# Chay PowerShell voi quyen Administrator tren MAY CUA TRE.
# Viec script nay lam (cong khai, dung muc F5 cua de):
#   1. Tao thu muc C:\ProgramData\OpenGuardKids va dat ACL chi SYSTEM +
#      Administrators duoc ghi (tai khoan cua tre chi doc de Tray ket noi IPC).
#   2. Cai Windows Service OpenGuardKidsAgent bang WinSW (tools\
#      ogk-service-host.exe): service chay agent o che do console bang
#      Python cua .venv, tu khoi dong cung Windows, tu chay lai khi loi.
#      Nhat ky cua service nam trong C:\ProgramData\OpenGuardKids
#      (ogk-service-host.*.log + service.log).
#   3. In huong dan tro DNS ve 127.0.0.1 de bat loc web (lam tay hoac GPO).
# Script KHONG an tien trinh/dich vu va KHONG cai co che chong go kieu ma doc:
# phu huynh go bang uninstall_agent.ps1 voi quyen Administrator.
# LICH SU: ban dau service dung pythonservice.exe cua pywin32. Tren may tre
# (17/11/2026) tien trinh chu pywin32 khong khoi tao duoc lop quan ly dich
# vu ("unable to locate the service manager") du da chay pywin32_postinstall
# - service dung ngay, ma thoat 0, khong de lai dau vet. Ban nay chuyen sang
# WinSW (ban WinSW.NET461 v2.12.0, SHA-256 ghi trong bao cao kiem thu) boc
# chinh agent console da chay on dinh; nghia vu service giu nguyen.
# LUU Y FILE NAY CHI DUOC CHUA KY TU ASCII: Windows PowerShell 5.1 doc file
# .ps1 khong co BOM theo bang ma ANSI, dau tieng Viet/dau gach dai (em dash)
# se bien thanh dau ngoac kep la va lam vo cu phap. Khong them dau vao file nay.

$ErrorActionPreference = "Stop"
$dir = "$env:ProgramData\OpenGuardKids"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# --- 1. ACL: SYSTEM + Administrators toan quyen ghi; Users chi doc/thuc thi
icacls $dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
Write-Host "ACL da ap cho $dir (SYSTEM/Administrators ghi, Users chi doc)."

# --- 2. Cai service bang WinSW
# Yeu cau: da chay enroll.py thanh cong truoc (co config.json trong
# ProgramData) va da cai requirements:  pip install -r agent\requirements.txt
$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
# Python chay agent: uu tien Python cua .venv (noi da cai du thu vien).
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPython) { $py = $venvPython } else { $py = "python" }
Write-Host "Dung Python: $py"
$hostExe = Join-Path $root "tools\ogk-service-host.exe"
if (-not (Test-Path $hostExe)) {
    Write-Host "THIEU FILE: $hostExe - khong cai duoc service."
    exit 1
}

# Go ban service cu (pywin32 hoac WinSW) neu dang ton tai cung ten
$svc = Get-Service -Name "OpenGuardKidsAgent" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") { Stop-Service OpenGuardKidsAgent -Force }
    & $hostExe uninstall 2>$null | Out-Null
    $svc = Get-Service -Name "OpenGuardKidsAgent" -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe delete OpenGuardKidsAgent | Out-Null
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            if (-not (Get-Service -Name "OpenGuardKidsAgent" -ErrorAction SilentlyContinue)) { break }
        }
    }
    Write-Host "Da go service cu."
}

# Sinh file cau hinh WinSW theo dung duong dan that cua may nay
$esc = { param($s) [System.Security.SecurityElement]::Escape($s) }
$xml = @'
<service>
  <id>OpenGuardKidsAgent</id>
  <name>OpenGuard Kids Agent</name>
  <description>OpenGuard Kids: ap dung gioi han thoi gian va quy tac su dung do phu huynh cau hinh tren may cua tre. Luon hien cong khai qua bieu tuong khay he thong; khong giam sat len.</description>
  <executable>__PYEXE__</executable>
  <arguments>"__ROOT__\agent\service.py" --console</arguments>
  <workingdirectory>__ROOT__</workingdirectory>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="5 sec" />
  <onfailure action="restart" delay="15 sec" />
  <onfailure action="restart" delay="60 sec" />
  <resetfailure>1 day</resetfailure>
  <logpath>__DATADIR__</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>2048</sizeThreshold>
    <keepFiles>4</keepFiles>
  </log>
</service>
'@
$xml = $xml.Replace("__PYEXE__", (& $esc $py)).Replace("__ROOT__", (& $esc $root)).Replace("__DATADIR__", (& $esc $dir))
$xmlPath = Join-Path $root "tools\ogk-service-host.xml"
Set-Content -Path $xmlPath -Value $xml -Encoding ASCII

& $hostExe install | Out-Null
Write-Host "Da cai service OpenGuardKidsAgent (WinSW)."
# Service Recovery Options bo sung o tang SCM: restart sau 5s / 15s / 60s
sc.exe failure OpenGuardKidsAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service OpenGuardKidsAgent
Start-Sleep -Seconds 2
$svc = Get-Service OpenGuardKidsAgent
Write-Host "Trang thai service: $($svc.Status)"

# --- 3. DNS: tro ve 127.0.0.1 de loc web (hien huong dan, khong tu sua)
Write-Host ""
Write-Host "DE BAT LOC WEB: tro DNS cua card mang ve 127.0.0.1"
Write-Host "  Settings > Network > adapter > DNS: Manual, Preferred DNS = 127.0.0.1"
Write-Host "  hoac PowerShell (admin):"
Write-Host '  Get-NetAdapter | Where Status -eq "Up" | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1'
Write-Host ""
Write-Host "Tray UI: them agent\tray.py vao Startup cua tai khoan tre de bieu tuong"
Write-Host "luon hien tren khay he thong khi dang nhap."
Write-Host "Luu y: tai khoan cua tre PHAI la Standard User (khong thuoc Administrators)."
