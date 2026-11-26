# OpenGuard Kids - cai dat Agent tren may tre (Windows 10/11 x64).
# Chay PowerShell voi quyen Administrator tren MAY CUA TRE.
# Viec script nay lam (cong khai, dung muc F5 cua de):
#   1. Tao thu muc C:\ProgramData\OpenGuardKids va dat ACL chi SYSTEM +
#      Administrators (chua config.json co bi mat thiet bi va CSDL). Rieng
#      thu muc con tray\ (chi chua tray.json: cong IPC + token IPC + ten tre)
#      cap Users quyen doc de Tray chay bang tai khoan tre ket noi duoc IPC.
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

param([string]$ChildUser = "")

$ErrorActionPreference = "Stop"
$dir = "$env:ProgramData\OpenGuardKids"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# --- 1. ACL (dung SID de khong phu thuoc ngon ngu Windows):
# Thu muc du lieu: chi SYSTEM (*S-1-5-18) + Administrators (*S-1-5-32-544).
# /remove:g go han ACE cua Users (*S-1-5-32-545) ma cac ban cai truoc da cap.
icacls $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /remove:g "*S-1-5-32-545" | Out-Null
# Thu muc con tray\: Users duoc doc (tray.json khong chua bi mat thiet bi).
$trayDir = Join-Path $dir "tray"
New-Item -ItemType Directory -Force -Path $trayDir | Out-Null
icacls $trayDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)R" | Out-Null
Write-Host "ACL da ap: $dir chi SYSTEM/Administrators; $trayDir Users duoc doc."

# --- 1b. Tai khoan Windows cua tre (cho watchdog WTS - F5.8):
# Service chi coi la "co phien" khi DUNG tai khoan nay dang dang nhap
# (trang thai WTS), nen: luc cai bang tai khoan admin agent khong tu
# dung oan; tre tat explorer.exe cung khong lach duoc watchdog.
# Cach dung: install_agent.ps1 -ChildUser <ten tai khoan cua tre>
if ($ChildUser -ne "") {
    $lu = Get-LocalUser -Name $ChildUser -ErrorAction SilentlyContinue
    if ($null -eq $lu) { throw "Khong thay tai khoan Windows '$ChildUser' tren may nay." }
    $adminGroup = Get-LocalGroup -SID "S-1-5-32-544"
    $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue
    if ($members | Where-Object { $_.Name -like "*\$ChildUser" }) {
        Write-Warning "Tai khoan '$ChildUser' la Administrator - nen dung tai khoan Standard cho tre."
    }
    $cfgPath = Join-Path $dir "config.json"
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $cfg | Add-Member -NotePropertyName child_windows_user -NotePropertyValue $ChildUser -Force
        $jsonOut = $cfg | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($cfgPath, $jsonOut, (New-Object System.Text.UTF8Encoding $false))
        Write-Host "Da ghi child_windows_user = $ChildUser vao config.json."
    } else {
        throw "Chua co config.json (chua enroll) - hay chay enroll o Buoc 4 truoc, roi chay lai script nay voi -ChildUser."
    }
} else {
    throw "Thieu tham so -ChildUser. Hay chay lai: install_agent.ps1 -ChildUser <ten tai khoan Windows cua tre> (xem ten bang lenh Get-LocalUser, hoac chay whoami trong phien dang nhap cua tre; voi tai khoan Microsoft, ten tai khoan cuc bo khac ten hien thi). Thieu khoa nay, watchdog khong phan biet duoc phien cua tre voi phien admin va agent co the tu dung oan ngay sau khi cai."
}

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
