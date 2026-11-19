# Hướng dẫn cài đặt MÁY TRẺ (Agent) — OpenGuard Kids v2, từ A tới Z

Agent chạy trên **máy tính của trẻ**: đếm thời gian sử dụng, áp dụng luật của
phụ huynh, lọc web bằng DNS và hiển thị biểu tượng đồng hành công khai ở khay
hệ thống. Làm đúng thứ tự dưới đây — mỗi bước đều có cách kiểm tra.

**Điều kiện tiên quyết:** server đã chạy xong theo
`HUONG-DAN-CAI-DAT-SERVER.md`; máy trẻ cùng mạng LAN với server;
`Test-NetConnection <IP-server> -Port 8000` cho kết quả `True`.

---

## Bước 0 — Chuẩn bị tài khoản Windows

- Tài khoản trẻ dùng hằng ngày phải là **Standard User** (không thuộc nhóm
  Administrators) — nếu trẻ có quyền admin, trẻ gỡ được agent.
- Cài đặt thực hiện bằng một tài khoản Administrator trên máy trẻ.

## Bước 1 — Giải nén mã nguồn

Giải nén `OpenGuardKids-v2.zip`, đặt thư mục dự án tại
`C:\OpenGuardKids-v2` (bên trong có `agent\`, `scripts\`, `shared\`...).
Các bước sau chạy PowerShell **Administrator** tại `C:\OpenGuardKids-v2`.

## Bước 2 — Cài thư viện cho agent

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\pip install -r agent\requirements.txt
```

## Bước 3 — Tạo mã ghép đôi trên dashboard

Trên máy phụ huynh, vào dashboard → chọn đúng hồ sơ trẻ → **Tạo mã ghép đôi**.
Mã gồm 8 ký tự, **chỉ sống 10 phút** — tạo xong sang bước 4 ngay.

## Bước 4 — Ghép đôi (enroll)

```powershell
.\.venv\Scripts\python agent\enroll.py
```

Nhập theo hướng dẫn trên màn hình:
- Server: `https://<IP-LAN-của-server>:8000` (ví dụ `https://192.168.1.36:8000`)
- SHA-256 fingerprint của chứng chỉ server (lấy ở bước tạo cert phía server
  hoặc xem trong dashboard, mục "Trẻ & thiết bị")
- Mã ghép đôi 8 ký tự
- Tên máy (ví dụ: "May phong be")

Thành công khi màn hình báo ghép đôi xong và có `device_id`. Cấu hình được
ghi vào `C:\ProgramData\OpenGuardKids\config.json`.

## Bước 5 — Chạy thử ở chế độ console (kiểm tra nhanh)

```powershell
.\.venv\Scripts\python agent\service.py --console
```

Mở thêm cửa sổ thứ hai chạy Tray:

```powershell
.\.venv\Scripts\python agent\tray.py
```

Kiểm tra: biểu tượng OpenGuard Kids hiện ở khay hệ thống; cửa sổ "Thời gian
còn lại" hiện đúng tên trẻ và số phút. Đạt thì `Ctrl+C` dừng console, sang
bước 6. (Chế độ console chỉ để kiểm tra — vận hành thật dùng Windows Service
ở bước 6.)

## Bước 6 — Cài Windows Service (chạy thường trực)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\install_agent.ps1
Get-Service OpenGuardKidsAgent
```

Script cài đặt làm các việc sau (công khai, đúng tinh thần "đồng hành minh
bạch"): tạo `C:\ProgramData\OpenGuardKids` với ACL chỉ SYSTEM +
Administrators được ghi (tài khoản trẻ chỉ đọc để Tray kết nối); cài service
**OpenGuardKidsAgent** bằng WinSW (`tools\ogk-service-host.exe`) chạy agent
bằng Python của `.venv`, tài khoản LocalSystem, tự khởi động cùng Windows,
tự chạy lại khi lỗi (5/15/60 giây); nhật ký nằm tại
`C:\ProgramData\OpenGuardKids\*.log`.

Đạt khi lệnh cuối báo **Running**.

> Gỡ service khi cần: `.\scripts\uninstall_agent.ps1` (quyền Administrator).
> Dữ liệu trong ProgramData được giữ lại.

## Bước 7 — Cho Tray tự chạy khi trẻ đăng nhập

Chạy PowerShell **thường** (không cần admin) trong **đúng tài khoản của trẻ**:

```powershell
$startup = [Environment]::GetFolderPath('Startup')
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$startup\OpenGuard Kids Tray.lnk")
$sc.TargetPath = "C:\OpenGuardKids-v2\.venv\Scripts\pythonw.exe"
$sc.Arguments = "C:\OpenGuardKids-v2\agent\tray.py"
$sc.WorkingDirectory = "C:\OpenGuardKids-v2"
$sc.Save()
```

Mở Tray ngay để kiểm tra (không cần chờ đăng nhập lại):

```powershell
Start-Process "C:\OpenGuardKids-v2\.venv\Scripts\pythonw.exe" -ArgumentList "C:\OpenGuardKids-v2\agent\tray.py" -WorkingDirectory "C:\OpenGuardKids-v2"
```

⚠️ **Nguyên tắc minh bạch (bất biến của dự án):** biểu tượng Tray phải LUÔN
hiển thị. Nếu Tray không tạo được biểu tượng, nó báo service và agent **tự
dừng** — không có chế độ chạy ẩn.

## Bước 8 — Trỏ DNS về agent để bật lọc web (làm CUỐI CÙNG)

Chỉ làm bước này **sau khi service đã chạy thường trực** — nếu agent chưa cố
định mà DNS đã trỏ về 127.0.0.1, máy sẽ mất mạng mỗi khi agent tắt.

Ghi lại DNS hiện tại trước khi đổi:

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4
```

Đổi cả hai họ địa chỉ (thiếu IPv6 là trình duyệt đi vòng qua router — xem
mục sự cố):

```powershell
Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "::1"
Clear-DnsClientCache
```

(Lệnh Set **không** có tham số `-AddressFamily` — nó tự hiểu họ qua địa chỉ
đưa vào. Card mạng có thể tên khác "Wi-Fi" — xem bằng `Get-NetAdapter`.)

Khôi phục khi cần (mất mạng, gỡ agent):

```powershell
Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ResetServerAddresses
```

## Bước 9 — Kiểm tra nghiệm thu trên máy trẻ

| # | Kiểm tra | Kỳ vọng |
|---|---|---|
| 1 | Dùng máy liên tục 3 phút, mở lại Tray | Số phút đã dùng tăng đúng ~3 |
| 2 | Để máy yên 12 phút không đụng chuột/phím | Chỉ tăng ~5 phút đầu rồi đứng (luật idle ≥ 5 phút) |
| 3 | Dashboard đặt hạn mức hôm nay = số đã dùng | Máy **tự khóa thật** trong ~1 phút, Tray báo đã hết giờ |
| 4 | Tray: "Xin thêm giờ" +15 → phụ huynh duyệt trên dashboard | Hạn mức tăng đúng +15 trên Tray |
| 5 | Đặt luật chặn một ứng dụng (ví dụ notepad.exe) trên dashboard | Mở ứng dụng đó → bị đóng + Tray báo "Ứng dụng bị chặn" |
| 6 | Mở tab mới vào `youtube.com` | Không tải được (đã bị chặn ở tầng DNS với trẻ 6–11 tuổi); `youtubekids.com` vào bình thường |
| 7 | Vào một trang được phép (ví dụ vnexpress.net), mở "Hôm nay em đã dùng gì" | Tên miền hiện trong mục trang web; số lần trang bị chặn tăng sau nhịp 6 |
| 8 | Dashboard đổi hạn mức bất kỳ, bấm Lưu | Tray cập nhật trong ~10 giây (đẩy tức thời qua WebSocket) — nhớ **đóng rồi mở lại** cửa sổ Tray vì cửa sổ đang mở không tự làm mới |

## Bước 10 — Sự cố thường gặp (đều đã gặp thật khi triển khai)

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `Test-NetConnection` tới server = False | Khác Wi-Fi / mạng đang ở profile **Public** (chuyển Private) / còn rule BLOCK `python.exe` trong firewall phía server / router bật AP Isolation |
| File `.ps1` báo "not digitally signed" | Chạy `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` trong cửa sổ đó rồi chạy lại |
| File `.ps1` báo lỗi cú pháp lạ (thiếu dấu ngoặc, chuỗi đứt) | File bị chèn ký tự ngoài ASCII (dấu tiếng Việt, dấu gạch dài) — PowerShell 5.1 đọc file không BOM theo ANSI nên vỡ cú pháp. Các script đóng gói sẵn đã thuần ASCII; đừng sửa thêm dấu vào |
| Service cài xong nhưng không khởi động được ở bản pywin32 cũ | Đã thay bằng WinSW — bản hiện tại không còn lỗi này; kiểm tra log tại `C:\ProgramData\OpenGuardKids\ogk-service-host.*.log` |
| Dùng máy mà số phút không tăng | Kiểm tra Tray có đang chạy không (agent nhận idle/khóa từ Tray trong phiên của trẻ — xem tài liệu kỹ thuật mạng, mục session-0) |
| Hết giờ, có thông báo nhưng máy không khóa | Tray chưa chạy hoặc đang chạy bản cũ — khóa máy do **Tray** thực thi trong phiên; khởi động lại Tray theo bước 7 |
| Vào web được nhưng báo cáo không có tên miền | Kiểm tra DNS **IPv6** của Wi-Fi: nếu còn `fe80::1` (DNS của router) thì đặt lại thành `::1` theo bước 8. Trình duyệt bật "Secure DNS" (DoH) cũng vòng qua DNS hệ thống — tắt mục đó khi kiểm tra |
| Báo cáo "ứng dụng đã dùng" lẫn tiến trình lạ (WUDFHost, ekrn...) | Đó là dịch vụ nền chạy từ lúc mở máy; agent đã lọc theo tài khoản SYSTEM + danh sách tên — dữ liệu ghi từ các bản cũ trong cùng ngày vẫn còn, sang ngày mới sẽ sạch |

## Bước 11 — Gỡ cài đặt hoàn toàn

1. Khôi phục DNS (lệnh ở bước 8).
2. `.\scripts\uninstall_agent.ps1` (PowerShell Administrator).
3. Xóa shortcut trong thư mục Startup của tài khoản trẻ.
4. (Tùy chọn) Xóa `C:\ProgramData\OpenGuardKids` và thư mục dự án.
5. Trên dashboard, thu hồi thiết bị (revoke) để server ngừng nhận dữ liệu.
