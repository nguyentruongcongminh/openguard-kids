# OpenGuard Kids (v2)

Ứng dụng hỗ trợ quản lý việc sử dụng máy tính của trẻ em — **công cụ đồng hành,
không phải phần mềm theo dõi lén**. Phụ huynh cấu hình từ xa (hạn mức giờ, lịch
tuần, luật ứng dụng/website); Agent trên máy trẻ thi hành minh bạch: trẻ luôn
thấy biểu tượng khay, biết mình còn bao nhiêu thời gian, vì sao bị chặn, và có
thể xin thêm giờ / báo chặn nhầm.

Đồ án môn học (HCMUS). Bản v2 được thiết kế lại theo file hướng dẫn đồ án và đã
triển khai thật trên máy phụ huynh + máy trẻ trong mạng LAN gia đình (xem báo
cáo kiểm thử trong `docs/`).

## Phương châm minh bạch (bắt buộc, bất biến)

- Không chụp màn hình, không ghi phím, không đọc nội dung tin nhắn/email/tài liệu.
- Không chế độ ẩn: biểu tượng khay luôn hiển thị khi agent chạy; **không hiển
  thị được biểu tượng thì agent tự dừng**.
- Mọi hành động chặn đều kèm lý do hiển thị cho trẻ; trẻ xem được cùng báo cáo
  với phụ huynh và nhật ký thay đổi luật.
- Danh sách miễn chặn vĩnh viễn: miền `.gov.vn` (gồm cổng Tổng đài quốc gia bảo
  vệ trẻ em 111) và cổng thông tin trường học do phụ huynh khai báo.
- Chỉ thu siêu dữ liệu: tên ứng dụng, tên miền cấp hai, thời lượng, dấu thời
  gian. Không gửi dữ liệu tới bên thứ ba.

## Kiến trúc

| Thành phần | Vai trò |
|---|---|
| `shared/contract.py` | Hợp đồng dữ liệu duy nhất hai phía: policy document (version + HMAC), lược đồ sự kiện, lịch 7×48, phân loại miền |
| `server/` (FastAPI + SQLite WAL) | Xác thực phụ huynh (Argon2id, cookie session + CSRF), mã ghép đôi 8 ký tự, phát hành policy có ký, báo cáo, audit, lưu trữ 90 ngày |
| `agent/` — Windows Service (SYSTEM) | Thi hành policy, đếm thời gian dùng máy, chặn ứng dụng (SHA-256), DNS Proxy 127.0.0.1 + `::1` cổng 53, bộ đệm ngoại tuyến |
| `agent/` — Tray UI (quyền user) | Đồng hồ còn lại, màn hình "Hôm nay em đã dùng gì", Xin thêm giờ, Báo chặn nhầm — nói chuyện với Service qua IPC loopback + token cục bộ; là cảm biến phiên (idle/khóa) cho Service |
| `dashboard/` | Web phụ huynh (dùng được trên trình duyệt điện thoại): hạn mức, ma trận lịch tuần 7×48, luật app/web, duyệt yêu cầu, báo cáo, audit |

Giao thức: heartbeat 60 giây (trạng thái + quota đã dùng + policy_version);
lệnh khẩn qua WebSocket (khóa ngay / mở khóa / cộng giờ) có ack; duyệt "báo
chặn nhầm" đẩy luật cho phép mới xuống máy trẻ **ngay lập tức**; policy chỉ
được agent áp dụng khi chữ ký HMAC đúng và version mới hơn; khi mất kết nối
dài ngày: **fail-closed 7 ngày đầu, sau đó fail-open có kiểm soát** (nới
quota/lịch, giữ nguyên chặn nhóm không phù hợp + miễn chặn, báo rõ cho trẻ).

## Tài liệu trong repo

| File | Nội dung |
|---|---|
| `docs/KIEN-TRUC-CHI-TIET-OGK-v2.md` | Kiến trúc chi tiết, mô hình dữ liệu, giao thức |
| `docs/BAO-CAO-THIET-KE.md` | Báo cáo thiết kế |
| `docs/BAO-CAO-KIEM-THU-OGK-v2.md` | Báo cáo kiểm thử 3 vòng + kết quả triển khai thật |
| `docs/HUONG-DAN-CAI-DAT-SERVER.md` | Cài server trên máy phụ huynh — chi tiết từng bước |
| `docs/HUONG-DAN-CAI-DAT-MAY-TRE.md` | Cài agent trên máy trẻ A–Z + bảng nghiệm thu + sự cố |
| `docs/KY-THUAT-MANG.md` | Kỹ thuật mạng: DNS hai họ IPv4/IPv6, firewall, session-0 |
| `PRIVACY.md` | Bảng dữ liệu ↔ mục đích ↔ thời hạn lưu ↔ người xem |

---

# Lộ trình cài đặt & chạy từ A tới Z

Thứ tự bắt buộc: **Giai đoạn 0 → 1 (server) → 2 (máy trẻ) → 3 (vận hành)**.
Không trỏ DNS về agent trước khi service chạy thường trực (xem Giai đoạn 2,
Bước 8).

## Giai đoạn 0 — Chuẩn bị chung

Yêu cầu:

| Hạng mục | Yêu cầu |
|---|---|
| Máy phụ huynh (server) | Windows 10/11 64-bit |
| Máy trẻ (agent) | Windows 10/11 64-bit; tài khoản trẻ là **Standard User** |
| Python | 3.11+ (đã kiểm chứng với 3.13 trên Windows) — khi cài tick **Add python.exe to PATH** |
| Mạng | Server và máy trẻ cùng LAN/Wi-Fi; router **không** bật AP/Client Isolation |
| Quyền | Administrator trên cả hai máy khi cài đặt |

Lấy mã nguồn về (clone repo này hoặc tải ZIP rồi giải nén) vào một thư mục cố
định — từ đây gọi là **thư mục gốc dự án**. Mọi lệnh chạy trong PowerShell tại
thư mục gốc dự án. Tạo môi trường ảo và cài thư viện:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\pip install -r server\requirements.txt -r agent\requirements.txt
# Chỉ khi cần chạy kiểm thử:
.\.venv\Scripts\pip install pytest httpx
```

### Giai đoạn 0.5 — Lấy WinSW (chỉ cần cho máy trẻ, khi cài Windows Service)

Repo này **không chứa file .exe**. Script cài service dùng WinSW để bọc agent
thành Windows Service; lấy đúng bản đã kiểm chứng:

1. Tải `WinSW.NET461.exe` từ trang phát hành chính thức của dự án WinSW,
   bản **v2.12.0** (github.com/winsw/winsw/releases).
2. Kiểm tra SHA-256 của file vừa tải phải đúng:
   `b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f`
   (kiểm tra bằng `Get-FileHash <file> -Algorithm SHA256`).
3. Đổi tên thành `ogk-service-host.exe` và đặt vào thư mục `tools\` của dự án.
   WinSW bản này cần .NET Framework 4.6.1+ — có sẵn trên Windows 10/11.

## Giai đoạn 1 — Server trên máy phụ huynh

Chi tiết đầy đủ: `docs/HUONG-DAN-CAI-DAT-SERVER.md`. Tóm tắt các bước:

**1.1 Khóa chủ (MASTER KEY) — tạo MỘT lần, giữ cố định mãi mãi.** Khóa chủ mã
hóa khóa chính sách của từng thiết bị đã ghép đôi; đổi khóa chủ sau khi đã
ghép đôi thì các máy trẻ phải ghép đôi lại.

```powershell
.\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Lưu khóa vào trình quản lý mật khẩu. **Không bao giờ đưa khóa chủ vào repo**
(file launcher `chay-server.ps1` chứa khóa chủ cũng đã bị `.gitignore` chặn).

**1.2 Chứng chỉ TLS cho địa chỉ LAN** — liệt kê mọi địa chỉ agent sẽ gọi:
`127.0.0.1` và IP LAN của máy phụ huynh (xem bằng `ipconfig`):

```powershell
.\.venv\Scripts\python scripts\make_cert.py --host 127.0.0.1 --host <IP-LAN>
```

Ghi lại dòng **SHA-256 fingerprint** in ra — bước ghép đôi ở máy trẻ cần nó.
Nên đặt IP tĩnh / DHCP reservation cho máy phụ huynh; IP đổi thì phải tạo lại
chứng chỉ và ghép đôi lại.

**1.3 Firewall + profile mạng Private:**

```powershell
Get-NetConnectionProfile   # nếu là Public thì chuyển:
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
New-NetFirewallRule -DisplayName "OpenGuard Kids Server" -Direction Inbound `
  -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
```

⚠️ Bẫy đã gặp thật: rule **BLOCK** theo chương trình `python.exe` (Windows tự
tạo khi ai đó bấm Cancel ở hộp thoại firewall) **thắng** rule ALLOW theo cổng.
Kiểm tra và xóa nếu có:

```powershell
Get-NetFirewallRule -Direction Inbound -Action Block |
  Where-Object { $_.DisplayName -eq 'python.exe' } | Remove-NetFirewallRule
```

**1.4 Chạy server:**

```powershell
$env:OGK_MASTER_KEY = "<khóa chủ ở bước 1.1>"
$env:OGK_TLS_CERT   = "<thư mục gốc dự án>\certs\server-cert.pem"
.\.venv\Scripts\python scripts\run_server.py
```

Server chạy tại `https://0.0.0.0:8000`; mở dashboard tại
`https://127.0.0.1:8000` (bỏ qua cảnh báo chứng chỉ tự ký — chứng chỉ nội bộ
gia đình). Tài khoản demo tự tạo khi chạy lần đầu — **chỉ để thử, đổi/xóa
trước khi dùng thật**: `demo@ogk.local` / `Demo12345!`.

**1.5 Việc cần làm ngay trên dashboard:** tạo hồ sơ trẻ thật (ngày sinh quyết
định luật web mặc định theo lứa tuổi); đối chiếu mục "SHA-256 chứng chỉ
server" trong dashboard phải trùng fingerprint ở bước 1.2.

**1.6 Kiểm tra từ máy trẻ trước khi cài agent:**

```powershell
Test-NetConnection <IP-LAN-server> -Port 8000   # TcpTestSucceeded = True
```

**1.7 Sao lưu & dọn dữ liệu thử:** toàn bộ dữ liệu nằm ở `server\ogk.db` —
sao lưu là copy file này khi server đã dừng (kèm đúng khóa chủ). Dọn dữ liệu
thử bằng `scripts\cleanup_test_data.py` (server đã dừng, script hỏi xác nhận).

## Giai đoạn 2 — Agent trên máy trẻ

Chi tiết đầy đủ + bảng nghiệm thu 8 mục + bảng sự cố:
`docs/HUONG-DAN-CAI-DAT-MAY-TRE.md`. Tóm tắt các bước (PowerShell
Administrator tại thư mục dự án trên máy trẻ, ví dụ `C:\OpenGuardKids-v2`):

1. **Tài khoản trẻ phải là Standard User** — trẻ có quyền admin là gỡ được agent.
2. Cài thư viện: như Giai đoạn 0 (ít nhất `agent\requirements.txt`).
3. **Tạo mã ghép đôi** trên dashboard: chọn trẻ → Tạo mã ghép đôi (8 ký tự,
   sống 10 phút — làm bước 4 ngay).
4. **Ghép đôi:** `.\.venv\Scripts\python agent\enroll.py` rồi nhập: địa chỉ
   server `https://<IP-LAN>:8000`, SHA-256 fingerprint, mã ghép đôi, tên máy.
   Cấu hình ghi vào `C:\ProgramData\OpenGuardKids\config.json`.
5. **Chạy thử console:** `.\.venv\Scripts\python agent\service.py --console`
   và ở cửa sổ khác `.\.venv\Scripts\python agent\tray.py` — thấy biểu tượng
   khay + đúng tên trẻ/số phút là đạt; `Ctrl+C` để dừng.
6. **Cài Windows Service** (cần WinSW ở Giai đoạn 0.5):

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   .\scripts\install_agent.ps1 -ChildUser <tên tài khoản Windows của trẻ>
   Get-Service OpenGuardKidsAgent   # phải là Running
   ```

   Gỡ khi cần: `.\scripts\uninstall_agent.ps1`.
7. **Cho Tray tự chạy khi trẻ đăng nhập:** tạo shortcut trong thư mục Startup
   của **tài khoản trẻ** trỏ tới `.venv\Scripts\pythonw.exe` với tham số
   `agent\tray.py` (lệnh đầy đủ trong tài liệu chi tiết, Bước 7). Nhớ nguyên
   tắc minh bạch: Tray không hiện được biểu tượng thì agent tự dừng.
8. **Trỏ DNS về agent — LÀM CUỐI CÙNG**, chỉ sau khi service đã chạy thường
   trực (DNS trỏ về 127.0.0.1 khi agent chưa cố định = máy mất mạng mỗi lần
   agent tắt). Phải đặt **cả hai họ** — thiếu IPv6 là trình duyệt đi vòng qua
   DNS của router và lọc web bị vô hiệu:

   ```powershell
   Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1
   Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "::1"
   Clear-DnsClientCache
   # Khôi phục khi cần:
   Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ResetServerAddresses
   ```

   (Lệnh `Set-DnsClientServerAddress` **không** có tham số `-AddressFamily` —
   nó tự hiểu họ qua địa chỉ đưa vào.)
9. **Nghiệm thu** theo bảng 8 mục trong tài liệu chi tiết: đếm phút đúng, idle
   ≥ 5 phút dừng đếm, hết hạn mức → máy tự khóa thật, xin thêm giờ +15 đúng số,
   chặn ứng dụng, chặn `youtube.com` nhưng mở `youtubekids.com` với trẻ 6–11
   tuổi, báo cáo có tên miền, đổi luật trên dashboard → Tray cập nhật ~10 giây.

## Giai đoạn 3 — Vận hành hằng ngày

Trên dashboard (mở được từ điện thoại): đặt hạn mức ngày + ma trận lịch tuần
7×48 cho từng trẻ; thêm luật chặn/cho phép theo ứng dụng và tên miền; duyệt
yêu cầu **xin thêm giờ** và **báo chặn nhầm** từ trẻ (duyệt báo chặn nhầm thì
luật cho phép được đẩy xuống máy trẻ ngay); xem báo cáo thời gian dùng
app/web và nhật ký audit. Dữ liệu sự kiện lưu 90 ngày.

---

## Kiểm thử

```powershell
.\.venv\Scripts\python -m pytest tests\ -v          # Vòng 1: unit + contract + API (32 test)
.\.venv\Scripts\python scripts\e2e_round2.py        # Vòng 2: tích hợp server thật + agent thật
.\.venv\Scripts\python scripts\acceptance_round3.py # Vòng 3: nghiệm thu theo tiêu chí đề
```

Kết quả phải đọc kèm nền tảng: số test đạt trên Linux/macOS **không** thay thế
kết quả trên Windows thật (cài service SCM, khóa phiên, biểu tượng khay chỉ
kiểm chứng được trên Windows). Kết quả 3 vòng + triển khai thật nằm trong
`docs/BAO-CAO-KIEM-THU-OGK-v2.md` — không mục nào được khai PASS khi chưa chạy.

## Sự cố hay gặp (rút gọn — chi tiết trong 2 hướng dẫn cài đặt và `docs/KY-THUAT-MANG.md`)

| Triệu chứng | Nguyên nhân & xử lý |
|---|---|
| Máy trẻ không tới được server | Khác Wi-Fi / profile mạng Public / còn rule BLOCK `python.exe` / router bật AP Isolation |
| Vào web được nhưng không bị lọc | DNS IPv6 còn trỏ router (`fe80::1`) — đặt lại `::1`; hoặc trình duyệt bật Secure DNS (DoH) đi vòng qua DNS hệ thống |
| Dùng máy mà phút không tăng; hết giờ mà máy không khóa | Tray chưa chạy — đếm idle và khóa máy do **Tray** thực thi trong phiên của trẻ (service ở session-0 không thấy thao tác người dùng) |
| File `.ps1` lỗi cú pháp lạ | PowerShell 5.1 đọc file không BOM theo ANSI — các script đóng gói sẵn thuần ASCII; đừng chèn ký tự tiếng Việt/dấu dài vào script |
| Đổi IP LAN của server | Tạo lại chứng chỉ với IP mới + ghép đôi lại máy trẻ; nên đặt IP tĩnh/DHCP reservation ngay từ đầu |
| Báo cáo lẫn tiến trình hệ thống | Đã lọc theo tài khoản SYSTEM + danh sách tên ở cả lúc ghi và lúc đọc; dữ liệu cũ trong ngày vẫn còn, sang ngày mới sẽ sạch |

## Bảo mật & riêng tư

- Repo này **không chứa**: khóa chủ, chứng chỉ/khóa riêng TLS (`certs/`),
  database (`*.db`), cấu hình thiết bị thật (`config.json`), file launcher
  chứa khóa chủ (`chay-server.ps1`) — `.gitignore` đã chặn sẵn các mục này.
- Khóa chủ chỉ truyền qua biến môi trường `OGK_MASTER_KEY`; chứng chỉ tự ký +
  ghim SHA-256 fingerprint khi ghép đôi để chống server giả mạo trong LAN.
- Mật khẩu phụ huynh băm Argon2id; policy ký HMAC; token thiết bị 15 phút +
  refresh/thu hồi. Tài khoản demo phải đổi/xóa trước khi dùng thật.
- Xem `PRIVACY.md` cho bảng dữ liệu đầy đủ.

## Cấu trúc thư mục

```
shared/      contract.py — hợp đồng dữ liệu dùng chung server ↔ agent
server/      FastAPI app (app/), dữ liệu phân loại miền (data/), requirements.txt
agent/       service, tray, enroll, dns_proxy, ipc, local_store...
dashboard/   trang quản trị phụ huynh (HTML tĩnh, server phục vụ)
scripts/     run_server.py, make_cert.py, install/uninstall_agent.ps1,
             e2e_round2.py, acceptance_round3.py, cleanup_test_data.py
tests/       pytest vòng 1 (unit + contract + API)
tools/       nơi đặt ogk-service-host.exe (WinSW) — xem Giai đoạn 0.5
docs/        tài liệu kỹ thuật & hướng dẫn chi tiết
```

## Phạm vi sử dụng hợp pháp

Phần mềm chỉ dành cho phụ huynh/người giám hộ hợp pháp quản lý thiết bị của
trẻ vị thành niên thuộc quyền giám hộ của mình, hoặc thiết bị do gia đình sở
hữu, với sự biết rõ của trẻ (biểu tượng khay + thông báo luôn bật). Không sử
dụng để giám sát người trưởng thành hoặc thiết bị của người khác.
