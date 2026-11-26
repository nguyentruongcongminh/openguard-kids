# Hướng dẫn cài đặt SERVER — OpenGuard Kids v2

Server là trung tâm điều khiển của phụ huynh: chạy trên **máy tính của phụ huynh**
(trong cùng mạng LAN với máy trẻ), phục vụ trang quản trị (dashboard) và nhận
dữ liệu từ agent trên máy trẻ. Tài liệu này đi từ máy trống đến server chạy thật.

---

## 1. Yêu cầu

| Hạng mục | Yêu cầu |
|---|---|
| Hệ điều hành | Windows 10/11 64-bit |
| Python | 3.11–3.13 (kiểm chứng với 3.13) — khi cài nhớ tick **Add python.exe to PATH** |
| Mạng | Cùng mạng LAN/Wi-Fi với máy trẻ; router **không** bật AP/Client Isolation |
| Quyền | Administrator (để mở firewall) |

## 2. Giải nén mã nguồn

Giải nén `OpenGuardKids-v2.zip` vào một thư mục cố định, ví dụ
`D:\OpenGuardKids-v2\openguard-kids`. Từ đây gọi là **thư mục gốc dự án**.
Mọi lệnh dưới đây chạy trong PowerShell tại thư mục gốc dự án.

## 3. Tạo môi trường ảo và cài thư viện

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\pip install -r server\requirements.txt
```

## 4. Tạo khóa chủ (MASTER KEY) — làm MỘT lần, giữ cố định mãi mãi

Khóa chủ mã hóa khóa chính sách của từng thiết bị đã ghép đôi. **Nếu đổi khóa
chủ sau khi đã có máy trẻ ghép đôi, các máy đó sẽ không giải mã được chính
sách — phải ghép đôi lại.** Tạo một khóa ngẫu nhiên dài và lưu vào nơi an toàn
(trình quản lý mật khẩu):

```powershell
.\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## 5. Tạo chứng chỉ TLS cho địa chỉ LAN

Liệt kê **mọi** địa chỉ mà agent sẽ dùng để gọi server: `127.0.0.1` và IP LAN
của máy phụ huynh (xem bằng `ipconfig`, ví dụ `192.168.1.36`):

```powershell
.\.venv\Scripts\python scripts\make_cert.py --host 127.0.0.1 --host 192.168.1.36
```

Kết quả: thư mục `certs\` có `server-cert.pem`, `server-key.pem` và dòng
**SHA-256 fingerprint** — ghi lại dấu vân tay này, bước ghép đôi ở máy trẻ cần
nó để xác thực server (chống server giả mạo).

> Nếu IP LAN của máy phụ huynh thay đổi (router cấp IP mới), chạy lại lệnh này
> với IP mới và ghép đôi lại máy trẻ bằng fingerprint mới. Nên đặt IP tĩnh /
> DHCP reservation cho máy phụ huynh trên router.

## 6. Mở firewall và đặt mạng ở chế độ Private

```powershell
# Xem profile mạng hiện tại — nếu là Public thì chuyển sang Private:
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private

# Mở cổng 8000 cho server (chỉ trên mạng Private):
New-NetFirewallRule -DisplayName "OpenGuard Kids Server" -Direction Inbound `
  -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
```

⚠️ **Bẫy đã gặp thật:** Windows từng tự tạo 2 rule **BLOCK** cho `python.exe`
(khi ai đó bấm "Cancel" ở hộp thoại hỏi quyền firewall). Rule BLOCK theo
chương trình **thắng** rule ALLOW theo cổng — server sẽ không truy cập được
dù đã mở cổng. Kiểm tra và xóa nếu có:

```powershell
Get-NetFirewallRule -Direction Inbound -Action Block |
  Where-Object { $_.DisplayName -eq 'python.exe' } |
  Remove-NetFirewallRule
```

## 7. Chạy server

Cách tiện nhất: dùng file `chay-server.ps1` (đặt cạnh thư mục dự án): điền
khóa chủ vào đúng một chỗ đã đánh dấu trong file, file sẽ tự đặt biến môi
trường và chạy server. **File này chứa khóa chủ — chỉ giữ trên máy phụ huynh.**

Chạy thủ công thì tương đương:

```powershell
$env:OGK_MASTER_KEY = "<khóa chủ ở bước 4>"
$env:OGK_TLS_CERT   = "D:\OpenGuardKids-v2\openguard-kids\certs\server-cert.pem"
.\.venv\Scripts\python scripts\run_server.py
```

Server chạy tại `https://0.0.0.0:8000`. Mở dashboard tại
`https://127.0.0.1:8000` (trình duyệt sẽ cảnh báo chứng chỉ tự ký — chọn
"Advanced → Proceed", đây là chứng chỉ nội bộ của gia đình).

> Nếu file `.ps1` bị Windows chặn ("not digitally signed"), chạy lệnh sau
> trong đúng cửa sổ PowerShell đó rồi chạy lại:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`

## 8. Tài khoản dùng thử và việc cần làm ngay

Server tự tạo tài khoản demo khi chạy lần đầu:

- Email: `demo@ogk.local` — Mật khẩu: `Demo12345!`

Đăng nhập được là server khỏe. Sau đó:

1. Tạo hồ sơ trẻ thật (tên, ngày sinh — ngày sinh quyết định luật web mặc
   định theo lứa tuổi).
2. Kiểm tra mục **"SHA-256 chứng chỉ server"** trong dashboard (phần
   "Trẻ & thiết bị") — phải trùng fingerprint ở bước 5. Nếu không hiện,
   nghĩa là biến `OGK_TLS_CERT` chưa được đặt khi chạy server.
3. Đổi mật khẩu / tạo tài khoản phụ huynh thật nếu dùng lâu dài.

Lưu ý bảo mật của launcher (`scripts/run_server.py`, từ vòng sửa 11/2026):
cookie phiên đăng nhập luôn có cờ **Secure** khi chạy qua launcher (biến
`OGK_SECURE_COOKIES` được đặt sẵn =1; chỉ đặt =0 khi gỡ lỗi HTTP cục bộ),
và server **chỉ nhận TLS 1.2 trở lên** (sàn TLS ép trên SSL context —
trình duyệt/agent quá cũ dùng TLS 1.0/1.1 sẽ bị từ chối bắt tay).

## 9. Kiểm tra từ máy khác trong LAN

Trên máy trẻ (trước khi cài agent):

```powershell
Test-NetConnection 192.168.1.36 -Port 8000   # TcpTestSucceeded phải là True
```

`False` → kiểm tra lần lượt: cùng Wi-Fi chưa → profile mạng đã Private chưa →
rule BLOCK python.exe (bước 6) → router có bật AP Isolation không.

## 10. Dọn dữ liệu thử nghiệm

Sau các vòng test, dashboard có thể còn trẻ/thiết bị thử. Dùng script dọn
(chạy khi **server đã dừng**, script in kế hoạch và hỏi xác nhận `y`):

```powershell
.\.venv\Scripts\python scripts\cleanup_test_data.py --device 1 --demo-child
```

(`--device N` lặp lại cho từng thiết bị thử cần xóa.)

## 11. Sao lưu

Toàn bộ dữ liệu nằm trong `server\ogk.db` (SQLite). Sao lưu = copy file này
khi server đã dừng. Khôi phục = chép lại vào đúng chỗ, kèm đúng **khóa chủ**
đã dùng khi tạo dữ liệu.

## 12. Dừng / gỡ server

Dừng: `Ctrl+C` trong cửa sổ đang chạy server. Gỡ: xóa thư mục dự án và rule
firewall "OpenGuard Kids Server". Dữ liệu trẻ trên các máy con không bị ảnh
hưởng (agent vẫn áp chính sách đã lưu tại máy khi mất kết nối — xem tài liệu
kỹ thuật mạng về cơ chế offline).
