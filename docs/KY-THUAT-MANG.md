# Kỹ thuật mạng trong OpenGuard Kids v2

Tài liệu riêng về các kỹ thuật liên quan mạng máy tính mà phần mềm sử dụng:
kiến trúc truyền thông, bảo mật đường truyền, lọc web bằng DNS, và các bài
học thực tế rút ra khi triển khai trên mạng LAN gia đình thật.

---

## 1. Tổng quan các kênh truyền thông

| Kênh | Giao thức | Cổng / đích | Mục đích |
|---|---|---|---|
| Agent → Server (điều khiển) | HTTPS REST (TLS, chứng chỉ tự ký + ghim fingerprint) | TCP 8000 trên server | heartbeat, đồng bộ sự kiện, lấy chính sách, gửi yêu cầu |
| Server → Agent (đẩy lệnh) | WSS (WebSocket qua TLS) | TCP 8000, endpoint `/ws/device` | đẩy thay đổi chính sách và lệnh khẩn (khóa máy, cấp thêm giờ) trong < 5 giây |
| Tray ↔ Agent (trong máy trẻ) | TCP loopback 127.0.0.1, cổng ngẫu nhiên + token | cổng ghi trong `ipc.json` tại ProgramData | Tray lấy trạng thái/báo cáo, gửi yêu cầu; agent nhận xung phiên (idle/khóa) từ Tray |
| DNS nội bộ của agent | UDP 53 trên 127.0.0.1 **và** ::1 | loopback máy trẻ | lọc web theo tên miền, ghi nhận truy cập |
| DNS thượng nguồn (upstream) | UDP 53 tới 8.8.8.8 (cấu hình được) | Internet | phân giải thật cho các tên miền được phép |

Nguyên tắc thiết kế: **mọi giao tiếp đều do agent chủ động mở kết nối ra**
(kể cả WebSocket là kết nối agent mở tới server và giữ lâu dài) — máy trẻ
không cần mở cổng inbound nào, giảm bề mặt tấn công và tránh phải cấu hình
firewall phía máy trẻ.

## 2. Bảo mật đường truyền LAN

### 2.1. TLS với chứng chỉ tự ký và ghim fingerprint (certificate pinning)

Server dùng chứng chỉ tự ký chứa **cả hai SAN**: `127.0.0.1` và IP LAN của
máy phụ huynh. Vì không có CA công cộng cho mạng gia đình, agent không xác
thực theo chuỗi CA mà **ghim SHA-256 fingerprint**: lúc ghép đôi, phụ huynh
nhập fingerprint lấy từ dashboard; mọi kết nối HTTPS/WSS sau đó đều đối
chiếu fingerprint của chứng chỉ server trình ra — sai là hủy kết nối. Cách
này chống được server giả mạo trong cùng LAN (kẻ lạ dựng server nhái để
nhận dữ liệu trẻ hoặc phát chính sách giả).

### 2.2. Ghép đôi (pairing) và vòng đời token

1. Phụ huynh tạo **mã ghép đôi 8 ký tự, sống 10 phút, dùng 1 lần** trên
   dashboard.
2. Agent gọi `POST /pairing/redeem` kèm mã + fingerprint → server cấp
   **device token** và tạo **khóa chính sách riêng cho thiết bị** (được mã
   hóa bằng khóa chủ phía server, xem 2.4).
3. Access token của thiết bị sống **15 phút**; agent tự làm mới qua
   `POST /device/refresh`. Phụ huynh thu hồi thiết bị
   (`POST /devices/{id}/revoke`) thì token chết ngay — máy bị mất/bán đi
   không còn gửi hay nhận được gì.
4. Phiên đăng nhập dashboard của phụ huynh: cookie `HttpOnly + Secure +
   SameSite=Lax`, sống 12 giờ, kèm token CSRF.

### 2.3. Mật khẩu và chữ ký chính sách

- Mật khẩu phụ huynh băm bằng **Argon2id** (tối thiểu 10 ký tự; khóa đăng
  nhập 15 phút sau 5 lần sai).
- **Chính sách (policy) được ký HMAC** bằng khóa riêng của thiết bị và có số
  phiên bản tăng dần. Agent chỉ áp dụng chính sách có chữ ký đúng và phiên
  bản mới hơn bản đang chạy — chính sách giả hoặc cũ phát lại đều bị loại.

### 2.4. Mã hóa dữ liệu nhạy cảm phía server

Khóa chính sách của thiết bị và bí mật TOTP (khi bật xác thực 2 lớp) được
mã hóa **AES-GCM** bằng biến môi trường `OGK_MASTER_KEY`. Hệ quả vận hành:
khóa chủ phải **cố định từ lần ghép đôi đầu tiên** — đổi khóa là mọi thiết
bị phải ghép đôi lại.

## 3. Đồng bộ dữ liệu và chế độ offline

- **Heartbeat 60 giây**: agent báo còn sống, nhận số phiên bản chính sách
  hiện tại; lệch phiên bản là tải chính sách mới (đây là đường dự phòng khi
  WebSocket đứt).
- **WebSocket đẩy tức thời**: server giữ loop sự kiện và phát
  `policy_changed` ngay khi phụ huynh lưu thay đổi → agent áp dụng trong
  ~4 giây (đo thật). Lệnh khẩn (khóa máy từ xa, duyệt thêm giờ) đi cùng kênh
  này; agent xác nhận đã nhận bằng `POST /device/commands/{id}/ack`.
- **Hàng đợi sự kiện ngoại tuyến**: sự kiện sử dụng được ghi vào SQLite tại
  máy trẻ (`agent.db`, bảng `events`) và gửi dần khi có mạng; server khử
  trùng lặp theo `event_id` nên gửi lại không sinh dữ liệu đôi. Bản ghi đã
  phát hành/khóa thì bất biến.
- **Mất server không làm trẻ bị khóa oan vô hạn**: agent tiếp tục áp chính
  sách đã lưu tại máy; chính sách ngoại tuyến có hạn tin cậy 7 ngày theo cơ
  chế đã duyệt trong kiến trúc — sau 7 ngày không liên lạc được server thì
  **fail-open phần thời gian** (ngừng khóa theo quota/lịch/ngân sách nhóm,
  có ghi nhật ký và cảnh báo phụ huynh) để trẻ không bị khóa khỏi máy phục
  vụ học tập vô thời hạn; chặn web và chặn ứng dụng vẫn giữ nguyên.

## 4. Thời gian tin cậy (chống trẻ chỉnh đồng hồ)

Đếm giờ dựa trên **đồng hồ đơn điệu (monotonic)** cộng mốc giờ server gần
nhất; **ngày hiệu lực không bao giờ đi lùi**. Trẻ vặn đồng hồ hệ thống lùi
lại không làm hạn mức tăng trở lại; server phát hiện lệch giờ bất thường và
ghi cảnh báo `clock_tamper` trong nhật ký kiểm toán.

## 5. Lọc web bằng DNS tại máy trẻ

### 5.1. Cơ chế

Agent chạy một **DNS proxy** nghe trên `127.0.0.1:53` và `::1:53` (UDP).
Hệ điều hành của máy trẻ được trỏ DNS về hai địa chỉ loopback này, nên mọi
truy vấn phân giải đều qua agent:

1. Tra luật web theo tên miền (danh mục có sẵn 254 tên miền trong
   `domain_categories.csv` + luật riêng của phụ huynh; một số nhóm bị chặn
   theo lứa tuổi, ví dụ mạng xã hội chặn với trẻ 6–11).
2. **Bị chặn** → trả lời NXDOMAIN ("tên miền không tồn tại") + ghi sự kiện
   `blocked_domain` (gộp tối đa 1 lần/60 giây cho mỗi tên miền).
3. **Được phép** → chuyển tiếp truy vấn tới upstream (mặc định 8.8.8.8),
   trả kết quả nguyên vẹn + ghi sự kiện `domain_query` (gộp 5 phút).
4. **SafeSearch**: truy vấn A/AAAA của Google/Bing/DuckDuckGo được ánh xạ
   sang máy chủ ép chế độ an toàn (forcesafesearch/strict/safe) bằng bản
   ghi CNAME.

### 5.2. Quyền riêng tư theo thiết kế

Báo cáo chỉ lưu **tên miền cấp hai** (ví dụ `youtube.com`) — không lưu URL
đầy đủ, không lưu trang con, không lưu nội dung. Trẻ xem được đúng báo cáo
này trong Tray ("Bố mẹ và con đều nhìn thấy cùng báo cáo này") — minh bạch
hai chiều là yêu cầu bất biến của dự án. Truy vấn ngược (PTR,
`*.in-addr.arpa`, `*.ip6.arpa`) không được tính là "vào web".

### 5.3. Giới hạn đã biết

- **DNS-over-HTTPS (DoH)** trong trình duyệt có thể vòng qua DNS hệ thống.
  Từ vòng sửa 11/2026: các điểm cuối DoH đã biết (Google, Cloudflare,
  Quad9, AdGuard, NextDNS, 1.1.1.1 và miền canary của Firefox) bị **chặn
  theo mặc định** ở tầng luật web; phụ huynh vẫn cho phép đích danh được
  bằng luật allow. Giới hạn còn lại: DoH gọi thẳng địa chỉ IP
  (`https://1.1.1.1/dns-query`) không qua phân giải tên nên DNS proxy
  không chặn được — ghi nhận minh bạch, giảm thiểu thêm bằng cách tắt
  "Secure DNS" trong cài đặt trình duyệt của trẻ.
- Ứng dụng dùng địa chỉ IP cứng hoặc DNS riêng tự nhúng vẫn thoát khỏi bộ
  lọc DNS — đây là giới hạn chung của mọi giải pháp lọc tại DNS, được ghi
  nhận minh bạch thay vì che giấu.

## 6. Vấn đề session-0 và kênh IPC trong máy trẻ

Windows Service chạy ở **session 0**, tách biệt hoàn toàn với phiên đăng
nhập của trẻ. Hệ quả đo được trên máy thật:

- `GetLastInputInfo` ở session 0 không thấy thao tác của trẻ → idle tăng vô
  hạn → bộ đếm giờ đứng sau 300 giây.
- `LockWorkStation` gọi từ session 0 không khóa được phiên của trẻ (lệnh
  chạy "thành công" nhưng màn hình không khóa).

Giải pháp đã áp dụng: **Tray (chạy trong phiên của trẻ) làm cảm biến phiên
và tay thi hành khóa** — mỗi 3 giây Tray gửi xung `session_pulse` (idle
hiện tại, trạng thái khóa) qua IPC loopback cho service; service tin xung
còn tươi (≤ 90 giây), quá hạn thì lùi về đo cục bộ. Khi hết giờ, service
phát thông báo `locked`, Tray nhận và tự gọi `LockWorkStation` trong phiên
— khóa thật, đo được trên máy thật. Kênh IPC dùng cổng loopback ngẫu nhiên
công bố qua `ipc.json` trong thư mục ProgramData (ACL chỉ SYSTEM +
Administrators ghi, tài khoản trẻ đọc) kèm token riêng.

## 7. Bài học triển khai LAN thực tế (từ quá trình lắp đặt thật)

1. **Profile mạng Public chặn gần như mọi thứ**: Windows Firewall ở profile
   Public chặn kết nối inbound tới server dù đã mở cổng — phải chuyển Wi-Fi
   sang **Private** và gắn rule vào đúng profile Private.
2. **Rule BLOCK theo chương trình thắng rule ALLOW theo cổng**: hộp thoại
   firewall bị bấm hủy trước đó để lại 2 rule chặn `python.exe` khiến
   server "mở cổng mà không ai vào được". Chẩn đoán bằng
   `Test-NetConnection` (tầng TCP) tách bạch với kiểm tra tầng ứng dụng.
3. **Rò DNS qua IPv6**: router gia đình cấp DNS IPv6 (`fe80::1`) qua Router
   Advertisement. Chỉ trỏ DNS IPv4 về 127.0.0.1 là **chưa đủ** — Windows sẽ
   phân giải qua IPv6 của router, vòng qua toàn bộ bộ lọc. Phải nghe thêm
   trên `::1` và trỏ DNS IPv6 về `::1`. (Biểu hiện nhận biết: `nslookup`
   mặc định hiện `Server: fe80::1` và trả IP thật cho tên miền lẽ ra bị
   chặn.)
4. **AP/Client Isolation** trên một số router/Wi-Fi khách sẽ chặn thiết bị
   ngang hàng nhìn thấy nhau dù cùng SSID — luôn kiểm tra ping hai chiều
   trước khi nghi ngờ phần mềm.
5. Thứ tự an toàn khi cấu hình: **cài service cố định trước, trỏ DNS sau
   cùng** — trỏ DNS về một agent chưa chạy thường trực đồng nghĩa tự làm
   mất mạng của máy trẻ mỗi lần agent dừng.
