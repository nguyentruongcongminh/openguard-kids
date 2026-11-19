# Báo cáo thiết kế — OpenGuard Kids v2

Phần mềm quản lý việc sử dụng máy tính của trẻ dành cho phụ huynh: minh
bạch, đồng hành, không giám sát lén. Tài liệu này mô tả thiết kế **dữ
liệu**, **chức năng** và **giao diện** của bản v2 đang chạy thật. Kiến trúc
tổng thể và lịch sử kiểm thử nằm ở `KIEN-TRUC-CHI-TIET-OGK-v2.md` và
`BAO-CAO-KIEM-THU-OGK-v2.md`.

---

# Phần A — Thiết kế dữ liệu

## A.1. Dữ liệu phía server (SQLite `server/ogk.db`, SQLAlchemy)

| Bảng | Nội dung chính | Ghi chú thiết kế |
|---|---|---|
| `parents` | Tài khoản phụ huynh: email, mật khẩu băm Argon2id, bí mật TOTP (mã hóa AES-GCM) | Khóa đăng nhập 15 phút sau 5 lần sai |
| `web_sessions` | Phiên đăng nhập dashboard | Cookie HttpOnly + Secure + SameSite=Lax, 12 giờ, kèm CSRF |
| `children` | Hồ sơ trẻ: tên, ngày sinh | Ngày sinh → suy ra lứa tuổi → luật web mặc định |
| `pairing_codes` | Mã ghép đôi 8 ký tự | Sống 10 phút, dùng 1 lần, gắn với 1 trẻ |
| `devices` | Thiết bị đã ghép đôi: tên máy, token (băm), khóa chính sách (mã hóa AES-GCM), trạng thái thu hồi | Thu hồi = vô hiệu token ngay |
| `policies` | Chính sách theo thiết bị: hạn mức giờ, lịch tuần, luật ứng dụng, luật web, cài đặt | Có **số phiên bản** tăng dần + **chữ ký HMAC**; agent chỉ nhận bản mới hơn và đúng chữ ký |
| `usage_events` | Sự kiện sử dụng do agent gửi lên | Khử trùng lặp theo `event_id`; lưu trữ 90 ngày |
| `commands` | Lệnh từ xa (khóa máy, cấp thêm giờ...) | Có trạng thái chờ/xác nhận (ack) |
| `child_requests` | Yêu cầu của trẻ: xin thêm giờ, báo chặn nhầm | Trạng thái chờ/duyệt/từ chối |
| `audit_logs` | Nhật ký thay đổi luật của phụ huynh | Hiển thị lại cho trẻ trong Tray — minh bạch hai chiều |
| `domain_categories` | Danh mục tên miền theo nhóm | Nạp từ `domain_categories.csv` (254 dòng) |

## A.2. Lược đồ sự kiện (khóa cứng — `shared/contract.py`)

Đúng **9 loại sự kiện**, trường cố định
`{event_id, ts, type, subject, duration_sec, policy_id}`:

`app_start`, `app_stop`, `domain_query`, `blocked_app`, `blocked_domain`,
`quota_warning`, `locked`, `unlock_request`, `override_granted`.

`subject` chỉ là **tên ứng dụng** hoặc **tên miền cấp hai** — không URL đầy
đủ, không tiêu đề cửa sổ, không nội dung. Đây là ranh giới riêng tư của hệ
thống, được khóa ở tầng hợp đồng dùng chung (cả server lẫn agent đều kiểm
tra cùng một lược đồ, sự kiện sai lược đồ bị loại).

## A.3. Dữ liệu tại máy trẻ (SQLite `agent.db` trong ProgramData)

| Bảng | Nội dung |
|---|---|
| `policy_cache` | Chính sách mới nhất đã xác thực chữ ký — nền cho chế độ offline |
| `events` | Hàng đợi sự kiện chờ gửi (gửi dần theo heartbeat, khử trùng lặp phía server) |
| `kv_state` | Trạng thái đếm giờ theo ngày, ngân sách theo nhóm/ứng dụng, mốc thời gian tin cậy |

Cấu hình ghép đôi nằm ở `config.json` cùng thư mục: địa chỉ server,
fingerprint chứng chỉ, token thiết bị, token IPC. Thư mục
`C:\ProgramData\OpenGuardKids` được đặt ACL: SYSTEM + Administrators ghi,
Users chỉ đọc (đủ cho Tray kết nối IPC, không đủ để trẻ sửa cấu hình).

## A.4. Dữ liệu danh mục web

- `server/data/domain_categories.csv` — 254 tên miền đã phân nhóm (cờ bạc,
  hẹn hò, rượu bia = nhóm không phù hợp; mạng xã hội; giải trí; học tập...).
  Ví dụ quyết định theo thiết kế: `youtube.com` = mạng xã hội (bị chặn mặc
  định với trẻ 6–11), `youtubekids.com` = giải trí (được phép).
- `server/data/test_domains.csv` — 60 tên miền mẫu theo phụ lục đề bài, dùng
  cho kiểm thử phân loại.
- Nhóm **không bao giờ bị chặn** (miễn chặn tuyệt đối): cổng thông tin
  chính phủ `.gov.vn` (gồm đường dây nóng bảo vệ trẻ em 111) và các cổng
  trường học do phụ huynh khai báo.

---

# Phần B — Thiết kế chức năng

## B.1. Sơ đồ thành phần

```
[Dashboard phụ huynh] --HTTPS--> [Server FastAPI] <--WSS/HTTPS-- [Agent service]
                                        |                            |
                                   [SQLite ogk.db]        [TimeKeeper | Controller]
                                                            [DNS proxy :53 v4+v6]
                                        ^                            |
                                        |                       [IPC loopback]
                                   [Báo cáo]                         |
                                                                [Tray của trẻ]
```

Một **hợp đồng dùng chung duy nhất** (`shared/contract.py`) cho server và
agent: lược đồ sự kiện, danh sách tiến trình hệ thống, chuẩn hóa tên miền.
(Bản v1 từng có 8 lỗi đấu dây vì mỗi phía tự định nghĩa — v2 khóa bằng hợp
đồng chung và kiểm thử hợp đồng riêng.)

## B.2. Nhóm chức năng phía server (API)

- **Xác thực**: `POST /auth/register|login|logout`, `GET /auth/me` (trả kèm
  fingerprint chứng chỉ để dashboard hiển thị cho phụ huynh đối chiếu).
- **Trẻ & ghép đôi**: `POST/GET /children`, `DELETE /children/{id}/data`,
  `POST /pairing-codes`, `POST /pairing/redeem`, `POST /device/refresh`,
  `POST /devices/{id}/revoke`.
- **Kênh thiết bị**: `POST /device/heartbeat`, `GET /device/policy`,
  `POST /device/events`, `POST /device/alerts`,
  `POST /device/commands/{id}/ack`, `POST/GET /device/requests`,
  `WebSocket /ws/device`.
- **Chính sách**: `GET /policy/{device_id}`, `PUT /policy/{device_id}/time`,
  `POST/DELETE /policy/{device_id}/apps[/{rule_id}]`,
  `POST/DELETE /policy/{device_id}/web[/{rule_id}]`,
  `PUT /policy/{device_id}/web-settings`.
- **Lệnh & yêu cầu**: `POST /commands`, `GET /requests`,
  `POST /requests/{id}/decide`.
- **Báo cáo**: `GET /reports/{device_id}`, `GET /reports/{device_id}/week`,
  `GET /child/summary`, `GET /child/audit`, `GET /audit`, `GET /domains`,
  `GET /admin/overview`, `GET /health`.

Mọi thay đổi chính sách đều: tăng phiên bản → ký HMAC → **đẩy ngay qua
WebSocket** cho agent đang trực tuyến (đo thật ~4 giây); agent ngoại tuyến
sẽ nhận ở heartbeat kế tiếp.

## B.3. Nhóm chức năng phía agent (máy trẻ)

| Thành phần | Chức năng |
|---|---|
| `TimeKeeper` | Đếm thời gian dùng theo ngày (hạn mức ngày thường/cuối tuần, lịch tuần 7×48 ô 30 phút); trừ khi máy khóa hoặc idle ≥ 5 phút; cảnh báo còn 10/5/1 phút; ân hạn 60 giây trước khi khóa; thời gian tin cậy chống chỉnh đồng hồ |
| `AgentController` | Quét tiến trình (psutil): ghi phiên dùng ứng dụng, chặn ứng dụng theo luật (khớp SHA-256 trước, theo tên sau), ngân sách theo nhóm ứng dụng; điều phối đồng bộ và lệnh từ xa |
| `DnsProxy` | Lọc web tại 127.0.0.1:53 và ::1:53: chặn NXDOMAIN, chuyển tiếp upstream, SafeSearch, ghi sự kiện tên miền cấp hai (chi tiết ở tài liệu kỹ thuật mạng) |
| `ServerClient` + `WSListener` | HTTPS REST + WebSocket ghim fingerprint; làm mới token; hàng đợi sự kiện ngoại tuyến |
| `IPCServer` | Phục vụ Tray trong máy: trạng thái, báo cáo hôm nay, thông báo, yêu cầu của trẻ, xung phiên |
| `Tray` | Giao diện của trẻ (xem Phần C); đồng thời là **cảm biến phiên** (báo idle/khóa mỗi 3 giây) và **tay khóa máy** trong phiên khi hết giờ — giải pháp cho giới hạn session-0 của Windows Service |

Lọc nhiễu báo cáo 2 lớp: (1) không ghi phiên cho tiến trình thuộc tài khoản
SYSTEM/LOCAL SERVICE/NETWORK SERVICE; (2) danh sách tên tiến trình hệ thống
dùng chung (`SYSTEM_PROCESSES`) áp dụng cả khi ghi lẫn khi đọc báo cáo, ở
cả agent và server.

## B.4. Các luồng nghiệp vụ chính

1. **Ghép đôi**: dashboard tạo mã (10 phút) → `enroll.py` nhập mã +
   fingerprint → server cấp token + khóa chính sách → agent lưu cấu hình,
   bắt đầu heartbeat.
2. **Đếm giờ & khóa**: TimeKeeper cộng dồn theo xung phiên từ Tray → gần
   hết giờ cảnh báo 10/5/1 phút → hết giờ ân hạn 60 giây → phát sự kiện
   `locked` → Tray khóa máy trong phiên → sự kiện đồng bộ về server.
3. **Xin thêm giờ**: trẻ gửi từ Tray → hiện ở dashboard → phụ huynh duyệt →
   lệnh qua WebSocket → hạn mức hiệu lực tăng ngay (kiểm chứng thật:
   5 + 15 = 20 phút).
4. **Báo chặn nhầm**: trẻ báo từ Tray → phụ huynh xem và có thể nới luật →
   thay đổi chính sách đẩy xuống như luồng 3.
5. **Khóa máy từ xa**: phụ huynh bấm trên dashboard → lệnh WSS → agent xác
   nhận (ack) → Tray khóa máy.
6. **Thay đổi luật**: mọi sửa đổi ghi `audit_logs` và hiển thị lại trong
   Tray của trẻ ("Nhật ký thay đổi luật của phụ huynh").

---

# Phần C — Thiết kế giao diện

## C.1. Nguyên tắc giao diện

- **Minh bạch hai chiều**: trẻ và phụ huynh nhìn **cùng một báo cáo**.
  Không tồn tại màn hình "giám sát bí mật" trong thiết kế.
- **Giọng đồng hành**: thông báo cho trẻ viết ở ngôi thứ hai thân thiện
  ("Nhớ lưu bài nhé!"), không đe nẹt; cảnh báo hết giờ theo 3 mốc 10/5/1
  phút để trẻ chủ động lưu việc.
- **Không che giấu sự tồn tại của phần mềm**: biểu tượng khay hệ thống luôn
  hiện; không hiện được biểu tượng thì agent tự dừng.

## C.2. Dashboard phụ huynh (web, phục vụ ngay từ server)

Các khối chức năng trên một trang quản trị:

1. **Trẻ & thiết bị**: hồ sơ trẻ, trạng thái thiết bị (trực tuyến/lần cuối
   heartbeat), dòng **SHA-256 chứng chỉ server** để đối chiếu khi ghép đôi,
   tạo mã ghép đôi, thu hồi thiết bị.
2. **Thời gian**: hạn mức ngày thường / cuối tuần, lịch tuần, tạm dừng giới
   hạn hôm nay.
3. **Ứng dụng**: danh sách luật chặn (theo tên hoặc SHA-256), ngân sách theo
   nhóm.
4. **Web**: luật theo tên miền/nhóm, bật-tắt SafeSearch, danh sách miễn
   chặn.
5. **Yêu cầu chờ duyệt**: xin thêm giờ, báo chặn nhầm — duyệt/từ chối tại
   chỗ.
6. **Báo cáo**: hôm nay / tuần — thời gian đã dùng, ứng dụng dùng nhiều
   nhất, tên miền vào nhiều nhất, số lần bị chặn; biểu đồ tuần.
7. **Nhật ký kiểm toán**: ai thay đổi luật gì, lúc nào.

## C.3. Tray của trẻ (Windows, pystray + tkinter)

Menu khay hệ thống gồm 5 mục — cũng là toàn bộ bề mặt tương tác của trẻ:

| Mục | Nội dung |
|---|---|
| **Thời gian còn lại** (mặc định khi bấm đúp) | Lời chào theo tên trẻ; số phút còn lại hôm nay dạng lớn, dễ đọc; dòng tổng kết "đã dùng X / hạn mức Y. Còn lại: Z" — ba con số luôn khớp nhau (còn lại tính từ hai số đã hiển thị) |
| **Hôm nay em đã dùng gì** | Đúng báo cáo phụ huynh thấy: số lần ứng dụng/trang web bị chặn, ứng dụng dùng nhiều nhất, trang web vào nhiều nhất; chân trang ghi rõ "Bố mẹ và con đều nhìn thấy cùng báo cáo này" |
| **Xin thêm giờ** | Chọn số phút + lý do, gửi phụ huynh duyệt |
| **Báo chặn nhầm** | Báo một ứng dụng/trang bị chặn oan (tự điền sẵn đối tượng vừa bị chặn gần nhất) |
| **Nhật ký thay đổi luật** | Danh sách thay đổi phụ huynh đã áp dụng — trẻ biết luật đổi lúc nào, vì sao |

Thông báo hệ thống (toast) theo loại: sắp hết giờ (10/5/1 phút), ứng dụng
bị chặn, trang web bị chặn, máy bị khóa, phản hồi duyệt/từ chối từ phụ
huynh, agent khởi động. Các mốc cảnh báo quan trọng (sắp hết giờ, bị chặn,
khóa máy) kèm hộp thoại để trẻ không bỏ lỡ.

## C.4. Trạng thái và mã hóa trực quan

- Trạng thái kết nối agent ↔ server hiển thị ở cả dashboard (thiết bị trực
  tuyến/ngoại tuyến theo heartbeat) và Tray (dòng trạng thái khi không kết
  nối được service nội bộ).
- Số phút trên Tray cập nhật theo nhịp 3 giây của vòng lặp Tray; cửa sổ
  trạng thái chụp số liệu tại thời điểm mở (đóng/mở lại để làm mới) — hành
  vi này được ghi rõ trong hướng dẫn vận hành để tránh hiểu nhầm "số liệu
  không cập nhật".
