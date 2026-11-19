# OpenGuard Kids — Thiết kế lại kiến trúc chi tiết (v2) + Đối chiếu yêu cầu bắt buộc

- Nguồn yêu cầu: file hướng dẫn đồ án `MoTa_Doan_QLyViecSuDungPCCuaTre` (Minh gửi 13/11/2026).
- Phạm vi bản này: rà soát toàn bộ code đã giao 31/10/2026 (`~/workspace/openguard-kids/`), đối chiếu từng mục **BẮT BUỘC**, và thiết kế lại kiến trúc chi tiết để hiện thực đầy đủ. **Chờ Minh duyệt mới triển khai code** (cổng kiến trúc MASEL).
- Nguyên tắc xuyên suốt giữ nguyên: công cụ đồng hành minh bạch — không chụp màn hình, không ghi phím, không giám sát lén, không chế độ ẩn.

---

## 1. Kết luận rà soát code hiện tại

Khung sườn đúng hướng (FastAPI + SQLite, agent Service/Tray/DNS proxy, heartbeat 60s, WebSocket, hàng đợi sự kiện offline), nhưng có **8 lỗi lệch contract/nối dây khiến các chức năng chính "có code mà chết lặng"**, cộng nhiều mục bắt buộc chưa hề có. Các test server hiện tại (4 test) đều xanh vì chúng test server *cô lập* — không test nào chạy agent ↔ server cùng nhau, nên lệch contract không bị phát hiện.

### 1.1. Tám lỗi contract/nối dây nghiêm trọng (bằng chứng trong code)

| # | Lỗi | Hệ quả thực tế |
|---|---|---|
| L1 | Server trả policy với khóa `apps` / `web`; `controller.py` đọc `policy["app_rules"]` | **Chặn ứng dụng không bao giờ chạy** |
| L2 | `local_store.save_policy()` tìm danh sách miền ở các khóa `blocked_domains`/`blocklist`/`web_blocklist` (server không hề gửi); `dns_proxy.py` lại đọc khóa thứ ba `web_rules` | **Lọc web không bao giờ có dữ liệu — DNS cho qua tất cả** |
| L3 | `service.py` gọi `WSListener(client, command_queue)` trong khi hàm khởi tạo cần `(base_url, device_token, ...)` | **Kênh WebSocket chết — lệnh khẩn <5 giây không tồn tại** |
| L4 | `service.py` tạo DNS proxy bằng `cls(store, client)` — đối số `client` rơi vào tham số `bind` | DNS proxy có thể **không khởi động được**, lỗi bị nuốt lặng |
| L5 | `enroll.py` gửi `device_name`, server bắt buộc field `name` | **Đăng ký thiết bị trả 422 — enroll hỏng đầu-cuối** (file test đã ghi chú điều này nhưng code agent chưa từng được sửa) |
| L6 | `tray.py` gọi `ServerClient(self.cfg)` — truyền cả dict config thay vì `(base_url, token)` | Nút **"Xin thêm giờ" không bao giờ gửi được**; sự kiện dự phòng offline cũng không được server hiểu là yêu cầu |
| L7 | `service.py`: `queue_event('time_warning', payload)` — payload rơi vào tham số `app_name` | Sự kiện cảnh báo ghi sai định dạng |
| L8 | Không module nào phát sự kiện phiên dùng ứng dụng (mở/đóng + thời lượng); báo cáo server chỉ tính từ `payload.minutes` mà agent không gửi | **Báo cáo phụ huynh trống dữ liệu** — top ứng dụng/biểu đồ không có nguồn |

### 1.2. Bảng đối chiếu chức năng BẮT BUỘC (theo mục của đề)

Trạng thái: ✅ Đạt · 🟡 Một phần · ❌ Chưa có · 💥 Có code nhưng hỏng (mục 1.1)

**Triết lý minh bạch (§1 — NT1..NT6)**
- NT1 biểu tượng khay luôn hiển thị + thông báo khi agent khởi động: 🟡 (Tray hiện là cửa sổ tkinter, đóng được, không phải tray icon thật; không có cơ chế "không hiện được icon thì agent tự dừng")
- NT2 tối thiểu dữ liệu: 🟡 (sự kiện tự do qua `payload` JSON bất kỳ — chưa khóa lược đồ)
- NT3 trẻ có tiếng nói: 🟡 (xin thêm giờ 💥 L6; chưa có nút "trang này bị chặn nhầm")
- NT4 chặn phải giải thích lý do + ai đặt luật: ❌ (service kết thúc tiến trình lặng lẽ, không cửa sổ lý do)
- NT5 trẻ xem cùng báo cáo + xem nhật ký thay đổi luật: ❌ (màn "Báo cáo của con" chỉ đếm hàng đợi cục bộ, số liệu sai sau khi đồng bộ; không có xem audit)
- NT6 danh sách miễn chặn vĩnh viễn (cổng trường, Tổng đài 111, khẩn cấp): ❌

**Vòng đời & giao thức (§2.3)**
- Ghép đôi bằng mã 8 ký tự, hạn 10 phút, kèm device fingerprint, trả cặp token access/refresh, ghi nhận đồng ý của cha mẹ (NĐ 13/2023): ❌ (đang dùng mật khẩu phụ huynh trong CLI enroll 💥 L5)
- Heartbeat 60s mang trạng thái + quota đã dùng + policy_version; lệch phiên bản mới tải policy: 🟡 (có nhịp 60s nhưng gửi payload rỗng, server trả toàn bộ policy mỗi lần, không có khái niệm version)
- Lệnh khẩn WebSocket (khóa ngay / mở khóa / +15 phút) trễ < 5s: 💥 L3 (và chưa có lệnh *mở khóa*)
- Ngoại tuyến: đệm sự kiện + đồng bộ theo lô có idempotency key chống đếm trùng: 🟡 (có hàng đợi + gửi lô, nhưng **không có idempotency key** — mất phản hồi là gửi trùng)
- Chính sách hết hạn khi mất kết nối dài ngày (fail-open/fail-closed): ❌ — cần nhóm quyết định (mục 4.1)

**F1 — Quản lý thời gian**
- Quota ngày, cấu hình riêng ngày thường / cuối tuần: 🟡 (có quota ngày, **chưa tách thường/cuối tuần**)
- Lịch tuần 7×48 (ô 30 phút), ngoài khung giờ máy khóa trong 5 giây: ❌ (mới có khung giờ theo từng ứng dụng)
- Đếm thời gian thực (không tính khi khóa máy / không thao tác > 5 phút), sai số ≤ ±30s/giờ: ✅/🟡 (`timekeeper` đã trừ idle ≥300s và trạng thái khóa; cần test đo sai số)
- Cảnh báo ở mốc 10, 5, 1 phút + ân hạn 60 giây để lưu bài: 🟡 (mới có **một** mốc cảnh báo chung; khóa ngay khi ≤ 0)
- Chống chỉnh đồng hồ hệ thống (lùi 3 giờ: quota không tăng + ghi sự kiện): 🟡 (đếm bằng `monotonic` nên không bị kéo dài trong ngày, nhưng **chưa phát hiện/ghi sự kiện**, và lùi qua mốc nửa đêm sẽ reset bộ đếm theo ngày)

**F2 — Kiểm soát ứng dụng / website**
- Đối chiếu ứng dụng bằng tên tiến trình **kèm SHA-256 của file thực thi** (đổi tên notepad.exe → game.exe vẫn nhận diện đúng): ❌ (mới khớp theo tên)
- Khi chặn: kết thúc tiến trình **+ cửa sổ giải thích lý do**: 🟡 (có kết thúc, thiếu cửa sổ — xem NT4)
- DNS proxy 127.0.0.1:53, chặn miền + toàn bộ miền con: 💥 L2/L4 (bản thân engine DNS viết tốt: parse gói an toàn, NXDOMAIN/sinkhole, khớp miền con ✅ — chết vì không có dữ liệu)
- Phân loại 6 nhóm (giáo dục / giải trí / mạng xã hội / trò chơi / không phù hợp lứa tuổi / chưa phân loại) + chính sách mặc định cho trẻ 6–11 + bảng phân loại ≥ 200 mục: ❌
- Cưỡng chế SafeSearch bằng bản ghi DNS (forcesafesearch): ❌

**F3 — Ghi nhận & báo cáo**
- Lược đồ sự kiện khóa cứng: chỉ `ts, device_id, child_id, type, subject, duration_sec, policy_id`; `type` thuộc tập 9 giá trị của đề; `subject` là tên app hoặc tên miền cấp hai (không URL đầy đủ): ❌ (đang tự do)
- Dashboard: biểu đồ ngày + tuần, top 10 ứng dụng, top 10 tên miền, số lần chặn, danh sách yêu cầu của trẻ: 🟡 (mới có tổng phút theo ngày, theo app/nhóm; thiếu tuần, top miền, số lần chặn 💥 L8)
- Màn hình trẻ "Hôm nay em đã dùng gì" (cùng dữ liệu, ngôn ngữ đơn giản): 🟡 (có khung, số liệu sai nguồn)
- Lưu trữ 90 ngày + tác vụ tự xóa; nút "Xóa toàn bộ dữ liệu của con tôi" xóa cả server lẫn bộ đệm agent: ❌
- `PRIVACY.md` dạng bảng trường dữ liệu ↔ mục đích ↔ thời hạn ↔ người xem: ❌

**F4 — Cấu hình từ xa**
- Mô hình 1 phụ huynh : n trẻ : m thiết bị: ✅
- Policy hiệu lực ≤ 60s; lệnh khẩn ≤ 5s: 🟡 (heartbeat 60s ✅ biên; khẩn 💥 L3)
- Policy có **số phiên bản + ký toàn vẹn HMAC**, agent từ chối policy bị sửa: ❌
- Audit log: ai / lúc nào / **từ IP nào** / **giá trị cũ → mới**; trẻ được xem: 🟡 (có actor/action/detail; thiếu IP, thiếu cũ/mới; `/audit` còn trả log của **mọi** phụ huynh cho bất kỳ ai đăng nhập — lỗi phân quyền; trẻ không xem được)

**F5 — Bảo mật (bảng yêu cầu tối thiểu)**
- Mật khẩu Argon2id hoặc scrypt, tối thiểu 10 ký tự: ❌ (đang PBKDF2, min 8)
- Khóa tạm 15 phút sau 5 lần sai + rate limit theo IP: ❌
- Cookie HttpOnly + Secure + SameSite=Lax, phiên 12 giờ, đăng xuất hủy phiên phía server, CSRF mọi thao tác ghi: ❌ (đang Bearer JWT 7 ngày lưu ở localStorage của dashboard)
- Token thiết bị: access 15 phút + refresh, thu hồi khi gỡ thiết bị: 🟡 (đã có cờ `revoked`; chưa tách access/refresh)
- Mã hóa trường nhạy cảm AES-GCM, khóa từ biến môi trường/DPAPI, không hardcode: ❌ (JWT secret còn mặc định `dev-change-me-in-prod`)
- Ba vai trò parent / child-view / admin + chống IDOR ở tầng truy vấn: 🟡 (chống IDOR khá tốt ở đa số endpoint — trừ `/audit` ở trên; chưa có vai trò child-view/admin)
- Tài khoản trẻ không thuộc Administrators; ACL thư mục agent chỉ SYSTEM/Administrators ghi: 🟡 (vị trí ProgramData ✅; chưa có bước áp ACL trong cài đặt)
- Không chế độ ẩn; không hiện được biểu tượng thì agent tự dừng; tài liệu nêu phạm vi sử dụng hợp pháp: 🟡/❌

**Tổng kết:** nền móng ≈ 40% khối lượng bắt buộc; phần còn lại là (a) sửa 8 lỗi contract, (b) bổ sung các cơ chế chưa có. Kiến trúc v2 dưới đây giữ nguyên stack theo đề (Python 3.11 · FastAPI · SQLite/SQLAlchemy · pywin32/psutil), chỉ thiết kế lại contract và bổ sung module — không viết lại từ đầu.

---

## 2. Kiến trúc đích v2

### 2.1. Nguyên tắc thiết kế lại

1. **Một contract duy nhất, có test khóa**: toàn bộ JSON trao đổi server ↔ agent được định nghĩa một chỗ (module `shared/contract.py` dùng chung hai phía + bộ test contract chạy cả hai chiều). Đây là thuốc đặc trị cho 8 lỗi ở mục 1.1.
2. **Policy là một tài liệu có phiên bản và chữ ký**: server phát hành `policy_document` (JSON) kèm `version` tăng đơn điệu và `signature = HMAC-SHA256(policy_key, canonical_json)`. Agent chỉ áp dụng khi chữ ký đúng và version mới hơn bản đang giữ.
3. **Sự kiện khóa lược đồ đúng §F3** — server từ chối (422) mọi trường ngoài lược đồ; mỗi sự kiện mang `event_id` (UUID do agent sinh) làm idempotency key.
4. **Service ↔ Tray qua named pipe** có token cục bộ (đúng §2.2 của đề): Service (SYSTEM) là nơi duy nhất ghi DB cục bộ và nói chuyện với server; Tray (quyền user) chỉ hiển thị và gửi yêu cầu qua pipe. Nhờ đó ACL thư mục agent giữ đúng "chỉ SYSTEM/Administrators được ghi".

### 2.2. Tài liệu chính sách (policy document) — contract trung tâm

```json
{
  "device_id": 12, "child_id": 5, "version": 17,
  "issued_at": "2026-11-14T08:00:00Z",
  "time": {
    "quota_weekday_min": 90, "quota_weekend_min": 150,
    "schedule": [[...48 ô 0/1...] x 7 ngày],        // 1 = được dùng máy
    "warn_at_min": [10, 5, 1], "grace_sec": 60,
    "group_budgets": {"hoc_tap": null, "game": 45}  // NÊN CÓ, sẵn cấu trúc
  },
  "apps": [{"name": "notepad.exe", "sha256": "ab12…", "action": "allow|block",
            "windows": [{"from": "07:00", "to": "20:00"}], "daily_cap_min": null}],
  "web": {
    "rules": [{"domain": "youtube.com", "action": "block|allow"}],
    "category_policy": {"giao_duc": "allow", "giai_tri": "allow", "mang_xa_hoi": "block",
                        "tro_choi": "block", "khong_phu_hop": "block", "chua_phan_loai": "allow"},
    "safesearch": true
  },
  "signature": "hmac-sha256 hex"
}
```

- Danh sách **miễn chặn vĩnh viễn** (NT6) không nằm trong policy — nó được *đóng cứng trong agent* và thắng mọi luật: cổng thông tin trường (danh sách cấu hình lúc cài đặt theo trường của trẻ), các miền/tên miền dịch vụ của Tổng đài 111 và cứu hộ khẩn cấp; policy dù ghi "block" cũng bị agent bỏ qua đối với các miền này, đồng thời ghi sự kiện cảnh báo về server.
- Phân loại miền: server giữ bảng `domain_categories` (≥ 200 mục, 6 nhóm, kèm bộ dữ liệu kiểm thử 60 miền theo phụ lục của đề — chỉ dùng miền công khai/trung tính) và gửi xuống agent *bản rút gọn chỉ gồm các miền bị chặn theo category_policy* trong policy document; agent không cần biết toàn bộ bảng.

### 2.3. Server (FastAPI + SQLite WAL)

Module hóa lại `server/app/` (hiện dồn vào `main.py` ~350 dòng):

| Module | Trách nhiệm | Điểm mới so với code cũ |
|---|---|---|
| `auth.py` | Đăng ký/đăng nhập phụ huynh | **Argon2id** (passlib), mật khẩu ≥ 10 ký tự; khóa tài khoản 15 phút sau 5 lần sai; rate limit theo IP; **phiên cookie** HttpOnly/Secure/SameSite=Lax 12 giờ lưu phía server (bảng `sessions`, đăng xuất = xóa phiên); **CSRF token** cho mọi POST/PUT/DELETE; TOTP giữ nguyên (điểm cộng đã có) |
| `pairing.py` | Ghép đôi thiết bị | Mã 8 ký tự (bảng chữ không gây nhầm lẫn), hạn 10 phút, dùng 1 lần; agent gửi mã + device fingerprint (hash của MachineGuid + tên máy); server trả `device_id` + **access token 15 phút + refresh token** (chỉ lưu hash), ghi audit "consent" làm điểm ghi nhận đồng ý của cha mẹ |
| `policies.py` | Phát hành policy document | Tăng `version` mỗi lần sửa bất kỳ thành phần nào (quota/lịch/luật app/luật web); ký HMAC bằng khóa riêng của thiết bị (sinh khi ghép đôi, lưu hash phía server; agent giữ khóa trong config được bảo vệ ACL); audit ghi **giá trị cũ → mới + IP** |
| `events.py` | Nhận sự kiện | Validate lược đồ §F3 nghiêm ngặt; **dedupe theo `event_id`**; lưu `child_id`, `policy_id` (= policy version lúc sự kiện xảy ra) |
| `reports.py` | Báo cáo | Ngày + **tuần**, top 10 app, **top 10 miền**, số lần chặn theo loại, danh sách yêu cầu của trẻ; phân trang |
| `requests.py` | Yêu cầu của trẻ | Hai loại: `extra_time` và `false_block` (báo chặn nhầm — kèm miền/app bị chặn); phụ huynh duyệt/từ chối, mọi quyết định đều có phản hồi về agent để Tray hiển thị cho trẻ |
| `commands.py` | Lệnh khẩn | `lock_now` (khóa ≤ 5s qua WS), `unlock`, `grant_extra` (+phút tùy ý, mẫu nhanh 15), `break`, `pause_today`, `wipe_cache` (phục vụ xóa dữ liệu); agent bắt buộc **ack** từng lệnh, server theo dõi trạng thái pending → sent → done |
| `audit.py` | Nhật ký kiểm toán | actor, ts, **ip**, action, `old`, `new`; API chỉ trả log thuộc phạm vi phụ huynh đang đăng nhập (sửa lỗi lộ chéo); endpoint child-view cho trẻ xem (NT5) |
| `children.py` / `devices.py` | Hồ sơ 1:n:m | Thêm endpoint **"Xóa toàn bộ dữ liệu của con tôi"**: xóa sự kiện/báo cáo/yêu cầu của trẻ trên server, phát lệnh `wipe_cache` xuống mọi thiết bị của trẻ, ghi audit |
| `retention.py` | Tác vụ nền | Xóa sự kiện quá 90 ngày (chạy hằng ngày), dọn phiên hết hạn, dọn mã ghép đôi hết hạn |
| `childview.py` | Vai trò child-view | Token xem-chỉ-đọc gắn với thiết bị: lấy báo cáo của chính mình + audit của phụ huynh về mình (NT5), không sửa được gì |
| `security.py` (dùng chung) | — | Mã hóa **AES-GCM** cho trường nhạy cảm (TOTP secret, khóa HMAC thiết bị ở dạng lưu trữ) bằng khóa từ biến môi trường `OGK_MASTER_KEY`; bỏ secret mặc định — server từ chối khởi động nếu thiếu khóa trong chế độ production |

Dashboard: giữ dạng web tĩnh một file nhưng chuyển sang **cookie session + CSRF** (bỏ localStorage token), bổ sung: ma trận lịch tuần 7×48 kéo-thả theo ô 30 phút, quota riêng ngày thường/cuối tuần, biểu đồ tuần + top 10 miền, trang duyệt yêu cầu (cả hai loại), nút xóa toàn bộ dữ liệu, xem trên trình duyệt điện thoại được (responsive).

### 2.4. Agent (Windows Service + Tray)

Giữ cấu trúc file hiện tại, sửa/nâng cấp theo module:

| Module | Thay đổi chính |
|---|---|
| `service.py` | Sửa nối dây L3/L4/L7; cấu hình **Service Recovery Options** (tự khởi động lại khi sập) ở bước cài đặt; khi khởi động phát sự kiện + yêu cầu Tray hiển thị thông báo "OpenGuard Kids đang đồng hành cùng con" (NT1) |
| `client.py` | Heartbeat gửi `{status, used_today_sec, policy_version, clock_offset_sec}`; chỉ tải policy khi server báo version mới; **ghim chứng chỉ** (lưu SHA-256 fingerprint của cert server trong config lúc ghép đôi, sai là từ chối kết nối); tự refresh access token bằng refresh token, bị thu hồi thì dừng đồng bộ và báo rõ trên Tray; gửi ack lệnh qua WS |
| `policy.py` (mới) | Lớp dùng chung duy nhất: nạp policy document, **kiểm HMAC**, kiểm version, cấp phát cho timekeeper/controller/dns cùng một bản đã chuẩn hóa — chấm dứt tình trạng mỗi module đọc một khóa khác nhau |
| `timekeeper.py` | Nâng cấp: quota theo thứ (thường/cuối tuần); **lịch 7×48** — ngoài khung cho phép thì khóa máy (kiểm mỗi 5s, đạt yêu cầu "khóa trong 5 giây"); cảnh báo tại **10/5/1 phút** (mỗi mốc một lần, qua pipe cho Tray hiện cửa sổ); **ân hạn 60s** sau khi hết quota rồi mới khóa; **chống chỉnh giờ**: so độ lệch giữa đồng hồ hệ thống và nhịp monotonic + mốc thời gian server trả trong heartbeat — lùi giờ > 120s thì ghi sự kiện `clock_tamper` (nằm ngoài tập type của §F3 nên mã hóa thành sự kiện hệ thống riêng phía agent→server audit, không lẫn vào báo cáo của trẻ), ngày hiệu lực **không bao giờ đi lùi** (lưu `last_seen_date`, ngày mới = max(hôm nay, last_seen_date) cho tới khi server xác nhận) |
| `controller.py` | Nhận diện ứng dụng: lấy đường dẫn exe qua psutil → tính **SHA-256** (cache theo path+mtime) → khớp luật theo hash trước, theo tên sau (đạt test đổi tên notepad); khi chặn: kết thúc tiến trình + gửi qua pipe cho Tray **cửa sổ giải thích**: ứng dụng/trang gì, vì sao bị chặn, luật do phụ huynh đặt lúc nào (NT4); theo dõi phiên ứng dụng ở foreground để phát `app_start`/`app_stop` kèm `duration_sec` (nguồn dữ liệu cho báo cáo — sửa L8); bộ đếm ngân sách theo nhóm ứng dụng được **lưu xuống SQLite** (khởi động lại không mất) |
| `dns_proxy.py` | Giữ engine; nguồn dữ liệu chuyển sang `policy.py` (sửa L2); thêm: **SafeSearch** — trả bản ghi CNAME tới `forcesafesearch.google.com` (và tương đương Bing/DuckDuckGo) khi policy bật; ghi sự kiện `domain_query` (chỉ tên miền cấp hai, lấy mẫu gom theo phút để không phình hàng đợi) và `blocked_domain`; **miễn chặn vĩnh viễn** thắng mọi luật (NT6); miền DoH đã biết được xếp vào nhóm riêng trong bảng phân loại để phụ huynh thấy và quyết định |
| `local_store.py` | Sự kiện có `event_id` UUID + đúng lược đồ §F3; thêm bảng `history` cục bộ (bản sao sự kiện 90 ngày phục vụ màn hình của trẻ, không bị xóa khi đồng bộ — sửa lỗi số liệu của Tray); thực thi lệnh `wipe_cache` |
| `ipc.py` (mới) | Named pipe `\\.\pipe\OpenGuardKids` + token cục bộ sinh lúc cài đặt: kênh Service ↔ Tray cho trạng thái, cảnh báo, cửa sổ lý do, gửi yêu cầu của trẻ (thay cho việc Tray tự gọi server — sửa L6 và đúng §2.2) |
| `tray.py` | Viết lại thành **tray icon thật** (pystray): icon luôn hiện khi agent chạy; menu/cửa sổ: đồng hồ còn lại, "Hôm nay em đã dùng gì" (từ `history` — cùng số liệu phụ huynh thấy), nút **Xin thêm giờ**, nút **Báo chặn nhầm**, xem **nhật ký thay đổi luật**; cửa sổ cảnh báo 10/5/1 phút và cửa sổ lý do khi bị chặn; nếu không tạo được tray icon → báo Service **tự dừng** (F5 chống lạm dụng) |
| `enroll.py` | Viết lại theo luồng mã ghép đôi: nhập mã 8 ký tự + địa chỉ server → gửi fingerprint → nhận device_id + cặp token + khóa HMAC + cert fingerprint → lưu config (sửa L5) |

### 2.5. Bảo mật — đối chiếu F5

Argon2id · khóa tài khoản 5 lần/15 phút · rate limit IP · cookie session 12h + hủy phía server + CSRF · TLS 1.2+ (CA tự ký cho phòng lab) + agent ghim chứng chỉ · access token thiết bị 15 phút + refresh + danh sách thu hồi · AES-GCM cho trường nhạy cảm, khóa từ biến môi trường · chống IDOR ở tầng truy vấn cho **mọi** endpoint (kèm test) · 3 vai trò parent/child-view/admin · ACL thư mục `%ProgramData%\OpenGuardKids` chỉ SYSTEM + Administrators ghi (script cài đặt áp ACL bằng `icacls`) · không chế độ ẩn, mất tray icon thì agent dừng · `PRIVACY.md` + mục "Phạm vi sử dụng hợp pháp" trong README.

---

## 3. Các điểm cần nhóm chốt (để bảo vệ khi vấn đáp)

### 3.1. Chính sách hết hạn khi mất kết nối dài ngày — **đề xuất: fail-closed có điều kiện**
- Trong **7 ngày** đầu mất kết nối: agent vẫn áp policy gần nhất (fail-closed) — an toàn cho trẻ là ưu tiên của đề (NT6).
- Sau 7 ngày: chuyển **fail-open có kiểm soát** đối với quota/lịch (tránh khóa trẻ khỏi máy học tập vô thời hạn vì lỗi hạ tầng), nhưng **danh sách chặn theo nhóm "không phù hợp lứa tuổi" và miễn chặn NT6 vẫn giữ nguyên**, Tray hiện thông báo rõ "đang mất kết nối với bố mẹ N ngày", mọi sự kiện vẫn đệm để đồng bộ sau.
- Lý do bảo vệ được: cân bằng an toàn ↔ quyền học tập; có mốc thời gian cụ thể; minh bạch với trẻ thay vì âm thầm ngừng hoạt động.

### 3.2. Các quyết định phụ (em đề xuất, nhóm có thể đổi nhanh)
- Sự kiện `domain_query`: chỉ ghi tên miền cấp hai (đúng §F3) và gom theo (miền, phút) — đủ cho top-10 mà không phình dữ liệu (NT2).
- Lệnh `lock_now` từ phụ huynh khóa **ngay** (≤5s theo F4); ân hạn 60s chỉ áp cho hết quota/lịch (F1) — hai tình huống khác nhau, tránh lẫn.
- Admin role: chỉ phục vụ demo/vấn đáp (xem trạng thái hệ thống, không xem dữ liệu của trẻ) — giữ tối thiểu dữ liệu.

---

## 4. Kế hoạch hiện thực (module nhỏ, theo thứ tự)

1. `shared/contract.py` + test contract hai chiều (policy document, event schema, heartbeat, commands).
2. Server: models v2 (migration bằng cách tạo DB mới — dữ liệu demo không cần giữ) + `auth.py` (Argon2id, lockout, rate limit, cookie session, CSRF).
3. Server: `pairing.py` + token cặp access/refresh + khóa HMAC thiết bị.
4. Server: `policies.py` (phát hành version + HMAC, audit cũ/mới/IP) + `events.py` (lược đồ cứng + dedupe) + `commands.py` ack + `requests.py` hai loại.
5. Server: `reports.py` v2 + `audit.py` sửa phân quyền + `children.py` xóa toàn bộ dữ liệu + `retention.py` + `childview.py`.
6. Server: bảng phân loại ≥ 200 miền (6 nhóm) + bộ kiểm thử 60 miền theo phụ lục + `PRIVACY.md`.
7. Dashboard: cookie/CSRF, ma trận 7×48, quota thường/cuối tuần, biểu đồ tuần, top miền, duyệt 2 loại yêu cầu, responsive.
8. Agent: `policy.py` + sửa `service.py`/`client.py` (heartbeat v2, pinning, refresh, ack).
9. Agent: `timekeeper.py` v2 (quota theo thứ, lịch 7×48, cảnh báo 10/5/1, ân hạn, chống chỉnh giờ).
10. Agent: `controller.py` v2 (SHA-256, phiên ứng dụng, ngân sách nhóm bền vững, lý do chặn qua IPC).
11. Agent: `dns_proxy.py` v2 (policy.py làm nguồn, SafeSearch, miễn chặn, sự kiện miền).
12. Agent: `ipc.py` + `tray.py` viết lại (tray icon, các màn của trẻ, báo chặn nhầm) + `enroll.py` mã ghép đôi + script cài đặt (ACL + Service Recovery + cắm DNS 127.0.0.1).

## 5. Kế hoạch kiểm thử — 3 vòng (bằng chứng chạy thật, không tự khai)

- **Vòng 1 — Unit + contract**: pytest cho server (auth/lockout/CSRF/IDOR/pairing/policy-HMAC/event-dedupe/reports/audit) và cho logic agent chạy được trên mọi nền (timekeeper với đồng hồ giả lập: quota 3 phút, cảnh báo 10/5/1, ân hạn, lùi giờ 3 giờ; ma trận lịch 7×48; khớp hash ứng dụng; quyết định DNS gồm miền con, miễn chặn, SafeSearch).
- **Vòng 2 — Tích hợp đầu-cuối trên máy này (Linux)**: chạy server thật + agent ở chế độ console với lớp Windows được giả lập (mock LockWorkStation/psutil) — kịch bản: ghép đôi → đặt quota 3 phút → khóa đúng hạn; đổi policy → hiệu lực ≤ 60s; lệnh khóa qua WS ≤ 5s; mất mạng → đệm sự kiện → có mạng → đồng bộ không trùng; xóa toàn bộ dữ liệu hai phía.
- **Vòng 3 — Nghiệm thu theo đúng tiêu chí của đề**: bộ 50 miền kiểm thử (theo phụ lục: 20 giáo dục phải **0 chặn nhầm**, các nhóm còn lại đạt **≥ 95% chặn** theo policy mặc định 6–11 tuổi), kiểm SafeSearch bằng truy vấn DNS, test đổi tên file + hash, đo sai số đếm giờ so với bấm giờ, checklist NT1–NT6/F5 từng mục.
- **Giới hạn trung thực**: Service Windows thật (cài SCM, LockWorkStation, tray icon trên Windows, bind cổng 53) **không chạy được trên máy Linux này** — các phần đó được test ở mức logic + mock trong 3 vòng trên, và cần nhóm chạy lại trên máy Windows thật theo checklist bàn giao (em ghi rõ mục nào là PASS thật, mục nào là NOT_RUN-chờ-Windows trong báo cáo test).

---
