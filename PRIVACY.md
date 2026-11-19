# PRIVACY.md — OpenGuard Kids: dữ liệu nào được thu thập, vì sao, bao lâu, ai xem

Nguyên tắc NT2 (tối thiểu dữ liệu): chỉ thu **siêu dữ liệu sử dụng** — tên ứng dụng,
tên miền cấp hai, thời lượng, dấu thời gian. Trường nào không giải thích được mục
đích thì bị loại khỏi lược đồ (lược đồ sự kiện bị khóa cứng ở `shared/contract.py`
và server từ chối mọi trường nằm ngoài danh sách này).

## Bảng dữ liệu

| Trường dữ liệu | Thu thập ở đâu | Mục đích | Thời hạn lưu | Ai xem được |
|---|---|---|---|---|
| `event_id` | Agent (UUID sinh tại máy trẻ) | Khóa chống trùng khi đồng bộ lại sau mất mạng (idempotency) | 90 ngày | Phụ huynh (qua báo cáo tổng hợp), hệ thống |
| `ts` | Agent | Dấu thời gian của sự kiện để vẽ báo cáo theo ngày/tuần | 90 ngày | Phụ huynh, trẻ (màn hình của trẻ) |
| `device_id` | Server | Gắn sự kiện với đúng thiết bị của trẻ | 90 ngày (theo sự kiện) | Phụ huynh |
| `child_id` | Server | Gắn sự kiện với đúng trẻ trong mô hình 1 phụ huynh : n trẻ | 90 ngày (theo sự kiện) | Phụ huynh |
| `type` | Agent | Loại sự kiện trong tập cố định: app_start, app_stop, domain_query, blocked_app, blocked_domain, quota_warning, locked, unlock_request, override_granted | 90 ngày | Phụ huynh, trẻ |
| `subject` | Agent | Tên ứng dụng hoặc **tên miền cấp hai** (vd `youtube.com`) — không bao giờ là URL đầy đủ | 90 ngày | Phụ huynh, trẻ |
| `duration_sec` | Agent | Thời lượng phiên ứng dụng để tính top ứng dụng và tổng thời gian | 90 ngày | Phụ huynh, trẻ |
| `policy_id` | Agent | Phiên bản chính sách đang áp dụng khi sự kiện xảy ra (truy vết "vì sao bị chặn") | 90 ngày (theo sự kiện) | Phụ huynh |
| Email phụ huynh | Dashboard | Đăng nhập và định danh người cấu hình | Tới khi xóa tài khoản | Chính phụ huynh, admin hệ thống (chỉ định danh) |
| Mật khẩu (băm Argon2id) | Dashboard | Xác thực — server không lưu mật khẩu gốc | Tới khi đổi/xóa tài khoản | Không ai (chỉ dùng để kiểm tra) |
| TOTP secret (mã hóa AES-GCM) | Dashboard | Yếu tố xác thực thứ hai (tùy chọn, điểm cộng) | Tới khi tắt 2FA | Không ai |
| Tên + ngày sinh của trẻ | Dashboard | Hiển thị và chọn chính sách mặc định theo độ tuổi | Tới khi phụ huynh xóa | Phụ huynh, trẻ (tên hiển thị ở Tray) |
| Tên thiết bị + device fingerprint (băm SHA-256 của MachineGuid/tên máy) | Agent khi ghép đôi | Chống ghép đôi nhầm thiết bị; ghi nhận điểm đồng ý của cha mẹ (NĐ 13/2023) | Tới khi thu hồi thiết bị | Phụ huynh |
| Access/refresh token của thiết bị (chỉ lưu băm) | Server | Xác thực agent, thu hồi khi gỡ thiết bị | Access 15 phút; refresh tới khi thu hồi | Không ai |
| Khóa HMAC của policy (mã hóa AES-GCM phía server) | Server | Ký tài liệu chính sách để agent chống giả mạo | Tới khi thu hồi thiết bị | Không ai |
| Nội dung chính sách (quota, lịch, luật app/web) | Dashboard | Cấu hình mà agent thi hành; hiển thị lại cho trẻ qua Tray | Tới khi sửa/xóa | Phụ huynh, trẻ |
| Nhật ký kiểm toán: actor, thời gian, IP, giá trị cũ/mới | Server | Mọi thay đổi đều giải thích được (NT4); trẻ có quyền xem (NT5) | 90 ngày | Phụ huynh, trẻ (chỉ phần liên quan tới mình) |
| Bộ đếm cục bộ: used_seconds, ngân sách nhóm, cờ cảnh báo | Agent (SQLite tại máy trẻ) | Đếm giờ ngoại tuyến, cảnh báo đúng mốc, không mất khi khởi động lại | Theo ngày (tự lăn sang ngày mới); sự kiện cục bộ đã gửi giữ 90 ngày cho màn hình của trẻ | Trẻ, phụ huynh (qua đồng bộ) |

## Dữ liệu KHÔNG bao giờ thu thập (danh mục cấm của đề)

- Nội dung tin nhắn, email, tài liệu của trẻ.
- URL đầy đủ, tiêu đề cửa sổ, nội dung gõ phím, ảnh chụp màn hình.
- Vị trí, danh bạ, tập tin cá nhân.
- Không gửi bất kỳ dữ liệu nào tới dịch vụ bên thứ ba — chỉ có OGK-Server của
  gia đình/trường trong mạng LAN hoặc VPS lab.

## Quyền xóa

- Tác vụ nền của server tự xóa sự kiện quá **90 ngày**.
- Nút **"Xóa toàn bộ dữ liệu của con tôi"** trên dashboard xóa sự kiện + yêu cầu
  của trẻ trên server đồng thời phát lệnh `wipe_cache` xuống agent để xóa bộ đệm
  cục bộ; hành động xóa được ghi vào nhật ký kiểm toán.
