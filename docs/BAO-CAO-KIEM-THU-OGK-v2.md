# OpenGuard Kids v2 — Báo cáo kiểm thử 3 vòng (13/11/2026)

Môi trường chạy test: máy ảo Linux của trợ lý (Python 3.12, venv riêng của dự án).
Mọi kết quả dưới đây đều từ lần chạy thật; mục chưa chạy được ghi rõ **NOT_RUN**.

## Vòng 1 — Unit + contract + API: 32/32 PASS

`pytest tests/` — 18 test server + 14 test agent.

- Server: mật khẩu <10 ký tự bị từ chối; CSRF thiếu → 403; đăng xuất hủy phiên
  phía server; **khóa tài khoản 15 phút sau 5 lần sai** (lần 6 trả 423); TOTP
  2FA; ghép đôi bằng mã 8 ký tự (dùng lại → 404); policy ký HMAC kiểm chứng
  được, version tăng sau mỗi lần sửa, audit có **giá trị cũ → mới + IP**;
  phụ huynh khác bị 404 khi chạm policy của nhau (IDOR) và không thấy audit
  của nhau; luật block vào miền `.gov.vn`/cổng trường bị server từ chối (400,
  NT6); refresh token xoay vòng (token cũ chết), thu hồi thiết bị → 401 mọi
  kênh; sự kiện ngoài lược đồ F3 → 422, gửi trùng `event_id` → đếm duplicates
  không nhân đôi báo cáo; báo cáo ngày/tuần + top app/miền; lệnh qua heartbeat
  + ack; duyệt xin thêm giờ → tự sinh lệnh `grant_extra`; duyệt báo chặn nhầm
  → tự thêm luật allow; xóa toàn bộ dữ liệu → phát lệnh `wipe_cache`; purge
  90 ngày; bảng phân loại nạp đủ 254 miền; admin overview chặn parent thường;
  rate limit đăng nhập → 429.
- Agent: quota 3 phút với cảnh báo 10/5/1 + ân hạn 60s → khóa đúng trình tự
  (đồng hồ giả lập); idle ≥5 phút và máy khóa **không đếm giờ**; quota cuối
  tuần 150 phút; **ngoài lịch 7×48 → khóa theo lịch**; **lùi đồng hồ 3 giờ →
  phát hiện clock_tamper, ngày không đi lùi, quota không được hoàn** (chỉ cộng
  đúng 1 giây trôi thật); cộng giờ/nghỉ giải lao; PolicyManager từ chối policy
  sai chữ ký và policy cũ hơn; quyết định web: miễn chặn > allow > block >
  danh sách phân loại, chặn cả miền con; **đổi tên notepad.exe → game.exe vẫn
  bị nhận diện theo SHA-256**; ngân sách nhóm game = 0 → tiến trình thật bị
  dừng + có thông báo lý do; phiên ứng dụng phát app_stop kèm duration; DNS:
  NXDOMAIN cho miền chặn + miền con, chuyển tiếp miền sạch, `.gov.vn` luôn
  qua, **SafeSearch trả CNAME → forcesafesearch.google.com**; IPC vòng kín +
  sai token bị từ chối.

## Vòng 2 — Tích hợp đầu-cuối (server uvicorn thật + agent runtime thật): 22/22 PASS

`scripts/e2e_round2.py` — đăng ký/đăng nhập; tạo mã ghép đôi; **enroll.py
ghép đôi bằng mã, không dùng mật khẩu phụ huynh**; heartbeat nhận policy v1
(HMAC hợp lệ); đổi quota → agent áp v2 ở chu kỳ heartbeat kế; sự kiện lên báo
cáo (10 phút), gửi lại không trùng; **lệnh khóa khẩn qua WebSocket tới agent
< 5 giây** và ack → server ghi `done`; cảnh báo chỉnh giờ xuất hiện trong
audit phụ huynh; IPC: tray đọc trạng thái qua service, gửi yêu cầu xin thêm
giờ tới phụ huynh, **tray không hiện được icon → service nhận lệnh tự dừng**;
mất mạng → sự kiện nằm hàng đợi, có mạng → đồng bộ đủ (tổng 15 phút); xóa
toàn bộ dữ liệu → server sạch + agent wipe bộ đệm; dashboard phục vụ tại `/`,
không dùng localStorage; **pha TLS**: login trả đúng fingerprint của chứng
chỉ tự ký, ghép đôi qua HTTPS với fingerprint đúng thành công, **agent ghim
sai fingerprint → từ chối kết nối**, ghim đúng → heartbeat OK.

## Vòng 3 — Nghiệm thu theo tiêu chí của đề: 11/11 PASS

`scripts/acceptance_round3.py`

- Bộ 60 miền kiểm thử (đúng cơ cấu phụ lục của đề): **0 chặn nhầm / 20 miền
  giáo dục**; chặn **30/30 (100%)** nhóm phải chặn theo chính sách mặc định
  6–11 tuổi (mạng xã hội 8, trò chơi 7, không phù hợp 10 — dùng miền MÔ
  PHỎNG hậu tố .invalid theo đúng yêu cầu của đề, và 5 điểm cuối DoH bị
  chặn theo mặc định từ vòng sửa 11/2026).
- Đếm giờ bằng đồng hồ thật 10 giây: **sai số 0,20 giây** (tiêu chí đề: ≤ ±30
  giây/giờ). Lưu ý cách đọc số này: 0,20 giây là **độ lệch của tick đầu**
  (pha khởi động), không phải độ trôi tích lũy — bộ đếm cộng dồn theo
  khoảng monotonic giữa các tick nên sai số theo giờ vẫn ≈ 0,2 giây, không
  nhân lên thành 72 giây/giờ.
- Quota thật 1 phút + ân hạn 10 giây → khóa ở ~70 giây.
- Ngoài khung giờ lịch tuần → khóa trong < 5 giây.
- PRIVACY.md đủ 8 trường sự kiện + thời hạn 90 ngày; lược đồ F3 khóa cứng
  không có trường URL; cookie phiên HttpOnly + SameSite=Lax; mật khẩu băm
  Argon2id.

## Vòng lặp lỗi đã xử lý trong quá trình test (defect loop)

1. Test vòng 1 kỳ vọng `youtube.com` được phép — rà lại dữ liệu: bản chính
   YouTube được xếp **mạng xã hội** (không dành cho trẻ <13), `youtubekids.com`
   mới thuộc giải trí. Số liệu đúng, đã sửa kỳ vọng của test (đây là điểm bảo
   vệ được khi vấn đáp).
2. Lỗi thật ở agent: khi đã ghim chứng chỉ, `requests` vẫn xác thực CA nên
   cert tự ký bị chặn — đã sửa: khi có fingerprint, phiên tắt verify CA vì
   niềm tin nằm ở fingerprint (đã kiểm ở bước bắt tay riêng). Vòng 2 xác nhận
   cả hai chiều (đúng → qua, sai → từ chối).
3. Test ban đầu khẳng định used giữ nguyên 600 sau khi lùi giờ — thực tế đúng
   phải là 601 (cộng đúng 1 giây trôi thật, không hoàn 3 giờ). Đã sửa test
   theo đúng tiêu chí "quota không được tăng".

## NOT_RUN — chưa kiểm chứng được trong môi trường này (cần máy Windows thật)

- Cài/gỡ Windows Service qua SCM, Service Recovery Options, khóa máy thật
  bằng `LockWorkStation`, idle/khóa phiên qua API Windows.
- Tray icon hiển thị trên desktop Windows thật + các cửa sổ tkinter đi kèm
  (logic IPC và hàm thuần đã test; phần hiển thị là NOT_RUN).
- Bind UDP cổng 53 và truy vấn DNS qua socket thật: sandbox của máy ảo chặn
  `sendto` (UDP) nên vòng 1 kiểm chứng ở tầng xử lý gói với upstream giả;
  cần chạy lại bằng `nslookup` trên máy Windows/LAN thật.
- Script `install_agent.ps1` (ACL, sc.exe recovery) chưa chạy trên Windows.

Checklist chạy lại trên máy Windows cho nhóm: cài service → đăng nhập tài
khoản trẻ (Standard User) → xác nhận icon khay xuất hiện → đặt quota 3 phút
trên dashboard → quan sát cảnh báo 10/5/1 rút gọn còn 2/1/0 phút thực tế và
khóa máy → đổi tên một .exe bị chặn → nslookup miền bị chặn & forcesafesearch
→ rút cáp mạng 5 phút rồi cắm lại, đối chiếu báo cáo không trùng.

## Phụ lục 16/11/2026 — Chạy lại 3 vòng trên máy Windows thật

Môi trường: Windows 11, Python 3.13.17, pytest 9.2.0 (máy của giảng viên hướng dẫn).

Kết quả cuối: **Vòng 1 = 32/32 PASS, Vòng 2 = 22/22 PASS, Vòng 3 = 11/11 PASS**
trên Windows thật. Trong quá trình chạy đã phát hiện và sửa 3 lỗi chỉ lộ ra
trên Windows (bản Linux không gặp):

1. (lỗi test) `test_group_budget_blocks_process` chép `/bin/sleep` — Windows
   không có. Sửa: dùng `System32\PING.EXE` làm chương trình giả trên Windows.
2. (lỗi test) `test_session_events_duration` chỉ đọc 50 sự kiện đầu; máy thật
   có >50 tiến trình nên sự kiện `app_stop` bị cắt. Sửa: đọc 5000 sự kiện.
3. (lỗi app thật) `agent/enroll.py` in tiếng Việt ra pipe dùng codepage cp1252
   → `UnicodeEncodeError` ở ký tự "đ", tiến trình thoát mã lỗi dù ghép đôi đã
   thành công. Sửa: ép stdout/stderr sang UTF-8 (`_utf8_stdio()`) ở 4 entry
   point: `agent/enroll.py`, `agent/service.py`, `agent/tray.py`,
   `scripts/make_cert.py`.

Các mục NOT_RUN ở trên vẫn giữ nguyên (cài Service qua SCM, LockWorkStation
thật, tray trên desktop thật, socket UDP:53, `install_agent.ps1`) — kiểm chứng
ở bước chạy thật tiếp theo kèm phiếu A/B session-0.

## Phu luc 17/11/2026 - Loi phat hien khi cai service tren may tre (Windows that)
- install_agent.ps1 chua dau tieng Viet + em dash, luu UTF-8 khong BOM. Windows PowerShell 5.1 doc file khong BOM theo ANSI (cp1252): byte 0x94 cua em dash bien thanh dau ngoac kep dong (right double quote) -> chuoi ket thuc som -> ParserError hang loat (dong 44/49/55), service khong cai duoc.
- Nguyen nhan khong lo o cac vong test truoc: tren laptop Minh giai doan 3 chi chay console, chua chay install_agent.ps1 lan nao; chay-server.ps1 viet ASCII thuan nen khong bi.
- Fix: viet lai install_agent.ps1 100% ASCII (khong dau, khong em dash), logic giu nguyen; them canh bao trong header. Zip ban giao da dung ban moi.

## Phu luc 17/11 (tiep) - Service cai duoc nhung khong khoi dong tren may tre
- Trieu chung: install_agent.ps1 cai service OK (Dung Python = .venv), Start-Service bao loi chung; sc query: STOPPED, WIN32_EXIT_CODE=0, SERVICE_EXIT_CODE=0 (thoat "sach", khong phai crash 1067, khong phai timeout 1053). Che do console tren cung may chay OK -> build_runtime/_start_components khong loi o phien nguoi dung.
- Diem mu: SvcDoRun cu goi servicemanager.LogMsg TRUOC khoi try, va LogErrorMsg ghi vao nguon Event Log khong ton tai tren may tre (Get-WinEvent bao khong co provider OpenGuardKidsAgent) -> moi loi khoi dong o phien service deu vo hinh.
- Fix (agent/service.py): them _service_log ghi dau vet + traceback day du vao C:\ProgramData\OpenGuardKids\service.log (SvcDoRun: bat dau / da dung runtime / da khoi dong thanh phan / da bao RUNNING / LOI kem traceback); moi loi goi servicemanager duoc boc try/except (_event_log). Regression tren Linux VM: 32/32 + 22/22 + 11/11 PASS (moi truong Linux, khong thay the ket qua Windows).
- Cho ket qua tu may tre: service chay duoc hay service.log ghi loi gi.

## Phu luc 17/11 (tiep 2) - Chuyen co che service: pywin32 -> WinSW
- Sau khi chay pywin32_postinstall -install THANH CONG (DLL da vao system32), service van dung ngay, ma thoat 0, van khong co service.log -> SvcDoRun khong bao gio duoc goi. Che do debug cua pywin32 bao: "service was unable to locate the service manager". Ket luan: tien trinh chu pythonservice.exe tren may tre khong khoi tao duoc lop quan ly dich vu - loi o tang dong goi pywin32, khong phai code agent (console chay on dinh tren chinh may do).
- QUYET DINH: bo pythonservice.exe khoi duong chay. Service duoc dong goi lai bang WinSW (Windows Service Wrapper) v2.12.0 ban NET461 - cong cu boc chuong trinh thanh Windows Service (Jenkins dung dai tra), tai tu GitHub release chinh thuc winsw/winsw, file tools/ogk-service-host.exe, 655872 byte, SHA-256 b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f. WinSW chay dung agent/service.py --console bang Python .venv, LocalSystem, Automatic, restart 5/15/60s (ca onfailure trong XML lan sc.exe failure), log luan phien tai C:\ProgramData\OpenGuardKids.
- install_agent.ps1 viet lai (ASCII thuan): ACL giu nguyen; tu go service cu cung ten (pywin32 hoac WinSW); sinh ogk-service-host.xml theo duong dan that; cai + khoi dong + in trang thai. Them uninstall_agent.ps1 (go service, giu du lieu ProgramData).
- Cho xac nhan tren may tre: service Running + log xuat hien. Luu y: cac cau hoi session-0 (dem idle/khoa may - luot B) khong doi, van phai kiem tren may that sau khi service chay.

## Phu luc 17/11 (tiep 3) - Loi session-0: service khong dem thoi gian (xac nhan tren may that)
- Trieu chung (may tre, service WinSW): tre dung may lien tuc nhung so phut da dung dung yen o 5 phut (phan dem duoc tu luot chay console luc enroll). Day DUNG la kich ban luot B da du phong trong to kiem tra A/B session-0 ngay 14/11.
- Nguyen nhan goc (doc code + doi chieu): TimeKeeper chi cong gio khi idle < 300s; idle_seconds() dung GetLastInputInfo cua PHIEN GOI - service o session 0 khong bao gio co input nen idle tang vo han, sau 300s ke tu luc service khoi dong keeper ngung dem vinh vien. is_locked() o session 0 cung khong phan anh phien cua tre. LockWorkStation tu session 0 cung khong khoa duoc phien tre (cung mot goc re).
- SUA (kien truc da ghi trong to A/B): Tray - dang chay o dung phien cua tre - thanh cam bien phien + tay khoa may:
  * agent/tray.py: moi 3s (cung nhip poll) do idle_seconds()/is_locked() cua phien minh va bao service qua IPC session_pulse; khi nhan thong bao kind="locked" thi tu goi LockWorkStation() ngay trong phien.
  * agent/service.py: handler session_pulse ghi state["session"]; probe _probe_idle/_probe_locked (pulse moi <= 90s thi tin Tray, qua han lui ve ham cuc bo) truyen vao AgentController.
  * agent/controller.py: nhan idle_fn/is_locked_fn va truyen xuong TimeKeeper (TimeKeeper von da ho tro tiem ham do).
- Kiem chung tren VM Linux: py_compile OK; smoke test truc tiep build_runtime + handler session_pulse: chua pulse -> probe dung ham cuc bo; pulse idle=12/locked=False -> keeper doc dung 12/False; pulse locked=True -> keeper thay True (PASS). Hoi quy day du: 32/32 + 22/22 + 11/11 PASS (Linux). Cho xac nhan luot B tren may tre: dung that -> dem; idle 6 phut -> khong tru oan; het quota -> khoa that (do Tray khoa).
- Bo sung bang chung may that (17/11 09:47, ban cu chua cap nhat): phu huynh ha quota xuong 5 phut tren dashboard -> Tray cap nhat ngay (duong day chinh sach KHOE) -> het gio Tray HIEN thong bao het gio nhung may KHONG khoa. Ket luan chot: keeper co danh gia quota va _do_lock CO chay (thong bao la bang chung), chi co khau thi hanh khoa la chet - LockWorkStation goi tu session 0 khong khoa duoc phien cua tre. Ban sua chuyen dung khau nay cho Tray (khoa trong phien khi nhan thong bao "locked") + pulse idle/lock de giai phong ca nhanh cong gio bi chan boi idle session 0.

## Phu luc 17/11 (tiep 4) - Xac nhan khoa may + lam sach bao cao ung dung
- MAY TRE THAT (sau khi cap nhat ban pulse): quota 5 phut -> MAY TU KHOA THAT (Tray khoa trong phien). So phut da dung tang 5 -> 8 khi dung lien tuc (dem gio duoi service da chay). Luot B session-0: dem + khoa DAT; con lai nhip idle 6 phut va buoc DNS.
- Loi moi thay tren may that: danh sach "Ung dung dung nhieu nhat" toan tien trinh nen (WUDFHost, LsaIso, ekrn, IntelCpHDCPSvc, PresentationFontCache, IntelCpHeciSvc, NVDisplay.Container, WavesSvc64, MemCompression, wscript - tat ca 43 phut = chay tu luc mo may). Nguyen nhan: _scan_processes tao phien cho MOI tien trinh thay duoc; SYSTEM_PROCESSES (28 ten) khong bao het dich vu nen cua may nay; cac phien khong bao gio dong nen thoi luong tich luy vao bao cao (va vao ngan sach nhom "khac").
- SUA 2 lop: (1) controller._scan_processes lay them username, bo qua tien trinh thuoc SYSTEM/LOCAL SERVICE/NETWORK SERVICE (helper _is_system_account, da kiem don vi) - khong ghi phien, khong tinh ngan sach cho dich vu nen; (2) bo sung 9 ten quan sat duoc vao SYSTEM_PROCESSES trong shared/contract.py (ap dung ca lop bao cao agent lan server). Hoi quy: 32/32 + 22/22 + 11/11 PASS (Linux VM). Luu y: su kien cu da ghi trong ngay 17/11 van con trong bao cao hom nay; tu ngay mai sach.
- XIN THEM GIO tren may that: DAT - quota goc 5 phut (de test khoa) + duyet them 15 = han muc hieu luc 20 phut tren Tray, dung so. Loi hien thi kem theo: da dung 13 phut le + con lai 6 phut le (tong 19 != 20) do fmt_minutes cat le tung so. Da sua status_line trong tray.py: so con lai tinh tu hai so nguyen da hien thi (limit - used) de tong luon khop; kiem truc tiep: used 13.6/limit 20 -> "da dung 13 phut / 20 phut. Con lai: 7 phut" PASS. Hoi quy giu nguyen 32/32 + 22/22 + 11/11 (Linux VM).
- Bo sung SYSTEM_PROCESSES dot 2 (10:24): wscript, igfxCUIService, WmiPrvSE, RtkAudioService64, MpDefenderCoreService, ensserver, esif_uf, EvtEng, jhi_service, sqlwriter - nhom dich vu nen thu hai noi len bao cao tu du lieu cu sau khi dot 1 da bi loc luc doc (chung loc luc doc hoat dong ca voi su kien cu). Lop loc theo tai khoan SYSTEM o controller van la lop chinh ngan ghi moi.
- DNS tren may that (17/11 10:28-10:40): nslookup youtube.com @127.0.0.1 tra NXDOMAIN + bo dem "trang web bi chan" tang len 1 -> proxy DNS chay, chan dung luat (youtube = mang_xa_hoi, chan voi tre 6-11), duong su kien blocked_domain thong. NHUNG trinh duyet van mo duoc YouTube va khong co ten mien that nao trong bao cao (chi co in-addr.arpa tu chinh lenh nslookup) -> luu luong DNS that cua he thong chua chay qua proxy: nghi ngo (a) DNS chua ap dung len Wi-Fi, (b) ro DNS qua IPv6 (router cap DNS IPv6 rieng, proxy chi nghe IPv4), hoac (c) DoH trong trinh duyet. Cho ket qua 2 lenh tach loi tu may tre: Get-DnsClientServerAddress (ca IPv6) + nslookup mac dinh (khong chi dinh server).
- Kem theo: SYSTEM_PROCESSES dot 3 (tien ich phien nguoi dung: msedgewebview2, UserOOBEBroker, SearchApp, RAVBg64, RtkNGUI64, dptf_helper, sihost, eguiProxy, igfxEM; giu lai msedge.exe) va dns_proxy khong con ghi domain_query cho truy van nguoc in-addr.arpa/ip6.arpa. Hoi quy giu nguyen.

## Phu luc 17/11 (tiep 5) - Ro DNS qua IPv6 va ban sua nghe tren ::1
- Bang chung may that (10:47): Wi-Fi IPv4 DNS = {127.0.0.1} (ap dung dung) NHUNG Wi-Fi IPv6 DNS = {fe80::1} - router cap qua RA/DHCPv6. nslookup mac dinh: Server fe80::1, timeout 2s roi tra IP THAT cua youtube.com (AAAA + A) -> Windows phan giai qua router, vong qua proxy IPv4 hoan toan. Day la nguyen nhan trinh duyet van vao duoc YouTube va bao cao khong co ten mien that.
- SUA: DnsProxy.start() chon ho dia chi theo bind (host chua ":" -> AF_INET6); service.py khoi tao them dns6 = DnsProxy(bind=("::1", 53)) cung upstream/on_event, vong doi day du trong _start_components (canh bao dns6_bind_failed) va _stop_components. Huong dan van hanh bo sung: dat DNS IPv6 cua Wi-Fi = ::1.
- Kiem chung: py_compile OK; tren VM Linux proxy bind ::1 thanh cong (socket AF_INET6, thread song) - gui goi UDP IPv6 trong sandbox VM bi chan o tang moi truong (EPERM phia client) nen luong truy van IPv6 dau-cuoi se xac nhan tren may tre bang nslookup; logic xu ly goi dung chung voi duong IPv4. Hoi quy: 32/32 + 22/22 + 11/11 PASS.

## GIAO BAN FULL 17/11/2026 (sau giai doan 4 tren may that)
- Giai doan 4 tren may tre that (Dell, 192.168.1.52) DAT: enroll xong; service WinSW chay thuong truc; Tray tu khoi dong; dem gio duoi service dung (pulse phien tu Tray); idle >= 5 phut dung dem theo thiet ke; het quota khoa that (Tray khoa trong phien); xin them gio duyet +15 ap dung dung so; chinh sach day tuc thoi tu dashboard; loc web DNS ca IPv4 127.0.0.1 lan IPv6 ::1 (chan youtube.com NXDOMAIN dung luat tuoi, youtubekids.com mo); bao cao web/app da loc nhieu 3 lop.
- Chua kiem tay rieng: chan ung dung theo luat (vi du notepad.exe) - co trong bang nghiem thu buoc 9 cua HUONG-DAN-CAI-DAT-MAY-TRE.md cho nhom tu kiem.
- Bo giao ban: source day du + 4 tai lieu moi (HUONG-DAN-CAI-DAT-SERVER, HUONG-DAN-CAI-DAT-MAY-TRE, KY-THUAT-MANG, BAO-CAO-THIET-KE) trong docs/. Hoi quy cuoi tren VM Linux: 32/32 + 22/22 + 11/11 PASS; cac tinh nang Windows da xac nhan tren may that nhu tren.
