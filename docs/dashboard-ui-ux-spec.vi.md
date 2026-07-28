# Đặc tả UI/UX — NIDS Ops & Evaluation Dashboard

Trạng thái: draft v1. Chưa có implementation nào trong repo (đã grep toàn bộ
`python/`, `scripts/`, `docs/` — không tìm thấy Flask/FastAPI/Streamlit/React
hay thư mục frontend nào). Đây là spec cho một dashboard **mới hoàn toàn**.

## 1. Vì sao cần dashboard này

Hiện trạng repo là một pipeline NIDS (C++ core + Python ML) chạy hoàn toàn qua
CLI, kết quả nằm rải rác dạng file:

- Alert runtime: `run_log/t8.5/detection.jsonl`, `run_log/t8.5/live-attacks/<run-id>/<attack>/`
- Acceptance/receipt: `run_log/<task>/acceptance.json`, `run_log/receipt-index.json` (đang stale)
- Model/eval: `run_log/full-flow-v1/model/manifest.json`, `native-parity.json`
- Lab VM control: `tools/labctl.py status|exec` (SSH tới Kali/Ubuntu/Windows)
- Trạng thái tiến độ: `docs/context.md` (1289 dòng, cập nhật thủ công)

Không có cách nào xem nhanh "hệ thống đang ở trạng thái nào" mà không đọc
nhiều file JSON + một file markdown 1300 dòng. Dashboard giải quyết đúng vấn
đề này — **không phải để thay pipeline**, chỉ để quan sát nó.

## 2. Người dùng & bối cảnh dùng

| Persona | Nhu cầu | Tần suất |
|---|---|---|
| Chính bạn (tác giả) khi demo hội đồng | Trình chiếu live alert khi tấn công từ Kali, chứng minh sensor hoạt động | Một buổi bảo vệ, ~30-45 phút |
| Chính bạn khi làm việc hằng ngày | Xem nhanh: task nào `passed`/`accepted_for_demo`/`deferred`, receipt nào stale | Nhiều lần/ngày |
| Giảng viên hướng dẫn xem lại | Hiểu kiến trúc, xem metric mô hình, không cần đọc code | Vài lần |

Không có multi-user, không cần auth phức tạp — chạy local trên máy Windows
dev, đọc file trong workspace, tuỳ chọn SSH tới Ubuntu qua `labctl`.

## 3. Nguyên tắc bắt buộc (kế thừa từ AGENTS.md — không được vi phạm)

Đây là ràng buộc UX, không phải chỉ backend:

1. **Mọi số liệu hiển thị phải kèm nguồn** (đường dẫn file + hash nếu có).
   Không có ô số liệu "trần" nào không click/hover ra được provenance.
2. **Phân biệt rõ 3 trạng thái quyết định**: `known_attack` (đỏ),
   `unknown_candidate` (vàng cam), `benign` (xanh). Không gộp
   `unknown_candidate` vào "phát hiện thành công" ở bất kỳ label hay tooltip nào.
3. **Badge trạng thái nghiệm thu phải dùng đúng 5 mức** đang tồn tại trong
   repo, không tự chế thêm: `passed`, `technical passed`,
   `accepted_for_demo`, `accepted_for_speed_run_demo`, `deferred_by_current_user`.
   Không tô màu xanh cho `accepted_for_demo` giống hệt `passed` — phải phân
   biệt được bằng mắt (ví dụ: passed = xanh đặc, accepted_for_demo = xanh viền/gạch chéo).
4. **Test partition sealed**: dashboard không được có bất kỳ view/API nào đọc
   `run_log/full-flow-v1/dataset` phần `test`. Nếu chưa unseal, ẩn hẳn control
   đó thay vì disable (disable còn ngầm gợi ý "sắp có").
5. **Giới hạn diễn giải phải hiện cùng số liệu**, không nhét vào trang "About"
   riêng. Ví dụ cạnh `703,99 alerts/hour` luôn có dòng nhỏ "synthetic
   benchmark, không thay thế alerts/hour của detection study T8.1".
6. Không polling/ghi vào bất cứ file `run_log/` nào — dashboard là read-only
   consumer. Hành động duy nhất được phép kích hoạt là `labctl status/exec`
   (đã có sẵn timeout + non-interactive), hiển thị kết quả, không tự động lặp
   lại lệnh nguy hiểm.

## 4. Kiến trúc thông tin — 5 màn hình

```
┌─ Overview (trang chủ)
├─ Live Detection      (alert stream, cho demo)
├─ Lab Topology        (labctl: Kali/Ubuntu/Windows)
├─ Model & Evaluation  (metric, confusion, ablation A-E)
└─ Pipeline Status     (task/phase, receipt, governance)
```

Điều hướng: sidebar trái cố định, 5 mục trên. Không có nested nav sâu hơn
2 cấp — người dùng ADHD-thời-gian-ít (chính bạn, giữa lúc chạy pipeline) cần
thấy trạng thái trong ≤2 click.

## 5. Đặc tả từng màn hình

### 5.1 Overview

Mục đích: trả lời "hệ thống ổn không" trong 5 giây.

Bố cục: 4 thẻ trạng thái (status tile) hàng trên, timeline addendum bên dưới.

| Thẻ | Nguồn dữ liệu | Nội dung |
|---|---|---|
| Active task | `config/agent/current-task.json` | task/phase hiện tại, mode, priority |
| Pipeline health | `run_log/*/acceptance.json` mới nhất theo mtime | N passed / M accepted_for_demo / K deferred |
| Lab VM | cache kết quả `labctl status` gần nhất (nếu có) | 3 chấm tròn Kali/Ubuntu/Windows: xanh=ok, xám=chưa probe, đỏ=lỗi |
| Model production | `run_log/full-flow-v1/model/manifest.json` | profile đã chọn, threshold, ngày publish |

Bên dưới: danh sách addendum rút từ `docs/context.md` (parse heading `##
Addendum DD/MM/YYYY - ...`), mới nhất trên đầu, mỗi item là 1 dòng có thể
expand ra đoạn markdown gốc. Đây là cách duy nhất tránh phải đọc 1300 dòng.

Trạng thái rỗng: nếu `config/agent/current-task.json` không tồn tại, thẻ hiện
"Không có active task" — không hiện số 0 gây hiểu lầm là "0 lỗi".

### 5.2 Live Detection

Mục đích chính: **demo trước hội đồng**. Đây là màn hình quan trọng nhất về
mặt trình diễn.

Nguồn dữ liệu: tail `run_log/t8.5/detection.jsonl` hoặc file tương ứng do
người dùng chọn (dropdown chọn run: `t8.5/detection.jsonl`,
`t8.5/live-attacks/<run-id>/<attack>/*.jsonl`, ...). File append-only, dashboard
tail bằng polling mtime+offset mỗi 1s (không cần websocket cho local file nhỏ).

Bố cục:
- Header: chọn nguồn log + nút "Pause/Resume tail" + đồng hồ tổng số alert theo 3 loại.
- Bảng alert realtime, mới nhất trên đầu, cột:
  `timestamp | decision (badge màu) | candidate family | confidence | flow 5-tuple (che 1 phần IP nếu demo public) | probability`.
- Click 1 dòng → panel chi tiết bên phải: raw JSON gốc + breadcrumb checkpoint
  (F3→F5→F7→F9, tô đậm checkpoint mà quyết định này dựa vào — hiện tại luôn F9
  vì runtime là F9-only, phải ghi chú rõ điều này ngay trên panel).
- Banner cảnh báo cố định phía trên bảng khi nguồn dữ liệu là log rehearsal
  (`live-attacks/teacher-demo-*`): "Dữ liệu rehearsal, `unknown_candidate` với
  candidate `DDoS`/`DoS GoldenEye` — không phải xác nhận đúng family."
- Sparkline nhỏ alerts/phút ở header — có tooltip nhắc synthetic benchmark
  rate không áp dụng cho log detection study thật.

Trạng thái lỗi: file log bị xoá/không tồn tại giữa lúc tail → banner đỏ "Mất
kết nối tới log, dữ liệu đứng lúc <timestamp cuối>", không tự retry im lặng.

### 5.3 Lab Topology

Mục đích: xem trạng thái 3 VM và bắn lệnh chẩn đoán bounded qua `labctl`,
thay thế việc gõ CLI thủ công khi demo.

Bố cục: sơ đồ mạng tĩnh (SVG, không phải diagram tương tác phức tạp) vẽ lại
đúng bảng trong `docs/context.md`:

```
Kali (eth1, VMnet1, 192.168.252.10)  ──┐
                                        ├─ VMnet1 host-only (data)
Windows victim (VMnet1, 192.168.252.20)┘
Ubuntu sensor: ens160 (VMnet1, data, passive RX-only)
               ens33  (VMnet8 NAT, management, 192.168.100.100)
```

Mỗi node là một status pill (dùng dữ liệu `labctl status` cache), click vào
node → panel chạy `labctl exec <role> "<command>"` với **whitelist lệnh cố
định trong config**, không có ô input tự do (tránh biến dashboard thành shell
console không kiểm soát). Whitelist ban đầu: `hostname`, `uptime`, `ip addr
show ens160`/`eth1`, các script đã có `run_t85_live_sensor_ubuntu.sh --status`
nếu tồn tại.

Nút "Refresh trạng thái" gọi `labctl.py status` (đồng bộ, có timeout hiện có
sẵn trong tool) — không tự động polling nền, vì mỗi lần status là một
`vmrun`+SSH round-trip thật, không phải đọc file rẻ.

Trạng thái đặc biệt phải hiển thị đúng — không được gộp:
`ok` / `remote_error` / `ssh_error` / `timeout` / `local_error` /
`discovery_error` / `powered_off` / `user_confirmation_required` (5 mức khác
nhau ngoài ok, xem `tools/labctl.py`). Nếu `user_confirmation_required=true`,
hiện đúng câu hỏi lấy từ JSON response, có nút "Đã xác nhận, thử lại" — không
tự đoán trạng thái VM.

### 5.4 Model & Evaluation

Mục đích: trình bày kết quả nghiên cứu (dùng khi bảo vệ và khi viết báo cáo).

Tabs con:
- **F9 baseline (schema 54 feature)**: bảng recall/FPR đã khoá — known
  recall 99,884%, unknown recall 41,471%, benign FPR 0,119% — kèm ghi chú
  "unknown recall đo trên family bị giữ lại của từng anomaly model, không
  phải tỉ lệ runtime gắn nhãn unknown_candidate; macro unknown-candidate
  recall sau fusion hiệu chuẩn là 0,162%, PortScan case study 0%" (lấy đúng
  nguyên văn từ `docs/final-report.vi.md`, không diễn giải lại).
- **Terminal full-flow (T9.1, 70 feature, profile A-E)**: bảng so sánh 5
  profile, cột length 54/61/64/66/70, đánh dấu profile A là profile được
  chọn production (threshold `0.9984837643022101`), biểu đồ cột validation
  attack recall / benign FPR / macro F1 theo family (Benign, FTP-Bruteforce,
  SSH-Bruteforce, PortScan, DoS, Other) — dữ liệu lấy từ
  `run_log/full-flow-v1/model/manifest.json`.
- **Parity**: bảng Python ORT vs Native, max abs probability error, so với
  tolerance 1e-5 — vẽ dạng thanh ngang error/tolerance để thấy trực quan biên
  an toàn (2.87e-7 và 1.23e-7 đều rất nhỏ so với 1e-5).
- **Sealed test banner**: mọi tab của màn hình này có banner cố định trên
  cùng "Test partition: sealed — 0 feature/metric reads. Không hiển thị vì
  chưa unseal", kèm nút xám "Xem trạng thái unseal" dẫn tới điều kiện unseal
  (đã khoá model/threshold/algorithm) lấy từ `docs/context.md`.

Không vẽ confusion matrix bằng dữ liệu suy diễn nếu repo chưa publish ma
trận thật — chỉ vẽ khi có file nguồn (`validation-predictions.npz` cộng
với script tính). Nếu chưa có, để trống kèm nút "Chưa có — cần
`scripts/` tính từ `validation-predictions.npz`".

### 5.5 Pipeline Status (governance)

Mục đích: bảng T0–T9.1 theo phase, thay thế phần "Tiến độ theo phase" trong
`docs/context.md` bằng UI có thể lọc/sort.

Bảng: `Task | Phase | Trạng thái | Receipt path | SHA-256 (rút gọn, hover xem
đủ) | Ghi chú giới hạn`. Dữ liệu nguồn: bảng "Receipt chính" trong
`docs/context.md` + `run_log/receipt-index.json`.

Vì `receipt-index.json` được ghi rõ là **stale từ T5.2 trở đi**, dashboard
phải hiện banner đỏ cố định ở đầu bảng: "receipt-index.json stale từ T5.2,
không dùng làm trạng thái cuối — nguồn đúng là bảng Receipt chính trong
context.md" và tô mờ (không xoá) các dòng lấy từ index để phân biệt với dòng
lấy từ context.md.

Filter theo trạng thái (5 mức ở mục 3.3), filter theo phase (0-9).

## 6. Design system

- **Màu trạng thái quyết định** (dùng nhất quán toàn app, không dùng lại cho
  mục đích khác): known_attack = đỏ `#dc2626`, unknown_candidate = cam
  `#f59e0b`, benign = xanh lá `#16a34a`, uncertain = xám xanh `#64748b`.
- **Màu trạng thái nghiệm thu** (khác hệ màu ở trên để không lẫn):
  passed = xanh dương đặc `#2563eb`, technical passed = xanh dương viền,
  accepted_for_demo = tím `#7c3aed` nét đứt viền, accepted_for_speed_run_demo
  = tím nhạt hơn + icon đồng hồ, deferred_by_current_user = xám `#94a3b8`.
- Typography: monospace cho mọi hash/path/JSON (`ui-monospace, "Cascadia Code"`),
  sans-serif cho label/prose.
- Dark mode mặc định (dùng ban đêm khi debug pipeline), light mode cho máy
  chiếu lúc bảo vệ — toggle ở header, không theo system vì phòng hội đồng
  ánh sáng khác nhau thất thường.
- Không dùng animation ở bảng alert (Live Detection) ngoài fade-in nhẹ 150ms
  cho dòng mới — tránh giật mắt khi tail nhanh lúc hping3 bắn hàng nghìn gói.

## 7. Tech stack đề xuất (tối thiểu, phù hợp máy dev Windows đơn lẻ)

- Backend: FastAPI (Python), đọc trực tiếp file trong `run_log/`, `docs/`,
  `config/` — không DB, không cache bền vững ngoài in-memory tail offset.
- Tail file: watch mtime, đọc phần mới bằng offset lưu in-memory — đủ cho 1
  process, không cần Kafka/queue.
- Frontend: React + Vite, no heavy state library cần thiết (dữ liệu ít, poll
  đơn giản đủ dùng — dùng SWR/React Query cho polling định kỳ 1-2s ở Live
  Detection, on-demand fetch ở các tab khác).
- Biểu đồ: Recharts (bar/line đơn giản, không cần D3 tuỳ biến nặng cho scope này).
- Không cần auth (chạy local). Nếu demo qua máy chiếu nối mạng chung, bind
  `127.0.0.1` mặc định, không mở ra `0.0.0.0`.

## 8. MVP vs Full

| Ưu tiên | Màn hình | Lý do |
|---|---|---|
| P0 (bắt buộc trước bảo vệ) | Live Detection, Overview | Cái hội đồng nhìn thấy trực tiếp |
| P1 | Model & Evaluation | Trả lời câu hỏi số liệu khi hội đồng chất vấn |
| P2 | Lab Topology (view-only, bỏ phần exec whitelist) | Đẹp nhưng không bắt buộc để chứng minh kết quả |
| P3 | Pipeline Status, Lab Topology exec | Có ích cho việc bạn tự quản lý, không cần cho buổi bảo vệ |

Ước lượng thời gian build riêng phần P0 (Overview + Live Detection, FastAPI +
React tối giản, không auth, không test suite đầy đủ): **1.5–2 ngày làm việc**
cho một người đã quen stack, giả định schema JSONL alert đã ổn định (không
đổi format `nids_alert` giữa chừng).

## 9. Rủi ro/giả định cần xác nhận trước khi code

1. Format chính xác của một dòng `nids_alert` trong `detection.jsonl`
   (field names) chưa được xem trực tiếp trong phiên đọc workspace này — chỉ
   suy ra từ mô tả trong `docs/final-report.vi.md`/`docs/context.md`. Cần
   `officecli`/`Read` trực tiếp 1 file JSONL thật trước khi code parser.
2. `run_log/receipt-index.json` stale — cần quyết định dashboard đọc trực
   tiếp từng `acceptance.json` (chậm hơn, đúng hơn) hay đợi index được fix.
   Spec này giả định đọc trực tiếp từng acceptance.json.
3. Chưa rõ có muốn dashboard chạy được trên Ubuntu (đọc `/mnt/hgfs/TTTN`) hay
   chỉ Windows — ảnh hưởng path handling. Giả định hiện tại: chạy trên
   Windows, đọc `E:\DATTTN\TTTN` cục bộ.

---

## 10. Ước lượng token của phiên làm việc này

Đây là ước lượng, không phải số đo chính xác (client không lộ token-per-call
count) — công cụ đếm token không có trong bộ tool hiện tại.

| Hạng mục | Ước lượng token | Ghi chú |
|---|---:|---|
| Đọc `docs/context.md` (1289 dòng) | ~26.000–30.000 | 2 lần Read (đã bị truncate 1 lần, phải đọc tiếp offset 909) |
| Đọc `AGENTS.md`, `draft-t91-labctl.md`, `plan-2.md` (phần đầu), grep/bash output | ~5.000–7.000 | |
| System prompt + skill/tool schema nạp sẵn (ADHD skill, memory system, tool list) | ~8.000–12.000 | Cố định mỗi lượt, không phụ thuộc task |
| Suy luận + soạn thảo spec này (output) | ~3.500–4.500 | Văn bản tiếng Việt, ~2.400 từ |
| **Tổng phiên này (input+output, ước lượng)** | **~45.000–55.000 token** | Tương đương một request tầm trung, không phải toàn workspace |

**Không đọc hết workspace theo nghĩa đen** — repo có C++ (`cpp/`), hàng chục
script Python (`scripts/`), `python/nids_mvp/*.py`, hai file `.docx` báo cáo
(375KB + 440KB), `run_log/` (log thật). Đọc toàn bộ các file này sẽ tốn thêm
đáng kể:

| Nếu đọc thêm | Ước lượng token |
|---|---:|
| Toàn bộ `python/nids_mvp/*.py` (~20 file, nhiều file >500 dòng theo tên gọi) | +40.000–80.000 |
| Toàn bộ `cpp/include` + `cpp/src` + `cpp/tests` | +30.000–60.000 |
| Toàn bộ `scripts/*.py` (~40+ script) | +50.000–100.000 |
| Nội dung hai file `.docx` báo cáo | +20.000–35.000 (docx text, không tính ảnh/bảng phức tạp) |
| `run_log/` đầy đủ (nhiều JSON/JSONL) | biến thiên lớn, có thể +50.000+ nếu JSONL alert dài |

Nếu cần độ chính xác cao hơn cho toàn bộ workspace (ví dụ để lập ngân sách
token cho một agent chạy tự động dài hơi), nên đo trực tiếp bằng
`tokenizer`/`tiktoken`-tương-đương trên các file thật thay vì ước lượng theo
số dòng như trên — cách này sẽ cho số chính xác thay vì khoảng ước lượng.
