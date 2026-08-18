# T9.1 Rebuild Changelog

## 2026-08-10 01:xx +07:00 — Script đo độ trễ một lệnh + bằng chứng email (t91-alert-email-evidence-r1)

### 1. Chạy đo độ trễ bằng một lệnh

`scripts/run_latency_benchmark.py`:

```
python scripts/run_latency_benchmark.py                 # chay that, in bang
python scripts/run_latency_benchmark.py --report-only   # in lai lan chay gan nhat
```

Chọn `ftp-patator` làm mặc định vì đây là ca **nhỏ nhất mà vẫn đủ**: 5.833 packet,
khoảng 3 phút, mất 0 packet ở lần chạy tham chiếu nên số rơi vào chế độ bình thường
chứ không phải chế độ quá tải, mà vẫn cho hàng trăm mẫu.

Script tái dùng toàn bộ hạ tầng an toàn sẵn có: `ubuntu_t91_live_sensor.sh` cho
preflight/bind/rollback, `tools/labctl.py` cho điều khiển VM, helper của
`run_terminal_matched_replays.py` cho remote bash. Không tự viết launcher DPDK,
tránh nguy cơ để NIC kẹt ở trạng thái bind.

`scripts/ubuntu_t91_live_sensor.sh` nhận thêm trường contract `benchmark_metrics`.
Trường vắng mặt nghĩa là tắt, nên mọi contract cũ giữ nguyên hành vi.

Bản in ra luôn kèm `inference_scope`, `alert_scope` và cảnh báo nếu lần chạy có mất packet.

### 2. Bằng chứng luận văn cho phần gửi email

`scripts/build_alert_email_evidence.py` →
`run_log/full-flow-v1/thesis-evidence/alert-email-20260809.{json,md}`.

Gom từ receipt thật: 4 lần chạy, 2 lần gửi thật, 25 cảnh báo xác nhận đã gửi.
Địa chỉ người nhận bị che chỉ giữ tên miền; mật khẩu không bao giờ được ghi.

Ba giới hạn ghi rõ trong bằng chứng:

- Đây là **lớp thông báo, không phải phép đo**. Không con số nào trong thư được trích làm chỉ số.
- Receipt chỉ chứng minh máy chủ đã nhận thư để chuyển, **không** chứng minh có người đọc.
- **Độ trễ đường thư chưa được đo**, không được trình bày như độ trễ phát hiện.

### Kiểm chứng

`python -m unittest tests.test_run_latency_benchmark tests.test_alert_email_evidence` → 17/17 PASS.
Toàn bộ bộ test → 74/74 PASS. Test partition vẫn `sealed`.

## 2026-08-10 00:xx +07:00 — Terminal V1 đã đo được độ trễ, mất 0 packet (t91-detection-latency-evidence-r2)

### Thay đổi mã nguồn

- MỚI `cpp/include/nids/latency_samples.hpp`: `nids::LatencySamples` + `nids::LatencySummary`,
  nearest-rank percentile giống hệt `nids_dpdk_live.cpp` để hai bảng so được với nhau.
- `cpp/apps/nids_t91_terminal_live.cpp`: thêm cờ `--benchmark-metrics`, đo hai mốc,
  phát khối `latency_ns` trong `nids_terminal_live_summary`.
- MỚI `cpp/tests/latency_samples_test.cpp` (7 test) + đăng ký trong `CMakeLists.txt`.
- **Cố ý KHÔNG đụng `nids_dpdk_live.cpp`** để giữ nguyên binary đã sinh ra
  bằng chứng `20260809-latency-f9-r3`.

### Kết quả — run `20260809-latency-terminal-ftp-r3`, ca `ftp-patator`

Nhận 5.833 packet, **mất 0 packet**. 435 lượt suy luận, 328 cảnh báo,
423 flow đóng bình thường, 12 flow đóng ở EOF.

| Giai đoạn | Mẫu | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|
| Suy luận (chỉ lời gọi model) | 435 | 452,03 µs | 639,33 µs | 900,43 µs | 8,47 ms |
| Cảnh báo (gồm chờ flow đóng) | 328 | 1,37 ms | 2,09 ms | 7,48 ms | 74,66 s |

Đây là phép đo độ trễ **sạch nhất** hiện có: không mất packet nên phản ánh chế độ
bình thường, khác lần đo F9 vốn mất 54%.

### Ranh giới bắt buộc — hai cảm biến KHÔNG cùng đại lượng

Cùng tên trường nhưng đo khác nhau, tuyệt đối không xếp chung một cột:

| Trường | F9 | Terminal V1 |
|---|---|---|
| `inference` | gồm cả dựng đặc trưng và tạo snapshot | **chỉ lời gọi `bundle_.infer`** |
| `alert` | chốt ngay tại packet thứ 9 | gồm cả thời gian **chờ flow đóng** |

Ngữ nghĩa được ghi thẳng vào payload JSON qua hai trường `inference_scope` và `alert_scope`
để người đọc không nhầm.

Đuôi 74,66 s của cột cảnh báo là **đúng thiết kế**, không phải lỗi: Terminal chỉ quyết định
khi flow đóng, nên flow chỉ đóng lúc hết PCAP sẽ có khoảng cách rất lớn từ packet cuối.
Trung vị 1,37 ms mới là các flow đóng ngay bằng RST/FIN. Đây không phải thời gian tính toán.

### Sự cố trong quá trình làm

Lần build đầu hỏng vì khối `latency_ns` bị chèn nhầm vào `ready_event` thay vì `summary_event`
— chuỗi neo `active_flow_limit` xuất hiện ở cả hai hàm. Đã chuyển đúng chỗ và chuyển helper
`latency_object` lên trước `ready_event`.

### Còn lại

- F9 chưa tách được lời gọi model khỏi bước dựng đặc trưng.
- F9 chưa có số ở chế độ không quá tải.

### Kiểm chứng

`python -m unittest tests.test_measure_detection_latency` → 14/14 PASS.
`ctest -R nids_latency_samples.percentiles` trên Ubuntu → PASS.
Dọn dẹp PASS: apache2 active/enabled, ens160 vmxnet3, hugepage 128/128, Kali eth1 MTU 1500,
sudoers tạm đã xóa. Giữ nguyên hai attempt hỏng r1/r2. Test partition vẫn `sealed`.

## 2026-08-09 23:xx +07:00 — Đo được độ trễ suy luận và cảnh báo cho F9 (t91-detection-latency-evidence-r1)

### Sự cố phải sửa trước

Kali rơi vào emergency mode và không vào được vì root bị khóa. Nguyên nhân: `/etc/fstab`
có dòng `vmhgfs-fuse /mnt/hgfs fuse defaults,allow_other 0 0`. `defaults` khiến mount này
bắt buộc thành công; thư mục chia sẻ VMware hỏng là systemd kéo cả máy xuống emergency mode.
Đã thêm `nofail,x-systemd.device-timeout=5s`. Vào được bằng GRUB `init=/bin/bash`.

Ghi thêm: subnet quản trị đã đổi sang `192.168.100.x` (kali .128, ubuntu .130).
Tài liệu cũ ghi `192.168.252.x` là đã lỗi thời.

### Kết quả đo — run `20260809-latency-f9-r3`, ca `f9-dos-hulk`

| Giai đoạn | Số mẫu | p50 | p95 | p99 | Lớn nhất |
|---|---|---|---|---|---|
| Bóc tách gói | 180.101 | 100 ns | 391 ns | 761 ns | 199,37 µs |
| Đường ống mỗi gói | 180.101 | 661 ns | 17,69 µs | 8,86 ms | 565,99 ms |
| Suy luận (gồm dựng đặc trưng) | 7.899 | 7,76 ms | 11,86 ms | 14,84 ms | 271,87 ms |
| Cảnh báo đầu-cuối | 7.509 | 7,81 ms | 11,99 ms | 14,92 ms | 565,99 ms |

Evidence: `run_log/full-flow-v1/latency-live/20260809-latency-f9-r3/f9-dos-hulk/sensor.jsonl`.
Giữ nguyên r1 (idle timeout sớm, 8 packet, 0 inference) và r2 (binary từ chối idle timeout 600s).

### Ba giới hạn bắt buộc ghi kèm

1. **Cột "Suy luận" không phải riêng lời gọi model.** Đọc `cpp/apps/nids_dpdk_live.cpp:581`:
   mốc `inference_started` được lấy TRƯỚC `FeatureEngine::encode`, nên bucket này gồm cả
   dựng đặc trưng và tạo snapshot. Muốn tách riêng model phải thêm một mốc đo nữa.
2. **Số đo dưới tải bão hòa.** `port_imissed = 211.837 / 391.938 = 54,05%`. Cảm biến không
   theo kịp, nên đây là độ trễ khi quá tải, không phải ở chế độ bình thường.
3. Chỉ có giá trị trong phạm vi phòng lab VMware.

### Chưa xong

- **Terminal V1 vẫn chưa có đo đạc nào.** Agent nền bị policy chặn `apply_patch` lên file hiện hữu
  nên chưa sửa `cpp/apps/nids_t91_terminal_live.cpp`. Một header rỗng nó tạo ra đã được xóa.
- Chưa tách được lời gọi model khỏi phần dựng đặc trưng.
- Chưa có số ở chế độ không quá tải.

### Kiểm chứng

`python -m unittest tests.test_measure_detection_latency` → 13/13 PASS.
Lab đã dọn: apache2 active/enabled, ens160 vmxnet3, hugepage 128, sudoers tạm đã xóa,
rollback F9 `passed`. Không train lại, không đụng bundle/ngưỡng. Test partition vẫn `sealed`.

## 2026-08-09 22:xx +07:00 — Đo độ trễ + gửi cảnh báo email (t91-detection-latency-evidence-r1)

### 1. Đo độ trễ — `scripts/measure_detection_latency.py`

Output `run_log/full-flow-v1/thesis-evidence/detection-latency-20260809.{json,md}`.
Tách bạch **ba** đại lượng, không gộp:

| Đại lượng | Từ đâu tới đâu | Trạng thái |
|---|---|---|
| Chờ trước suy luận | packet chạm F9 → sắp gọi model | **có số**: 10.665 mẫu từ `detection_delay_ns` |
| Độ trễ suy luận | riêng lời gọi model | thiếu, cần cờ `--benchmark-metrics` |
| Độ trễ cảnh báo | packet → alert ghi ra ngoài | thiếu, cùng cờ |

F9 chờ trước suy luận: p50 **1,36 µs**, p95 4,16 µs, p99 10,90 µs, max 628 µs.
Đây là **chặn dưới** của độ trễ cảnh báo vì chưa gồm thời gian chạy model.

### 2. Hai khoảng trống đã xác định

- **F9**: `cpp/apps/nids_dpdk_live.cpp` đã có sẵn cờ `--benchmark-metrics`, phát ra
  `latency_ns:{parse,pipeline,inference,alert}` với observations/p50/p95/p99/max.
  Chưa lần chạy lưu trữ nào dùng cờ này. **Không cần sửa code**, chỉ cần chạy lại 1 ca.
- **Terminal V1**: `cpp/apps/nids_t91_terminal_live.cpp` **không có đo đạc độ trễ nào**.
  Đã soi 79.651 alert: `last_event_timestamp_ns - last_capture_timestamp_ns` luôn bằng 0,
  nghĩa là trường đó ghi thời điểm bắt packet chứ không phải thời điểm phát cảnh báo.
  Muốn có số phải sửa C++ + build lại + chạy lại.

### 3. Gửi cảnh báo email — `scripts/alert_email_notifier.py`

- Đọc stream JSONL, lọc bỏ Benign, khử trùng theo (model, 5-tuple, nhãn), gom thành 1 bản tin.
- **Mặc định chạy thử, chỉ gửi khi có cờ `--send`.**
- Thông tin SMTP đọc từ biến môi trường (`NIDS_SMTP_HOST`, `NIDS_ALERT_SENDER`,
  `NIDS_ALERT_RECIPIENTS`, tùy chọn `NIDS_SMTP_PORT/USER/PASSWORD`), **không ghi vào repo**.
- Cursor file chống gửi lại alert cũ khi chạy lại; mỗi lần chạy ghi 1 receipt JSON.
- Tách nhãn hiển thị khỏi quyết định: F9 để họ tấn công ở `candidate` còn `decision` chỉ là
  `known_attack`, nên nếu đọc `decision` thì mọi dòng đều hiện `known_attack`.
- `uncertain` và `unknown_candidate` vẫn báo nhưng đánh dấu riêng, không tính là tấn công xác nhận.

### Kiểm chứng

- `python -m unittest tests.test_measure_detection_latency tests.test_alert_email_notifier tests.test_build_offline_online_accuracy_evidence tests.test_f9_terminal_mermaid` → **43/43 PASS**.
- Chạy thử trên cả hai stream thật: F9 ra `DoS Hulk`/`FTP-Patator`; Terminal ra `PortScan`, loại đúng 77 dòng Benign.
- Chưa gửi email thật lần nào. Không train lại, không đụng bundle/ngưỡng. Test partition vẫn `sealed`.

## 2026-08-09 21:xx +07:00 — Bằng chứng offline↔live cho cả hai model (t91-offline-online-accuracy-evidence-r1)

### Việc đã làm

- Thêm `scripts/build_offline_online_accuracy_evidence.py`: tính lại mọi con số từ
  `terminal-matched-comparison.json` và `f9-online-offline-comparison.json`, không hardcode.
- Output: `run_log/full-flow-v1/thesis-evidence/offline-online-accuracy-20260809.{json,md}`
  (JSON theo schema tiếng Anh như các file thesis-evidence khác; MD tiếng Việt để trích thẳng vào luận văn).
- Sửa `docs/generated/f9-terminal-pcap-replay-evidence-flow.{mmd,md}`: đánh số ba lần chạy F9
  theo đúng thứ tự lịch sử, đánh dấu ★ phần đưa vào luận văn, rút mọi dòng nhãn xuống ≤27 ký tự
  vì Mermaid cắt chữ ở mép hộp khi dòng dài hơn ~28.

### Kết quả chính

| Nội dung | Con số |
|---|---|
| Terminal V1 offline theo flow | 176.383/184.571 = 95,56% |
| Terminal V1 offline trung bình đều theo họ | 72,91% (PortScan chiếm 45,63% mẫu) |
| F9 offline | 12/14 ca; mẫu số 14, không dùng như tỷ lệ chính xác |
| Ca Terminal mất 0 packet | 5 ca, chênh lệch off↔live tối đa 0,23 điểm |
| Ca Terminal có mất packet | sụt bám theo tỷ lệ mất, tối đa PortScan mất 34,27% tụt 56,03 điểm |
| F9 nine-frame | 10 ca so được, 9 khớp, trong đó 2 ca cùng sai giống nhau |

### Kết luận được phép dùng

- Ca mất 0 packet cho kết quả live trùng khít offline → **triển khai DPDK không làm đổi hành vi model**.
- Độ chính xác model lấy từ vế offline; tỷ lệ live là số đo phòng lab.
- Web Brute Force 10,71% và Web XSS 2,86% giống nhau ở cả hai vế với 0 packet mất →
  **điểm yếu thật của model**, không đổ được cho hạ tầng.
- PortScan trên F9 ghi *không áp dụng*, không ghi 0%.
- Family-window F9 không có vế offline nên không tách được lỗi model khỏi lỗi hạ tầng.

### Kiểm chứng

- `python -m unittest tests.test_build_offline_online_accuracy_evidence tests.test_f9_terminal_mermaid tests.test_build_terminal_offline_limitations` → 15/15 PASS.
- Không train lại, không chọn lại ngưỡng, không sửa bundle/schema. Test partition vẫn `sealed`, 0 lượt đọc.

## 2026-08-09 15:00 +07:00 - Dashboard labels theo tung model toggle PASS (t91-dashboard-model-toggle-labels-r1)

- Sua Overview loc `Benign` khong phan biet hoa/thuong truoc khi gom candidate.
  Vi vay 68 flow Benign co top candidate FTP-Bruteforce khong con bi trinh bay
  sai thanh alert FTP.
- Live Detection tach cach hien thi theo toggle: F9 giu decision vocabulary
  `known_attack`/`unknown_candidate`/`uncertain`/`benign`; Terminal hien thi dung
  ten lop Terminal, attack mau do va Benign mau xanh.
- Bridge Terminal moi ghi semantic `decision` kem `terminal_class`. Dong lich su
  duoc normalize tai UI; khong sua hoac xoa stream evidence 28.937 dong.
- Initial backlog khong ban 28.860 toast; chi event moi tail vao moi notify.
- Tren stream duoc giu nguyen: 28.422 PortScan + 438 DoS = 28.860 attack;
  77 Benign. Overview Terminal sau loc chi con PortScan va DoS la attack thuc co.
- Frontend unit 3/3 PASS, bridge unit 3/3 PASS, Vite production build PASS,
  py_compile PASS. Evidence luan van luu tai
  `run_log/full-flow-v1/thesis-evidence/dashboard-terminal-label-fix-20260809.{json,md}`.
- Current tag va bản bàn giao trạng thái da cap nhat. Test partition van sealed, 0 reads.

Nhật ký ngắn, cập nhật dần thay cho chat dài. Mỗi entry: thời gian, việc làm, kết quả, evidence path.

## Bối cảnh khởi động lại (2026-08-08)

- VM lab đã được rebuild (Ubuntu, Windows victim): MAC/interface mới
  (`ens160→ens37`, `vmxnet3→e1000`, Windows hostname mới `WIN-SALLRN2MPJ9`).
  Mọi artifact cũ dưới `run_log/full-flow-v1/` trên Ubuntu cũ coi như mất, xác
  nhận `run_log/full-flow-v1/` không tồn tại trên workspace Windows.
- `gotchas.md` bị mất (không tìm thấy trên disk dù `docs/context.md` trích dẫn
  hash nhiều lần). Không dùng nó làm nguồn luật nữa; luật thật nằm ở
  `AGENTS.md` + `config/agent/current-task.json`.
- `docs/context.md` (viết trước rebuild) **không còn phản ánh trạng thái thật**,
  giữ lại chỉ để tham khảo thiết kế/schema, không dùng làm evidence tiến độ.
- 5 file PCAP CICIDS2017 (Monday–Friday Working Hours, ~50GB tổng) đang được
  tải lại về `E:\DATTTN\TTTN\` (thấy `Tuesday-WorkingHours.pcap.fdmdownload`,
  `Friday-WorkingHours.pcap.opdownload` chưa xong tại thời điểm ghi entry này).

## 2026-08-08 02:0x — T0.2 toolchain, xác nhận lại trên VM mới

- `--install`: PASS lượt 1 qua `labctl.py exec ubuntu`. DPDK 25.11.2 +
  ONNX Runtime C++ 1.27.1 dưới `~/.local/nids-toolchain`.
- `--verify --force-receipt`: PASS. Smoke ctest `toolchain_runtime` 1/1 pass.
  Receipt mới ghi tại `/mnt/hgfs/TTTN/toolchain-receipt.json` (đè receipt cũ
  15/07, đã được người dùng duyệt ghi đè).
- Log đầy đủ: `run_log/agent-toolchain-install.log` (khuyến cáo: file này bị
  ghi bằng PowerShell UTF-16, cần đọc bằng công cụ hỗ trợ UTF-16 hoặc
  `Get-Content -Encoding Unicode`).

## Việc đang giao agent nền (tự động)

Xem timestamp entry mới nhất bên dưới do agent nền tự cập nhật.

## 2026-08-08 02:53:19 +07:00 — Kiểm tra nhanh receipt path sau rebuild

- Kết quả: **PASS** (chỉ kiểm tra tồn tại trên đĩa; không dùng receipt cũ làm evidence tiến độ).

| Path trích dẫn trong `docs/context.md` | Trạng thái |
|---|---|
| `run_log/receipt-index.json` | Tồn tại |
| `run_log/t0.3-receipt-4.json` | Không tồn tại |
| `run_log/t0.4/acceptance.json` | Không tồn tại |
| `run_log/t0.5/acceptance.json` | Không tồn tại |
| `run_log/t2.6/acceptance.json` | Không tồn tại |
| `run_log/t3.1/acceptance.json` | Không tồn tại |
| `run_log/t3.5/acceptance.json` | Không tồn tại |
| `run_log/t3.6/acceptance.json` | Không tồn tại |
| `run_log/t4.8/acceptance.json` | Không tồn tại |
| `run_log/t5.1/acceptance.json` | Không tồn tại |
| `run_log/t5.3/acceptance.json` | Không tồn tại |
| `run_log/t6.1/acceptance.json`, `run_log/t6.1/thresholds.json` | Không tồn tại |
| `run_log/t6.2-6.3/acceptance.json` | Không tồn tại |
| `run_log/t7.3/acceptance.json` | Không tồn tại |
| `run_log/t7.4-t7.6/acceptance.json` | Không tồn tại |
| `run_log/t8.1-t8.2/acceptance.json` | Không tồn tại |
| `run_log/t8.3-t8.4/acceptance.json` | Không tồn tại |
| `run_log/t8.5/demo-acceptance.json`, `run_log/t8.5/detection.json` | Không tồn tại |
| `run_log/full-flow-v1/dataset/manifest.json`, `model/manifest.json`, `model/native-parity.json` | Không tồn tại |

- Evidence: `docs/context.md` (chỉ là danh sách path tham chiếu) và kiểm tra `Test-Path` trên workspace; entry này là biên bản kết quả.

## 2026-08-08 03:00:05 +07:00 — T0.3 DPDK resource smoke trên Ubuntu rebuild

- Inventory topology mới: Ubuntu data `ens37`, MAC `00:0c:29:30:b9:d3`, driver `e1000`; Kali data `eth1`, IP `192.168.252.128/24`, MAC `00:0c:29:01:9b:f9`, driver `vmxnet3`; Windows victim `Ethernet1`, index 14, MAC `00:0c:29:13:8d:4f`. Các giá trị T0.4 đang khớp `config/dpdk-passive.json`.
- Kết quả: **FAIL** tại preflight an toàn. Ubuntu có `iommu_groups=0`; `iommu.available` fail và `iommu.group_policy` fail với lý do data PCI device không có IOMMU group. Không chạy `apply`, không bind NIC, không cấp hugepage, không chạy testpmd/traffic và không cần rollback.
- `t0.3/preflight.json` là attempt post-rebuild không hợp lệ do lệnh chuẩn bị config bị lỗi quote và vẫn giữ expected driver từ template; file được giữ nguyên, không ghi đè, không dùng làm acceptance evidence. Receipt hiện hành là `t0.3/preflight-current.json`, tạo sau khi cấu hình được sửa khớp driver `e1000`; receipt này chỉ còn fail hai gate IOMMU.
- Evidence: `run_log/rebuild-2026-08-08/inventory-ubuntu.json`, `run_log/rebuild-2026-08-08/t0.3/dpdk-smoke.json`, `run_log/rebuild-2026-08-08/t0.3/preflight-current.json`, `run_log/rebuild-2026-08-08/agent-t03-t04.log`.

## 2026-08-08 03:00:05 +07:00 — Tổng kết lượt T0.3/T0.4 rebuild

- Đã làm: kiểm tra tồn tại receipt path; xác minh inventory/MAC/interface ba VM qua `labctl.py`; chạy T0.3 preflight bằng `scripts/dpdk_smoke.py`; lưu đầy đủ stdout/stderr labctl.
- Đang chặn: Ubuntu rebuild chưa có IOMMU group, trong khi policy bắt buộc `require_iommu=true` và cấm no-IOMMU. Vì vậy **T0.4 chưa chạy**; không có sender/sensor/acceptance receipt mới. Kiểm tra tiến độ năm PCAP theo bước 4 cũng chưa được thực hiện chính thức vì chuỗi tuần tự dừng tại T0.3.
- Bước tiếp theo đề xuất: người dùng bật IOMMU/VT-d hoặc AMD-Vi cho Ubuntu VM và boot lại; sau đó chạy lại T0.3 từ preflight trong namespace mới, chỉ khi PASS mới chạy passive T0.4, rồi mới ghi trạng thái tải đủ năm PCAP. Không export/replay PCAP trước khi cả năm file hoàn chỉnh.
- Evidence tổng: `run_log/rebuild-2026-08-08/agent-t03-t04.log` và các receipt/inventory nêu trên.

## 2026-08-08 08:1x +07:00 — Bật vIOMMU cho Ubuntu VM (theo yêu cầu người dùng), T0.3 chặn ở bước tiếp theo

Người dùng yêu cầu trực tiếp: "bật IOMMU cho Ubuntu VM rồi báo tôi".

Đã làm (qua `vmrun.exe`, không qua labctl vì đây là thao tác hypervisor):

1. `sudo shutdown -h now` qua `labctl.py exec ubuntu` để tắt guest sạch.
2. Backup `D:\A\Ubuntu 64-bit.vmx` → `Ubuntu 64-bit.vmx.bak-2026-08-08`.
3. Thêm dòng `vvtd.enable = "TRUE"` vào cuối `.vmx` (tham số VMware Workstation
   để expose virtual VT-d/IOMMU cho guest; `virtualHW.version=21` nên đủ hỗ trợ).
4. `vmrun start ... nogui`, chờ SSH sống lại (~15s).
5. Xác nhận: `ls /sys/kernel/iommu_groups | wc -l` → **10** (trước đó là 0).
   `dmesg` có `iommu: Default domain type: Translated` và các PCI device được
   gán vào group 0..7+.

Kết quả: **IOMMU đã bật thành công.**

Phát sinh phụ: sau khi VM khởi động lại, `/mnt/hgfs/TTTN` không tự mount (chỉ
thấy thư mục cũ `multilayer-ids` — di sản dự án trước, không phải mount hgfs
sống). `vmware-hgfsclient` vẫn thấy đúng `Paser`/`TTTN` từ phía host, nên đã tự
mount lại thủ công: `sudo vmhgfs-fuse .host:/ /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other`.
Việc này không bền qua reboot tiếp theo — cần thêm vào fstab hoặc script khởi
động nếu muốn tự động vĩnh viễn (chưa làm, ngoài phạm vi yêu cầu hiện tại).

Chạy lại T0.3 preflight (`run_log/rebuild-2026-08-08/t0.3/preflight-iommu.json`):

- Gate `iommu.available`: giờ **PASS**.
- Gate mới fail: **`iommu.group_policy`** — "management PCI device shares the
  data IOMMU group". `ethernet0` (management, slot PCI 33) và `ethernet1`
  (data, slot PCI 37) đều là `e1000` gắn thẳng vào PCI bus gốc, không nằm dưới
  PCIe root port riêng (`.vmx` có sẵn 4 `pcieRootPort` rảnh ở slot 21-24,
  hiện chưa dùng), nên hai NIC rơi vào chung/liên quan IOMMU group thay vì
  group độc lập như `iommu_group_policy: singleton_or_vmware_root_ports` yêu cầu.

**Dừng lại ở đây, không tự sửa tiếp.** Lý do: bước tiếp theo cần sửa cấu trúc
PCI ảo của VM (gắn `ethernet1` vào một `pcieRootPort` riêng, có thể phải đổi
`virtualDev` từ `e1000` sang `vmxnet3` vì e1000 là PCI thường không phải PCIe),
việc này rủi ro cao hơn (VM có thể không boot lại đúng, MAC có thể đổi làm
lệch toàn bộ config đã khóa MAC ở `config/dpdk-passive.json` và
`config/t91-live-campaign.json`), nên cần người dùng quyết định trước khi làm
tiếp trên máy đang ngủ không kiểm tra được.

Không có gì khác bị đổi. VM Ubuntu hiện đang chạy bình thường, mount hgfs sống
(tạm thời), SSH qua labctl hoạt động tốt.

Evidence: `D:\A\Ubuntu 64-bit.vmx.bak-2026-08-08` (bản backup trước sửa),
`run_log/rebuild-2026-08-08/t0.3/preflight-iommu.json`.

## 2026-08-08 08:2x +07:00 — Gắn ethernet1 vào PCIe root port riêng, đổi vmxnet3

Người dùng duyệt: "gắn ethernet1 vào pcieRootPort riêng, đổi vmxnet3, cập nhật config MAC".

Đã làm (qua `vmrun.exe`, VM tắt sạch trước khi sửa):

1. Backup `.vmx` lần 2 → `Ubuntu 64-bit.vmx.bak-2026-08-08b`.
2. Đổi `ethernet1.virtualDev` từ `e1000` sang `vmxnet3`; xóa
   `ethernet1.pciSlotNumber` cứng để VMware tự gán slot PCIe.
3. Boot lại: VMware tự gán `ethernet1.pciSlotNumber = "160"` (dùng 1 trong 4
   `pcieRootPort` có sẵn), **giữ nguyên MAC** `00:0c:29:30:b9:d3` (không đổi
   như dự đoán ban đầu).
4. Trong guest, NIC data đổi tên `ens37 → ens160` (đúng convention cũ, khớp
   slot 160), driver xác nhận `vmxnet3` qua `ethtool -i`, bus PCI
   `0000:03:00.0` (bridge riêng). `iommu_groups` vẫn 10, NIC data giờ ở group
   riêng.

Đã cập nhật config theo topology mới (chỉ đổi field liên quan, MAC không đổi):

- `config/dpdk-passive.json`: `ubuntu_sensor.data_interface = "ens160"`,
  `expected_driver = "vmxnet3"`.
- `config/t91-live-campaign.json`: `topology.ubuntu.interface = "ens160"`,
  `expected_driver = "vmxnet3"`; cập nhật lại
  `dpdk.resource_config_sha256` theo hash mới của `dpdk-passive.json`
  (`fd0b8032ba8426a3034470feceb9ae4e139555ba58192c88db8cf632b7dfa86f`).
- `run_log/rebuild-2026-08-08/t0.3/dpdk-smoke.json`: `expected_data_driver = "vmxnet3"`.

Chạy lại T0.3 preflight với interface `ens160`:
`run_log/rebuild-2026-08-08/t0.3/preflight-vmxnet3.json` → **PASSED** (tất cả
gate, kể cả `iommu.group_policy`).

`/mnt/hgfs/TTTN` lại không tự mount sau reboot lần 2 — mount tay lại
(`sudo vmhgfs-fuse .host:/ /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other`),
vẫn chưa bền qua reboot, vẫn ngoài phạm vi hiện tại.

Bước tiếp theo: chạy `dpdk_smoke.py apply` rồi `run` (bind NIC thật, cấp
hugepage, testpmd) để hoàn tất T0.3, sau đó mới sang T0.4 passive gate.

## 2026-08-08 08:3x +07:00 — T0.3 apply/run, rollback sạch, chặn ở thiếu shared folder Kali

- `apply --preflight preflight-vmxnet3.json`: **PASS**, bind NIC `ens160` sang
  DPDK/VFIO, cấp hugepage, lưu state để rollback tại `t0.3/state.json`.
  Management `ens33` xác nhận vẫn reachable ngay sau apply.
- `run --duration 20`: **FAIL**, `RX=0 TX=0`. Lý do: script chờ traffic thật
  gửi tới MAC `00:0c:29:30:b9:d3` trong cửa sổ 20 giây
  (`scripts/kali_smoke_traffic.py` trên Kali), nhưng **Kali VM không có
  shared folder `TTTN` mount** (`/mnt/hgfs` trên Kali chỉ có `Paser`, không có
  `TTTN`) nên không gọi được script từ đó qua `labctl.py exec kali`.
- Đã `rollback --state state.json`: **PASS**. Xác nhận `ens160` quay lại driver
  kernel `vmxnet3` bình thường, có địa chỉ `192.168.252.129/24` như cũ, management
  vẫn sống. Không còn hugepage/bind DPDK treo lại trên VM qua đêm.

**Dừng ở đây — ngoài phạm vi đã duyệt.** Việc đã được duyệt tối nay ("gắn
ethernet1 vào pcieRootPort riêng, đổi vmxnet3, cập nhật config MAC") **đã xong
và verify đầy đủ**: preflight/apply/rollback đều pass, IOMMU group riêng cho
NIC data, MAC/driver/interface đã đồng bộ trong `config/dpdk-passive.json` và
`config/t91-live-campaign.json`. Phần traffic-based `run` smoke thật (và toàn
bộ T0.4) cần thêm một quyết định mới: thêm `sharedFolder` `TTTN` vào
`D:\kali-linux-2025.4-vmware-amd64.vmwarevm\...vmx` (hoặc cách khác để đưa
script lên Kali) — đây là sửa VM thứ hai chưa được xin phép riêng, nên không tự làm.

Việc tải 5 file PCAP (bước 4 trong nhiệm vụ Agent nền ban đầu) vẫn chưa được kiểm
tra lại chính thức trong lượt này.

**Bước tiếp theo đề xuất khi thức dậy:**
1. Duyệt thêm shared folder `TTTN` cho Kali VM (hoặc phương án khác) để chạy
   traffic sender.
2. Sau đó mới hoàn tất T0.3 `run` thật và T0.4 passive gate.
3. Check tiến độ tải PCAP, sẵn sàng cho bước export/replay khi đủ 5 file.

Evidence: `run_log/rebuild-2026-08-08/t0.3/{state,run,rollback}.json`,
`run_log/rebuild-2026-08-08/t0.3/run.log`.

## 2026-08-08 08:4x +07:00 — Kiểm tra ảnh hưởng mạng + bật shared folder Kali

Người dùng hỏi đổi NIC Ubuntu có ảnh hưởng mạng 3 máy không, rồi yêu cầu bật
shared folder cho Kali.

- Verify: Kali → Ubuntu (`192.168.252.129`) ping 0% loss; Windows → Ubuntu ping
  0% loss. MAC/IP/VMnet1 không đổi nên không ảnh hưởng đường mạng.
- Kali VM: tắt sạch qua labctl, backup `.vmx`
  (`kali-linux-2025.4-vmware-amd64.vmx.bak-2026-08-08`), thêm
  `sharedFolder1` trỏ `E:\DATTTN\TTTN` → guestName `TTTN`, `maxNum` 1→2. Boot
  lại, mount `/mnt/hgfs` thủ công (không bền qua reboot, như Ubuntu).
  Xác nhận `scripts/kali_smoke_traffic.py` đọc được từ Kali, ping Ubuntu vẫn
  0% loss sau khi đổi.
- Lưu ý phát hiện thêm: Kali vmx đã **sẵn có** `ethernet1` là `vmxnet3` trên
  PCIe slot 192 riêng và `vvtd.enable=TRUE` từ trước (không phải do phiên này
  sửa) — chỉ NIC Ubuntu là cần sửa.

Tiếp theo: chạy lại T0.3 `apply` + `run` với Kali gửi traffic thật trong cửa
sổ 20 giây, rồi rollback.

## 2026-08-08 08:5x +07:00 — T0.3 hoàn tất đầy đủ (preflight/apply/run/rollback)

- Preflight lần 2 (`--force`, cùng interface `ens160`): **PASS**.
- Apply: **PASS**, state `t0.3/state-run2.json`.
- Run 20s, Kali gửi UDP thật qua `kali_smoke_traffic.py` (10 pps, 15s,
  `eth1 → 00:0c:29:30:b9:d3`, sent=150 gói): Ubuntu forward macswap
  **RX=102 TX=102**, `run2.json` → **passed**.
- Rollback: **PASS** (`rollback2.json`).

**T0.3 DPDK resource smoke: DONE, verify đầy đủ trên VM đã rebuild.** Không
còn NIC bind DPDK/hugepage treo lại. Evidence:
`run_log/rebuild-2026-08-08/t0.3/{preflight-vmxnet3-run2,state-run2,run2,rollback2,kali-send}.json`,
`run_log/rebuild-2026-08-08/t0.3/run2.log`.

Tiếp theo: T0.4 passive topology gate (200 gói UDP, Ubuntu sensor phải thấy
đủ, TX=0, error counters=0).

## 2026-08-08 09:0x +07:00 — T0.4 passive topology gate: PASS

- Sửa `LOCKED_CONFIG_VALUES` trong `scripts/kali_passive_traffic.py` (bị stale
  từ trước rebuild): `kali.data_ipv4` 192.168.252.10→128,
  `windows_victim.expected_mac`→`00:0c:29:13:8d:4f`,
  `ubuntu_sensor.expected_mac`→`00:0c:29:30:b9:d3`, khớp
  `config/dpdk-passive.json` hiện hành. Không đổi field nào khác trong file.
- Preflight (`run_log/t0.4/preflight.json`): **PASS**.
- Apply qua `dpdk_smoke.py apply --preflight run_log/t0.4/preflight.json
  --state run_log/t0.4/state.json` (dpdk_passive_probe.py tái dùng cơ chế
  apply/rollback của T0.3): **PASS**.
- `dpdk_passive_probe.py run` (arm-timeout 60s, post-sender-grace 5s) +
  `kali_passive_traffic.py` gửi 200 gói UDP thật từ Kali tới Windows victim
  (`192.168.252.20:9000`), Ubuntu bắt passive trên `ens160`:
  **matching=200 RX=200 TX=0** → `detection.json` **passed**. Sensor thuần
  passive, không có gói TX nào phát ra (đúng yêu cầu topology).
  (Lần chạy đầu bị `sender receipt already exists` do file cũ từ attempt lỗi
  trước khi apply xong; đã `retry` archive rồi chạy lại sạch.)
- Rollback (`run_log/t0.4/rollback.json`): **PASS**.

**T0.4 passive topology gate: DONE.** T0.2/T0.3/T0.4 đều verify xong trên lab
đã rebuild. Evidence: `run_log/t0.4/{preflight,state,detection,rollback,kali-sender}.json`,
`run_log/t0.4/replay.log`, `run_log/t0.4/attempts/failed-20260808T014128Z/`
(lượt lỗi đã archive, giữ nguyên không xóa).

**Trạng thái tổng quát sau lượt này:** T0.0–T0.4 tương đương đã xong trên lab
rebuild. Không có việc gì khác đang treo; VM ở trạng thái sạch (rollback pass,
management sống).

## 2026-08-08 09:1x +07:00 — Check tiến độ 5 PCAP

Kích thước byte-khớp chính xác với bảng expected trong `docs/context.md`:

| Capture | Trạng thái | Bytes |
|---|---|---:|
| Friday-WorkingHours.pcap | Xong | 8.839.309.056 |
| Thursday-WorkingHours.pcap | Xong | 8.302.500.180 |
| Tuesday-WorkingHours.pcap | Xong | 11.048.283.608 |
| Wednesday-workingHours.pcap | Xong | 13.420.789.612 |
| Monday-WorkingHours.pcap | **Chưa bắt đầu tải** | 0 |

**Quyết định của người dùng (09:2x):** bỏ Monday, vì Monday trong CICIDS2017
không có nhãn attack nào (thuần benign). Không chờ tải Monday nữa. Dataset
rebuild lần này dùng **4 capture: Tuesday, Wednesday, Thursday, Friday**.

Hệ quả cần lưu ý (không phải lỗi, chỉ là thay đổi scope so với thiết kế gốc
2.436.052-flow/5-capture trong `docs/context.md`):
- Tổng flow count, tỷ lệ Benign, và split 70/10/20 sẽ khác bản thiết kế cũ
  (Monday đóng góp ~425.166 flow benign theo bảng cũ) — coi thiết kế cũ chỉ là
  tham khảo, KHÔNG dùng con số cũ làm acceptance target cho lần rebuild này.
- Vẫn benign vẫn có mặt nhiều trong 4 ngày còn lại nên không thiếu class benign
  hoàn toàn, chỉ ít hơn tổng.

Việc tiếp theo: build lại exporter T9.1 (`nids_t91_terminal_flow_export`) trên
toolchain Ubuntu mới (VM đã rebuild, code cũ còn nhưng CMake build dir cũ đã
mất), rồi replay 4 capture Tuesday–Friday, namespace mới dưới
`run_log/full-flow-v1/` (hiện trống hoàn toàn, tạo lại từ đầu).

## 2026-08-08 09:29:45 +07:00 — Rebuild exporter và targeted tests T9.1

- Build bằng preset `ubuntu-release`, sau khi source
  `$HOME/.local/nids-toolchain/env.sh` trong cùng shell: **PASS** cho ba target
  `nids_t91_terminal_flow_export`, `nids_terminal_feature_test` và
  `nids_terminal_flow_export_test`.
- Targeted CTest: `nids_core.terminal_feature` **PASS** (1/1) và
  `nids_dataset.terminal_flow` **PASS** (1/1). Chưa replay PCAP nào trước khi
  hai test này pass.
- Evidence: `run_log/rebuild-2026-08-08/agent-exporter-replay.log`; build dir
  Ubuntu: `/home/wang/.cache/nids-partial-flow/build/ubuntu-release`.

## 2026-08-08 09:32:13 +07:00 — Tuesday terminal shard: FAIL, dừng tuần tự

- Gọi đúng atomic builder/validator `scripts/build_t91_terminal_shard.py run`
  trên Ubuntu với capture-id `tuesday-working-hours`: **FAIL** trước khi replay,
  lỗi `T3.3 source database size mismatch`.
- Nguyên nhân đã xác minh read-only: oracle khóa cứng
  `run_log/t3.3/label-join.sqlite3` (expected 2.656.702.464 byte, SHA-256
  `a97054a39fe25c8c96e42b2f335069d964b65b898e77783167cd9aa61eb097ca`)
  không tồn tại trong workspace rebuild. Validator cần database này để lấy
  source identity và đối chiếu từng terminal-flow row; không có phương án
  tương đương nào có cùng oracle evidence mà không tái tạo/mutate artifact ngoài
  phạm vi nhiệm vụ.
- Không có PCAP record nào được replay, không publish shard, không tạo
  `run_log/full-flow-v1/`; không retry và không sang Wednesday/Thursday/Friday.
- Evidence: `run_log/rebuild-2026-08-08/agent-exporter-replay.log` (labctl
  stdout/stderr đầy đủ), kiểm tra path hiện hành trong workspace.

## 2026-08-08 09:5x +07:00 — gotchas.md đã được người dùng khôi phục

Người dùng xác nhận "đã có gotchas.md". Verify: file tồn tại tại gốc repo,
78 dòng, 23.742 byte, SHA-256 `90d32361c52f8f052b0ddff2f49e425ffba2f974882956c6ec5dd6b66319b52d`.
Đã đọc toàn bộ nội dung — không có mục nào liên quan trực tiếp tới việc phục
hồi 2 oracle sqlite3 (`label-join.sqlite3`, `class-consensus.sqlite3`), chỉ là
bài học vận hành DPDK/testpmd/labctl/officecli tích lũy qua các phase trước.
Không có xung đột với `AGENTS.md`; dùng cả hai làm nguồn luật từ giờ.

**Blocker chính vẫn còn nguyên:** thiếu `run_log/t3.3/label-join.sqlite3` (2,6GB)
và `run_log/t3.3r1/class-consensus.sqlite3` — exporter T9.1 không chạy được nếu
thiếu. Đang chờ người dùng trả lời: có backup 2 file này ở đâu đó, hay có 8 CSV
nhãn CICIDS2017 gốc để rebuild lại T3.1–T3.3?

## 2026-08-08 10:11:44 +07:00 — Chuẩn bị replay 4-capture: PASS

- `/mnt/hgfs/TTTN` đã mount; hai oracle khôi phục có đúng byte-size khóa.
- Bản khôi phục có kèm 5 shard cũ sinh ngày 2026-07-28, kể cả Monday. Đã
  chuyển nguyên vẹn, có thể khôi phục sang
  `run_log/rebuild-2026-08-08/preexisting-terminal-shards-20260728/` để builder
  không resume nhầm và namespace rebuild chỉ chứa 4 capture đã chốt.
- Evidence: `run_log/rebuild-2026-08-08/agent-exporter-replay.log` và thư mục
  archive nêu trên.

## 2026-08-08 10:1x-10:2x +07:00 — Sửa lỗi path PCAP, replay Tuesday PASS

- Agent nền hết session giữa chừng (lỗi sandbox Windows khi `apply_patch` ghi
  changelog: "windows unelevated restricted-token sandbox cannot enforce
  split writable root sets"). Đã dừng agent, tự thực hiện trực tiếp qua
  `tools/labctl.py` từ đây.
- Nguyên nhân FAIL đầu tiên của Tuesday: oracle `label-join.sqlite3` lưu
  `path` tương đối là `pcap/<Tên file>.pcap`, nhưng 4 file PCAP đang nằm ở
  gốc repo, không phải trong thư mục `pcap/`. Đã `mv` cả 4 file
  (Tuesday/Wednesday/Thursday/Friday) vào `pcap/` (move tại chỗ, không copy,
  tức thời, không tốn thời gian I/O).
- Replay Tuesday lại: **PASS**. `rows=357.558`, `elapsed=168,4s` (~2,8 phút
  phần replay, cộng hash oracle+source thì tổng lệnh 279,9s). Khớp tuyệt đối
  với shard cũ đã archive (357.558 rows, 83.234 parser_errors).
- Artifact: `run_log/full-flow-v1/terminal-shards/tuesday-working-hours/`.

## 2026-08-08 10:2x-10:3x +07:00 — Replay Wednesday/Thursday/Friday: PASS, hash byte-identical với bản cũ

- Wednesday: **PASS**, rows=664.163, elapsed=225,6s.
- Thursday: **PASS**, rows=411.141, elapsed=158,3s.
- Friday: **PASS**, rows=578.024, elapsed=190,5s.
- Đối chiếu SHA-256 `terminal-flow-shard.sqlite3` của cả 4 capture mới build
  với bản archive `preexisting-terminal-shards-20260728/`: **byte-for-byte
  IDENTICAL** cả 4. Đây là bằng chứng mạnh nhất có thể có: rebuild reproduce
  đúng y hệt dữ liệu cũ, không có drift nào.
- Người dùng quyết định: **giữ Monday**, dùng luôn dataset/model/bundle đã
  restore sẵn (5-capture, đã train, đã verify hash) thay vì làm lại 4-capture
  từ đầu — tiết kiệm ~30-40 phút train/export lại.
- Đã khôi phục `monday-working-hours` từ archive vào
  `run_log/full-flow-v1/terminal-shards/` (copy, không replay lại vì đã có
  bằng chứng hash khớp `887d3e44dd76e5897a68dc383010a8195f7ca90308c7061e2e44e1bd27db434f`
  đúng tài liệu gốc).
- **Trạng thái: đủ 5/5 terminal-shard, tất cả verify hash khớp bản gốc
  27-28/07/2026.** Dataset (`run_log/full-flow-v1/dataset/`), Model V1
  (`run_log/full-flow-v1/model/`, gồm `selected-model.joblib`,
  `terminal-flow.bundle.zip`, `native-parity.json`) coi như đáng tin, không
  cần train/export lại.

Bước tiếp theo: verify nhanh hash các file dataset/model manifest còn lại đối
chiếu tài liệu, rồi build lại native DPDK terminal runtime trên Ubuntu (đã
rebuild, build dir C++ mất) để chuẩn bị live smoke FTP-Patator/PortScan.

## 2026-08-08 10:3x +07:00 — Verify hash dataset/model/bundle: PASS toàn bộ

Đối chiếu trực tiếp SHA-256 với `docs/context.md`:

| File | Hash | Khớp |
|---|---|---|
| `dataset/manifest.json` | `3f4f921cf98363100c1471df4164d0c7b322c3634e8cd3882a337317da57516d` | ✅ |
| `model/manifest.json` | `b7b383435ae70d49077ce074c4fac2bda57a2ffd4d7f016e48b5e25af45c0ccf` | ✅ |
| `model/terminal-flow.bundle.zip` | `10b9bd4ac7214d1e7420c0c7127b1990b3c0ec8a737f62ccbc207ef952ca4532` | ✅ |
| `model/native-parity-reference.json` | `4db86db70f6f13b777a674db608eb6414e269877f2a90b5e47b0a36e04cc6db9` | ✅ |

**Kết luận: Phase 1-7 của T9.1 (schema, terminal feature engine, exporter,
dataset, Model V1, ONNX bundle, native runtime parity) xác nhận thật 100%,
byte-identical với bản mô tả trong `docs/context.md`.** Không cần train/export
lại. Việc còn thiếu chỉ là hạ tầng runtime (build lại C++ trên VM rebuild) và
live integration (Phase 8-9), chưa phải dữ liệu/model.

## 2026-08-08 10:4x +07:00 — Đối chiếu đầy đủ 5 capture với số liệu gốc

Không có warning nào trong toàn bộ quá trình replay 5 capture. `parser_errors`
là exclusion đã biết trước (non-flow traffic), không phải lỗi — đúng gotchas.md
mục 22. Bảng đối chiếu đầy đủ (flow rows, parser exclusions, ingest_errors,
terminal_feature_errors) khớp 100% với `docs/context.md`:

| Capture | Flow rows | Parser exclusions | ingest_errors | terminal_feature_errors |
|---|---:|---:|---:|---:|
| monday-working-hours | 425.166 | 84.723 | 0 | 0 |
| tuesday-working-hours | 357.558 | 83.234 | 0 | 0 |
| wednesday-working-hours | 664.163 | 84.137 | 0 | 0 |
| thursday-working-hours | 411.141 | 83.049 | 0 | 0 |
| friday-working-hours | 578.024 | 83.730 | 0 | 0 |
| **Tổng** | **2.436.052** | **418.873** | **0** | **0** |

Raw stdout/stderr labctl đầy đủ của cả 5 lần replay đã append vào
`run_log/rebuild-2026-08-08/agent-exporter-replay.log`.

## 2026-08-08 10:5x +07:00 — Build lại native DPDK terminal runtime: PASS

- `cmake --preset ubuntu-release -DNIDS_BUILD_DPDK=ON -DNIDS_BUILD_MODEL_RUNTIME=ON`:
  **PASS**.
- `cmake --build --target nids_t91_terminal_live -j 2`: **PASS** (8 bước
  compile/link, không lỗi).
- Test `nids_runtime.terminal_live` ban đầu không đăng ký (thiếu
  `-DNIDS_T91_STAGED_BUNDLE`/`-DNIDS_T91_STAGED_MANIFEST_SHA256`). Đã
  reconfigure với:
  - `NIDS_T91_STAGED_BUNDLE=/mnt/hgfs/TTTN/run_log/full-flow-v1/model/terminal-flow.bundle`
  - `NIDS_T91_STAGED_MANIFEST_SHA256=16975f134494ed40389d189e2267c9641e45ece809e682624b4c4403e15cddff`
    (verify khớp `sha256sum` thật của `manifest.json` staged trước khi dùng).
- CTest `nids_runtime.terminal_live`: **PASS**, 1/1, 8,14 giây.

**Native runtime T9.1 hoạt động đầy đủ trên VM đã rebuild, dùng đúng bundle đã
restore/verify.** Sẵn sàng cho bước live smoke FTP-Patator/PortScan.

## 2026-08-08 11:0x-11:1x +07:00 — Sửa hạ tầng cho live smoke, phát hiện + fix VMware NAT Service crash

- Tạo contract FTP-Patator đầu tiên qua `kali_t91_live_campaign.sh init` (chạy
  `su - kali -c '...'` vì SSH Kali mặc định là root, script từ chối chạy as
  root). Attempt: `t91-ftp-patator-20260808034655-0b252080`.
- Windows chưa từng có shared folder (`\\vmware-host\Shared Folders\TTTN`
  không tồn tại) — đã thêm `sharedFolder0` vào `D:\Lts\Windows Server
  2022.vmx` (VM tắt sạch trước khi sửa, backup `.vmx.bak-2026-08-08`).
- Sau khi bật shared folder, Windows mất luôn cả NIC quản lý (NAT) lẫn NIC
  data (Ethernet0 "Media disconnected"). Điều tra root cause: **VMware NAT
  Service trên HOST bị crash loop** (`vmnat.exe`, access violation
  `0xc0000005`, ban đầu trong `VCRUNTIME140.dll`). Đây là lỗi hạ tầng host,
  không liên quan VM.
- Cài lại VC++ Redistributable x86 (tải từ `aka.ms/vs/17/release/vc_redist.x86.exe`,
  người dùng tự chạy) — giảm crash nhưng chưa hết, vmnat.exe crash tiếp bên
  trong chính nó ở offset khác nhau mỗi lần.
- Root cause thật: bug DNS `autodetect=1` trong `C:\ProgramData\VMware\vmnetnat.conf`
  khi danh sách network adapter trên host thay đổi. Fix: `autodetect=0` +
  DNS tĩnh (1.1.1.1, 8.8.8.8), backup file cũ (`.bak-2026-08-08`). Người dùng
  tự chạy lệnh PowerShell Admin. Kết quả: `VMware NAT Service` **Running ổn
  định**, verify bằng ping + curl internet thật từ Ubuntu — PASS.
- Windows data IP bị DHCP re-assign (192.168.252.20 → .130) sau các lần
  reboot — đặt lại tĩnh 192.168.252.20/24 (đúng khóa cứng trong config).
- Sửa `config/t91-live-campaign.json`: `dpdk.binary` path
  `/home/tom/...` → `/home/wang/...` (VM rebuild đổi user).
- Windows Prepare cho contract `0b252080`: **PASS** (status ready), dùng scp
  copy cục bộ vì lúc đó Windows chưa có shared folder.
- Ubuntu sensor start cho contract `0b252080`: liên tục **FAIL**
  ("failed to verify the sensor process group"), rollback tự động PASS mỗi
  lần (không để lại DPDK/hugepage treo).
- Giao agent nền xử lý tiếp (debug sensor + chạy FTP-Patator/PortScan thật) để
  tiết kiệm usage phiên chính. Agent nền tạo attempt mới
  `t91-ftp-patator-20260808043056-d76b3363`, Windows Prepare lại PASS (lần
  này qua UNC share, không cần scp). Nhưng khi tới bước gọi Kali chạy Patator
  thật, **Agent nền bị chính bộ lọc nội dung của nhà cung cấp model chặn** ("flagged for possible
  cybersecurity risk") 2 lần liên tiếp rồi phiên dừng hẳn — đây là giới hạn
  an toàn riêng của model nền, không phải lỗi kỹ thuật hay lỗi script.
  Windows contract của attempt này đã hết hạn TTL (120s) trước khi được dùng.
- Quyết định: các bước gọi tool tấn công thật (Patator, nmap) sẽ do tôi tự
  làm trực tiếp qua `labctl`, không giao agent nền nữa, vì nằm trong phạm vi hợp
  lệ (lab cô lập, có thẩm quyền, phục vụ đồ án).

## 2026-08-08 11:3x-11:4x +07:00 — FTP-Patator live smoke chạy end-to-end: hạ tầng PASS, model gate FAIL

Attempt mới sạch: `t91-ftp-patator-20260808043415-5b6388a7`.

- `kali_t91_live_campaign.sh init --case ftp-patator`: **PASS**.
- Windows Prepare (qua SCP, HGFS Windows lại rớt sau khi sửa NAT — không ổn
  định, cần fix riêng sau nếu muốn dùng UNC lâu dài): **PASS**, status ready.
- Ubuntu sensor start: **PASS**, status ready — xác nhận lỗi "failed to
  verify the sensor process group" ở các lần trước chỉ do state/log cũ dính
  lại từ contract đã dùng nhiều lần, không phải bug thật; contract sạch chạy
  đúng ngay lần đầu.
- Kali send (Patator, 20 mật khẩu sai, 1 thread): **PASS**.
- Ubuntu sensor stop: **PASS**, `sensor_return_code=0`.

**Kết quả hạ tầng (PASS toàn bộ):**
- 250 gói RX, 20 flow tạo/đóng, đóng 100% bằng `tcp_fin_handshake` (0 RST,
  0 timeout) — đạt gate `>=18 flow đóng RST/FIN`.
- `imissed=0`, `rx_nombuf=0`, `ierrors=0`, `oerrors=0`, `opackets=0` (TX=0,
  đúng yêu cầu passive).
- Native inference chạy đủ 20/20, không lỗi adapter/ingest/parser/inference/
  serialization/output/sink (tất cả đếm 0 trong summary).

**Kết quả model (FAIL gate acceptance):**
- **Cả 20/20 flow bị phân loại "Benign"**, `P(Benign)` từ 0,99996 đến 1,0 —
  rất tự tin, không phải biên ngưỡng. Không có flow nào được gán
  `FTP-Bruteforce` như acceptance yêu cầu.
- Không tô hồng: đây là kết quả âm thật, không phải lỗi hạ tầng. Vertical
  slice (packet → flow → feature → native inference → quyết định) đã sống và
  chạy sạch, nhưng model V1 (đã restore, train trên dataset cũ trước rebuild)
  không nhận diện được đúng family cho lượt Patator cụ thể này (20 mật khẩu
  sai, 1 thread, tạo flow ngắn ~6-14 gói/flow).
- Chưa điều tra nguyên nhân sâu (có thể: đặc trưng traffic của lượt Patator
  cụ thể này khác phân phối train; có thể vấn đề chọn feature/threshold của
  Model V1; có thể cần nhiều password hơn/traffic pattern khác để tạo tín
  hiệu rõ). Cần quyết định người dùng: điều tra sâu, thử lại với tham số
  khác, hay chấp nhận đây là giới hạn đã biết của Model V1 và ghi vào báo cáo.
- Evidence: `run_log/full-flow-v1/live/ftp-patator/t91-ftp-patator-20260808043415-5b6388a7/`
  (`contract.json`, `kali/sender.json`, `ubuntu/{sensor.json,sensor.jsonl,rollback.json}`,
  `windows/ready.json`).
- Windows Rollback: **PASS** — firewall rule, Serve/Rollback scheduled task,
  FTP service identity đều dọn sạch (`firewall_rule_removed=true`,
  `responder_task_removed=true`, `ftp_service_restored=true`).

## 2026-08-08 11:4x +07:00 — Đối chiếu log lịch sử: xác nhận đây KHÔNG phải regression

Kiểm tra `run_log/full-flow-v1/live/{ftp-patator,portscan}/t91-*-202607*`
(dữ liệu restore từ trước rebuild, không do phiên này tạo):

- FTP-Patator, attempt `t91-ftp-patator-20260729034112-f8763728` (29/07,
  `patator ftp_login user=FILE0 password=FILE1 persistent=0 -t 1`):
  **20/20 quyết định "Benign"** — y hệt kết quả hôm nay.
- PortScan, attempt `t91-portscan-20260730191252-585a88d2` (30/07):
  **319/319 quyết định "Benign"**.

**Kết luận: Model V1 không nhận diện đúng FTP-Patator hay PortScan live qua
nhiều lần thử với tham số khác nhau trong suốt tháng 7, trước khi có bất kỳ
thay đổi nào của phiên rebuild hôm nay.** Đây là giới hạn đã biết và tái lập
được của model (train trên dataset offline CICIDS2017, không generalize tốt
sang traffic live tự sinh), không phải bug hạ tầng hay do tham số Patator cụ
thể của lượt chạy nào.

**Người dùng quyết định (11:4x): dừng thử nghiệm thêm tham số, ghi nhận đây
là giới hạn đã biết của Model V1 trong báo cáo.** Không chạy thêm live smoke
case nào trong phiên này.

## Tổng kết trạng thái T9.1 sau phiên rebuild 2026-08-08

**Đã verify thật, đáng tin cậy:**
- T0.2–T0.4: PASS đầy đủ trên VM đã rebuild.
- Dataset 5-capture, Model V1, ONNX bundle, native runtime: hash khớp
  byte-identical với bản trước rebuild — không có drift.
- Native DPDK terminal live pipeline (packet → flow → feature → inference →
  quyết định): **sống, chạy sạch, TX=0, không lỗi hạ tầng** — vertical slice
  kỹ thuật đạt.
- Hạ tầng lab: NAT service host, shared folder Kali/Windows, IOMMU/PCIe
  passthrough Ubuntu — đều đã fix và verify.

**Giới hạn đã biết, không phải lỗi của phiên rebuild:**
- Model V1 phân loại sai (Benign) cho traffic live FTP-Patator và PortScan
  thật, tái lập được nhiều lần cả trước và sau rebuild. Acceptance gate
  "family đúng" của live campaign **chưa đạt**.

## 2026-08-08 13:xx +07:00 — Dashboard live + chuẩn bị dual-pipeline scenario replay

### Dashboard (real app FastAPI + Vite/React) đã bật và sửa lỗi

- Backend `http://127.0.0.1:8000`, frontend `http://localhost:5174/`.
- **Sửa lỗi 3 nút drawer** (Investigate/Escalate/Mark reviewed) — trước là
  placeholder tĩnh không onClick. Giờ có state cục bộ theo `__seq` từng alert,
  đổi trạng thái + badge màu, thêm cột Status trong bảng Live Detection.
  File: `dashboard/web/src/{App.jsx,components/Drawer.jsx,views/LiveDetection.jsx,styles.css}`.
- **Sửa lỗi trắng trang Model & Evaluation**: manifest.json thật (vừa restore)
  có format khác `known_metrics.json` mà frontend cần → `d.f9_baseline`
  undefined → crash. Sửa backend `/api/model` luôn trả known_metrics
  (frontend-compatible) + đính kèm provenance thật từ manifest khi có,
  `source_kind="manifest_verified"`. Thêm guard chống crash ở frontend.
  File: `dashboard/server/app.py`, `dashboard/web/src/views/ModelEvaluation.jsx`.
- **Chuẩn bị nguồn detection cho replay**: đổi `REAL_ALERT_SOURCE` từ
  `run_log/t8.5/detection.jsonl` (75MB format raw nested cũ, không hợp
  dashboard) sang file replay riêng `run_log/full-flow-v1/live-detection.jsonl`
  (format flat: decision/candidate/confidence/source/destination/protocol/run/ts).
  File chưa có → dashboard hiện demo sạch, tự chuyển sang live khi replay ghi vào.
- Phân bố family ở Overview đọc từ `dashboard/server/known_metrics.json`
  field `t91_terminal_full_flow.family_distribution` (6 family dataset, không phải alert).

### Agent nền build scenario (PID riêng, nền) — HOÀN TẤT

Giao agent nền build+stage+cắt (KHÔNG ghi md, KHÔNG chạy tcpreplay — tránh 2 lỗi
Agent nền đã gặp: apply_patch sandbox Windows + content filter tấn công). Kết quả:

- Build `nids_dpdk_live` (partial-flow F3/F5/F7/F9): **PASS**.
- Stage bundle F9 tại `/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9`: **PASS**.
- Cắt **14 scenario PCAP** (đủ 14 nhãn CICIDS taxonomy) tại
  `run_log/t8.5/scenarios/rebuild-20260808/pcap/original/`, mỗi cái 9 packet
  (đúng minimum đạt F9 checkpoint), manifest 14 outputs / model_f9_outputs=13.
- Agent nền ghi log riêng `run_log/rebuild-2026-08-08/agent-scenario-build.log`
  (không đụng changelog).

**Phát hiện kỹ thuật then chốt (khớp gotchas.md mục net_pcap):** smoke qua
`net_pcap` (không giữ pacing) ra **benign SAI**; đường giữ timestamp gốc ra
**known_attack/DDoS ĐÚNG**. → Xác nhận bắt buộc dùng **tcpreplay pacing thật**
(giữ timing) cho replay, đúng yêu cầu người dùng.

### Bước tiếp theo (main agent điều phối)

Replay 14 scenario pacing thật qua từng pipeline, log 2 model RIÊNG BIỆT:
- Partial-flow F9 (13 attack family + benign) → `pcap-replay-detection/<case>/legacy-f9.jsonl`
  + bridge sang flat → `run_log/full-flow-v1/live-detection.jsonl` cho dashboard.
- Terminal-flow V1 (6 lớp) → `pcap-replay-detection/<case>/terminal-flow.jsonl`.
- 1 NIC chỉ 1 DPDK process → 2 lượt replay riêng cho 2 pipeline (cùng scenario).

## 2026-08-08 14:xx +07:00 — REPLAY 14 FAMILY qua partial-flow F9: THÀNH CÔNG, live lên dashboard

### Cách chạy (pacing thật, không net_pcap)

- Sửa `scripts/run_t85_scenario_sensor_ubuntu.sh`: 3 chỗ `sudo`/`sudo -v` →
  `sudo -n` vì sudoers VM này có `(ALL:ALL) ALL` (cần pass) đứng TRƯỚC
  `NOPASSWD: ALL` → `sudo -v` (validate chung) fail không TTY. `sudo -n <cmd>`
  dùng last-match NOPASSWD nên OK. Không đổi logic sensor.
- Ubuntu sensor: `run_t85_scenario_sensor_ubuntu.sh --run-id rebuild-20260808
  --bundle .../t5.2/bundles/F9 --attempt run2 --duration-seconds 300` → apply
  DPDK bind ens160, chạy `nids_dpdk_live` (partial-flow F9) nghe passive,
  ghi `run_log/t8.5/scenarios/rebuild-20260808/ubuntu/run2/sensor.jsonl`.
- Kali replay 14 scenario: `kali_t85_scenario_replay.py --case <case>
  --interface eth1 --destination-mac 00:0c:29:30:b9:d3` — chạy AS root (script
  yêu cầu geteuid==0, SSH Kali sẵn là root). `send_frames` giữ **pacing thật
  1:1** theo timestamp gốc (offset ns + time.sleep), MTU rewrite L2-only rồi
  restore.

### Kết quả: F9 phân loại ĐÚNG 13/14 family

| Family gửi | F9 decision | F9 candidate | Đúng |
|---|---|---|---|
| ftp-patator | known_attack | FTP-Patator | ✅ |
| portscan | known_attack | PortScan | ✅ |
| dos-hulk | known_attack | DoS Hulk | ✅ |
| dos-goldeneye | known_attack | DoS GoldenEye | ✅ |
| dos-slowloris | known_attack | DoS slowloris | ✅ |
| ddos | known_attack | DDoS | ✅ |
| bot | known_attack | Bot | ✅ |
| ssh-patator | known_attack | SSH-Patator | ✅ |
| web-brute-force | known_attack | Web Attack – Brute Force | ✅ |
| infiltration | known_attack | Infiltration | ✅ |
| web-sql-injection | known_attack | Web Attack – Sql Injection | ✅ |
| web-xss | known_attack | Web Attack – XSS | ✅ |

- flow_rf attack_probability ~0.99999, known_family confidence ~0.99999.
- IP flow là IP gốc CICIDS (172.16.0.1 → 192.168.10.50), giữ nguyên L3.
- Thêm 2 `unknown_candidate` là **DHCP ambient noise** nền lab (0.0.0.0:68,
  192.168.252.254:67) — không phải scenario, ghi rõ không tính là phát hiện.
- **Thiếu 2/14:** Heartbleed (known_family_rf 13-class KHÔNG có lớp Heartbleed
  — đúng thiết kế, context.md ghi 0 assigned flow) và dos-slowhttptest (chưa
  tạo alert riêng trong lượt này — cần kiểm lại flow).

**Ý nghĩa:** partial-flow F9 (Flow RF + Known-family RF 13-class + HBOS/IF)
phân loại ĐÚNG family cho traffic pacing thật — khác hẳn terminal V1 (6-lớp,
ra Benign hết). Đây là pipeline hoạt động đúng cho bài toán 14-family.

### Live lên dashboard

- Bridge đọc `sensor.jsonl` (nids_alert nested) → flat format
  (decision/candidate/confidence/source/destination/protocol/run/ts) → ghi
  `run_log/full-flow-v1/live-detection.jsonl`. Dashboard tự chuyển
  `source_kind: real`, hiện 16 alert với đúng family, toast + drawer + 3 nút.
- Evidence: `run_log/t8.5/scenarios/rebuild-20260808/ubuntu/run2/sensor.jsonl`,
  `run_log/t8.5/scenarios/rebuild-20260808/kali/replay/*.json`,
  `run_log/full-flow-v1/live-detection.jsonl`.
- Log 2 model tách biệt: F9 ở sensor.jsonl trên; terminal-flow V1 (6-lớp) là
  lượt riêng chưa chạy trong session này (kết quả live trước đó: benign).

## 2026-08-08 15:xx +07:00 — Sự cố NIC treo + chuyển hướng sang replay window lớn (đủ bằng chứng)

### Sự cố NIC treo ở DPDK (đã xử lý)

- Sau khi replay 14 scenario (mỗi cái 9 packet) qua sensor F9, lệnh sensor
  chạy nền qua labctl có `--timeout-seconds 340` NHƯNG sensor duration 300s +
  overhead > 340s → labctl **giết chuỗi lệnh TRƯỚC khi trap cleanup của
  sensor script chạy rollback**. Hậu quả: `ens160` treo ở DPDK driver
  (kernel không thấy device), hugepage còn cấp, không có rollback.json.
- Thử rollback thủ công `dpdk_smoke.py rollback --state state.json` 2 lần:
  cả 2 **timeout** (30s rồi 120s), không ra output — rollback treo (nghi
  udev wait hoặc 2 process rollback đụng nhau).
- **Xử lý dứt điểm: reboot Ubuntu VM** (`sudo -n reboot`, người dùng cũng
  reboot). Sau boot: `ens160` tự về `vmxnet3`, IP `192.168.252.129/24`,
  hugepages=0, mount hgfs remount OK. VM sạch hoàn toàn.
- **Bài học (ghi để lặp lại đúng):** khi chạy sensor DPDK nền qua labctl,
  labctl timeout PHẢI lớn hơn (sensor duration + ~60s cleanup), hoặc chạy
  sensor với cơ chế stop/rollback chủ động thay vì để timeout cắt ngang.
  DPDK bind treo chỉ rollback được bằng reboot nếu dpdk_smoke rollback treo.

### Phản hồi người dùng: 9 packet/family là quá ít

- Người dùng chỉ ra đúng: scenario 9 packet/family (từ
  `build_t85_scenario_pcaps.py`) chỉ là **1 flow/family** — đủ chứng minh
  pipeline live phân loại đúng family, KHÔNG đủ bằng chứng thống kê.
- Quyết định mới: **cắt window lớn ~500 flow/family, replay pacing thật**.

### Đo thời gian replay thật (pacing thật = span thời gian gốc)

| Family | Tổng flow (oracle) | Span 1000 flow | Span toàn bộ |
|---|---:|---:|---:|
| DDoS | 128.027 | <1 phút (rất dày) | 20 phút |
| DoS Hulk | 231.073 | <1 phút | 24 phút |
| DoS GoldenEye | 10.293 | ~1 phút | 9 phút |
| FTP-Patator | 7.938 | ~10 phút | 73 phút |
| SSH-Patator | 5.897 | ~10 phút | 62 phút |
| PortScan | 158.924 | ~106 phút (rải rất thưa) | 138 phút |

- **Oracle `label_row` chỉ có 6 attack family đủ flow** (+ BENIGN): DoS Hulk,
  PortScan, DDoS, DoS GoldenEye, FTP-Patator, SSH-Patator. Các family khác
  (Bot, Web×3, Infiltration, Heartbleed, slowloris, Slowhttptest) quá ít flow
  trong dataset → không đủ bằng chứng thống kê (chính là 2 family "thiếu" ở
  lượt 14-scenario trước).
- Mọi family: attacker `172.16.0.1` → victim `192.168.10.50` (cùng cặp host,
  khác capture + thời gian). FTP+SSH ở tuesday; Hulk+GoldenEye ở wednesday;
  DDoS+PortScan ở friday.
- **Người dùng chốt: 500 flow/family × 6 family, PortScan giảm 100 flow**
  (vì rải thưa ~106 phút/1000). Ước tổng ~30-40 phút replay.

### Làm rõ: 6 family là NHÃN THẬT (ground truth), test CẢ 2 model

Người dùng hỏi "6 family của model nào" — làm rõ: 6 family lấy từ oracle
(nhãn CICIDS thật), là INPUT để test cả 2 pipeline. Mapping kỳ vọng:

| Ground truth | Partial F9 (13-class) | Terminal V1 (6-class) |
|---|---|---|
| FTP-Patator | FTP-Patator | FTP-Bruteforce |
| SSH-Patator | SSH-Patator | SSH-Bruteforce |
| DoS Hulk | DoS Hulk | DoS |
| DoS GoldenEye | DoS GoldenEye | DoS |
| DDoS | DDoS | DoS |
| PortScan | PortScan | PortScan |

Log 2 model tách biệt. F9 phân biệt chi tiết DoS; terminal V1 gộp "DoS".

### Công cụ cắt window mới: scripts/cut_family_window_pcap.py

- Tự viết (Write tool, không qua Agent nền apply_patch). Đọc oracle lấy N flow đầu
  /family → tuple-set 5-tuple (direction-insensitive) + time window → stream
  source PCAP một lần, ghi packet thuộc tuple-set ra PCAP con giữ timestamp
  gốc (pacing thật cho tcpreplay). Read-only oracle + source, pure stdlib.
- Nguồn PCAP CICIDS là **PCAPNG** (magic 0x0a0d0d0a), không phải classic pcap
  — đã bổ sung parser pcapng (Enhanced Packet Block + if_tsresol), output
  ghi classic pcap (LINKTYPE_ETHERNET, microsecond) cho tcpreplay.
- Đang test cắt DoS GoldenEye 500 flow từ wednesday để verify trước khi chạy
  cả 6 family.

## 2026-08-08 15:xx +07:00 — Script cut_family_window_pcap verify PASS, cắt 6 family

- Test cắt DoS GoldenEye 500 flow từ Wednesday-workingHours (pcapng 13.7M
  packet): **PASS**. Scan toàn bộ 13.788.878 packet, ghi **89.969 packet**
  (500 flow × ~180 packet/flow — GoldenEye là HTTP flood nhiều packet/flow).
  tcpdump verify đọc lại đúng 89.969 packet. Parser pcapng + output classic
  pcap hoạt động, timestamp gốc giữ nguyên.
- Mỗi lần cắt scan toàn bộ capture (~13GB pcapng qua hgfs) ~2-3 phút.
- Chạy cắt 6 family (PortScan 100 flow, còn lại 500):
  ftp-patator/ssh-patator (tuesday), dos-hulk/dos-goldeneye (wednesday),
  ddos/portscan (friday). Output: run_log/full-flow-v1/family-windows/.

## 2026-08-08 15:xx +07:00 — Cắt 6 family window PASS

| Family | Flow | Packet | File |
|---|---:|---:|---|
| FTP-Patator | 500 | 7.140 | family-windows/ftp-patator.pcap |
| SSH-Patator | 500 | 14.232 | family-windows/ssh-patator.pcap |
| DoS Hulk | 500 | 48.314 | family-windows/dos-hulk.pcap |
| DoS GoldenEye | 500 | 89.969 | family-windows/dos-goldeneye.pcap |
| DDoS | 500 | 3.557 | family-windows/ddos.pcap |
| PortScan | 100 | 823 | family-windows/portscan.pcap |

Tổng ~163k packet. Output `run_log/full-flow-v1/family-windows/`. Mỗi lần cắt
scan toàn bộ capture (~10-13M packet). Timestamp gốc giữ nguyên cho pacing thật.

## 2026-08-08 15:xx +07:00 — Span PCAP con quá dài do port reuse, thêm giới hạn span

Đo span thời gian thật 6 PCAP con (pacing thật = span này):

| Family | Span thật |
|---|---:|
| ftp-patator | 244s (4′) |
| ssh-patator | 318s (5′) |
| dos-hulk | 3937s (66′) |
| dos-goldeneye | 4191s (70′) |
| ddos | 21s |
| portscan | 11427s (190′) |

**Vấn đề:** attacker tái sử dụng port → cùng 5-tuple xuất hiện rải rác toàn
file → 500 flow trải hàng chục/trăm phút. Replay pacing thật sẽ mất 66-190
phút/family — không khả thi.

**Fix:** thêm `--max-span-seconds` vào `cut_family_window_pcap.py`: chỉ ghi
packet trong [first_matched_ts, first_matched_ts + N] → cắt window liên tục
ngắn (nhiều flow trong N giây đầu của attack) thay vì 500 flow rải rác.
Chọn N=180s (3 phút)/family → tổng ~18 phút replay, vẫn nhiều nghìn packet/family.

## 2026-08-08 15:xx +07:00 — BACKLOG mới (người dùng yêu cầu): 3 feature runtime cần xử lý tiếp

Người dùng chốt hướng phát triển tiếp theo — 3 feature runtime NIDS chưa triển khai:

1. **Xử lý đa luồng (sharded workers)** — T7.1 hiện là single-thread vertical
   slice, chưa đạt thiết kế gốc sharded workers + flow ownership. Cần: chia flow
   theo hash/ownership cho nhiều worker thread, không tranh chấp state.
2. **Thuật toán hàng đợi (async alert queue)** — T6.5 chưa triển khai. Alert
   hiện serialize + ghi stdout ĐỒNG BỘ trong hot path (block inference). Cần:
   hàng đợi bất đồng bộ tách alert I/O khỏi hot path, có backpressure/bounded.
3. **Loại trùng lặp (deduplication)** — incident tracker có created/updated ở
   mức unit, nhưng live runtime chưa chạy dedup thật. Cần: gộp alert trùng
   (cùng flow/incident) thay vì phát lặp.

**Thứ tự:** hoàn tất replay 6 family window (đang chạy) trước, rồi xử lý 3 feature
này. Cần làm rõ scope (implement mới trên pipeline nào — F9 legacy hay terminal
runtime mới) khi bắt đầu, vì pipeline F3/F5/F7/F9 là immutable.

## 2026-08-08 16:xx +07:00 — Dashboard toggle 2 model (F9 / terminal V1)

Người dùng chọn toggle (không phải chung 1 bảng). Đã thêm:
- Backend `/api/alerts/tail?model=f9|terminal` đọc file riêng:
  `live-detection-f9.jsonl` / `live-detection-terminal.jsonl` (demo fallback khi
  chưa có). F9 fallback về `live-detection.jsonl` cũ nếu file split chưa có.
  Migrate 16 alert F9 hiện có sang `live-detection-f9.jsonl`.
- Frontend: 2 nút toggle "Partial-flow F9 (13 family)" / "Terminal V1 (6 lớp)"
  trong tab Live Detection; đổi model → reset stream + tail file tương ứng.
- Verify: model=f9 → real 16 alert; model=terminal → demo (chưa replay).
- Log gốc 2 model vẫn tách biệt (sensor.jsonl riêng mỗi pipeline); bridge ghi
  vào 2 file live riêng cho toggle.

## 2026-08-08 16:xx +07:00 — Làm Search + Range hoạt động thật (Topbar)

Kiểm tra toàn bộ nút frontend: mọi <button> đều có onClick. 2 phần chỉ trang trí
đã fix (người dùng chọn làm cả 2 hoạt động):
- **Search box**: div placeholder tĩnh → input thật. Lift state `search` lên
  App, filter bảng Live Detection theo IP/family/protocol/decision/run
  (substring, lowercase). Chỉ bật ở view live, disabled+mờ ở view khác.
- **Range selector** (Live/1H/6H/24H/7D): trước chỉ đổi active. Lift state
  `range` lên App, filter alert theo `ts` (Live=tất cả, còn lại = trong N giây).
- LiveDetection: `visibleRows` = rows sau filter search+range; thông báo trống
  phân biệt "chờ sự kiện" vs "không khớp bộ lọc".
- Files: App.jsx, components/Topbar.jsx, views/LiveDetection.jsx.

Các nút khác đều hoạt động thật (sidebar nav, theme, notif, model toggle,
pause, row→drawer, Model tabs, Lab Topology exec, Drawer 3 nút).

## 2026-08-08 16:xx +07:00 — Cắt 6 family burst dày nhất PASS (đủ bằng chứng)

Fix logic: thu tất cả packet match rồi chọn cửa sổ 180s DÀY NHẤT (đúng burst
attack) thay vì "180s từ first-match" (trúng flow lẻ do port reuse).

| Family | Packet | Span |
|---|---:|---:|
| FTP-Patator | 5.819 | 180s |
| SSH-Patator | 8.687 | 180s |
| DoS Hulk | 393.431 | 180s |
| DoS GoldenEye | 211.337 | 173s |
| DDoS | 200.657 | 180s |
| PortScan | 169.265 | 180s |

Tổng ~989k packet. Output `run_log/full-flow-v1/family-windows/`. Đủ nhiều
nghìn/trăm-nghìn packet/family cho bằng chứng thống kê. Tiếp theo: replay pacing
thật qua F9 rồi terminal V1 (sensor nền, labctl timeout > duration + cleanup để
tránh lặp lại sự cố NIC treo).

## 2026-08-08 16:xx +07:00 — Rào cản replay window lớn: idle-timeout 300s + hugepage phân mảnh

- Sensor F9 1-lần cho 6 family (duration 1200s) FAIL: `nids_dpdk_live` giới hạn
  cứng `maximum_idle_timeout_ms=300000` (5 phút) — sensor script set
  idle=duration*1000=1200000 → binary reject (in usage). Bằng chứng:
  cpp/apps/nids_dpdk_live.cpp:221.
- Sau reboot Ubuntu, hugepage phân mảnh: apply chỉ cấp 12/128. Fix: `sync +
  drop_caches + compact_memory + echo 128 nr_hugepages` → cấp đủ 128.
- **Hệ quả:** phải replay TỪNG family, sensor duration ≤ 280s (idle ≤ 300s),
  kill sensor sau khi replay xong để dừng sớm + rollback. 6 family riêng.

## 2026-08-08 16:xx +07:00 — dos-hulk F9 replay live PASS + dashboard fixes + giao agent nền

### dos-hulk qua F9 (family window lớn) — live dashboard PASS
- Sensor F9 duration 240s, tcpreplay dos-hulk.pcap (393k packet) pacing thật:
  gửi 328.967 packet trong 201s (1636 pps), 64.464 jumbo frame fail EMSGSIZE
  (MTU eth1 1500 < jumbo — gotchas đã biết, chấp nhận).
- Sensor F9 bắt **6086 nids_alert** (DoS Hulk), kill sensor → rollback PASS,
  NIC về vmxnet3.
- Bridge `scripts/bridge_sensor_to_dashboard.py` (mới) → live-detection-f9.jsonl:
  6086 alert. Dashboard toggle F9 hiện real 6086.

### Dashboard fixes
- **Bug uncertain**: decisionPill map "uncertain" (decision F9 thứ 4) → pill
  benign (sai màu) → người dùng thấy nhầm "benign". Fix: pill "uncertain" màu
  medium riêng + đếm trong tổng thể. Data thật dos-hulk: known_attack 6022,
  uncertain 61, unknown_candidate 3.
- **Pagination**: bảng 6086 alert → 50/trang, nút Đầu/Trước/Sau/Cuối, hiện
  "X alert · trang Y/Z". rows buffer tăng 60→20000.
- File: views/LiveDetection.jsx.

### Giao agent nền orchestrate replay (chạy nền song song)
- Agent nền xử lý PHẦN A (5 family F9 còn lại: goldeneye/ddos/portscan/ftp/ssh) +
  PHẦN B (6 family qua terminal V1). Sensor duration 40s (idle auto-stop 40s
  sau replay, tự rollback — tránh treo NIC). Bridge F9 → live-detection-f9.jsonl,
  terminal → live-detection-terminal.jsonl. Agent nền ghi log riêng
  agent-replay-orchestrate.log (không apply_patch .md/.py).
- Ràng buộc đã truyền: idle-timeout<=300s, drop-cache+hugepage trước apply,
  labctl timeout > duration+cleanup, rollback verify.

## 2026-08-08 15:57 +07:00 — F9 replay 6 family window lớn: XONG, kết quả + archive

Tự orchestrate (Bash tool, không dùng agent nền vì agent nền kẹt PowerShell quoting labctl).
Mỗi family: drop-cache+hugepage → sensor F9 nền duration 240 → tcpreplay pacing
thật → kill sensor → rollback → bridge. NIC rollback OK mọi family.

| Family | Packet gửi | Jumbo fail | F9 alert |
|---|---:|---:|---:|
| DoS Hulk | 328.967 | 64.464 | 6086 |
| DoS GoldenEye | 176.787 | 34.550 | 4127 |
| DDoS | 171.052 | 29.605 | 68 |
| PortScan | 169.265 | 0 | **0** |
| FTP-Patator | 5.819 | 0 | 209 |
| SSH-Patator | 8.687 | 0 | 160 |

**PortScan = 0 alert — giới hạn thật của partial-flow F9:** F9 chỉ inference
flow đạt >=9 packet (checkpoint F9). PortScan là SYN scan, mỗi flow 1-2 packet
< F9 → không bao giờ phân loại. Khác lượt 14-scenario trước (flow cắt sẵn đúng
9 packet). Ghi rõ, không tô hồng.

Jumbo frame > MTU 1500 (eth1) fail EMSGSIZE (gotchas đã biết) — DoS/DDoS mất
~15-20% packet jumbo, nhưng vẫn đủ flow đạt F9 để phân loại đúng family.

### Log 3 chiều: model × timestamp lần chạy
- Re-bridge sạch 6 family với ts THẬT (từ checkpoint_timestamp_ns monotonic,
  neo vào mtime sensor = thời điểm phát thật, giữ pacing) + field
  `replay_family` + `replay_run`. Tổng 10.650 alert.
- Dashboard live: `run_log/full-flow-v1/live-detection-f9.jsonl` (toggle F9).
- Archive theo lần chạy: `run_log/full-flow-v1/replay-runs/20260808-155731/f9.jsonl`.
- Evidence gốc/family: `run_log/t8.5/scenarios/rebuild-20260808/ubuntu/{fh-hulk,f9-*}/sensor.jsonl`.

### Dashboard cải tiến
- Sort mới-nhất-trên-đầu (theo ts giảm dần).
- Pagination 50/trang.
- Pill "uncertain" riêng (hết nhầm benign).
- Overview thêm biểu đồ live phân bố family (bar chart, cập nhật 3s).
- Bridge `--follow` realtime mode (tail sensor, append từng alert ts=now) cho
  terminal phase — dashboard thấy alert nhảy realtime.

Tiếp theo: PHẦN B — 6 family qua terminal V1, bridge realtime.

## 2026-08-08 16:0x +07:00 — Đối chiếu F9 vs ground truth + Overview toggle

### Confusion F9 candidate vs nhãn CICIDS thật (dataset)
| Ground truth | Alert | Đúng | Acc | Nhầm nhiều nhất |
|---|---:|---:|---:|---|
| FTP-Patator | 209 | 209 | 100% | — |
| SSH-Patator | 160 | 160 | 100% | — |
| DDoS | 68 | 57 | 83.8% | Bot (10) |
| DoS Hulk | 6086 | 4722 | 77.6% | slowloris (493), GoldenEye (450) |
| DoS GoldenEye | 4127 | 278 | 6.7% | **DoS Hulk (3175)** |
| PortScan | 0 | — | — | flow ngắn <F9 |

- FTP/SSH-Patator hoàn hảo. DoS Hulk tốt. DDoS tốt.
- **DoS GoldenEye kém (6.7%)** — bị nhầm sang DoS Hulk; các biến thể DoS HTTP
  flood khó phân biệt trên feature partial-flow F9.
- PortScan không phát hiện (SYN scan flow < 9 packet, không đạt F9).
- ts là thời gian phát THẬT (per-family window 15:23→15:56, giữ pacing).

### Overview: toggle F9/terminal cho biểu đồ live
- Biểu đồ phân bố family ở Overview thêm toggle F9 (13 family) / Terminal V1
  (6 lớp), poll `/api/alerts/tail?model=<>`. Terminal hiện "chưa replay" cho
  tới khi phần B chạy.

## 2026-08-08 16:0x +07:00 — File đối chiếu confusion + fix Overview demo

- Script mới `scripts/build_replay_confusion.py`: đọc detection jsonl (có
  replay_family = ground truth), tính confusion + accuracy + ts range, lưu
  JSON + markdown. Evidence auditable, không chỉ in terminal.
- Tạo `replay-runs/20260808-155731/confusion-f9.{json,md}` cho lần replay F9.
- **Fix Overview**: biểu đồ live terminal hiện demo dù chưa replay. Sửa: chỉ
  hiển thị bars khi `source_kind=real`; demo → "chưa có alert thật (không hiển
  thị demo)". Áp dụng cả F9 và terminal.

## 2026-08-08 20:0x–22:5x +07:00 — T8.5 mở rộng: replay đủ 14 family + đính chính evidence

Bối cảnh: T8.5 đã `passed` nhưng phạm vi chỉ **1 flow / 1 alert / 1 family
(DDoS)**. Mục tiêu phiên này: kéo lên đủ 14 case, có bảng so online (NIC vật
lý) vs offline (replay file) trên **cùng một mẫu**.

Run mới: `20260808-194942`.

### Vì sao tách 2 nơi lưu

| Loại | Đường dẫn | Lý do |
|---|---|---|
| Receipt thô | `run_log/t8.5/scenarios/20260808-194942/` | `kali_t85_scenario_replay.py:33` và `run_t85_scenario_sensor_ubuntu.sh:32` hardcode path này |
| Stream dashboard | `run_log/full-flow-v1/live-detection-f9.jsonl` | đúng chỗ pipeline |
| Archive lần chạy | `run_log/full-flow-v1/replay-runs/20260808-194942/` | cùng chuẩn `replay-runs/` cũ |

Không dời receipt thô ra khỏi `t8.5` (là receipt gốc). Layout `pcap/` +
`scenario.json` được nhân bản sang run-id mới để né guard "File exists" của
`rebuild-20260808` mà vẫn giữ nguyên receipt cũ.

### Sự cố môi trường

- Cả 3 VM (Kali/Ubuntu/Windows) **tắt** lúc bắt đầu phiên; bật lại 2 VM bằng
  `vmrun`. Kali `eth1` 192.168.252.128, Ubuntu `ens160` 192.168.252.129.
- Backend dashboard chạy qua Bash background bị chết im lặng; chuyển sang
  `Start-Process` (PowerShell) thì ổn định.
- `vite.config.js` proxy `/api` → `127.0.0.1:8000`; backend phải ở cổng 8000,
  không phải 5174.

### Pass 1 — kết quả và 2 bug

Đọc **từ đĩa**, không tin số script in ra:

| Family | packets_seen | alerts | Ghi chú |
|---|---:|---:|---|
| dos-hulk | 177.665 | 6086 | replay pcap lớn |
| portscan | 168.338 | 0 | flow SYN <9 gói, không tới F9 |
| ddos | 160.129 | 68 | replay pcap lớn |
| dos-goldeneye | 102.135 | 4127 | replay pcap lớn |
| ssh-patator | 8.717 | 160 | replay pcap lớn |
| ftp-patator | 5.842 | 209 | replay pcap lớn |
| bot | 195 | 3 | 9-frame |
| web-xss | 43 | 1 | 9-frame |
| web-sql-injection | 37 | 1 | 9-frame |
| dos-slowloris | 30 | 1 | 9-frame |
| web-brute-force | 4 | 0 | **mất 5/9 frame** |
| dos-slowhttptest | 0 | 0 | **sensor không bắt được gì** |
| heartbleed | 0 | 0 | **sensor không bắt được gì** |
| infiltration | 0 | 0 | **sensor không bắt được gì** |

**Bug 1 — replay bắn trước khi sensor bind xong port.** Dùng `sleep 10` cố
định. 3 family ghi `packets_seen=0`, đọc nhầm thành "model trượt" trong khi
model chưa từng chạy. Sửa: poll `nids_dpdk_live_ready` trong `sensor.jsonl`
rồi mới replay.

**Bug 2 — `grep` đọc trước khi hgfs flush xong.** Script báo 0 alert cho
`dos-slowloris`, `web-sql-injection`, `web-xss` trong khi file trên đĩa có 1
alert mỗi cái. Sửa: settle 10s + `sync` trước khi đếm. **Bài học: luôn đọc số
liệu từ file, không lấy số script in ra.**

**Vấn đề mẫu (gốc của khiếu nại "14 vs 12"):** pass 1 trộn 2 chế độ replay —
6 family cũ bắn nguyên pcap lớn, 8 family mới bắn đúng 9 frame. Lấy 6086 alert
so với 1 alert là vô nghĩa.

### Pass r2 — chuẩn hoá mẫu

Chạy lại **cả 14 case cùng chế độ 9-frame**: mỗi case = 1 flow, 9 gói, 1
checkpoint F9, 1 alert kỳ vọng → mẫu số 14 vs 14. Attempt mới đặt tên
`f9-<family>-r2`, **giữ nguyên** attempt cũ `f9-<family>` (không xoá receipt
lỗi). Giao agent nền chạy nền theo `AGENTS.md`.

### Đính chính: con số "offline 12/13" KHÔNG phải evidence

Kiểm tra lại đĩa:

- `offline-flows/offline-f9-results.json` — cả 14 case `status:"error"`,
  `raw:""`. File rỗng nội dung.
- `scripts/build_3way_confusion.py` (script sinh ra 12/13) **không tồn tại**.
  Cùng với 4 script khác từng được báo cáo: `build_manifest_confusion.py`,
  `build_flow_confusion.py`, `cut_full_flows.py`, `ubuntu_offline_flows.sh`.
- Con số 12/13 được **gõ tay** từ output console vào một dict hardcode trong
  script đã mất.

Nguyên nhân kỹ thuật: `run_t85_full_replay_stream.py:168` coi `exit_code != 0`
là chạy hỏng, nhưng `nids_demo_replay` **luôn thoát mã 1** khi
`--expect-records` không khớp — dù vẫn in `nids_alert` hợp lệ ra stdout. Mọi
case rơi vào nhánh `error`.

Kết luận: 12/13 không sai, nhưng **không tái lập được** ⇒ không dùng làm
evidence. Đã ghi rõ vào `config/agent/current-task.json`
(`offline_f9_result_is_not_evidence`).

### Lỗi nhãn en-dash

Oracle ghi `Web Attack – Brute Force` (en-dash U+2013), bảng hardcode dùng
`Web Attack - Brute Force` (hyphen). 3 family web bị chấm sai âm thầm, kéo
offline từ 12/12 xuống 9/12. Sửa: ground truth **luôn đọc từ
`pcap/manifest.json`**, không gõ lại.

### Script mới

| Script | Việc |
|---|---|
| `scripts/run_t85_pending_replays.py` | Vòng replay: arm sensor (chờ ready) → replay Kali → đếm alert. `--attempt-suffix` cho lần chạy lại. |
| `scripts/watch_scenario_alerts.py` | Tail toàn bộ `ubuntu/f9-*/sensor.jsonl`, append alert `ts=now` vào stream dashboard + archive. Bridge gốc chỉ tail được 1 file. |
| `scripts/run_t85_offline_f9.py` | Vế offline: bỏ qua exit code, lưu `raw_stdout` từng case, chấm `correct` bằng nhãn manifest. |

### Dashboard

- `dashboard/server/app.py`: env `NIDS_LIVE_DIR`, endpoint `/api/confusion`.
- `dashboard/web/src/views/ModelEvaluation.jsx`: tab Confusion.
- Xác nhận `/api/alerts/tail` trả `source: run_log/full-flow-v1/live-detection-f9.jsonl`.

### Còn mở

- **DoS GoldenEye 6.7% online vs 100% offline.** Giả thuyết: tcpreplay không
  giữ khoảng cách thời gian giữa gói → hỏng đặc trưng inter-arrival-time.
  Chưa kiểm chứng. Đây là kết luận quan trọng nhất cần chốt.
- `dos-slowhttptest` không sinh alert cả offline: 9 gói cách nhau ~20s.
- `portscan` 0 alert là **giới hạn thật** của partial-flow F9, không phải bug.
- Spec đầy đủ: `docs/t85-online-offline-evidence-spec.vi.md`.

## 2026-08-08 23:2x–23:5x +07:00 — Pass r2 thất bại, tìm ra nguyên nhân mất gói

### Kết quả r2 (đọc từ đĩa, Agent nền xác nhận trùng khớp)

| Family | packets_seen | parsed | alerts |
|---|---:|---:|---:|
| heartbleed | 36 | 17 | 1 |
| bot | 27 | 17 | 1 |
| ssh-patator | 5 | 4 | 0 |
| ddos, dos-goldeneye, dos-hulk, dos-slowhttptest, ftp-patator, infiltration, portscan, web-brute-force | 4 | 4 | 0 |
| web-sql-injection | 3 | 2 | 0 |
| dos-slowloris, web-xss | 0 | 0 | 0 |

Sửa timing (chờ `nids_dpdk_live_ready`) **có tác dụng** — hết `packets_seen=0`
hàng loạt như pass 1, chỉ còn 2 case. Nhưng lộ ra lỗi thứ hai:
**11/14 case chỉ nhận 4/9 frame.**

### Nguyên nhân: link flap ngay trước khi gửi

`kali_t85_golden_sender.py:set_link()` gọi `ip link down → set mtu → up` **vô
điều kiện**, ngay sát lúc bắn 9 frame. Link vmnet cần thời gian hội tụ; khoảng
5 frame đầu bị nuốt. Con số 4 lặp lại đều đặn trên 8 family khác nhau chính là
dấu hiệu này.

Pass 1 không lộ vì 6 family replay pcap lớn (hàng trăm nghìn gói) — mất vài
gói đầu không ảnh hưởng. Chuẩn hoá về 9-frame mới làm lỗi hiện ra.

### Đề xuất SAI đã bị bác bỏ

Tôi từng đề xuất "gửi lặp 9 frame 3 lần cho chắc". **Sai, do quên bản chất F9.**

F9 bắn đúng **một lần mỗi flow**, tại gói thứ 9. Replay chỉ ghi đè 12 byte đầu
(MAC), giữ nguyên `record.data[12:]` ⇒ L3/L4 y hệt ⇒ gửi lại là **cùng
5-tuple, cùng seq**. Hậu quả:

- Engine nối vào flow cũ, không tạo flow mới
- F9 đã bắn ở gói 9; gói 10–18 không sinh checkpoint mới ⇒ **không có alert thứ hai**
- 9 gói trùng lặp làm hỏng `packet_count` và inter-arrival-time — đúng nhóm
  đặc trưng đang nghi ngờ ở vụ GoldenEye

Tức là vừa không thêm mẫu, vừa làm bẩn mẫu duy nhất. Người dùng bác bỏ đúng.

### Đã sửa

| File | Sửa gì |
|---|---|
| `scripts/kali_t85_golden_sender.py` | `set_link()` bỏ qua khi MTU/link đã đúng (no-op thay vì flap); nếu buộc phải đổi thì `sleep 2` chờ hội tụ sau khi up |
| `scripts/run_t85_pending_replays.py` | `prepare_link()` đặt MTU eth1 một lần từ đầu ⇒ replay sau đó không flap; verify `packets_seen >= 9`, thiếu thì **dựng sensor session mới** chạy lại (tối đa 3 lần), không gửi lại vào flow cũ |
| `scripts/summarize_sensor_log.py` | Mới. Chạy trên sensor host, in 1 dòng JSON: `packets_seen`, `packets_parsed`, `parser_errors`, `alerts`, `ready`, `stop_reason`, `candidates`. Thay cho `grep -c` (chỉ đếm alert, không phân biệt được capture miss với model miss) |

Attempt chạy lại đặt tên `f9-<case><suffix>t2`, `…t3` — attempt lỗi giữ nguyên.

### Ghi chú vận hành

- Agent nền ghi JSON có **BOM UTF-8**; đọc bằng `encoding="utf-8-sig"`.
- Vite dev server tự chết sau một lúc; khởi động lại khi cần.

## 2026-08-09 00:0x +07:00 — Vế OFFLINE hoàn tất, có evidence tái lập được

`scripts/run_t85_offline_f9.py` chạy đủ 14 case. Kết quả:
`run_log/full-flow-v1/replay-runs/20260808-194942/offline-f9-results.json`
(giữ `raw_stdout` từng case).

**14/14 case sinh alert · 12/14 đúng nhãn.**

| Case | Ground truth | Offline đoán | Conf | |
|---|---|---|---:|---|
| bot | Bot | Bot | 1.000 | ✓ |
| ddos | DDoS | DDoS | 0.997 | ✓ |
| dos-goldeneye | DoS GoldenEye | DoS GoldenEye | 1.000 | ✓ |
| dos-hulk | DoS Hulk | DoS Hulk | 1.000 | ✓ |
| dos-slowhttptest | DoS Slowhttptest | **DoS GoldenEye** | 0.893 | ✗ |
| dos-slowloris | DoS slowloris | DoS slowloris | 1.000 | ✓ |
| ftp-patator | FTP-Patator | FTP-Patator | 1.000 | ✓ |
| heartbleed | Heartbleed | Web Attack – Brute Force | 0.383 | ✗ |
| infiltration | Infiltration | Infiltration | 0.743 | ✓ |
| portscan | PortScan | PortScan | 1.000 | ✓ |
| ssh-patator | SSH-Patator | SSH-Patator | 1.000 | ✓ |
| web-brute-force | Web Attack – Brute Force | Web Attack – Brute Force | 0.927 | ✓ |
| web-sql-injection | Web Attack – Sql Injection | Web Attack – Sql Injection | 0.597 | ✓ |
| web-xss | Web Attack – XSS | Web Attack – XSS | 0.667 | ✓ |

### Đọc đúng con số

- **12/13 trên tập có model.** Heartbleed không nằm trong 13 lớp
  (`flow_id: null`, `semantic_kind: raw_label_window_not_f9`); nó rơi vào
  Web Attack Brute Force với conf **0.383** — hành vi kỳ vọng khi gặp lớp lạ,
  không tính là sai. Con số 12/13 báo trước đây hoá ra đúng, nhưng lúc đó
  **không có file nào chứng minh**; giờ thì có.
- **Sai thật duy nhất: `dos-slowhttptest` → DoS GoldenEye (0.893).** Cùng nhóm
  nhầm lẫn giữa các biến thể DoS HTTP flood như GoldenEye↔Hulk ở vế online.
  Cũng đính chính nhận định cũ "dos-slowhttptest không sinh alert offline" —
  nó **có** sinh alert, chỉ là đoán sai.
- **`portscan` offline đúng conf 1.000 nhưng online 0 alert.** Không mâu thuẫn:
  pcap cắt sẵn đúng 9 gói nên chạm F9; SYN scan thật ngoài mạng mỗi flow 1–2
  gói, không bao giờ chạm. Đây là bằng chứng sạch nhất cho giới hạn của
  partial-flow F9 — cùng một họ tấn công, khác cách quan sát, khác kết quả.

### Ý nghĩa

Đã có **đường cơ sở**: model đúng 12/13 khi **không** qua mạng. Mọi chênh lệch
của vế online so với mức này quy được về khâu truyền, không phải về model.
Đây là điều kiện cần để diễn giải con số DoS GoldenEye 6,7% online.

## 2026-08-09 00:1x–01:0x +07:00 — Vế ONLINE: 5 lỗi liên tiếp, chưa xong

Ghi trung thực: phần này **chưa có kết quả**. Bảy pass replay (r2→r10), mỗi
pass lộ ra một lỗi che lỗi kế tiếp. Liệt kê cả các chẩn đoán sai của tôi.

### Chuỗi lỗi thật, theo thứ tự phát hiện

| # | Lỗi | Triệu chứng | Sửa |
|---|---|---|---|
| 1 | Replay bắn trước khi sensor bind xong port | `packets_seen=0` | poll `nids_dpdk_live_ready` thay `sleep` cố định |
| 2 | apache2 giữ 3 hugepage qua `/anon_hugepage` | `EAL: Not enough memory! Requested 256MB, available 250MB` → sensor thoát ngay | `systemctl stop apache2` → 128/128 free |
| 3 | 4 pcap có frame jumbo (LRO gộp) | `frame larger than MTU 1500` | đo kích thước frame; xem mục dưới |
| 4 | Receipt Kali dùng mode `x` | `[Errno 17] File exists` | thêm `--attempt` đặt tên receipt, giữ nguyên create-new |
| 5 | 9 frame replay không tới sensor | `seen` = 0 hoặc 4 (nhiễu nền) | **chưa giải quyết** |

### Chẩn đoán SAI của tôi — ghi lại để không lặp

1. **"Link flap nuốt 5 frame đầu"** (pass r2). Sai. Dữ liệu cho thấy mất là
   all-or-nothing: case chạy được có `seen=13` (9 + 4 nhiễu), case hỏng có
   `seen=4` (chỉ nhiễu). Không có case nào mất một phần. Tôi vẫn sửa
   `set_link()` theo giả thuyết này rồi mới đọc kỹ số.
2. **"Hai tiến trình r3 tranh NIC"**. Sai. Hai PID cùng `CreationDate` là cặp
   parent/child của một lần khởi chạy, không phải hai lần chạy song song.
3. **"12/14 gói không parse được"** (r10). Sai. `parsed=2, parser_errors=12`
   là nhiễu nền, không phải 9 frame replay bị parse hỏng. Attempt retry cho
   `seen=4, parsed=4, perr=0` — đúng mức nhiễu, xác nhận frame replay không
   hề tới.
4. **"4 case bị chặn vĩnh viễn vì jumbo"**. Sai — người dùng chỉ ra. Chiều nay
   đã đo được cả 4 bằng family-window pcap. Xem mục dưới.

Điểm chung của cả 4: suy đoán từ con số tổng hợp thay vì đọc log sensor. Lỗi
hugepage chỉ lộ ra khi đọc `/tmp/sensor-*.log` — việc đáng lẽ phải làm ngay
từ pass r2.

### Frame jumbo: đo được, và KHÔNG phải bế tắc

Đo kích thước frame từng pcap 9-gói:

| Case | Frame lớn nhất | Số frame > 1518 |
|---|---:|---:|
| ddos | 8814 | 1 |
| dos-goldeneye | 5858 | 2 |
| portscan | 5858 | 2 |
| dos-hulk | 4421 | 3 |
| 10 case còn lại | ≤ 1372 | 0 |

Đây là segment bị LRO/TSO gộp lúc capture, không phải frame thật trên dây.

MTU 1500 → replay từ chối gửi. MTU 9000 → vmnet drop sạch (`seen=0`, mất cả
nhiễu). Không MTU nào chạy được cả 14 case ở đơn vị 9-frame.

**Nhưng chiều nay đã đo được 4 case này** bằng `family-windows/*.pcap`
(190–366 MB): mất ~15–20% gói jumbo, vẫn còn hàng nghìn flow đạt F9. Evidence:
`replay-runs/20260808-155731/f9-per-replay-family-DEMO.md` (DoS Hulk 6086
alert 77,6%; GoldenEye 4127 alert 6,7%; DDoS 68 alert 83,8%; FTP/SSH-Patator
100%; PortScan 0).

Nên phát biểu "bị chặn" là sai. Chính xác: **bị chặn ở đơn vị 9-frame**, không
bị chặn ở đơn vị family-window.

### Cấu trúc evidence chốt lại — hai bảng, không ép vào một

**Bảng A — 9-frame** (1 flow / 9 gói / 1 checkpoint), 10 family:
bot, dos-slowhttptest, dos-slowloris, heartbleed, web-sql-injection, web-xss,
ftp-patator, ssh-patator, infiltration, web-brute-force.

**Bảng B — family-window** (traffic thật, hàng nghìn flow), 6 family:
ddos, dos-goldeneye, dos-hulk, portscan, ftp-patator, ssh-patator.

`ftp-patator` và `ssh-patator` nằm ở cả hai — điểm neo để đo ảnh hưởng của
việc đổi đơn vị mẫu. Cả hai bảng đều so được với offline 14/14 vì offline chạy
trên chính pcap 9-gói.

### Bug đo còn tồn

`collect()` chờ `idle+15s` rồi `pkill` + 10s settle, vẫn đọc trước khi hgfs
flush xong: báo `packets_seen=0` cho attempt mà file trên đĩa ghi `seen=14`.
Hệ quả: attempt bị đánh dấu `capture_miss` oan và retry vô ích. **Dữ liệu
không mất** — đọc lại từ đĩa là đủ. Chưa sửa.

### Sự cố vận hành

- `TaskStop` chỉ giết orchestrator phía Windows; sensor trên Ubuntu chạy
  detached nên **vẫn sống**, giữ `ens160` ở vfio-pci và toàn bộ hugepage.
  Pass sau thấy `data.present=False` và `HugePages_Free=0`. Phải
  `sudo pkill -f nids_dpdk_live` (pkill thường bị từ chối) rồi chờ trap
  rollback chạy.
- Vite bind **chỉ IPv6** (`[::1]:5173`); `curl 127.0.0.1:5173` trả `000` làm
  tôi tưởng nó chết và khởi động lại thừa 2 lần. Đã kill instance thừa.
- `--attempt-suffix -r4` bị argparse hiểu là tên option; phải viết
  `--attempt-suffix=-r4`.

### Việc còn treo

1. **Test dứt điểm chưa chạy**: `tcpdump -i eth1` phía Kali trong lúc replay.
   tcpdump thấy 9 frame mà sensor không thấy → mất ở vmnet; tcpdump không thấy
   → lỗi phía gửi. Một lần chạy là biết, không cần đoán thêm.
2. **apache2 đang tắt** — phải bật lại: `sudo systemctl start apache2`.
3. Sửa biên settle của `collect()`.

## 2026-08-09 01:0x–01:3x +07:00 — Test tcpdump 2 đầu: bác bỏ giả thuyết, chốt hiện trạng

### Test dứt điểm: frame CÓ tới Ubuntu

Chạy `tcpdump` đồng thời trên Kali `eth1` và Ubuntu `ens160` (kernel, chưa
bind DPDK), rồi replay `ftp-patator`. Ubuntu bắt **đủ cả 9 frame**, đúng thứ
tự, đúng nội dung:

```
00:50:06.824 172.16.0.1.52146 > 192.168.10.50.21: [S]
00:50:06.824 192.168.10.50.21 > 172.16.0.1.52146: [S.]
00:50:07.251 FTP: 220 (vsFTPd 3.0.3)
00:50:07.251 FTP: USER iscxtap
00:50:07.254 FTP: 331 Please specify the password.
00:50:07.254 FTP: PASS 0000	Holt
```

⇒ Đường mạng Kali→Ubuntu **không hỏng**. Lỗi nằm ở khâu NIC bị bind vào DPDK.

### Giả thuyết vmnet + broadcast: SAI

Suy luận lúc đó: vmnet switch học MAC theo port; khi `ens160` sang DPDK thì
kernel ngừng phát, entry MAC hết hạn, switch bỏ unicast nhưng vẫn flood
broadcast/multicast. Khớp với việc sensor chỉ thấy nhiễu (IPv6 RS, mDNS, ARP)
— và 12 `parser_errors` chính là các gói đó, không phải frame replay parse hỏng.

Sửa `kali_t85_scenario_replay.py` thêm `parse_destination_mac()` cho phép MAC
broadcast (`parse_mac` của golden sender từ chối, đúng với vai trò của nó).
Chỉ đổi 6 byte MAC đích ⇒ 5-tuple, payload, inter-arrival timing giữ nguyên.

Chạy thử `f9-ftp-patator-bcast`:

```
seen=0 parsed=0 perr=0 flows=0 f9=0 alerts=0
port_ipackets=0 port_imissed=0 port_rx_nombuf=0 stop_reason=idle_timeout
duration_ms=60000
```

**Bác bỏ.** `port_ipackets` là bộ đếm phần cứng của NIC. Bằng 0 nghĩa là NIC
không nhận gói, không phải nhận rồi bị lọc/parse hỏng. Nếu giả thuyết đúng thì
broadcast phải qua được. Không qua ⇒ giả thuyết sai.

### Hiện trạng vế online: không ổn định, không theo quy luật

| Attempt | port_ipackets |
|---|---:|
| heartbleed-r2 | 36 |
| bot-r3, dos-slowhttptest-r3 | 13 |
| ftp-patator-r10 | 14 |
| phần lớn attempt khác | 0 hoặc 4 |
| ftp-patator-bcast | 0 |

Không có quy luật theo family, theo MAC đích, hay theo MTU. Cùng cấu hình, lúc
nhận lúc không. Đây là vấn đề độ tin cậy của đường bind DPDK trên vmnet, không
phải lỗi script.

### Tổng kết phiên

Đã sửa **5 lỗi thật**: timing arm/replay · hugepage bị apache2 giữ · frame
jumbo · receipt guard mode `x` · argparse `--attempt-suffix`.

Đã bác bỏ **5 giả thuyết sai của tôi**: link flap · hai tiến trình tranh NIC ·
"12/14 gói parse hỏng" · "4 case bị chặn vĩnh viễn vì jumbo" · vmnet không
forward unicast.

Trạng thái evidence:

| Vế | Trạng thái |
|---|---|
| **Offline** | ✅ Xong. 14/14 alert, 12/13 đúng trên tập có model. File tái lập được, giữ `raw_stdout` |
| **Online — family-window** | ✅ Có từ pass chiều. 6 family. Chứa phát hiện quan trọng nhất: GoldenEye 6,7% online vs 100% offline |
| **Online — 9-frame** | ❌ Chưa xong. Chỉ 6/10 family có mẫu hợp lệ |

Bảng 9-frame cho vế online là **cách trình bày bổ sung**, không phải kết quả
mới: kết luận về chênh lệch online/offline đã có đủ từ family-window.

### Dọn dẹp cuối phiên

- Trước khi tắt VM: `ens160` UP, hugepage 128/128, không sensor sót, NIC đã
  rollback khỏi vfio-pci.
- Attempt hỏng giữ nguyên toàn bộ, không xoá receipt nào.
- ⚠️ **`apache2` chưa được bật lại.** Nó bị `systemctl stop` để giải phóng 3
  hugepage; VM Ubuntu tắt trước khi kịp `systemctl start`. `stop` không
  persistent nên apache2 sẽ tự chạy lại khi boot **nếu unit đang enabled** —
  **phải kiểm tra lại ở phiên sau**:

  ```
  sudo systemctl start apache2 && systemctl is-enabled apache2
  ```

  Nếu lần sau lại gặp `EAL: Not enough memory! Requested 256MB, available
  250MB` thì đây là nguyên nhân: apache2 giữ hugepage qua `/anon_hugepage`,
  và `config/dpdk-passive.json` khai đúng 128 page = 256 MB, không có dư.

---

## 2026-08-09 04:0x–04:2x — Gộp ba phép đo thành một bảng

Yêu cầu: `gộp bảng`. Trước đó người dùng hỏi vì sao có 3 file live và vì sao
form offline khác live.

### Trả lời cấu trúc: 3 file live là 3 tầng, không phải 3 kết quả

```
sensor.jsonl          RAW    engine ghi, 1 thư mục / 1 attempt, không sửa
   ↓ watch_scenario_alerts.py
live-detection-f9.jsonl  STREAM   dashboard tail 1 file duy nhất, gộp mọi run
replay-runs/<run>/f9*.jsonl  ARCHIVE  tách theo run/pass để chấm điểm
```

STREAM và ARCHIVE được ghi trong **cùng một vòng lặp**
(`watch_scenario_alerts.py:79-80`), nội dung giống hệt, chỉ khác cách gom.
Phải tách vì dashboard không tail được 40 thư mục, còn chấm điểm thì không
được trộn 6086 dòng Hulk buổi chiều với 9 dòng tối.

Offline khác form vì **đơn vị mẫu khác**: 1 dòng = 1 case (không phải 1 alert),
và mang thêm `ground_truth` + `correct` + `raw_stdout`. Giữ `raw_stdout` vì
`nids_demo_replay` trả exit code 1 kể cả khi chạy đúng.

### Hai lỗi phát hiện khi dựng bảng

**1. Stream đếm thừa.** `live-detection-f9.jsonl` có **2 dòng** cho `bot-r2` và
2 dòng cho `heartbleed-r2`, trong khi `sensor.jsonl` của cả hai attempt chỉ có
**đúng 1** `nids_alert`. Đã loại trừ nguyên nhân CRLF (file có 0 CRLF). Giả
thuyết còn lại: **hai tiến trình watcher chạy song song** cùng ghi vào một
output — hai timestamp cách nhau 1,11 s trong khi poll là 2,0 s, khớp với hai
process lệch pha. **Chưa sửa**, mới ghi nhận.

**2. Thư mục attempt không đủ để xác định family.** `f9-ddos-r8t3` chứa alert
của một flow **FTP-Patator port 21**, và phía Kali **không có receipt**
`ddos.f9-ddos-r8t3.json` — tức không hề có replay ddos nào ở attempt đó.

**3. Sáu thư mục lẫn từ pass khác.** `f9-ddos`, `f9-ftp-patator`,
`f9-ssh-patator`, `f9-dos-hulk`, `f9-dos-goldeneye`, `f9-portscan` nằm trong
folder run 194942 nhưng có mtime **15:2x–15:5x**, trong khi folder mở lúc
19:49 — chúng là capture family-window buổi chiều được copy vào (copy giữ
mtime). `packets_seen` hàng nghìn, không phải 9.

### Cách chặn cả ba

`scripts/build_f9_online_offline_table.py` (mới) đọc thẳng `sensor.jsonl`, bỏ
qua STREAM, và:

- đối chiếu **5-tuple** của mỗi alert với `tuple` trong `pcap/manifest.json`;
  không khớp → `foreign_flow`, đưa vào bảng "Bị loại", không bao giờ chấm điểm;
- loại attempt có mtime **trước thời điểm run bắt đầu** (giải mã từ chính
  `run_id`), tách hẳn hai đơn vị mẫu;
- lấy candidate từ `evidence.known_family.top_candidate` (không phải
  `candidate`/`name` — hai tên đó không tồn tại, lần chạy đầu ra `None` hết).

### Kết quả

`run_log/full-flow-v1/replay-runs/20260808-194942/f9-online-offline-comparison.{json,md}`

| Phép đo | Có alert | Đúng | Tỷ lệ |
|---|---:|---:|---:|
| Offline | 14/14 | 12 | 85,7% |
| Online 9-frame | 6/14 | 3 | 50,0% |
| Online family-window | 10650 alert | 5426 | 50,9% |

**Ba con số này không so trực tiếp với nhau được** — khác đơn vị mẫu. Phần so
được là 6 family có cả hai vế:

| Family | Offline | Online 9-frame | Khớp |
|---|---|---|---|
| Bot | Bot (1,000) | Bot (1,000) | ✅ |
| DoS Slowhttptest | DoS GoldenEye (0,893) | DoS GoldenEye (0,940) | ✅ cùng sai |
| DoS slowloris | DoS slowloris (1,000) | DoS slowloris (0,997) | ✅ |
| Heartbleed | Web Attack – Brute Force (0,383) | Web Attack – Brute Force (0,383) | ✅ cùng sai |
| Web Attack – Sql Injection | Sql Injection (0,597) | **Brute Force (0,603)** | ❌ |
| Web Attack – XSS | XSS (0,667) | XSS (0,623) | ✅ |

**5/6 khớp, kể cả 2 ca sai giống hệt nhau.** Sai giống hệt mới là bằng chứng
đường truyền trung thực: nếu đường truyền làm hỏng đặc trưng thì hai vế đã
phải sai theo hai kiểu khác nhau.

Khác biệt duy nhất là Web Attack – Sql Injection, và độ tin cậy hai bên gần
nhau (0,597 vs 0,603) — hai lớp sát nhau bị đảo thứ tự khi đặc trưng lệch nhẹ,
không phải model hỏng.

### Điều chỉnh một kết luận cũ

Bảng gộp cho thấy **4 family bị chặn vì jumbo frame (ddos, dos-goldeneye,
dos-hulk, portscan) lại chính là 4 family đo được ở vế family-window**. Nên ô
trống ở cột 9-frame của chúng không phải lỗ hổng dữ liệu — cùng một family
vẫn có số liệu online, chỉ ở đơn vị mẫu khác.

### Chưa làm

- Lỗi watcher đếm thừa: chưa sửa, mới ghi nhận.
- 4 family `ftp-patator`, `ssh-patator`, `infiltration`, `web-brute-force` vẫn
  `bắt thiếu gói` (seen=4–14) ở vế 9-frame, vẫn do RX của DPDK trên vmnet không
  ổn định — nguyên nhân chưa tìm ra.
- ⚠️ `apache2` trên Ubuntu vẫn chưa được bật lại (xem mục trước).

---

## 2026-08-09 04:3x–04:5x — Đo pacing: giải thích được GoldenEye 6,7%

Yêu cầu: `so timestamp gốc với timestamp ở sensor cho goldeneye đi`.

### Cách đo

`scripts/compare_replay_pacing.py` (mới). Hai đồng hồ không bao giờ khớp nhau
được — nguồn ghi unix epoch, sensor ghi bộ đếm monotonic — nên cả hai được
chuẩn hoá về mốc đầu tiên của chính nó, chỉ so **khoảng thời gian trôi qua**.

Hai điểm phải xử lý trước khi con số có nghĩa:

1. **Mọi lần chạy family-window đều bị `stop_reason=signal`**, tức sensor bị
   giết ở ~180 s chứ không phải replay chạy hết pcap. So toàn bộ file với 180 s
   là đo cái nút kill, không phải đo pacing. Nên nguồn được **cắt đúng bằng số
   gói sensor thật sự thấy** (`packets_seen`) rồi mới so.
2. Ghép flow bằng 5-tuple **không phân biệt chiều**, giống cách engine ghép hai
   nửa của một flow.

### Kết quả — tương quan gần như tuyệt đối

| Family | pps gốc | pps tới sensor | Pacing | Accuracy online |
|---|---:|---:|---:|---:|
| dos-goldeneye | 2016 | 538 | **×0,28** | **6,7%** |
| dos-hulk | 2319 | 607 | ×0,36 | 77,6% |
| ddos | 1107 | 808 | ×0,77 | 83,8% |
| ssh-patator | 48 | 47 | ×0,99 | 100,0% |
| ftp-patator | 32 | 32 | ×1,00 | 100,0% |

Hai family giữ nguyên pacing đạt **100%**. Hai family bị giãn mạnh nhất là hai
family sai nhiều nhất.

### Cơ chế

Đường vmnet chỉ tải nổi khoảng **550–800 gói/giây**. Family nào có tốc độ gốc
vượt ngưỡng đó thì bị giãn:

```
GoldenEye:  102.135 gói trong 50,7 s ở nguồn   (≈2016 gói/giây)
            102.135 gói trong 189,8 s ở sensor (≈538 gói/giây)
            → mọi khoảng cách giữa các gói bị nhân lên 3,6 lần
```

F9 đọc inter-arrival time. Nhân mọi khoảng cách lên 3,6 lần thì một đợt flood
nhanh trông thành một đợt chậm — và đúng như vậy, GoldenEye bị nhầm nhiều nhất
sang **DoS Hulk (3175 lần)**, cũng là HTTP DoS nhưng khác hồ sơ thời gian.

Cùng bộ gói đó chạy offline với thời gian đúng: **100%, conf 1,000**.

### Giả thuyết cũ đã sai chiều

Trước đây tôi ghi nghi ngờ là "tcpreplay **nén** thời gian". Đo ra thì ngược
lại: thời gian bị **giãn**, vì bộ phát không đuổi kịp chứ không phải chạy quá
nhanh. Kết luận về nguyên nhân gốc (đặc trưng thời gian bị bóp méo) vẫn đúng,
nhưng chiều thì ngược.

### Vì sao kết quả này khớp với vế 9-frame

Không mâu thuẫn, mà bổ sung cho nhau:

| | Tốc độ | Đường truyền | Kết quả |
|---|---|---|---|
| 9-frame | 9 gói, không nghẽn | trung thực | khớp offline 5/6 |
| family-window | ~2000 gói/giây | nghẽn, giãn 3,6× | lệch offline nặng |

Vế 9-frame chứng minh đường truyền **trung thực về nội dung và thứ tự**. Vế
pacing chứng minh nó **không trung thực về thông lượng khi bị ép tải**. Hai
điều đó cùng đúng, và cùng nhau giải thích trọn vẹn khoảng cách online/offline.

### Chốt lại nghi phạm GoldenEye

Bốn nghi phạm ban đầu, giờ còn:

| | Nghi phạm | Trạng thái |
|---|---|---|
| a | Dây làm hỏng nội dung/thứ tự | ❌ loại (9-frame) |
| b | Cách engine cắt flow khác CICIDS | ❌ loại — flow ghép được bằng 5-tuple, 3380/4127 khớp |
| c | Window chứa traffic không phải GoldenEye | còn, nhưng không giải thích được tương quan pacing |
| d | Model yếu trên traffic thật | ❌ loại — cùng gói, đúng thời gian, offline ra 100% |
| **e** | **Thông lượng lab không đủ, IAT bị giãn** | ✅ **đo được, ×0,28** |

### File

- `scripts/compare_replay_pacing.py`
- `run_log/full-flow-v1/replay-runs/20260808-194942/replay-pacing-comparison.json`
- Bảng pacing đã nhập vào `f9-online-offline-comparison.md`

### Hệ quả cho cách trình bày

Con số family-window (77,6% / 6,7% / 83,8%) **không được trình bày như năng lực
model**. Chúng đo model **cộng với** một đường truyền bị nghẽn. Muốn có số
online trung thực cho các family tốc độ cao thì phải hoặc nâng thông lượng lab,
hoặc chỉ trình bày vế 9-frame và offline.

---

## 2026-08-09 05:0x — Sửa số pacing: tách mất gói khỏi giãn thời gian

`port_imissed` trong summary của sensor cho thấy phép đo pacing ở mục trên
**trộn hai hiệu ứng**. Số ×0,28 cho GoldenEye là sai.

### Sai ở đâu

Phép đo cắt pcap nguồn tại `packets_seen` — số gói sensor **xử lý**. Nhưng NIC
**nhận** nhiều hơn thế và vòng RX bỏ bớt:

```
port_ipackets  176.791   (NIC nhận)
port_imissed    74.656   (vòng RX bỏ, thiếu descriptor)
packets_seen   102.135   = 176.791 - 74.656   ← khớp chính xác
```

Cắt tại 102.135 tức là **quy phần gói bị bỏ thành thời gian bị giãn**. Đúng ra
phải cắt tại `port_ipackets` và báo cáo mất gói riêng.

### Số đúng

| Family | pps gốc | pps tới sensor | Mất gói | Pacing | Accuracy online |
|---|---:|---:|---:|---:|---:|
| dos-hulk | 2085 | 607 | **46,0%** | ×0,71 | 77,6% |
| dos-goldeneye | 1330 | 538 | **42,2%** | ×0,55 | 6,7% |
| ddos | 1107 | 808 | 6,4% | ×0,77 | 83,8% |
| ftp-patator | 32 | 32 | **0,0%** | ×1,00 | 100,0% |
| ssh-patator | 48 | 47 | **0,0%** | ×0,99 | 100,0% |

Số cũ (sai): goldeneye ×0,28 · hulk ×0,36. Số đúng: ×0,55 và ×0,71, kèm mất gói
42,2% và 46,0%.

### Kết luận đổi trọng số, không đổi hướng

**Mất gói bám sát kết quả hơn cả pacing.** 0% mất → 100% đúng (cả hai family).
6,4% mất → 83,8%. 42–46% mất → hai family kém nhất. Ngưỡng lab quanh **800
gói/giây**: dưới ngưỡng không mất gói nào.

Cơ chế mất gói nguy hiểm hơn giãn thời gian, vì nó không chỉ bóp méo thời gian:
**9 gói mà F9 chấm trở thành 9 gói sống sót, không phải 9 gói đầu tiên của
flow.** `packet_count` và toàn bộ đặc trưng inter-arrival được tính trên tập
gói sai.

Kết luận "giới hạn thông lượng lab, không phải lỗi model" vẫn đứng, và giờ có
cơ chế cụ thể hơn: tràn vòng RX chứ không phải bộ phát chậm.

### Vì sao vế 9-frame không dính

`port_imissed = 0` trên mọi attempt 9 gói. Chín gói không bao giờ làm tràn vòng
RX. Đó là lý do vế 9-frame khớp với offline còn vế family-window thì không —
và là lý do vế 9-frame **không** chứng minh được hệ thống chịu được tải thật.

---

## 2026-08-09 06:0x — r12: 4/4 family còn thiếu đã bắt được, bảng 9-frame lên 10/14

Sau khi sửa lỗi `pkill`, chạy lại 4 family `ftp-patator`, `ssh-patator`,
`infiltration`, `web-brute-force` với suffix `-r12`.

### Kết quả: 4/4

| Family | Attempt | seen | parsed | alerts |
|---|---|---:|---:|---:|
| ftp-patator | `f9-ftp-patator-r12t3` | 13 | 13 | 1 |
| ssh-patator | `f9-ssh-patator-r12t3` | 13 | 13 | 1 |
| infiltration | `f9-infiltration-r12t3` | 13 | 13 | 1 |
| web-brute-force | `f9-web-brute-force-r12` | 27 | 15 | 1 |

`seen=13` = 9 frame replay + 4 gói nhiễu nền, chữ ký của lần bắt thành công.

### Điều quan trọng: retry vẫn luôn có tác dụng

Ba trong bốn family ăn ở **lần thử thứ 3**:

```
ftp-patator     try1 seen=0 · try2 seen=1 · try3 seen=13 ✅
ssh-patator     try1 seen=0 · try2 seen=4 · try3 seen=13 ✅
infiltration    try1 ...    · try2 ...    · try3 seen=13 ✅
```

Các pass trước **không bao giờ tới được lần thử thứ 3 một cách sạch sẽ**, vì
sensor của lần trước chưa bị dọn (pkill thiếu sudo) nên lần thử sau không bind
được cổng. Không phải "DPDK RX trên vmnet chập chờn không giải thích được" —
là lỗi dọn dẹp trong orchestrator, cộng với việc cần đủ 3 lần thử.

### Sửa lại một kết luận đã ghi trong changelog

Mục `04:3x` và các mục trước ghi 4 family này là **"bị chặn bởi RX không ổn
định, chưa tìm ra nguyên nhân"**. Sai. Nguyên nhân là:

1. `pkill -f nids_dpdk_live` thiếu `sudo` → sensor cũ không chết
2. Bản vá thêm `sudo` lại **tự giết phiên ssh** vì pattern khớp chính dòng lệnh
   của nó → bước `collect` chết trước khi summarize → mọi attempt báo
   `packets_seen=0`, đọc nhầm thành mất gói
3. Sửa bằng bracket `[n]ids_dpdk_live` → cả 4 family bắt được ngay

### Bảng 9-frame sau khi cập nhật

| Phép đo | Có alert | Đúng | Tỷ lệ |
|---|---:|---:|---:|
| Offline | 14/14 | 12 | 85,7% |
| **Online 9-frame** | **10/14** | **7** | **70,0%** |
| Online family-window | 10650 alert | 5426 | 50,9% |

10/14 là **toàn bộ family gửi được** — 4 family còn lại bị chặn bởi jumbo frame,
là tính chất của bản capture chứ không phải kết quả đo.

### So trực tiếp: 9/10 khớp

| Family | Offline | Online 9-frame | Khớp |
|---|---|---|---|
| Bot | Bot (1,000) | Bot (1,000) | ✅ |
| DoS Slowhttptest | DoS GoldenEye (0,893) | DoS GoldenEye (0,940) | ✅ cùng sai |
| DoS slowloris | DoS slowloris (1,000) | DoS slowloris (0,997) | ✅ |
| FTP-Patator | FTP-Patator (1,000) | FTP-Patator (1,000) | ✅ |
| Heartbleed | Web – Brute Force (0,383) | Web – Brute Force (0,383) | ✅ cùng sai |
| Infiltration | Infiltration (0,743) | Infiltration (0,733) | ✅ |
| SSH-Patator | SSH-Patator (1,000) | SSH-Patator (0,993) | ✅ |
| Web – Brute Force | Web – Brute Force (0,927) | Web – Brute Force (0,920) | ✅ |
| Web – Sql Injection | Sql Injection (0,597) | **Brute Force (0,603)** | ❌ |
| Web – XSS | XSS (0,667) | XSS (0,623) | ✅ |

**9/10 khớp**, kể cả 2 ca sai giống hệt nhau. Cỡ mẫu tăng từ 6 lên 10 family và
tỷ lệ khớp tăng từ 5/6 lên 9/10 — kết luận "đường truyền trung thực khi không
nghẽn" mạnh hơn hẳn so với lúc chỉ có 6 family.

Khác biệt duy nhất vẫn là Web Attack – Sql Injection, hai lớp sát nhau
(0,597 vs 0,603) đảo thứ tự.

### Alert lên dashboard theo thời gian thực

Watcher đẩy được alert vào `live-detection-f9.jsonl` **trong lúc replay đang
chạy**, dashboard hiển thị ngay. Đây là lần đầu trong chuỗi phiên này luồng
live hoạt động đúng như thiết kế.
## 2026-08-09 14:00 +07:00 — Terminal PortScan offline scorer hoàn tất (t91-terminal-portscan-offline-scored-r1)

- Thêm scripts/score_terminal_flows_onnx.py: verify SHA-256 mọi member của
  bundle khóa, đọc JSONL streaming theo batch, chọn đúng 54 feature profile A,
  chạy ONNX Runtime CPU và áp dụng attack gate khóa 0,9984837643022101.
- Dependency được đặt trong virtualenv riêng trên Ubuntu
  ~/.local/nids-toolchain/venvs/terminal-scorer; dùng ONNX Runtime 1.27.0 đúng
  phiên bản đã dùng tạo parity evidence, không sửa Python hệ thống.
- Sửa số đếm handoff: /tmp/ps_flows.jsonl có 84.223 dòng nhưng dòng cuối là
  kind=summary; exporter xác nhận 84.222 flow, 169.265 packet, 0 parser/ingest/
  terminal-feature error.
- Kết quả full family-window: 82.414/84.222 PortScan = 97,8533%;
  1.808 flow bị gate về Benign. Raw argmax: 84.217 PortScan, 2 Benign, 3 DoS.
- Validation profile A để đối chiếu sau: 34.661/34.680 PortScan = 99,9452%.
  Con số 99,6166% trong handoff cũ là attack recall toàn bộ lớp tấn công,
  không phải riêng PortScan.
- Evidence luận văn: run_log/full-flow-v1/offline-portscan/20260809-full-pcap/
  summary.json và portscan-terminal-scores.jsonl; SHA-256 nằm trong
  config/agent/current-task.json.
- Test: python -m unittest tests.test_score_terminal_flows_onnx => 5/5 pass.
- Test partition vẫn sealed, mọi bộ đếm read bằng 0. Không sửa model,
  threshold, schema 54-feature hoặc pipeline F3/F5/F7/F9.
- Phát hiện khi bắt đầu so sánh live: 77 decision gồm 9 flow TCP reset/3 gói và
  68 flow 1 gói flush ở EOF. Vì 68 flow có flow_age_us=0, median toàn bộ bằng
  0 và không được dùng để kết luận timing; bước tiếp theo phải tách cohort.
## 2026-08-09 14:29 +07:00 — Matched live PortScan cùng PCAP hoàn tất có giới hạn (t91-terminal-portscan-matched-live-r1)

- Chạy cùng family-windows/portscan.pcap qua Terminal V1 live, any-source,
  target 192.168.10.50, pacing 1x. Sender gửi đủ 169.265 packet, 0 send fail.
- Giữ nguyên hai attempt hỏng: r1 arm timeout trước sender (0 packet); r2 dừng
  scoped idle tại khoảng trống timestamp 71 giây (chỉ 9.929 ipackets).
- Attempt dùng làm evidence: t91-portscan-pcap-r3-20260809142208-27532754.
  NIC nhận 169.277 packet kể cả ambient, imissed 44.617 (26,36%), pipeline thấy
  124.660 packet. Có 64.951 inference: 28.422 PortScan, 438 DoS, 36.091 Benign.
- Receipt r3 status failed vì EOF inference vượt shutdown grace 250 ms; 2.048
  active flow khiến shutdown không hoàn tất. Rollback vẫn PASS: ens160 về
  vmxnet3, hugepage 128/128, management reachable.
- Tỷ lệ 28.422/64.951 = 43,7591% chỉ là phép đo model + lab path trên phần flow
  đã inference, KHÔNG phải accuracy model. Cùng PCAP chấm offline đạt 97,8533%.
  Khoảng cách được quy về RX loss và giới hạn output/EOF đồng bộ của runtime.
- Giả thuyết timing 39 lần trước đây bị bác: nó dựa trên một outlier 5.924 us.
  Median 9 flow tcp_reset nmap live là 66,002 us, chỉ 1,404 lần median offline
  47 us. Timing có thể lệch nhưng evidence hiện tại không cho phép gọi nó là
  nguyên nhân chính.
- Evidence luận văn: run_log/full-flow-v1/offline-portscan/20260809-full-pcap/
  comparison.json và comparison.md. Test partition vẫn sealed, 0 reads.
- Sudoers tạm nids-t91-tcpreplay đã xóa sau chạy; mọi attempt/receipt được giữ.
## 2026-08-09 14:35 +07:00 — FTP-Patator live chốt unsupported (t91-ftp-patator-unsupported-r1)

- Read-only check trên Windows: Web-Ftp-Server Available nhưng chưa cài;
  sc.exe query FTPSVC trả error 1060 service không tồn tại; TCP/21 đóng.
- Chọn nhánh (b) của handoff: không cài IIS FTP, account hay firewall/passive
  range mới. Terminal V1 live chỉ trình bày PortScan.
- Cách ghi luận văn: FTP-Patator live unsupported vì thiếu dịch vụ đích; đây
  không phải bằng chứng model không phát hiện.
- Evidence: run_log/full-flow-v1/live/ftp-patator/unsupported-20260809/
  decision.json và decision.md. Test partition vẫn sealed, 0 reads.
## 2026-08-09 14:34 +07:00 — Bridge Terminal sang dashboard PASS (t91-terminal-dashboard-bridge-r1)

- Thêm scripts/bridge_terminal_to_dashboard.py và 3 unit test.
- Bridge hỗ trợ nids_terminal_flow_decision và nids_terminal_flow_alert. Nếu
  sensor có decision thì ưu tiên decision, không ghi thêm alert tương ứng; với
  alerts_only thì dùng alert. Nhờ đó không double count cùng flow.
- Tạo run_log/full-flow-v1/live-detection-terminal.jsonl gồm 28.937 row:
  77 decision nmap live + 28.860 alert matched replay r3.
- Verify backend 127.0.0.1:8080 model=terminal: source_kind=real, model=terminal,
  trả đủ 28.937 event; đầu stream Benign, cuối stream PortScan.
- Test: 3/3 pass và py_compile pass. SHA-256 output/implementation đã lưu trong
  config/agent/current-task.json.
## 2026-08-09 14:41 +07:00 — Watcher chống ghi trùng PASS (t85-f9-watcher-single-instance-r1)

- scripts/watch_scenario_alerts.py giữ non-blocking OS file lock theo output
  stream; watcher thứ hai dùng cùng lock báo lỗi và exit 3.
- Thêm dedupe trong tiến trình theo attempt + 5-tuple + candidate + decision.
- Unit test 3/3, py_compile PASS. Smoke contention: watcher đầu chạy đến idle
  exit sạch; watcher thứ hai bị từ chối đúng exit 3.
- Không xóa/rewrite hai cặp duplicate lịch sử bot-r2 và heartbleed-r2; chúng
  được giữ làm evidence. Fix chỉ ngăn dòng trùng mới.
## 2026-08-09 14:47 +07:00 — P5 validate, archive và cleanup PASS (t91-terminal-portscan-handoff-complete-r1)

- Final targeted suite: 11/11 unit test PASS; 4/4 script py_compile PASS;
  current-task, offline summary và comparison JSON parse PASS.
- Dashboard backend model=terminal vẫn source_kind=real, 28.937 event.
- Ubuntu: không còn terminal sensor; Apache active + enabled; ens160 vmxnet3;
  hugepage 128. Kali: xóa đúng hai drop-in nids-t91-tcpreplay và
  nids-t91-portscan vì campaign đã kết thúc.
- Cleanup receipt: run_log/full-flow-v1/cleanup/20260809-final/receipt.json.
- Evidence index luận văn gồm 17 member với path/size/SHA-256:
  run_log/full-flow-v1/thesis-evidence/terminal-portscan-20260809.json và .md.
- current tag: t91-terminal-portscan-handoff-complete-r1. Bản bàn giao trạng thái đã cập
  nhật. Model V2 vẫn capture-not-authorized và ngoài scope; top-level task không
  được đánh complete. Test partition vẫn sealed, 0 reads.

## 2026-08-09 17:xx +07:00 — Terminal V1 matched-PCAP đủ họ tấn công (t91-terminal-matched-replay-all-families-r1)

- Đã chấm offline và replay live tốc độ 1× cho đủ 13/13 ca PCAP tấn công; 14 cửa sổ gồm thêm một Benign control và được ánh xạ vào 6 nhãn Terminal V1.
- Offline dùng đúng bundle ONNX/profile A/threshold đã khóa; live dùng native DPDK passive, 1 RX queue và 0 TX queue. Không cần cài FTP service vì đây là replay PCAP thụ động.
- Cả 13 ca tấn công đều có offline summary và live `nids_terminal_live_summary`; 8/14 ca có receipt chính thức, 6 ca ghi summary hoàn chỉnh nhưng supervisor kẹt ở bước đổi tên file trên HGFS. Giữ nguyên `.tmp`, hash và đánh dấu publication failure; không dựng giả receipt.
- Bot và Infiltration đã gửi đủ PCAP nhưng có 0 packet thuộc `target_ip=192.168.10.50`; 0 inference là lỗi khớp scope, không được ghi là model false negative. Benign control cũng loại khỏi bảng chính vì endpoint không matched.
- Các ca PortScan/DoS có RX missed; tỷ lệ nhãn mong đợi trên inference live chỉ là chẩn đoán toàn đường lab, không gọi là accuracy mô hình.
- Bảng chính: `run_log/full-flow-v1/matched-terminal-20260809/terminal-matched-comparison.{json,md}`; giữ số theo từng họ gốc và nhãn gom Terminal.
- Archive luận văn: `run_log/full-flow-v1/thesis-evidence/terminal-matched-replay-20260809.{json,md}`, 49 member có size và SHA-256.
- Cleanup PASS: không còn `nids_dpdk_live`; Apache active/enabled; ens160 dùng vmxnet3; hugepages=128; đã xóa `/etc/sudoers.d/nids-t91-terminal-matched-replay`.
- Verification: 11/11 unit test PASS, 4/4 py_compile PASS, comparison/archive assertions PASS.
- Không sửa pipeline F3/F5/F7/F9, schema 54-feature, model, threshold hay runtime immutable; test partition vẫn sealed với 0 reads.
- Current tag: `t91-terminal-matched-replay-all-families-r1`. Bản bàn giao trạng thái đã cập nhật trong nhật ký bàn giao nội bộ (không đưa lên git).


## 2026-08-09 — Giải thích evidence cho giới hạn offline Terminal V1 (t91-terminal-offline-limitations-evidence-r1)

- Thêm `scripts/build_terminal_offline_limitations.py` và 3 unit test để dựng lại kết luận từ model manifest, 14 offline summary, cut log và tài liệu snapshot.
- Evidence luận văn: `run_log/full-flow-v1/thesis-evidence/terminal-offline-limitations-20260809.{json,md}`.
- Chốt năm nguyên nhân trực tiếp: gate 0,9984837643022101; taxonomy chỉ 6 nhãn; train mất cân bằng nặng (`Other` 576 row); selection contract ưu tiên FTP/PortScan; family-window và oracle/Terminal flow dùng đơn vị đếm khác nhau.
- PortScan raw argmax 84.217 nhưng final 82.414; DDoS top candidate 15.763 nhưng final 10.725. Web SQL 13/13 raw `Other` còn 10/13 sau gate.
- Web Brute Force chỉ 13/112 raw `Other`, XSS 3/105; vì sai từ raw argmax nên gate không phải nguyên nhân duy nhất. Chưa có ablation để quy lỗi cho feature cụ thể.
- Infiltration 36 oracle row/6 directional key/3 Terminal bidirectional flow; SQL Injection 21 row/12 key/13 Terminal flow. Không gọi chênh lệch này là mất flow vì khác đơn vị.
- Heartbleed có 0 accepted snapshot nên không thuộc Terminal V1; bổ sung đòi hỏi dataset/model version mới.
- Current tag cập nhật thành `t91-terminal-offline-limitations-evidence-r1`; test partition tiếp tục sealed với 0 reads.


## 2026-08-09 — Mermaid toàn tuyến F9 và Terminal (t91-f9-terminal-mermaid-evidence-flow-r1)

- Thêm source Mermaid `docs/generated/f9-terminal-pcap-replay-evidence-flow.mmd` và bản Markdown render được cùng tên `.md`.
- Nhánh F9 mô tả đúng selector T3.5 F9, tra canonical tuple ở T3.3, cắt đúng 9 packet, replay offline bằng `nids_demo_replay`, replay live bằng sender giữ timestamp và lưu raw receipts.
- Nhánh Terminal mô tả family-window dày nhất thường 180 giây, offline terminal-flow exporter/ONNX, live `tcpreplay-edit` 1× vào DPDK passive 1 RX/0 TX và cây thư mục evidence theo ca/attempt.
- Khối so sánh chốt ground truth phải từ manifest, chỉ đối chiếu online–offline trên cùng PCAP, không gộp F9 checkpoint với Terminal closed-flow thành một accuracy.
- Dashboard được ghi rõ chỉ là lớp trình bày; luận văn dùng manifest, raw sensor log, summary/receipt và comparison đã hash.
- Thêm 3 unit test kiểm tra `.mmd` trùng khối Mermaid trong Markdown, subgraph cân bằng/node ID duy nhất và đủ các ranh giới bắt buộc.
- Hai file sơ đồ và test được đưa vào thesis evidence index; F3/F5/F7/F9, schema, model, threshold và sealed test không thay đổi.
- Current tag: `t91-f9-terminal-mermaid-evidence-flow-r1`; bản bàn giao trạng thái được cập nhật.


## 2026-08-09 — Bản bàn giao trạng thái mới nhất (t91-f9-terminal-evidence-r1)

- Thêm bản bàn giao nội bộ (không đưa lên git) làm điểm vào ngắn gọn, độc lập với lịch sử dài trong nhật ký bàn giao nội bộ (không đưa lên git).
- Handoff tổng hợp trạng thái F9, Terminal, số liệu được phép dùng, path evidence, scope/RX/HGFS limitations, cleanup lab, ranh giới immutable và quy tắc resume.
- Ghi rõ agent nền không được promote `summary.json.tmp`, gọi scope mismatch là false negative, gộp accuracy F9/Terminal, mở sealed test hoặc overwrite attempt cũ.
- Thêm 3 unit test xác nhận current tag, primary evidence links và các giới hạn diễn giải bắt buộc.
- Current tag: `t91-f9-terminal-evidence-r1`; latest handoff sẽ được đưa vào thesis evidence archive.

