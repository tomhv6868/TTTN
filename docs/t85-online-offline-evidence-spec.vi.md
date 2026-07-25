# Spec: Evidence so sánh Online vs Offline cho F9 (mở rộng T8.5)

Phiên bản 1.0 · 2026-08-08 · Run tham chiếu `20260808-194942`

---

## 1. Mục tiêu và phạm vi

### 1.1 Vấn đề

T8.5 đã đạt `passed` nhưng phạm vi rất hẹp: **một flow, một checkpoint F9, một
alert, một family (DDoS)**. Nó chứng minh được đường ống chạy được, không
chứng minh được model hoạt động ra sao trên phổ tấn công.

### 1.2 Mục tiêu

Với **cả 14 case CICIDS2017** (13 case có model + 1 case Heartbleed không có
model), trả lời hai câu hỏi tách bạch:

| Câu hỏi | Đo bằng |
|---|---|
| Model F9 phân loại đúng family không? | Vế **offline**: chạy trên file pcap, không qua mạng |
| Đưa qua NIC vật lý thì kết quả có đổi không? | Vế **online**: Kali bắn qua eth1 → Ubuntu DPDK bắt |

Chênh lệch giữa hai vế **chính là chi phí của việc chạy thật**. Đó là kết quả
có giá trị nhất của phần này, không phải con số accuracy đơn lẻ.

### 1.3 Ngoài phạm vi

- Không train model, không chọn lại threshold.
- Không đụng schema 54 feature legacy hay đường F3/F5/F7/F9 đã nghiệm thu.
- Không đụng T9.1 (Terminal V1 / Model V2) — đang bị chặn ở
  `blocked_pending_capture_authorization`.
- Không sửa/xoá receipt cũ dưới `rebuild-20260808`.

---

## 2. Ground truth

### 2.1 Nguồn duy nhất được chấp nhận

```
run_log/t8.5/scenarios/<run_id>/pcap/manifest.json
```

Mỗi entry mang: `case_id`, `label`, `capture_id`, `tuple`, `start_ns`,
`end_ns`, `semantic_kind`, `flow_id`, `assignment_method`, `path`, `sha256`,
`records`.

### 2.2 Ba cách làm SAI đã loại bỏ

**Sai 1 — tra `label_row` bằng 5-tuple.** Khoá 5-tuple không phân biệt hướng
va chạm ở **48%** số flow. Một 5-tuple ánh xạ tới nhiều nhãn khác nhau.

**Sai 2 — join online↔offline bằng 5-tuple.** Quá trình tái dựng pcap **đánh
số lại source port**: 0 trên 5343 port của sensor xuất hiện trong oracle. IP
thì được giữ nguyên (172.16.0.1, 192.168.10.50). Chỉ có `flow_id` trong
manifest là khoá nối tin cậy.

**Sai 3 — gõ tay nhãn vào bảng hardcode.** Oracle ghi en-dash
`Web Attack – Brute Force` (U+2013); bảng gõ tay dùng hyphen
`Web Attack - Brute Force`. Ba family web bị chấm sai âm thầm, kéo accuracy
offline từ 12/12 xuống 9/12 mà không có dấu hiệu lỗi nào.

> **Luật:** nhãn đúng đọc từ `manifest.json` tại thời điểm chấm điểm. Không
> gõ lại, không copy vào dict.

### 2.3 Ánh xạ family → capture

Suy ra từ oracle (`flow_assignment` ⋈ `flow`), không phỏng đoán:

| Capture | Family |
|---|---|
| wednesday-working-hours | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest |
| friday-working-hours | DDoS, PortScan, Bot |
| tuesday-working-hours | FTP-Patator, SSH-Patator |
| thursday-working-hours | Infiltration, Web Attacks (Brute Force / Sql Injection / XSS) |

---

## 3. Đơn vị mẫu

### 3.1 Định nghĩa

**Một case = một flow = 9 gói = một checkpoint F9 = một alert kỳ vọng.**

Mọi case phải cùng đơn vị này ở **cả hai vế**. Đây là điều kiện bắt buộc để
so sánh có nghĩa.

### 3.2 Vì sao bắt buộc

Lần chạy đầu vi phạm điều này: 6 family replay nguyên pcap lớn (dos-hulk
177.665 gói → 6086 alert), 8 family replay đúng 9 frame (→ 1 alert). Đặt 6086
cạnh 1 rồi tính accuracy là vô nghĩa. Tương tự, báo "online 5/14" cạnh
"offline 12/12" là so hai mẫu số khác nhau.

### 3.3 Case không sinh alert — phân loại nguyên nhân

`alerts = 0` có **ba** nguyên nhân khác hẳn nhau. Không được gộp:

| `packets_seen` | Ý nghĩa | Kết luận |
|---|---|---|
| `0` | Sensor không nhận gói nào | **Lỗi hạ tầng.** Model chưa chạy. Phải chạy lại, không được tính vào mẫu. |
| `< 9` | Mất gói giữa đường | **Lỗi truyền.** Flow không đủ tới checkpoint. Chạy lại. |
| `>> 9`, alert `0` | Gói tới đủ, không flow nào đạt 9 gói | **Tính chất thật của dữ liệu.** Tính vào mẫu, ghi rõ lý do. |

Trường hợp thứ ba đúng với **PortScan**: SYN scan mỗi flow 1–2 gói, không bao
giờ chạm mốc F9. Đây là giới hạn thật của partial-flow F9, phải ghi thẳng,
không tô hồng và không sửa thành "bug".

---

## 4. Kiến trúc đường dẫn

### 4.1 Bảng phân chia

| Loại | Đường dẫn | Ràng buộc |
|---|---|---|
| Receipt thô | `run_log/t8.5/scenarios/<run_id>/` | Bắt buộc — script lab hardcode |
| Stream dashboard | `run_log/full-flow-v1/live-detection-f9.jsonl` | Nơi pipeline đọc |
| Archive lần chạy | `run_log/full-flow-v1/replay-runs/<run_id>/` | Cùng chuẩn cũ |

### 4.2 Vì sao receipt thô nằm ở `t8.5`

Hai script lab hardcode đường dẫn:

- `scripts/kali_t85_scenario_replay.py:33` → `run_log/t8.5/scenarios/<run_id>`
- `scripts/run_t85_scenario_sensor_ubuntu.sh:32` → cùng gốc

Receipt thô là bằng chứng gốc, **không dời**. Chỉ dữ liệu **dẫn xuất** (stream,
archive, evidence) mới đưa về `full-flow-v1`.

### 4.3 Cấu trúc bên trong một run

```
run_log/t8.5/scenarios/<run_id>/
├── scenario.json                    # định nghĩa 14 case
├── pcap/
│   ├── manifest.json                # GROUND TRUTH
│   └── original/<case>.pcap         # 14 file, mỗi file 9 gói
├── kali/replay/<case>.json          # receipt phía Kali
└── ubuntu/f9-<case>[-rN]/
    ├── preflight.json
    ├── resource-config.json
    ├── state.json                   # trạng thái bind DPDK
    ├── rollback.json                # xác nhận đã trả NIC về
    └── sensor.jsonl                 # ready + alert* + summary
```

### 4.4 Quy tắc chạy lại

Script sensor **từ chối ghi đè** evidence đã có. Chạy lại **không** được xoá
thư mục cũ — dùng attempt mới với hậu tố:

```
f9-<case>      → lần 1
f9-<case>-r2   → lần 2
```

Attempt lỗi được giữ nguyên làm lịch sử.

---

## 5. Quy trình vế Online

### 5.1 Các bước

1. **Arm sensor** trên Ubuntu (detached qua `setsid` + `disown`):
   `run_t85_scenario_sensor_ubuntu.sh` → sinh preflight → bind NIC vào DPDK →
   chạy `nids_dpdk_live` → in `nids_dpdk_live_ready`.
2. **Chờ ready** — poll `nids_dpdk_live_ready` trong `sensor.jsonl`, tối đa 60s.
3. **Replay** từ Kali: `kali_t85_scenario_replay.py` bắn 9 frame qua `eth1`,
   chỉ ghi lại L2 (đổi MAC), giữ nguyên L3/L4 và pacing gốc.
4. **Chờ idle timeout** (60s) → sensor tự thoát → tự rollback NIC.
5. **Đếm** — settle 10s + `sync`, rồi `grep` từ file.

### 5.2 Hai bẫy bắt buộc tránh

**Bẫy 1 — `sleep` cố định thay vì chờ ready.** Bind NIC vào DPDK mất thời gian
không đoán trước được. `sleep 10` làm 3 family bắn trước khi port sẵn sàng và
ghi `packets_seen=0`. Con số đó **trông giống hệt** model trượt.

**Bẫy 2 — đọc số ngay sau khi sensor thoát.** `/mnt/hgfs` flush trễ. `grep`
ngay lập tức trả 0 cho 3 family mà file thực tế có 1 alert.

> **Luật:** mọi con số trong evidence phải đọc từ file trên đĩa, không lấy từ
> stdout của script điều phối.

**Bẫy 3 — bounce link ngay trước khi gửi.** `set_link()` gọi
`ip link down → mtu → up` vô điều kiện ngay sát lúc bắn. Link vmnet cần thời
gian hội tụ; khoảng 5 frame đầu bị nuốt. Pass r2 ghi `packets_seen=4` trên
11/14 family — cùng một con số, trên các family không liên quan gì nhau.

Cách tránh: đặt MTU **một lần** từ đầu vòng chạy, để lời gọi trong replay
thành no-op; nếu buộc phải đổi thì chờ ≥2s sau khi link up.

### 5.4 Chạy lại thế nào cho đúng — hệ quả trực tiếp của "F9"

**F9 = checkpoint tại gói thứ 9 của một flow. Model bắn đúng một lần mỗi flow.**

Replay chỉ ghi đè 12 byte đầu (MAC), giữ nguyên `record.data[12:]` ⇒ L3/L4 y
hệt ⇒ **gửi lại là cùng 5-tuple, cùng seq number**.

| Cách chạy lại | Kết quả |
|---|---|
| ❌ Gửi lại 9 frame vào sensor đang chạy | Engine nối vào flow cũ. F9 đã bắn ở gói 9 ⇒ **không có alert thứ hai**. 9 gói trùng lặp làm hỏng `packet_count` và inter-arrival-time — đúng nhóm đặc trưng đang điều tra. Vừa không thêm mẫu, vừa bẩn mẫu. |
| ✅ Dựng sensor session mới rồi gửi | Flow bắt đầu lại từ gói 1, chạm F9 sạch, sinh đúng 1 alert. |

> **Luật:** capture thiếu gói thì **hủy attempt và dựng session mới**, không
> bao giờ gửi thêm gói vào một flow đang dở.

### 5.5 Tiêu chí nghiệm thu một attempt

Đọc bằng `scripts/summarize_sensor_log.py` (chạy trên sensor host):

| Điều kiện | Kết luận |
|---|---|
| `ready=false` | Sensor chưa bind xong. Hủy, chạy lại. |
| `packets_seen < 9` | **Capture miss.** Hủy, dựng session mới, tối đa 3 lần. |
| `packets_seen >= 9`, `alerts >= 1` | Hợp lệ. Lấy `candidates[0].top_candidate`. |
| `packets_seen >> 9`, `alerts = 0` | Hợp lệ. Không flow nào đạt F9 (PortScan). Giữ trong mẫu, ghi rõ lý do. |

Chỉ đếm `alerts` (ví dụ `grep -c nids_alert`) là **không đủ**: nó gộp capture
miss với model miss thành cùng một con số 0.

### 5.3 Ràng buộc mạng lab

- Kali `eth1` = 192.168.252.128 (vmxnet3, không có default route)
- Ubuntu `ens160` = 192.168.252.129, MAC `00:0c:29:30:b9:d3`
- Management Ubuntu `ens33` = 192.168.100.130 — **phải giữ liên lạc được**
- MTU 1500 trên `eth1`: frame jumbo fail `EMSGSIZE`. Với pcap 9-gói đã cắt sẵn
  thì không gặp; với replay pcap lớn thì mất ~15–20% gói jumbo.

---

## 6. Quy trình vế Offline

### 6.1 Các bước

1. Copy pcap từ `/mnt/hgfs` sang `/tmp` trên đĩa local Ubuntu.
2. `source $HOME/.local/nids-toolchain/env.sh` **trong cùng shell** — thiếu
   bước này thì lỗi `librte_kvargs.so.26: cannot open shared object file`.
3. Chạy `nids_demo_replay --input … --bundle … --expect-records 9 --expect-f9 1`.
4. Parse stdout, lưu cả `raw_stdout`.

### 6.2 Bẫy exit code — nguyên nhân hỏng evidence lần trước

`nids_demo_replay` **thoát mã 1** khi `--expect-records` không khớp, nhưng
**vẫn in `nids_alert` hợp lệ ra stdout**.

Code cũ (`run_t85_full_replay_stream.py:168`) coi `exit_code != 0` là hỏng ⇒
ghi cả 14 case thành `status:"error"`, `raw:""`. Kết quả thật chỉ còn trên màn
hình chat, rồi bị gõ tay vào một dict hardcode trong script sau đó bị mất.

Hệ quả: con số "offline 12/13" **không tái lập được từ đĩa** ⇒ không dùng làm
evidence.

> **Luật:** parse stdout bất kể exit code. Ghi lại exit code như dữ liệu quan
> sát, không dùng nó để phán đoán thành/bại.

### 6.3 Bẫy bộ nhớ

- File CICIDS gốc là **PCAPNG** (magic `0x0a0d0d0a`), không phải classic pcap.
  Parser `struct` cho classic pcap sẽ tìm thấy 0 gói.
- Các file cắt 9 gói là **classic pcap** (magic đọc little-endian: `0xa1b23c4d`),
  parse bằng `'<IIII'`.
- Đọc nguyên file 10 GB vào Python trên VM → `MemoryError`. Phải stream/mmap.

---

## 7. Streaming lên dashboard

### 7.1 Yêu cầu

Alert phải hiện trên dashboard **trong lúc** replay chạy, không phải sau khi
xong.

### 7.2 Cơ chế

`scripts/watch_scenario_alerts.py` poll toàn bộ `ubuntu/f9-*/sensor.jsonl`,
nhớ offset từng file, chuyển schema lồng → schema phẳng, gán `ts=now`, append
vào **hai** đích: stream chính + archive theo run.

Bridge gốc (`bridge_sensor_to_dashboard.py --follow`) chỉ tail được **một**
file; mỗi family lại sinh một `sensor.jsonl` riêng nên không dùng trực tiếp
được.

### 7.3 Chuyển đổi schema

| Nguồn (nids_alert) | Đích (dashboard) |
|---|---|
| `evidence.known_family.top_candidate` | `candidate` |
| `evidence.known_family.confidence` | `confidence` |
| `evidence.flow_rf.attack_probability` | `flow_rf_probability` |
| `flow.source.{ip,port}` | `source` (`ip:port`) |
| `decision` | `decision` |
| — | `replay_family`, `replay_run`, `ts` |

### 7.4 Về `clock_domain`

Replay offline phát timestamp `unix_epoch` (giờ CICIDS gốc); sensor live phát
`checkpoint_timestamp_ns` **monotonic**. Không so trực tiếp được. Watcher gán
`ts=now`; bridge chế độ batch neo alert cuối vào `mtime` của sensor log để giữ
pacing tương đối.

### 7.5 Vận hành dashboard

| Thành phần | Cổng | Ghi chú |
|---|---|---|
| Backend (uvicorn) | 8000 | `vite.config.js` proxy `/api` cứng vào đây |
| Frontend (vite) | 5173 | |

`NIDS_LIVE_DIR` override thư mục nguồn. Trên Windows, khởi động backend bằng
`Start-Process` — chạy qua Bash background bị chết im lặng.

---

## 8. Định dạng evidence

### 8.1 File offline

`run_log/full-flow-v1/replay-runs/<run_id>/offline-f9-results.json`

```json
{
  "kind": "offline_f9_results",
  "run_id": "...",
  "generated_at_utc": "...",
  "ground_truth_source": "run_log/t8.5/scenarios/<run_id>/pcap/manifest.json",
  "cases_total": 14,
  "cases_with_alert": 0,
  "cases_correct": 0,
  "rows": [{
    "case_id": "...", "ground_truth": "...", "status": "ok|no_alert",
    "candidate": "...", "confidence": 0.0, "correct": true,
    "process_exit_code": 1,
    "raw_stdout": "…giữ nguyên để kiểm chứng lại…"
  }]
}
```

`raw_stdout` là bắt buộc: nó cho phép dựng lại mọi con số mà không cần chạy lại.

### 8.2 File so sánh 3 chiều

| Cột | Nguồn |
|---|---|
| `case_id` | manifest |
| `ground_truth` | manifest `label` |
| `offline_candidate` | offline-f9-results.json |
| `online_candidate` | sensor.jsonl attempt mới nhất |
| `online_packets_seen` | `nids_dpdk_live_summary` |
| `verdict` | `both_correct` / `offline_only` / `online_only` / `both_wrong` / `no_sample` |

### 8.3 Quy tắc báo accuracy

1. Tử số và mẫu số phải cùng tập case. Không bao giờ đặt `5/14` cạnh `12/12`.
2. Case `packets_seen=0` **loại khỏi mẫu**, đếm riêng thành "capture miss".
3. Case đủ gói nhưng flow không đạt F9 (PortScan) **giữ trong mẫu**, ghi rõ lý do.
4. Mọi con số kèm đường dẫn file sinh ra nó.

---

## 9. Kết quả đã biết và câu hỏi mở

### 9.1 Đã xác lập

| Kết quả | Ghi chú |
|---|---|
| FTP-Patator, SSH-Patator | 100% online (209 / 160 alert, replay pcap lớn) |
| DoS Hulk | 77,6% — nhầm sang slowloris (493), GoldenEye (450) |
| DDoS | 83,8% — nhầm sang Bot (10) |
| PortScan | 0 alert — **giới hạn thật của partial-flow F9** |

### 9.2 Câu hỏi mở — ưu tiên cao nhất

**DoS GoldenEye: 6,7% online nhưng 100% offline.** 3175/4127 alert bị gán
thành DoS Hulk.

Giả thuyết: tcpreplay không giữ chính xác khoảng cách thời gian giữa các gói,
làm hỏng nhóm đặc trưng inter-arrival-time — nhóm đặc trưng chính để phân biệt
các biến thể HTTP flood. **Chưa kiểm chứng.**

Cách kiểm chứng đề xuất: đối chiếu delta timestamp trong pcap gốc với delta
quan sát được ở sensor, cho cùng một flow.

### 9.3 Câu hỏi mở khác

- `dos-slowhttptest` không sinh alert ở **cả hai** vế. 9 gói cách nhau ~20s —
  nghi flow timeout trước khi đạt checkpoint.
- Heartbleed có `flow_id: null`, `semantic_kind: raw_label_window_not_f9` —
  không có model family. Chạy để đủ 14 case nhưng không tính vào accuracy.

---

## 10. Checklist trước khi công bố số

- [ ] Ground truth đọc từ `manifest.json`, không từ dict gõ tay
- [ ] Online và offline cùng đơn vị mẫu (1 flow / 9 gói / 1 checkpoint)
- [ ] Tử số và mẫu số cùng tập case
- [ ] Mọi case `packets_seen=0` đã chạy lại hoặc bị loại khỏi mẫu và đếm riêng
- [ ] Số liệu đọc từ file, không từ stdout script điều phối
- [ ] Parse stdout bất kể exit code
- [ ] `raw_stdout` được lưu trong file kết quả
- [ ] Attempt lỗi được giữ, không xoá
- [ ] Rollback NIC pass ở mọi attempt (`rollback.json`)
- [ ] Management `ens33` vẫn liên lạc được sau khi chạy
