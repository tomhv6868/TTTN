# Hướng dẫn bài lab NIDS partial-flow

Tài liệu này gom luồng hoạt động, cách vận hành và cách đọc kết quả của bài lab NIDS. Receipt, log và báo cáo theo từng task trong `docs/lab/` vẫn là nguồn bằng chứng gốc.

## 1. Mục tiêu và phạm vi

Lab triển khai NIDS trong VMware. Sensor DPDK trên Ubuntu quan sát lưu lượng Kali gửi đến Windows victim, ghép packet thành flow hai chiều, trích xuất đặc trưng tại F9, chạy mô hình native và ghi cảnh báo JSON.

Đây là demo end-to-end: packet → flow → F9 snapshot → suy luận → quyết định → alert. Kết quả không phải bằng chứng hiệu năng production hoặc khả năng nhận diện mọi cuộc tấn công thực tế.

## 2. Topology lab

```text
Kali attacker                 Ubuntu sensor                 Windows victim
eth1 / VMnet1                 ens160 / VMnet1               Ethernet0 2 / VMnet1
192.168.252.10                passive DPDK NIC              192.168.252.20
       │                              │                              │
       └──────────── traffic ─────────┴──────────── traffic ──────────┘

Kali, Ubuntu, Windows đều giữ NIC quản trị riêng trên VMnet8.
```

Ubuntu `ens33` (192.168.100.100) là NIC quản trị, không được bind cho DPDK. Chỉ `ens160` được bind tạm thời, chạy passive single-port với 1 RX queue, 0 TX queue, và phải rollback về driver `vmxnet3` sau mỗi lần chạy.

T0.4 đã quan sát sensor nhận đủ 200/200 packet unicast Kali → Windows, TX=0, error counters=0 và rollback pass. Ubuntu không đóng vai inline bridge.

## 3. Luồng xử lý dữ liệu

```text
Frame Ethernet trên ens160 / PCAP
        ↓
Parser C++ chung (Ethernet, IPv4, TCP/UDP)
        ↓
Bidirectional FlowTable (5-tuple, hai chiều, timeout, TCP close)
        ↓
FeatureEngine (nids.flow_features.v1, 54 đặc trưng)
        ↓
Checkpoint snapshot F3 / F5 / F7 / F9
        ↓
Native ONNX + HBOS inference
        ↓
DecisionEngine dùng ngưỡng đã hiệu chuẩn
        ↓
JSON alert trên stdout / detection.jsonl
```

PCAP và DPDK adapter dùng chung parser, semantics thời gian, flow table và feature engine. Schema 54 đặc trưng và checkpoint F3/F5/F7/F9 là hợp đồng bất biến; không thay bằng schema terminal full-flow 70 đặc trưng.

Runtime live hiện chỉ suy luận tại F9. F3/F5/F7 vẫn thuộc thiết kế nhưng chưa chạy trong chuỗi multi-checkpoint live. Mỗi process chỉ load một bundle, demo dùng F9.

## 4. Luồng ra quyết định

1. Flow RF nhận vector F9 và tính xác suất tấn công.
2. Nếu xác suất vượt ngưỡng `0.5`, quyết định là `known_attack`; Known-family RF cung cấp `top_candidate`.
3. Nếu không vượt ngưỡng, HBOS và Isolation Forest bỏ phiếu độc lập: cả hai bất thường là `unknown_candidate`, một mô hình bất thường là `uncertain`, không mô hình nào bất thường là `benign`.
4. Runtime ghi JSON event; wrapper demo dừng sau alert đầu tiên và rollback NIC.

`unknown_candidate` chỉ là hai anomaly detector cùng bỏ phiếu bất thường. Nó không đồng nghĩa zero-day, không khẳng định CVE mới và không tự xác định family tấn công. Ngưỡng runtime là `run_log/t6.1/thresholds.json`, SHA-256 `82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4`.

## 5. Chuỗi bài lab

| Nhóm | Nội dung | Vai trò |
|---|---|---|
| T0.x | Inventory, toolchain, DPDK smoke/passive gate, workspace | Xác nhận VM, NIC, rollback và môi trường tái lập. |
| T1.x | Hợp đồng packet, flow, feature, checkpoint | Khóa cách hiểu dữ liệu đầu vào. |
| T2.x | Parser, FlowTable, FeatureEngine, adapters | Hiện thực đường đi từ frame đến snapshot. |
| T3.x | CICIDS2017, join nhãn, dataset, split | Tạo dữ liệu huấn luyện/đánh giá, split 70/10/20. |
| T4.x | RF, anomaly, LOAFO, chọn model | Chọn Flow RF làm binary classifier chính. |
| T5.x | ONNX bundle, parity Python–C++ | Đưa model vào native runtime. |
| T6.x | Calibration, DecisionEngine, JSON alert | Đặt ngưỡng và chuẩn hóa đầu ra. |
| T7.x | Runtime live, demo, speed-run | Nối pipeline lên NIC VMware. |
| T8.x | Detection study, demo, handoff | Diễn giải và nghiệm thu demo. |

Chi tiết theo task nằm ở `T0.*-report.vi.md`, `T1.*-report.vi.md`, `T2.*-report.vi.md`, `T4.3-eda.vi.md` và `T8.5-*.vi.md`.

## 6. Chuẩn bị và build

- Bật Ubuntu sensor, Kali attacker và Windows victim.
- Kiểm tra data NIC đều ở VMnet1; NIC quản trị vẫn ở VMnet8.
- Dùng process sensor mới cho từng attack hoặc từng segment để FlowTable bắt đầu rỗng.
- Luôn source toolchain trên Ubuntu trước build; nếu không có thể báo thiếu `libdpdk` dù dependency vẫn đủ.

```bash
cd /mnt/hgfs/TTTN
source "$HOME/.local/nids-toolchain/env.sh"
cmake --preset ubuntu-release \
  -DNIDS_BUILD_DPDK=ON \
  -DNIDS_BUILD_MODEL_RUNTIME=ON \
  -DNIDS_T52_STAGED_BUNDLE=/home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
cmake --build --preset ubuntu-release --target nids_dpdk_live -j 2
ctest --test-dir /home/tom/.cache/nids-partial-flow/build/ubuntu-release \
  -R '^nids_demo[.]dpdk_live_pcap$' --output-on-failure
```

Chỉ tiếp tục nếu CTest báo `100% tests passed`.

## 7. Demo chuẩn: golden PCAP 9 frame

Đây là workflow đã có evidence live pass. Sender chỉ đổi MAC Ethernet để gửi 9 frame của `run_log/t3.2/attack-tcp-f9.pcap` tới Windows; IP, TCP, payload, thứ tự và nhịp thời gian giữ nguyên.

1. Trên Ubuntu, arm sensor:

   ```bash
   cd /mnt/hgfs/TTTN
   bash scripts/run_t85_live_sensor_ubuntu.sh \
     --bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
   ```

   Wrapper preflight, bind `ens160`, đặt MTU 9000, bật promiscuous mode. Chờ `nids_dpdk_live_ready` và không đóng terminal.

2. Sau event ready, trên Kali:

   ```bash
   cd /mnt/hgfs/TTTN
   sudo python3 -B scripts/kali_t85_golden_sender.py
   ```

3. Receipt Kali phải có `status: passed`, `records_sent: 9`, `layer2_rewrite_only: true` và MTU được khôi phục.

4. Ubuntu phải in các event sau:

   ```text
   nids_dpdk_live_ready     (mtu: 9000)
   nids_alert               (decision: known_attack, top_candidate: DDoS)
   nids_dpdk_live_summary  (status: passed, stop_reason: alert)
   ```

5. Kiểm tra `f9_snapshots >= 1`, `alerts >= 1`, `sensor.jsonl` và `rollback.json` trong artifact directory. Chỉ nhận khi `rollback.json` có `status: passed`.

Kết quả đã xác nhận: Flow RF `0.9699991941`, `known_attack`, candidate `DDoS` confidence `0.9999991655`, 1 F9 snapshot, 1 alert, `port_imissed=0`, `port_rx_nombuf=0`; rollback Ubuntu/Kali pass. Receipt: `run_log/t8.5/demo-acceptance.json`.

Nếu wrapper không kịp rollback:

```bash
cd /mnt/hgfs/TTTN
sudo python3 -B scripts/dpdk_smoke.py rollback \
  --state <RUN_ROOT>/state.json \
  --output <RUN_ROOT>/rollback.manual.json
```

## 8. Attack trực tiếp từ Kali

Workflow này tách biệt golden demo. Khởi động HTTP/HTTPS/FTP trên Windows:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "\\vmware-host\Shared Folders\TTTN\scripts\windows_t85_all_services.ps1" -Action Start
```

Chạy `hping3` và FTP Patator bằng hai process sensor riêng, với `--source-cidr` đúng IP Kali. Lệnh đầy đủ nằm tại `T8.5-live-attacks.vi.md`.

Chỉ claim phân loại model khi `detection.jsonl` có `nids_alert`; receipt Kali chỉ chứng minh công cụ đã chạy. Rehearsal hiện có cho thấy hping3 và FTP Patator tạo `unknown_candidate`; FTP Patator không được gán đúng family. Cách báo cáo đúng: sensor bắt được traffic attack live và đánh dấu bất thường, không nói model phân loại đúng hai attack này.

## 9. Full replay 5 PCAP

Chạy theo thứ tự `monday`, `tuesday`, `wednesday`, `thursday`, `friday`; mỗi ngày dùng process sensor, `detection.jsonl` và thư mục `run_log/t8.5/segments/<day>/` riêng để tránh flow state ngày trước ảnh hưởng ngày sau.

1. Ubuntu: `bash scripts/ubuntu_t85_detection.sh --segment-id <day>`; chờ ready.
2. Kali: replay đúng một PCAP với `scripts/kali_t85_bulk_replay.sh`.
3. Kết thúc sender, dừng sensor có kiểm soát và kiểm tra rollback hai máy.
4. Tạo segment manifest khóa SHA-256 của `detection.jsonl`, rồi audit chronology.

`--speed topspeed` nén nhịp phát: timestamp/IAT tại sensor là thời điểm đến sau replay, scheduler và VMware, không phải timestamp PCAP gốc. Vì vậy không dùng kết quả này để khẳng định temporal-feature parity, traffic mix production hoặc hiệu năng production. Không ghi đè evidence và không dùng `--force` khi nghiệm thu.

## 10. Kết quả và giới hạn diễn giải

Trạng thái tổng thể: `accepted_for_demo`; formal Phase 7 và Phase 8 vẫn `false`.

- F9 Flow RF LOAFO: known recall 99,884%, unknown recall 41,471%, benign FPR 0,119%.
- Golden paced live: 9 frame, 1 `known_attack`/`DDoS` alert.
- Speed-run: 5.000 pps pass, 10.000 pps fail; chỉ công bố bracket `[5.000, 10.000) pps`.
- Full pipeline từng pass 1.800 pps, CPU 97,262%; stability rate 1.000 pps. Đây chỉ là số đo VMware.

Không được suy rộng `unknown_candidate` thành zero-day, PortScan thành đã nhận diện runtime (case study calibrated recall 0%), benchmark VMware thành hiệu năng production, hay full replay topspeed thành parity thời gian.

## 11. Checklist kết thúc

- [ ] Có `nids_dpdk_live_ready` và summary hợp lệ.
- [ ] Nếu claim detection, có `nids_alert` tương ứng.
- [ ] `port_imissed=0`, `port_rx_nombuf=0` trong evidence được báo cáo.
- [ ] Kali khôi phục MTU; Ubuntu `rollback.json` báo `passed`.
- [ ] `ens160` trở về `vmxnet3`; `ens33` còn management connectivity.
- [ ] Giữ nguyên log/receipt, không ghi đè lượt cũ.
- [ ] Kết luận không vượt quá mức bằng chứng ở mục 10.

## 12. Nguồn đối chiếu

- `docs/context.md`: kiến trúc, phase, receipt và giới hạn hiện hành.
- `docs/final-report.vi.md`: kết quả bàn giao MVP và lệnh tái lập.
- `docs/lab/T8.5-live-demo.vi.md`: golden demo, full replay và chronology.
- `docs/lab/T8.5-live-attacks.vi.md`: hping3/FTP Patator.
- `run_log/`: evidence gốc.
