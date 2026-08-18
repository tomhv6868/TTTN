# Trạng thái dự án NIDS partial-flow

Cập nhật: 26/07/2026, múi giờ Asia/Bangkok.

File này là handoff context tại thời điểm hiện tại. Khi thông tin giữa các nguồn
mâu thuẫn, ưu tiên theo thứ tự:

1. `config/agent/current-task.json`
2. task contract hoặc acceptance specification
3. `config/environment-contract.json` và `toolchain-receipt.json`
4. acceptance receipt trực tiếp của task
5. report
6. attempt receipt lịch sử

`run_log/receipt-index.json` đang stale từ T5.2 trở đi và còn giữ hash T8.5 cũ.
Không dùng phần đó làm trạng thái cuối cho các task mới cho đến khi index được
sửa và hash-validate lại.

## Quy tắc vận hành bắt buộc

- Tuân thủ `AGENTS.md` và các bài học trong `gotchas.md`.
- Không đọc, sửa, chạy hook hoặc hook test; không dùng output hook làm evidence.
- Không chạy `unittest discover` rộng. Chỉ chạy targeted test/validator của task.
- Mỗi phase sửa tối đa 5 file, đọc lại trước và sau từng edit, verify rồi xin duyệt.
- Không xóa raw receipt hoặc failed attempt cũ.
- Không train model, recalibrate threshold, cài dependency hoặc thay toolchain nếu
  chưa có phê duyệt mới và contract cho phép.
- Mọi lệnh Ubuntu cần DPDK/ONNX Runtime phải source
  `"$HOME/.local/nids-toolchain/env.sh"` trong chính shell đó.
- DPDK live trên `ens160` phải có preflight, apply và rollback bắt buộc; management
  qua `ens33` phải luôn còn reachable.

## Kiến trúc đã chốt

Luồng dùng chung:

```text
packet bytes
  -> parser C++ dùng chung
  -> bidirectional FlowTable
  -> FeatureEngine
  -> checkpoint snapshot
  -> native ONNX/HBOS inference
  -> calibrated DecisionEngine
  -> JSON alert
```

- PCAP và DPDK dùng cùng parser, flow engine, timestamp semantics và feature engine.
- Feature schema/version và bundle member hash được kiểm tra fail-fast khi load.
- Binary classifier chính là Flow RF. RF Stacker chỉ giữ làm ablation vì gate cải
  thiện không đạt.
- Known-family RF cung cấp candidate family cho `known_attack`.
- Khi Flow RF không báo attack, HBOS và Isolation Forest quyết định
  `unknown_candidate`, `uncertain` hoặc `benign` theo threshold đã hiệu chuẩn.
- Threshold artifact: `run_log/t6.1/thresholds.json`
  (`82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4`).

Runtime live hiện tại là F9-only:

- `nids_dpdk_live` bỏ qua F3/F5/F7 và chỉ inference khi đạt F9.
- Process chỉ load một bundle tương ứng với checkpoint của bundle đã truyền vào.
- Incident tracker có implementation/unit evidence cho `created/updated`, nhưng
  live runtime chưa chạy chuỗi F3 -> F5 -> F7 -> F9.
- JSON alert vẫn được serialize và ghi `stdout` đồng bộ trong hot path.
- T6.5 asynchronous alert queue chưa được triển khai.

## Toolchain đã khóa

Nguồn chính:

- `toolchain-receipt.json`
  - SHA-256: `e5c64877339e455b72fb0c3b1c559c4f4ad8438d38070d13a2c54ae711463915`
  - status: `passed`
- `config/toolchain.lock.json`
  - SHA-256: `f22dcdbce1e83f4d01066b0781edad1f6477fed46793a950d1a423fa2238a004`
- `config/environment-contract.json`
  - SHA-256: `437900675c6eb10c87a3cd7ec516a1104379dc1a4dbe2a0b611c7d3a8dadf62f`

Ubuntu execution target:

| Thành phần | Giá trị |
|---|---|
| Host | Ubuntu VMware, hostname `tom` |
| OS | Ubuntu 24.04 x86_64 |
| Kernel tại receipt | `6.17.0-35-generic` |
| Compiler | g++ 13.3.0, C++20 |
| CMake | 3.28.3 |
| Meson / Ninja | 1.3.2 / 1.11.1 |
| Python | 3.12.3 |
| DPDK | 25.11.2 |
| libpcap | 1.10.4 |
| ONNX Runtime | 1.27.1 CPU |
| Toolchain prefix | `/home/tom/.local/nids-toolchain` |
| Build jobs mặc định | 2 |

DPDK được build shared với `vmxnet3`, `pcap`, `ring` và Intel e1000 drivers.
`dpdk-testpmd`, `dpdk-dumpcap` và ONNX Runtime dynamic load đã pass linkage smoke.

Windows Python từng dùng cho các acceptance ML/reproducibility là Python 3.13.2.
Các version Python được khóa tại `config/reproducibility-requirements.txt`:

```text
joblib==1.5.2
ml_dtypes==0.5.3
numpy==2.2.5
onnx==1.20.1
protobuf==6.32.1
pyarrow==23.0.1
scikit-learn==1.7.2
scipy==1.15.2
skl2onnx==1.20.0
typing_extensions==4.14.1
```

Không tự cài lại dependency nếu shell Ubuntu chưa source environment. Lỗi
`Package 'libdpdk' ... not found` từng được xác định là lỗi môi trường shell,
không phải dependency bị thiếu.

## Workspace và setup VMware

| Vai trò | Máy/interface | Network/address |
|---|---|---|
| Workspace Windows | `D:\TTTN` | source tree chính |
| Workspace Ubuntu | `/mnt/hgfs/TTTN` | VMware shared folder của cùng source tree |
| Ubuntu management | `ens33` | VMnet8 NAT, `192.168.100.100`, gateway `192.168.100.2` |
| Ubuntu sensor data | `ens160`, `vmxnet3` | VMnet1 host-only, không có default route |
| Kali attacker data | `eth1`, `vmxnet3` | VMnet1, `192.168.252.10` |
| Windows victim data | `Ethernet0 2`, `vmxnet3` | VMnet1, `192.168.252.20` |

MAC đã khóa trong T0.4:

- Ubuntu sensor: `00:0c:29:eb:d8:c4`
- Windows victim: `00:0c:29:d5:43:8b`

T0.4 passive gate đã chứng minh sensor thấy đủ 200/200 packet unicast Kali ->
Windows, sensor TX=0, error counters=0 và rollback pass. Sensor mode được chấp
nhận là passive single-port; không cần inline fallback trong lab hiện tại.

Khi DPDK apply:

- `ens160` có thể tạm bind sang DPDK driver.
- Hugepages có thể được cấp theo receipt task rồi phải rollback về trạng thái cũ.
- Sau rollback phải chờ udev và xác nhận `ens160` trở lại driver `vmxnet3`.
- Không bind management NIC `ens33`.

## Lệnh setup/build chính

Ubuntu:

```bash
cd /mnt/hgfs/TTTN
source "$HOME/.local/nids-toolchain/env.sh"

cmake --preset ubuntu-release \
  -DNIDS_BUILD_DPDK=ON \
  -DNIDS_BUILD_MODEL_RUNTIME=ON \
  -DNIDS_T52_STAGED_BUNDLE=/home/tom/.cache/nids-partial-flow/t5.2/bundles/F9

cmake --build --preset ubuntu-release --target nids_dpdk_live -j 2
```

Build directory:

```text
/home/tom/.cache/nids-partial-flow/build/ubuntu-release
```

Staged F9 bundle:

```text
/home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
```

Continuous runtime:

```bash
cd /mnt/hgfs/TTTN
bash scripts/ubuntu_t85_detection.sh
```

Bounded live demo:

```bash
cd /mnt/hgfs/TTTN
bash scripts/run_t85_live_sensor_ubuntu.sh \
  --bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
```

Sau event `nids_dpdk_live_ready`, Kali sender:

```bash
cd /mnt/hgfs/TTTN
sudo python3 -B scripts/kali_t85_golden_sender.py
```

Raw runtime output:

- `run_log/t8.5/detection.jsonl`
- `run_log/t8.5/replay.log`
- DPDK task artifacts nằm dưới `run_log/t0.4/...`

## Tiến độ theo phase

### Phase 0–4

- T0.1 có inventory/report nhưng receipt index còn ghi `unverified_legacy`.
- T0.2 toolchain receipt thực tế đã `passed`; receipt index chưa phản ánh đúng.
- T0.3, T0.4 và T0.5 đã pass resource, passive topology và workspace gate.
- T1.x packet/flow/schema/checkpoint contracts đã hoàn thành.
- T2.x parser, flow table, feature engine, PCAP/DPDK adapters và core parity đã
  hoàn thành; T2.6 có formal acceptance.
- T3.x CICIDS2017 inventory, revised label join/audit, snapshot dataset và split
  70/10/20 đã hoàn thành.
- T4.x baseline, anomaly, OOF, stacker, known-family RF, RF300 LOAFO và model
  acceptance đã hoàn thành.
- T4.8 chọn Flow RF làm binary classifier; không hỗ trợ tuyên bố Stacker cải thiện.

### Phase 5

- T5.1 artifact bundles F3/F5/F7/F9: `passed`.
- T5.2 native runtime: implementation/smoke/parity vector đã pass nhưng chưa có
  formal acceptance receipt độc lập.
- T5.3 Python-C++ parity:
  - technical acceptance `passed`;
  - 4 checkpoint, mỗi checkpoint 6 case;
  - absolute tolerance `1e-5`;
  - maximum observed error dưới `2.142e-6`;
  - chưa được cập nhật đúng vào receipt index/manual governance.
- T5.4 single-thread batch-1 performance gate chưa thực hiện.
- Người dùng đã đồng ý: T5.3 chỉ hash-validate/formalize, không chạy lại computation.
- Người dùng đã quyết định: không làm performance ở thời điểm hiện tại; T5.4 phải
  ghi `deferred_by_current_user`, không được ghi `passed`.

### Phase 6

- T6.1 calibration technical acceptance `passed`, không dùng test partition và
  không train model.
- Người dùng đã đồng ý: chỉ hash-validate/formalize T6.1, không recalibrate lại.
- T6.2 calibrated decision engine và T6.4 JSON alert đã có implementation.
- `run_log/t6.2-6.3/acceptance.json` chỉ là `speed_run_minimal`/reduced acceptance.
- Full four-bundle incident replay của T6.3 chưa có.
- T6.5 async output chưa triển khai.
- Quyết định còn chờ: formalize deployment profile F9-only hay triển khai runtime
  multi-checkpoint F3/F5/F7/F9 theo thiết kế gốc.

### Phase 7

- T7.1 runtime vertical slice hoạt động, nhưng chưa đạt thiết kế gốc về sharded
  workers, flow ownership và async alert queue.
- T7.2 passive `vmxnet3` integration đã có live evidence và rollback pass, nhưng
  chưa có formal task acceptance.
- T7.3 `accepted_for_demo`; golden PCAP và paced live F9 cùng quyết định
  `known_attack`/`DDoS`.
- T7.3 còn thiếu:
  - CIC sample attacker-VM replay chính thức;
  - automated isolated flow-count equality;
  - automated feature-hash equality.
- T7.4–T7.6 chỉ có `accepted_for_speed_run_demo`, formal Phase 7=false.
- Người dùng đã quyết định không tính toán hiệu năng lúc này. Không chạy lại DPDK
  capacity/stability và không nâng speed-run thành formal acceptance.

Speed-run đã có:

- Baseline: 5.000 pps passed, 10.000 pps failed.
- Chỉ công bố bracket `[5.000, 10.000)`, không có exact maximum.
- Full pipeline: 1.800 pps passed, CPU 97,262%; stability rate chọn 1.000 pps.
- T7.5 tại 1.800 pps: 195,832 flows/s; parse p50/p95/p99
  0,079/0,516/0,858 microsecond; inference 4,771/6,358/8,317 ms; alert
  4,514/6,021/7,026 ms; `imissed=0`, `rx_nombuf=0`.
- T7.6: 30 phút, 1.800.000 sender packet, 999,982 pps, CPU 54,296%, max RSS
  342.440 KiB, tăng 64 KiB; DPDK drop=0 và rollback pass.

### Phase 8

- T8.1/T8.2 detection study và ablation chỉ `accepted_for_demo`.
- Đã có F3/F5/F7/F9, Flow RF, independent anomaly baselines và RF Stacker.
- F9 Flow RF:
  - known recall: 99,884%;
  - unknown recall: 41,471%;
  - benign FPR: 0,119%.
- Detection-study alerts/hour chưa tính được vì locked evidence không có
  wall-clock observation duration.
- Port-category ablation đang deferred; PortScan là case study và có calibrated
  unknown-candidate recall 0%, nên không được tự nâng thành confirmatory result.
- T8.3/T8.4 handoff đã cập nhật speed-run nhưng chỉ `accepted_for_demo`.
- T8.5 bounded physical-NIC live demo `passed`, formal Phase 8=false:
  - Flow RF probability `0.9699991941`;
  - decision `known_attack`;
  - candidate `DDoS`, confidence `0.9999991655`;
  - một F9 snapshot, một alert;
  - Ubuntu và Kali rollback pass.

## Receipt chính

| Receipt | Status/scope | SHA-256 |
|---|---|---|
| `run_log/t0.3-receipt-4.json` | passed | `79f8b4c2d8622c68d0393569930008d91669de707c97e419a16a4565c362387f` |
| `run_log/t0.4/acceptance.json` | passed | `4c53e99a832449e03e3c1d5761e51674c8f7345baad97d1969d6bacdf0644ad9` |
| `run_log/t0.5/acceptance.json` | passed | `b4e8f0296c7a8b6fb43efbf772f1c702add91d3eab2da63e0c2681c599bf50d7` |
| `run_log/t2.6/acceptance.json` | passed | `0a69d11ed5897216b8ef31816aad33c02e2935a2ffe138e470d7fee24909fcfe` |
| `run_log/t3.1/acceptance.json` | passed | `4a08454a0818b2665e2efd8c628db0e70f74f9f61da949185ec92cb9468522cd` |
| `run_log/t3.5/acceptance.json` | passed | `ed2cf650f862fcd102f9ba872f650da4a4c476c6198ade37def05a4b93f25042` |
| `run_log/t3.6/acceptance.json` | passed | `9e6249d65dfc7fab7a31d411c6fd27e18e3320edde0b823776d4261e31df69ca` |
| `run_log/t4.8/acceptance.json` | passed | `9bd14e7195c7affc8d7477939826a9fa5299f46a522cf71eecb02bdad6a3c086` |
| `run_log/t5.1/acceptance.json` | passed | `fbd0ee96ac3a84a5f9caf8d30d80cf260cd25f3a5841b11fa2f5173c12320ace` |
| `run_log/t5.3/acceptance.json` | technical passed | `1808f2ef433b0b239a5d8fca6cd829e0c42b22b971ed3b0889a5811ca834db90` |
| `run_log/t6.1/acceptance.json` | technical passed | `bd3cb0d6c539cfb95a8eb015cc086615fb0c960b39443ebba604421fdb8949ea` |
| `run_log/t6.2-6.3/acceptance.json` | reduced/speed-run | `e3b50b3fc8ac1eeb978182a11b1677127a4eb80b52d98aaef74ebe44a3da2f91` |
| `run_log/t7.3/acceptance.json` | accepted_for_demo | `da4df77a5b99efacaa5b0b228084a4d98677c29586d46fa0cb1355e80a143f26` |
| `run_log/t7.4-t7.6/acceptance.json` | accepted_for_speed_run_demo | `3066a0d56eb2fe14f8c02279cc48d6fd222b72aaed37f3fd81e3e672f38a3498` |
| `run_log/t8.1-t8.2/acceptance.json` | accepted_for_demo | `092c8ad88586eb16dd9b216aaf9cd610e8aa2909889b05d6f5e68badb43ed36e` |
| `run_log/t8.3-t8.4/acceptance.json` | accepted_for_demo | `ee70c9f5eabd089d171a73dd7fc21f3cc8c5796185e02afda05e289f19379178` |
| `run_log/t8.5/demo-acceptance.json` | passed demo, formal=false | `425dcfc29c09891c34450aa59314a3fe8b51ebe6fcbb341f837de3a86b7dc067` |

Raw benchmark receipts T7.4–T7.6 nằm dưới:

```text
run_log/t0.4/t7.4-t7.6/
```

Mọi lượt được dùng làm speed-run evidence có rollback pass; `ens160` trở lại
`vmxnet3`. Không xóa failed upper-bound attempt hoặc failed attempt lịch sử.

## Documentation chính

| Tài liệu | Nội dung |
|---|---|
| `plan.md` | Kế hoạch gốc T0–T8 và tiêu chí từng task |
| `docs/lab/T0.1-report.vi.md` | Inventory lab ban đầu |
| `docs/lab/T0.2-report.vi.md` | Toolchain |
| `docs/lab/T0.3-report.vi.md` | DPDK resource/smoke |
| `docs/lab/T0.4-report.vi.md` | Passive feasibility |
| `docs/lab/T0.5-report.vi.md` | Workspace/project setup |
| `docs/lab/topology.md` | Topology lịch sử ban đầu; topology hiện hành lấy từ environment contract |
| `docs/final-report.vi.md` | Final handoff demo và speed-run |
| `docs/lab/T8.5-live-demo.vi.md` | Bounded live demo runbook |
| `docs/lab/T8.5-runtime.vi.md` | Continuous runtime runbook |

Hash tài liệu hiện hành:

- `docs/final-report.vi.md`:
  `638c34a86275c3e062aa9f91f92cfa3a7e723de1e94467b0a9fb4a68a7cbd1c8`
- `docs/lab/T8.5-live-demo.vi.md`:
  `186089f513a4e2c77794b00e81899e13581ecef7dec95e43c8cb93edcd8683b9`
- `docs/lab/T8.5-runtime.vi.md`:
  `401f22d964a1612fd38b476567a12277e0ff8a2aa30cd0fe91ae756d49ba25dc`

## Validator an toàn hiện có

Các lệnh sau chỉ validate receipt hiện có, không chạy lại benchmark:

```powershell
python tests/test_t74_t76_speedrun_acceptance.py
python scripts/build_t74_t76_speedrun_acceptance.py validate
python tests/test_t83_t84_handoff.py
python scripts/build_t83_t84_handoff.py validate
```

Không chạy discovery rộng. Các test DPDK/Ubuntu khác chỉ được chạy trên Ubuntu
VMware sau khi source toolchain environment và theo allowlist của task đang active.

## Giới hạn diễn giải

- `unknown_candidate` không đồng nghĩa zero-day thực tế.
- VMware không phải bằng chứng hiệu năng production.
- Baseline capacity chỉ được bracket `[5.000, 10.000)`, không có exact maximum.
- Stability dùng synthetic multi-flow TCP F9, không phải production traffic mix.
- Stability có thêm 408 packet ngoài benchmark và 202 parser errors; không có
  identity-level delivery proof cho từng sender packet.
- `703,99 alerts/hour` là synthetic benchmark alert rate, không thay thế
  detection-study alerts/hour của T8.1.
- Alert queue pressure chưa có vì T6.5 chưa triển khai.
- `net_pcap` PMD giữ packet bytes nhưng không giữ source PCAP pacing; không dùng
  nó làm model-decision parity evidence cho timing-dependent features.
- Payload-truncated DDoS fixture đổi quyết định sang benign và không được dùng làm
  live acceptance evidence.

## Audit nghiêm ngặt và quyết định hiện tại

Người dùng yêu cầu audit các phase từng bị bỏ qua và quay lại tiêu chuẩn nghiệm
thu task-by-task như trước.

Đã xác nhận:

1. T5.3 và T6.1 không chạy lại computation; chỉ hash-validate, formalize và sửa
   governance/manual gate.
2. Không tính toán hiệu năng ở thời điểm hiện tại.
3. T5.4 và formal T7.4–T7.6 phải ghi `deferred_by_current_user`; không được nâng
   speed-run thành formal acceptance.

Còn chờ xác nhận rõ:

- **F9-only strict scope:** formalize T6.2/T6.4 và T8.5 cho deployment profile F9;
  T6.3 multi-checkpoint ghi ngoài phạm vi hiện tại.
- **Thiết kế gốc:** triển khai bốn bundle F3/F5/F7/F9 và incident lifecycle thực
  tế qua đủ checkpoint.

Khuyến nghị hiện tại là F9-only strict scope vì T8.5 đang cố ý inference tại F9,
nhưng chưa được coi là quyết định cuối cho đến khi người dùng xác nhận.

Sau khi scope được xác nhận, thứ tự phục hồi dự kiến:

1. Sửa governance/receipt index và formalize T5.2/T5.3.
2. Formalize T6.1, T6.2 và T6.4 theo scope đã duyệt.
3. Xử lý T6.3/T6.5 theo scope; không tuyên bố phần chưa làm là passed.
4. Formalize các phần T7 không liên quan performance.
5. Regenerate T8.1–T8.5 formal handoff trong phạm vi đã duyệt.

Mỗi task phải dừng ở manual acceptance gate trước khi chuyển task kế tiếp.

## Addendum 26/07/2026 - Live hping3/FTP Patator demo

Người dùng đã khóa scope demo live từ Kali:

1. Mỗi attack dùng một Ubuntu sensor process riêng, ghi evidence riêng dưới
   `run_log/t8.5/live-attacks/<run-id>/<attack>/`.
2. Patator dùng FTP vào Windows victim `192.168.252.20`; Windows service dùng
   `scripts/windows_t85_all_services.ps1`.
3. Kali dùng wrapper bounded, không cài dependency, fail-fast nếu thiếu `hping3`
   hoặc `patator`.

Trạng thái hiện tại: wrapper và runbook đã static-verified, nhưng chưa có live
receipt thật cho `hping3` hoặc `ftp-patator` trong `run_log/t8.5/live-attacks/`.
Không dùng `run_log/t8.5/detection.jsonl` cũ hoặc `run_log/t8.5/segments/<day>/`
làm evidence cho hai attack demo này.

Runbook rehearsal: `docs/lab/T8.5-live-attacks.vi.md`.
Runbook SHA-256:
`5221b82920a93eee27ad50be7888a2482f9caa3032409db8abc07e217129a209`.
Targeted verifier: `python -B tests/test_t85_live_attack_workflow.py`.

Rehearsal `teacher-demo-20260726a` da tao alert, nhung can dien giai dung:

- `hping3`: 2.337 `nids_alert`, tat ca la `unknown_candidate`, top candidate
  `DDoS`, source observed `192.168.252.129`.
- `ftp-patator`: 9 `nids_alert`, tat ca la `unknown_candidate`, top candidate
  `DoS GoldenEye`, source observed `192.168.252.129`.

Khong claim hai live tool nay la `known_attack` dung family. Claim hop le:
sensor DPDK da bat traffic live tu Kali vao Windows va danh dau bat thuong tai
F9. Golden PCAP live receipt van la bang chung `known_attack`/`DDoS` on-NIC.

## Addendum 28/07/2026 - T9.1 terminal full-flow max-speed

### Quyết định mới nhất của người dùng

Người dùng đã yêu cầu triển khai kế hoạch full-flow và sau đó chốt:

> không cần phải nghiệm thu lằng nhằng, triển khai max speed cho tôi, tôi gấp lắm rồi

Với riêng T9.1, quyết định này thay thế yêu cầu manual gate/contract trung gian ở các
phần lịch sử phía trên. Không tạo task contract, receipt mới hay cập nhật
`run_log/receipt-index.json`. Vẫn giữ các guard thực sự cần thiết:

- namespace riêng `run_log/full-flow-v1/`;
- không sửa schema/pipeline checkpoint F3/F5/F7/F9;
- schema/model/member hash fail-fast;
- không dùng metadata hoặc schedule làm model input;
- test partition bị seal đến khi khóa profile, thuật toán, hyperparameter và threshold;
- DPDK physical vẫn phải preflight/apply/rollback;
- mỗi phase tối đa 5 file và không đọc/chạy hook.

Quy tắc này đã được ghi thêm vào `gotchas.md`. SHA-256 hiện tại của `gotchas.md`:
`747546610a5725dfdd0a2dbc96cbe719b3712bab281e80cb4512d7532ab6782c`.

### Active task T9.1

`config/agent/current-task.json` đã được thay từ handoff T8.5 dài và xung đột thành
active task T9.1:

- task/phase: `T9.1` / `terminal_full_flow_vertical_slice`;
- mode: `demo_critical_path`, priority `urgent`;
- cho phép model training và threshold selection trên train/validation;
- cho phép dependency mutation chỉ trong `D:\TTTN\.venv-full-flow-v1`;
- không yêu cầu task contract hoặc manual acceptance trung gian;
- PCAP export chạy trên Ubuntu VMware 24.04 với toolchain CMake/libpcap đã khóa;
- package/train/ONNX export chạy trên Windows trong venv riêng;
- live sensor chạy trên Ubuntu VMware;
- ưu tiên FTP-Patator và PortScan trước benchmark/report mở rộng;
- pipeline F3/F5/F7/F9 cũ được ghi rõ là immutable.

SHA-256 hiện tại:
`2f01e9902205b1400479c6567a08452c7094a5978fecf185b0244f2ace53399b`.

Lưu ý: bản active task đầu tiên ghi nhầm PCAP export trên Windows. Audit xác nhận repo
không có Windows CMake preset, Windows PATH không có CMake/pkg-config/libpcap, nên
đã sửa đúng thành Ubuntu export. WSL không phải execution target.

### Schema terminal full-flow đã tạo

Đã tạo `config/terminal-flow-feature-schema-v1.json`:

- `schema_id`: `nids.terminal_flow_features.v1`;
- encoded type `float64`, finite-only;
- đúng 70 feature, index liên tục `0..69`, tên không trùng;
- feature `0..53` là object giống hệt schema legacy, chỉ quan sát tại terminal;
- feature `54..69`:
  - `protocol_number`;
  - mean TTL forward/reverse;
  - wire bit rate forward/reverse;
  - active/idle mean;
  - ba causal context counter 60 giây;
  - first-observed source/destination port;
  - bốn lifecycle one-hot: TCP reset, TCP FIN handshake, TCP other, UDP.

Profiles được khóa:

| Profile | Index | Length |
|---|---:|---:|
| A legacy terminal | `0..53` | 54 |
| B terminal traffic | `0..60` | 61 |
| C terminal context | `0..63` | 64 |
| D terminal ports | `0..65` | 66 |
| E terminal full | `0..69` | 70 |

Semantics quan trọng:

- emit đúng một row cho mỗi flow generation tại close hoặc EOF flush;
- closing RST/FIN/ACK packet được tính trước emit;
- tuple-reuse trigger packet chỉ thuộc generation mới;
- timeout/EOF không cộng synthetic packet hoặc thời gian chờ;
- idle khi và chỉ khi gap watermark `> 5_000_000_000 ns`;
- context freeze ở packet đầu sau khi đã đăng ký current generation;
- context dùng fixed block
  `floor(nondecreasing_event_watermark_ns / 60_000_000_000)`;
- offline reset mỗi capture, live giữ theo sensor process;
- lifecycle `66..69` exhaustive one-hot, exact close reason chỉ là metadata;
- port và lifecycle được đánh dấu shortcut-sensitive;
- cấm model input gồm ID/generation, capture/dataset origin `src`, raw IP, absolute
  timestamp, ordinal, label/status/method, partition, schedule, payload bytes,
  exact close reason và NAT port.

Schema terminal SHA-256:
`ebe260327df74e265c2dc89178e3d038c3183de55603187c4b1e503e06173dfc`.

Schema legacy không đổi, SHA-256 vẫn là:
`69241cb5069ce68f941836332cfc556d15fba00253288eb6f985155bac1bc6eb`.

### Dependency file đã tạo

Đã tạo `config/full-flow-reproducibility-requirements.txt` gồm toàn bộ 10 pin cũ và:

```text
lightgbm==4.6.0
onnxmltools==1.16.0
```

SHA-256:
`c583cd4e101f8bd89a2d29e3883c6cb940822e3b8e6eee4bf7568c36ea0f85c7`.

Chưa tạo `.venv-full-flow-v1` và chưa cài dependency. Audit Python lưu ý nếu cần
Python-vs-ONNX Runtime parity trước native runtime thì phải bổ sung pin
`onnxruntime==1.27.1`; file hiện tại chưa có pin này.

### Validation cấu hình đã chạy

PowerShell validation đã pass với output logic:

```text
CONFIG_VALIDATION=PASS
FEATURES=70 PROFILES=5 REQUIREMENTS=12
```

Validation đã kiểm tra:

- JSON parse được;
- 70 index liên tục và 70 tên duy nhất;
- từng object feature `0..53` bằng schema legacy;
- năm profile có length đúng;
- requirements mới chứa toàn bộ pin cũ và chỉ thêm LightGBM/onnxmltools;
- active task cho phép critical path nhưng khóa legacy pipeline;
- không yêu cầu manual acceptance trung gian.

Không hook/hook test nào được đọc hoặc chạy.

### C++ terminal feature core đã viết, chưa build

Đã thêm:

- `cpp/include/nids/terminal_feature.hpp`
  - `TerminalFeatureVector = std::array<double, 70>`;
  - typed error/result;
  - stateful `TerminalFeatureEngine`.
- `cpp/src/terminal_feature.cpp`
  - giữ per-generation state ngoài `FlowState`, nên không đổi memory/layout hoặc
    semantics của checkpoint legacy;
  - gọi `FeatureEngine::encode(state)` tại close rồi copy prefix `0..53`;
  - update directional TTL và active/idle trên mọi accepted packet;
  - causal context theo first packet và global nondecreasing watermark;
  - context map chỉ giữ current 60-second block và có hard cap 1,048,576 entry;
  - port/protocol lấy từ first accepted packet;
  - lifecycle lấy từ observed RST/FIN state, không dùng exact close reason;
  - xóa per-generation state sau terminal encode;
  - bắt allocation/overflow/non-finite failure trong API `noexcept`.
- `cpp/tests/terminal_feature_test.cpp`
  - kiểm tra prefix 54 feature bằng legacy encode;
  - closing RST được tính;
  - directional TTL, protocol, port, active/idle;
  - causal context count và reset qua 60-second block;
  - strict idle boundary: gap đúng 5 giây không phải idle;
  - TCP reset, TCP FIN handshake, TCP other và UDP one-hot.
- `CMakeLists.txt`
  - thêm `cpp/src/terminal_feature.cpp` vào `nids_core`;
  - thêm target/test `nids_terminal_feature_test` /
    `nids_core.terminal_feature`.

Current hashes:

| File | SHA-256 |
|---|---|
| `cpp/include/nids/terminal_feature.hpp` | `7625f6e1e6aa8c9f8e19c1549ae5d290c3dd38a59ce5adc17607726f5223f95c` |
| `cpp/src/terminal_feature.cpp` | `108efc83ed2006a853bc6b9f17758803a7a55a9bd10861f46ade08a62a076242` |
| `cpp/tests/terminal_feature_test.cpp` | `a637b548250327d09347844c1ecbb8ebc3c2bd0f554be7ac8655217dc9992926` |
| `CMakeLists.txt` | `7b2041a5e36357b9e56e212357f26b0cba381f0dac27c454560081ab9a6c375b` |

Quan trọng: chưa được phép ghi test này là passed. Windows hiện không có C++ compiler,
CMake hoặc libpcap; SSH tới Ubuntu không khả dụng trong sandbox của phiên này. Chưa
configure/build/ctest trên Ubuntu, nên bước đầu tiên của phiên tiếp theo là compile và
chạy targeted test, sửa raw compiler/test error nếu có.

Lệnh dự kiến trên Ubuntu:

```bash
cd /mnt/hgfs/TTTN
source "$HOME/.local/nids-toolchain/env.sh"
cmake --preset ubuntu-release
cmake --build --preset ubuntu-release --target nids_terminal_feature_test -j 2
ctest --test-dir /home/tom/.cache/nids-partial-flow/build/ubuntu-release \
  -R '^nids_core[.]terminal_feature$' --output-on-failure
```

### Audit lifecycle C++ đã xác nhận

Read-only audit xác nhận code hiện tại đã có terminal boundary phù hợp:

- `FlowTable` update feature/counter/TCP state trước callback;
- callback order là `on_packet` rồi `on_close`, nên closing packet được tính;
- tuple reuse close generation cũ trước khi tạo/update generation mới;
- `flush()` close mọi generation còn lại đúng một lần bằng `end_of_input`;
- base terminal prefix có thể lấy từ `FeatureEngine::encode(state)` mà không sửa
  checkpoint engine;
- `PacketView`, `FlowPacketContext` và `FlowState` đã có đủ TTL, protocol, ports,
  flags, windows, payload, direction, watermark và FIN state.

Không mở rộng `FlowExportRecord` legacy. Bước đúng là tạo parallel terminal exporter.
Native `ModelBundle` hiện tại khóa cứng schema 54 feature/T5.1 member hashes nên cũng
phải có parallel terminal bundle/runtime, không sửa semantics bundle cũ. Live path
nhanh nhất là terminal mode tường minh trong `nids_dpdk_live`, default vẫn là F9.

### Audit input/label đã xác nhận

Không thiếu input. Năm PCAP hiện tồn tại và size khớp lock:

| Capture | Size bytes | Expected terminal flows |
|---|---:|---:|
| monday-working-hours | 10,822,507,416 | 425,166 |
| tuesday-working-hours | 11,048,283,608 | 357,558 |
| wednesday-working-hours | 13,420,789,612 | 664,163 |
| thursday-working-hours | 8,302,500,180 | 411,141 |
| friday-working-hours | 8,839,309,056 | 578,024 |
| **Total** | | **2,436,052** |

Expected parser exclusions lần lượt:

```text
84,723; 83,234; 84,137; 83,049; 83,730
```

Expected ingest errors là 0.

Không join lại tám CSV. Tái sử dụng read-only immutable artifacts:

- `run_log/t3.3/label-join.sqlite3`
  - size `2,656,702,464`;
  - accepted SHA-256
    `a97054a39fe25c8c96e42b2f335069d964b65b898e77783167cd9aa61eb097ca`.
- `run_log/t3.3r1/class-consensus.sqlite3`
  - size `333,119,488`;
  - accepted SHA-256
    `cb31f170a183e5cc1e8bb63a443cd2a2a6f0889e59e46fd41fef902b59c57b31`.

Join terminal row vào source flow bằng `(capture_id, generation)`, sau đó lấy
`flow_id` và join `flow_assignment(flow_id, capture_id)`. Trước khi nhận label phải
assert toàn bộ identity/ports/generation/timestamps/counters/close reason; không dùng
export ordinal một mình.

Accounting đã khóa:

- raw terminal flow: `2,436,052`;
- trainable assigned: `2,366,094`;
- quarantine: `69,958`;
- quarantine breakdown: audit conflict `2,218`, mixed class `66,035`,
  no eligible label `1,705`.

Mapping sáu family T9.1:

| Family | Count |
|---|---:|
| Benign | 1,848,412 |
| FTP-Bruteforce | 4,942 |
| SSH-Bruteforce | 2,503 |
| PortScan | 158,976 |
| DoS | 350,338 |
| Other | 923 |
| **Total** | **2,366,094** |

Heartbleed có 0 assigned flow, phải ghi unavailable thay vì tạo metric giả.
Schedule/role chỉ dùng audit label, tuyệt đối không làm feature hoặc relabel oracle.

Split T3.6 cũ chỉ cover flow đạt F3 và thiếu 861,884 assigned short flow. Full-flow
phải tạo split mới:

- seed `3607`;
- group nguyên khối `(capture_id, floor(creation_timestamp_ns / 60s))`;
- ratio 70/10/20;
- persist/hash partition map trước training;
- fit/preprocess/model trên train, threshold trên validation;
- không đọc test đến khi khóa model/profile/threshold;
- so sánh F9 bằng cách join F9 flow vào chính terminal split map mới.

### Audit Python/model đã xác nhận

Không sửa/import trực tiếp `rf_baseline.py`, `artifact_bundle.py` hoặc
`model_runtime.cpp` vì chúng khóa T4/T5, checkpoint F3/F5/F7/F9, 54 feature và
accepted manifest hashes.

Đường Python được đề xuất cho phase tiếp theo:

1. `scripts/build_t91_terminal_shard.py`: stream terminal JSONL thành SQLite BLOB
   `70d`, exact metadata/accounting.
2. `python/nids_mvp/full_flow_dataset.py`: attach hai DB immutable, reconcile,
   package Parquet và manifest.
3. `python/nids_mvp/full_flow_model.py`: grouped split, profile A-E, LightGBM
   multiclass, validation selection, ONNX và manifest.
4. Hai targeted test riêng cho dataset và model.

Model nhanh nhất cho vertical slice là LightGBM multiclass sáu class, raw numeric
float32, identity preprocessing, lưu exact ordered feature list và class order.
Không cần scaler hoặc categorical encoder vì schema đã numeric.

### Chưa hoàn thành, không được claim

Các phần sau chưa được viết hoặc chưa chạy:

- parallel terminal exporter header/source/CLI/test;
- terminal JSONL/SQLite shard và Parquet packager;
- replay thực tế 5 PCAP và rehash 52.4 GB source;
- dataset/manifest/split map dưới `run_log/full-flow-v1/`;
- `.venv-full-flow-v1`, dependency install;
- LightGBM training, profile ablation, validation threshold;
- ONNX export/check/parity;
- terminal native bundle/runtime guards;
- terminal inference mode trong `nids_dpdk_live`;
- bounded FTP-Patator/PortScan live smoke;
- confusion matrix hoặc metric mới.

Không có receipt/acceptance mới và không có model/dataset artifact T9.1 nào tại thời
điểm addendum này.

### Thứ tự tiếp tục ngắn nhất

1. Build `nids_terminal_feature_test` trên Ubuntu và xử lý raw failure nếu có.
2. Thêm parallel terminal exporter, CLI JSONL và targeted PCAP test; không sửa T3.3
   exporter legacy.
3. Export từng capture atomic trên Ubuntu, kiểm tra hash/count rồi mới sang capture
   tiếp theo.
4. Reconcile với hai DB immutable, package raw + assigned dataset và tạo split map
   60 giây mới.
5. Tạo Windows venv riêng, cài exact pins, train LightGBM profiles A-E; khóa model và
   threshold bằng train/validation rồi mới evaluate test.
6. Export bundle ONNX có schema/feature/class/member hashes và native parity.
7. Thêm terminal mode vào `nids_dpdk_live`, giữ F9 default, sau đó chạy bounded
   FTP-Patator và PortScan.

## Addendum 28/07/2026 - T9.1 checkpoint tạm dừng và chuyển sang labctl ultra-MVP

### Trạng thái T9.1 tại lúc tạm dừng

Người dùng yêu cầu tạm dừng đường T9.1 sau phase 4 và ưu tiên một vertical slice SSH
để lớp điều khiển lab có thể trực tiếp điều khiển/đọc stdout-stderr của ba VM. Không chạy tiếp
training, không mở test cohort và không triển khai native/live T9.1 cho đến khi nhiệm
vụ labctl được xử lý.

Tiến độ thực tế theo plan-2:

| Phase | Trạng thái |
|---|---|
| 1. Governance/schema | Hoàn tất cho demo-critical-path; không tạo receipt mới theo quyết định max-speed |
| 2. Terminal feature tracker | Code và test đã viết; MSVC syntax-only pass, chưa link/run targeted test |
| 3. Offline exporter | C++ exporter code xong và syntax-only pass; shard builder synthetic 5/5 pass; replay 5 PCAP chưa chạy |
| 4. Parquet/split | Bốn file code/test xong, synthetic 6/6 pass; production split đã build/validate/resume; terminal dataset còn chờ shards |
| 5. Benchmark/training | Chỉ khóa thiết kế; hai file model chưa tồn tại, chưa train và chưa đọc test |
| 6-10 | Chưa triển khai |

### File và artifact đã tạo hoặc thay đổi sau addendum trước

C++ terminal exporter song song:

- cpp/include/nids/terminal_flow_export.hpp, 72 dòng,
  SHA-256 0f948db56e747c01f975905c57590b872334142a82fe3c35f923fdb0a4cf06db.
- cpp/src/terminal_flow_export.cpp, 224 dòng,
  SHA-256 6fb3715d8c51ac3af987d76ec58a62bc25b2acee5ad6717a7fb9cbbfbcb1edb7.
- cpp/apps/t91_terminal_flow_export.cpp, 378 dòng,
  SHA-256 188a6ecc28f7885b5e87db1d1eb94c64ed34b0c4ca9a6bcf8ce49c94e1c8a28a.
- cpp/tests/terminal_flow_export_test.cpp, 306 dòng,
  SHA-256 4d4537294b9d91b69582afc1755728f0f61b58cdd4e037958fd145d8efbc6431.
- CMakeLists.txt hiện có SHA-256
  711e072c3936d67a9b3dd4f6b31dd30ce17dfa70392aac7adeed6556452b79d4.

Exporter đã được sửa để giữ failure đầu tiên thay vì để lỗi PCAP sau đó ghi đè,
flush stdout trước khi báo success, xuất diagnostics/counters đầy đủ hơn và test
non-EOF TCP RST close. Giới hạn còn lại: observer PCAP cũ không có cancellation nên
sau failure có thể vẫn parse tiếp input; shard builder sẽ terminate producer khi
consumer fail, còn thay đổi API legacy được hoãn.

Terminal shard:

- scripts/build_t91_terminal_shard.py, 2.006 dòng,
  SHA-256 c2474e46a18c87e6fba570cc83b5075c225f329f7ddf550a4bf175fd94842035.
- tests/test_t91_terminal_shard.py, 545 dòng,
  SHA-256 8a6da9ad9fb8634640fa9f9b343f4598593b27a831a520270e6b9ab8dabb4ff5.
- Targeted result: 5 tests pass. Test-work và các thư mục .t91-* đã sạch.

Parquet/split:

- python/nids_mvp/full_flow_dataset.py, 1.255 dòng,
  SHA-256 217dd56d1cce0c37b5e9bc92d593824ed562009f0a9c46bccbf32df75ae5aab2.
- python/nids_mvp/full_flow_split.py, 750 dòng,
  SHA-256 882b1a44b7ec9e558c0062b084099cfa1b08c289c4ac20a3395a5b123dfbb7fc.
- tests/test_t91_full_flow_dataset.py, 562 dòng,
  SHA-256 76abde61e066af5818c8f7546a15307c4ca2b76030509807181e431f2c274141.
- tests/test_t91_full_flow_split.py, 383 dòng,
  SHA-256 5adedf0fe7b49fc4246e1a6c4609c23dfc8307cbe1065f479466426682f4979a.
- Dataset tests 3/3 pass; split tests 3/3 pass, toàn bộ dùng fixture synthetic.
- paired_f9 được khóa đúng packet_count >= 9, có membership hashes và không thuộc
  model feature allowlist.

Production split đã được tạo tại run_log/full-flow-v1/split:

- flow-partitions.parquet: 2.366.094 rows, 15.044.545 bytes,
  SHA-256 d46f9a1489335e35510b74d81befd14b23c2613d1a5b5d0d42f1fb4b16b4fa64.
- manifest.json: SHA-256
  5b2cf6be8b49945c8d2a63b735f075b8caa34bf1e401952aa72bc3d0fa091ac4.
- 1.504.210 F3 rows giữ nguyên; 861.884 short flows đều kế thừa locked block;
  không có short-only block.
- Build, validate và lần build resume/skip đều pass. Đây chỉ là partition metadata,
  không đọc feature hoặc metric của test.

### Python environment và lỗi đã xử lý

.venv-full-flow-v1 đã được tạo và sửa bootstrap bằng TEMP cục bộ trong workspace sau
khi ensurepip mặc định lỗi WinError 5 tại F:\\Temp. Dependency import và pip check pass.
Requirements hiện có 16 pin, SHA-256
0afc07c900ba8ab7862654fea570977fb30de6580b2cd5a963609e1930c3f0a5.
Các version chính: Python 3.13.2, LightGBM 4.6.0, PyArrow 23.0.1, ONNX 1.20.1,
ONNXMLTools 1.16.0 và Python ONNX Runtime 1.27.0. PyPI không có wheel 1.27.1;
native Ubuntu vẫn khóa ONNX Runtime 1.27.1. packaging 24.2 được pin vì import
ONNXMLTools thất bại nếu thiếu dependency này.

Các targeted test đầu tiên phát hiện handle SQLite/Parquet không đóng tường minh trên
Windows, gây WinError 5/32 khi atomic rename/cleanup. Product code và fixtures đã sửa
ownership/close rõ ràng rồi rerun pass. Lệnh python -m nids_mvp ban đầu không chạy vì
package chưa install editable; production split được gọi với python/ thêm tường minh
vào sys.path, không sửa packaging ngoài scope.

### C++ build evidence và blocker

Audit môi trường tìm thấy Visual Studio Community 2022, MSVC 14.44, CMake 3.31.6 và
Ninja 1.12.1 không nằm trong PATH. MSVC /Zs syntax-only đã pass cho terminal feature
test/core sources và cho terminal exporter/CLI. Đây không phải bằng chứng link hoặc
runtime test.

Windows chỉ có Npcap runtime DLL, không có pkg-config, pcap headers/import libraries
hoặc Npcap SDK, nên exporter PCAP chưa link/run được. VMware Ubuntu đang chạy tại
192.168.100.100 và TCP/22 mở, nhưng SSH user tom từ host bị authentication denied.
Không đoán password hoặc đọc credential. Khi có SSH key auth, cần build/ctest trên
Ubuntu 24.04 với toolchain env đã khóa.

### Thiết kế phase 5/6 đã khóa nhưng chưa implement

Demo-critical-path dùng một LightGBM multiclass sáu lớp theo thứ tự Benign,
FTP-Bruteforce, SSH-Bruteforce, PortScan, DoS, Other. attack_score bằng
1 - P(Benign); dưới threshold là Benign, trên threshold chọn argmax năm lớp attack.
Giữ A-E ablation, validation-only threshold/profile gate, deterministic ONNX,
Python/native parity và one-time sealed test.

Hai file dự kiến của phase 5 là python/nids_mvp/full_flow_model.py và
tests/test_t91_full_flow_model.py; tại checkpoint cả hai chưa tồn tại và chưa có test.
Agent chuẩn bị phase này đã chạm usage limit trước khi tạo patch.

Các mục plan-2 được ghi deferred_for_demo: binary head riêng, family head 13 lớp,
HistGradientBoosting, SGD, chín cặp thuật toán, wall-time/peak-RSS tie-break,
Heartbleed output và full formal benchmark. Không được claim các mục này đã pass.

### Tương tác agent trong phiên

- Agent C++ exporter audit tìm failure-order/stdout/counter/test gaps; main agent sửa
  ba file hiện hữu trong phase exporter.
- Agent terminal shard tạo đúng hai file và targeted tests.
- Agent dataset/split tạo đúng bốn file; raw tests tìm rồi sửa lỗi Windows handle.
- Agent model khóa thiết kế phase 5/6 nhưng hết usage trước khi tạo file.
- Agent build-environment tìm MSVC/CMake/Ninja ẩn và chạy syntax-only checks.
- Agent native-runtime chỉ audit read-only: legacy ModelBundle 54-feature phải giữ
  nguyên; phase terminal runtime sau này nên là API/source/test/CMake riêng.

### Nhiệm vụ mới đang ưu tiên

T9.1 dừng tại checkpoint này. Nhiệm vụ kế tiếp là vertical slice ultra-MVP host-side
SSH orchestration để lớp điều khiển lab trực tiếp chạy command và đọc stdout/stderr của Kali,
Ubuntu sensor và Windows target. Slice đầu chỉ cần alias/config ba host, executor
non-interactive có timeout, structured JSON, lệnh status/exec, targeted tests và
hướng dẫn setup thủ công. Chưa làm campaign, supervisor dài hạn hoặc MCP ở slice đầu.

## Addendum 28/07/2026 - labctl ultra-MVP hoàn tất code, chờ setup key trên VM

### Kết quả vertical slice

Đã hoàn tất phần host-side tối thiểu để lớp điều khiển lab chạy được command có giới hạn thời gian
trên Kali, Ubuntu và Windows qua SSH rồi nhận stdout/stderr dưới dạng một JSON duy nhất.
T9.1 vẫn tạm dừng tại checkpoint trước; không có training, replay hoặc native/live work
mới trong slice này.

DHCP được xử lý trên đường chạy chính: trước mỗi `status` hoặc `exec`, labctl gọi
`vmrun getGuestIPAddress <vmx> -wait` để lấy IPv4 hiện tại từ VMware Tools. Địa chỉ quan
sát được không được lưu vào config. SSH dùng `HostName=<IPv4 hiện tại>` và
`HostKeyAlias=<alias ổn định>`, nên lease có thể đổi mà identity/known-host vẫn ổn định.
Nếu VM tắt hoặc VMware Tools không trả địa chỉ, lệnh dừng ở discovery và không thử lease
cũ.

Ba file mới:

- tools/labctl.py, 454 dòng, 13.581 byte,
  SHA-256 f0263532984254e705ba7707ad2f9f18c6b7627aa00de68e57308a039637fc31.
- config/lab-hosts.example.json, 24 dòng, 588 byte,
  SHA-256 8be5dc13d7f7c9ea990a6e3f538c0dd3a0a281437b3229c17af76dce7f90dbd8.
- tests/test_labctl.py, 329 dòng, 11.026 byte,
  SHA-256 a88784d63ec9f4fb7ba9a257053e1f5a34d0b13018f5e364197bf00456985b6b.

Config local mặc định là config/lab-hosts.json và đã được rule hiện hữu trong .gitignore
che phủ; file này chưa được tạo vì SSH user/key của cả ba guest chưa được setup. Example
chỉ chứa đường dẫn tuyệt đối tới vmrun, ssh.exe, ba VMX, alias ổn định và timeout; không
chứa password hay IPv4 DHCP.

CLI hiện có:

- `py -3.13 -B tools/labctl.py status`: probe đồng thời ba role bằng `hostname`.
- `py -3.13 -B tools/labctl.py exec <role> "<command>"`: chạy một bounded command.
- SSH luôn non-interactive với BatchMode, không prompt password, một connection attempt,
  strict host-key checking, connect timeout và total command timeout riêng.
- Kết quả phân biệt `ok`, `remote_error`, `ssh_error`, `timeout`, `local_error`,
  `discovery_error` và `powered_off`; exit code CLI là 0/1/2 cho success/operational
  failure/input-config error.

### Xác minh và raw environment evidence

- Targeted command `py -3.13 -B tests/test_labctl.py`: 11/11 test pass trong 0,127 giây.
- Không còn thư mục `.labctl-test-*` sau test.
- Real read-only smoke qua vmrun khi cả ba VM đang tắt trả một JSON canonical, overall
  `failed`, và từng role đúng là `stage=discovery`, `status=powered_off`, `address=null`,
  `exit_code=-1`; process exit 1 là expected operational result.
- Windows host có OpenSSH client 9.5p2 nhưng chưa có `%USERPROFILE%\.ssh\config`, chưa có
  id_ed25519/id_rsa dùng cho lab, SSH agent không hoạt động và known_hosts vẫn dùng mặc
  định interactive.
- `vmrun -T ws list` xác nhận không VM nào đang chạy tại thời điểm smoke.
- Ubuntu user đã biết là `tom`. Kali user chưa có raw `whoami`; không đoán. Windows chưa
  có durable SSH management user; không tái sử dụng account disposable của rehearsal T8.5.
- Shared folder hiện hữu vẫn là artifact bus (`/mnt/hgfs/TTTN` trên Linux và
  `\\vmware-host\Shared Folders\TTTN` trên Windows), còn SSH là command/control.

### Vấn đề, giới hạn và phần setup còn lại

Lần smoke đầu cho thấy vmrun trên Windows trả mã unsigned 4294967295 khi VM tắt; labctl
đã normalize thành -1 và nhận diện raw VMware message thành `powered_off`. Một lệnh hash
PowerShell ban đầu sai vì đặt pipeline ngay sau khối `foreach`; lệnh được sửa bằng cách
gom rows trước rồi serialize JSON. Không thay đổi product code vì lỗi này.

Người dùng còn cần bật ba VM, cài/bật sshd nếu guest chưa có, tạo một key Ed25519 riêng
trên host, cài public key cho đúng user, tạo ba alias SSH không có `HostName`, và enroll
host key lần đầu sau khi đối chiếu fingerprint. Kali user phải lấy từ `whoami`; Windows
nên dùng account persistent riêng như `nidsctl`, non-admin cho slice cơ bản. Quyền root,
sudo wrapper hẹp, long-running sensor lifecycle, receipts/campaign và MCP đều deferred.

Timeout của SSH client không bảo đảm giết process remote nếu command tự detach hoặc bỏ
qua disconnect; vì vậy slice này chỉ dành cho command chẩn đoán bounded. VM vẫn được bật
tắt thủ công. Đây là ranh giới dừng của phase 5-file: context.md, gotchas.md và ba file
labctl ở trên; cần approval phase mới trước khi thêm docs hoặc lifecycle automation.

### Tương tác agent trong slice labctl

- Agent labctl_repo_audit rà pattern repo, giới hạn file/CLI/test và đề xuất scope ultra-MVP.
- Agent labctl_ssh_audit kiểm tra OpenSSH/key/config/known_hosts trên host và chỉ ra các
  bước manual enrollment còn thiếu.
- Agent labctl_topology_audit rà VMX, VMware Tools, topology NAT/host-only và shared-folder;
  lease quan sát được chỉ dùng làm evidence, tuyệt đối không đưa vào config bền vững.

### End-to-end setup hoàn tất trên ba VM

Người dùng đã hoàn tất SSH key distribution và enroll ED25519 host key cho cả ba alias.
Config local `config/lab-hosts.json` đã được tạo trong workspace từ example; SSH config
host dùng Kali user `kali`, Ubuntu user `tom` và Windows persistent user `nidsctl`.
Lỗi setup duy nhất là ban đầu dòng Ubuntu ghép `User tom IdentityFile ...` trên cùng một
dòng; sau khi tách hai directive, OpenSSH parse config bình thường.

Real command `py -3.13 -B tools/labctl.py status` hiện pass end-to-end:

- Kali: địa chỉ quan sát tại lượt chạy `192.168.100.101`, stdout `kali`, exit 0.
- Ubuntu: địa chỉ quan sát tại lượt chạy `192.168.252.128`, stdout `tom`, exit 0.
- Windows: địa chỉ quan sát tại lượt chạy `192.168.252.20`, stdout
  `WIN-SB1364KJ9KC`, exit 0.
- Cả ba result đều `stage=ssh`, `status=ok`; overall `status=ok`.

Các IPv4 trên chỉ là evidence của lease tại lượt chạy, không phải endpoint đã khóa.
Vertical slice command/control ba VM vì vậy đã vận hành được; lớp điều khiển lab có thể dùng
`labctl.py exec` cho các bounded command tiếp theo mà không cần người dùng chuyển tiếp
stdout/stderr thủ công.

## Addendum 28/07/2026 - T9.1 tiếp tục, khóa model production

Sau khi `labctl` pass trên cả ba VM, người dùng yêu cầu quay lại T9.1 và tiếp tục đúng
`plan-2.md`. Đường demo-critical vẫn dùng một LightGBM multiclass sáu lớp theo thứ tự
`Benign`, `FTP-Bruteforce`, `SSH-Bruteforce`, `PortScan`, `DoS`, `Other`; các head và
benchmark đầy đủ ghi `deferred_for_demo` không được claim.

### Trạng thái theo phase tại checkpoint này

| Phase | Trạng thái |
|---|---|
| 1. Governance/schema | Hoàn tất cho demo-critical path |
| 2. Terminal feature tracker | Build và targeted CTest thật trên Ubuntu pass |
| 3. Offline exporter/shards | Exporter build/test pass; 5/5 PCAP production đã replay và rehash pass |
| 4. Parquet/split | Dataset production 5 capture đã package; train/validation sẵn sàng, test sealed |
| 5. Benchmark/training | Code/test pass; A-E production đã train; profile A và threshold đã khóa |
| 6. ONNX/bundle/parity | Đang triển khai, chưa được claim pass tại checkpoint này |
| 7-10. Native/DPDK/live/acceptance | Chưa triển khai |

### C++ build và targeted runtime evidence trên Ubuntu

Lớp điều khiển lab dùng `tools/labctl.py exec ubuntu` để chạy trực tiếp trên Ubuntu thay vì yêu cầu
người dùng copy terminal. Configure `cmake --preset ubuntu-release` pass tại
`/home/tom/.cache/nids-partial-flow/build/ubuntu-release`. Ba target sau compile/link pass:

- `nids_terminal_feature_test`;
- `nids_terminal_flow_export_test`;
- `nids_t91_terminal_flow_export`.

Targeted CTest `nids_core.terminal_feature` và `nids_dataset.terminal_flow` đều 1/1 pass.
Lượt regex ghép đầu tiên chỉ lỗi vì SSH shell làm mất quoting quanh `()` và `|`; chạy lại
hai regex đơn pass, nên đây là lỗi command transport chứ không phải lỗi C++.

Exporter production:

- executable SHA-256
  `9a2c2e37f7beaf3649d11e8ec2840250e6798b71778c68dab76acd414c7790ec`;
- shard builder `scripts/build_t91_terminal_shard.py` SHA-256
  `c2474e46a18c87e6fba570cc83b5075c225f329f7ddf550a4bf175fd94842035`.

### Năm terminal shard production

Mỗi capture được build atomic rồi chạy validator độc lập với `--rehash-source` trên
Ubuntu. Cả năm manifest đều `passed`, SQLite `integrity_check=ok`, ingest error bằng 0,
terminal feature error bằng 0 và exact oracle mismatch bằng 0.

| Capture | Flow rows | Parser exclusions | SQLite bytes | SQLite SHA-256 |
|---|---:|---:|---:|---|
| Monday | 425.166 | 84.723 | 360.353.792 | `887d3e44dd76e5897a68dc383010a8195f7ca90308c7061e2e44e1bd27db434f` |
| Tuesday | 357.558 | 83.234 | 303.202.304 | `575e17be70b493e04c052a42d2aabaf3ae0ffa5ab4cbc91766a94e4963d82b94` |
| Wednesday | 664.163 | 84.137 | 563.322.880 | `84c7427cc80d2327ef1ea000cb3aff93b771e33fd9023123c7a53db55714857c` |
| Thursday | 411.141 | 83.049 | 348.717.056 | `c800c100b76932f29d093720574f77e145653c7e9a10a06a41da6895345de20d` |
| Friday | 578.024 | 83.730 | 490.311.680 | `fc73b8cb4adcfb4440a7b1c32a4076fa61edc85d4d7217b363447fc0f01ed103` |

Tổng cộng 2.436.052 terminal-flow row, 418.873 parser exclusion và 2.065.907.712
byte SQLite. Artifacts nằm dưới `run_log/full-flow-v1/terminal-shards/<capture>/`.

### Dataset Parquet production

Hai targeted suite `tests/test_t91_full_flow_dataset.py` và
`tests/test_t91_full_flow_split.py` đều 3/3 pass. Dataset manifest hiện hành:

- path `run_log/full-flow-v1/dataset/manifest.json`;
- SHA-256 `3f4f921cf98363100c1471df4164d0c7b322c3634e8cd3882a337317da57516d`;
- 2.436.052 row nguồn, 2.366.094 assigned, 69.958 quarantine;
- train 1.602.243 row, 227.025.536 byte, 5 part;
- validation 262.232 row, 32.380.262 byte, 5 part;
- test 501.619 row, 64.610.343 byte, 5 part, trạng thái `sealed`.

Family totals trước split: Benign 1.848.412, DoS 350.338, FTP-Bruteforce 4.942,
Other 923, PortScan 158.976 và SSH-Bruteforce 2.503. Model phase chỉ hash/read part
train và validation; test chỉ được kiểm inventory metadata trong manifest.

### Phase 5 model implementation và raw failures

Hai file mới:

- `python/nids_mvp/full_flow_model.py`, SHA-256
  `8e74a5ca1b074ef4bd7f99c8f5335a644657864fd297db934535b6cc975738e9`;
- `tests/test_t91_full_flow_model.py`, SHA-256
  `519f0a5b476a675a6907840cd6ad9ff2f466f91d6bf5d044cbe2d620648c7d42`.

Targeted test cuối cùng 7/7 pass và `py_compile` pass. Các lỗi thật trong quá trình test:

- Arrow fixture có metadata name trùng feature name; product chuyển sang positional
  extraction thay vì lookup bằng tên;
- `pq.read_table` tự unification schema khi path giống partition; chuyển sang
  `ParquetFile.read`;
- mmap/Parquet handles chưa đóng tường minh gây cleanup lỗi trên Windows; ownership và
  close được sửa;
- fixture null không thể biểu diễn dưới schema Arrow non-nullable nên test bất khả thi bị
  bỏ, trong khi non-finite và float32 overflow vẫn được giữ;
- fixture LightGBM quá nhỏ từng gây fatal; dữ liệu/config synthetic được làm hợp lệ.

Không còn thư mục `.t91-full-flow-model-*` hoặc `.model-*` tạm. Trainer dùng 300 tree,
learning rate 0,05, 31 leaves, balanced classes, deterministic seed 3607 và profiles
A-E lần lượt 54/61/64/66/70 feature.

### Model production đã khóa

Lệnh `check` pass với 1.602.243 train row, 262.232 validation row và test `sealed`.
Huấn luyện năm profile hoàn tất trong 557,2 giây. Lệnh `validate` độc lập sau publish pass.

Kết quả chọn model:

- selected profile `A`, 54 feature đầu;
- selected threshold `0.9984837643022101`;
- attack score `1 - P(Benign)`, comparator `>=`;
- validation attack recall `0.9961659985263447`;
- validation benign FPR `0.0007905181736834304`;
- validation macro F1 của profile A `0.9970458856815592`;
- FTP precision/recall `1.0 / 0.9956140350877193`;
- PortScan precision/recall `0.9961775018681381 / 0.9994521337946943`;
- test feature reads, metric reads và path-resolution/hash reads đều bằng 0.

Artifacts đã publish atomic:

- `run_log/full-flow-v1/model/manifest.json`, 39.806 byte, SHA-256
  `b7b383435ae70d49077ce074c4fac2bda57a2ffd4d7f016e48b5e25af45c0ccf`;
- `selected-model.joblib`, 2.539.937 byte, SHA-256
  `bebc58df5e90a2d6439a2bbbd73a1368bee7a74c9fa8f834473d9384148717ce`;
- `validation-predictions.npz`, 34.516.175 byte, SHA-256
  `fa142347df72acce4d50b9d2df193644a378642d8b86b0d56c4ce32e35720e33`.

LightGBM fit/predict phát cảnh báo sklearn rằng ndarray không có feature names dù model
đã được fit với ordered feature names. Cảnh báo không làm fail train/validate và reload
probability parity của từng profile là bitwise-equal. Không sửa source chỉ để triệt warning
sau khi model đã khóa vì việc đó sẽ làm source hash trong manifest drift và buộc retrain.

### Tương tác agent và bước tiếp theo

- Agent C++ build audit xác nhận target/preset/test boundary trước khi main agent chạy thật
  qua Ubuntu.
- Agent replay audit khóa command, atomicity và rehash requirements cho năm capture.
- Agent phase-5 triển khai đúng hai file model/test; main agent chạy lại targeted test và
  production train/validate độc lập.
- Agent phase-6 audit xác nhận quirks thật của ONNXMLTools 1.16.0: integer target opset,
  `zipmap=False`, graph name cố định và metadata label shape cần repair từ `[1]` sang `[N]`.
- Agent native audit chỉ read-only, yêu cầu terminal runtime song song và giữ legacy F9
  `ModelBundle` bất biến.

Checkpoint kế tiếp là deterministic ONNX bundle và Python ORT parity trên validation.
Native parity vẫn bắt buộc trước live nhưng chưa được claim; test partition tiếp tục sealed.

### Phase 6 ONNX bundle và Python ORT parity hoàn tất

Phase 6 giữ đúng bốn file mới:

- `python/nids_mvp/full_flow_bundle.py`, 1.081 dòng, SHA-256
  `32faaddd95b8b8abcad3b18a3fb51a0d92e26c48db52f4e928574a675cbcb060`;
- `python/nids_mvp/full_flow_parity.py`, 886 dòng, SHA-256
  `3fb13c6ad04ae3f18f95639745b20dd32f07e657cae304f760d1e529b418b38e`;
- `tests/test_t91_full_flow_bundle.py`, 409 dòng, SHA-256
  `f2096a9e26524e3511e235f795d61f4dc0c901f5cf507a129853d465246a6ae0`;
- `tests/test_t91_full_flow_parity.py`, 271 dòng, SHA-256
  `33e26697df81d4f65d52fb1fca8c01d87ebaf2fc0052dad1b0300cc9e8e91afd`.

Main agent reread code và tự chạy lại targeted tests: bundle 7/7 pass, parity 7/7 pass.
Bundle contract khóa `nids.terminal_flow_bundle.v1` version `1.0.0`, đủ 70 input
float64 hữu hạn, prefix A 0..53, cast float32 fail-fast, sáu class đúng thứ tự và
comparator `>=`. ZIP có member order/timestamp/attributes cố định và được build hai lần
byte-identical. Cùng lúc publish một staging directory atomic có đúng năm member để C++
không cần libzip/libarchive.

Raw compatibility issue: production `LGBMClassifier.classes_` là `uint8`, trong khi
ONNXMLTools 1.16.0 raw conversion gọi `.encode()` trên giá trị này và fail. Exporter
deep-copy estimator, xác nhận class 0..5, chỉ đổi `_classes` của bản copy sang `int64`,
đồng thời chứng minh source estimator và Booster serialization không đổi. Label output
metadata `[1]` được repair thành dynamic `[N]`; graph nodes và initializers trước/sau
repair phải byte-identical. Converter dùng integer target opset 15, `zipmap=False`, graph
name cố định; artifact thực tế khóa `ai.onnx=9`, `ai.onnx.ml=1`.

Raw test issue khác là `TemporaryDirectory` trên Python 3.13 gặp WinError 5 với ACL temp;
fixture chuyển sang thư mục UUID giới hạn trong workspace và cleanup tường minh. Validator
sau review được siết để từ chối semantic drift, evidence canonical bị sửa, symlink/member
tamper và cả empty directory thừa trong staging.

Production artifacts:

- `terminal-flow.bundle.zip`: 448.499 byte, SHA-256
  `10b9bd4ac7214d1e7420c0c7127b1990b3c0ec8a737f62ccbc207ef952ca4532`;
- staged `manifest.json` SHA-256
  `16975f134494ed40389d189e2267c9641e45ece809e682624b4c4403e15cddff`;
- ONNX member SHA-256
  `21f3a5c4eff068d6901c88a64bb6f0aa144c0a898f565d7dfb7b9ed36362b062`;
- `onnx-parity.json`: 2.890 byte, SHA-256
  `f8169daeebbf52331c53b67fc4142dfcf3f60efb0a7f5e2719b903e3222d998d`;
- `native-parity-reference.json`: 21.374 byte, SHA-256
  `4db86db70f6f13b777a674db608eb6414e269877f2a90b5e47b0a36e04cc6db9`.

Python ORT 1.27.0 chạy explicit `CPUExecutionProvider` trên toàn bộ 262.232 validation
row, 5 part/7 batch. Maximum absolute probability error là
`2.8726522216526718e-07`, dưới tolerance `1e-5`; model labels và thresholded final
decisions đều exact. Reference có 14 case và lưu cả numeric float32 lẫn IEEE-754 uint32
bit pattern. Hai lượt `run` tiếp theo đều trả `skipped`, chứng minh resume không đổi bytes.

Trạng thái parity cố ý là `python_ort_passed_native_pending`; manifest ghi
Python/C++ parity `claimed=false`, deferred tới phase 7 và bắt buộc trước live. Không có
test feature/metric/path read; test partition vẫn `sealed`.

### Phase 7 native terminal runtime đã build và test

Phase 7 giữ đúng bốn file:

- `cpp/include/nids/terminal_model_runtime.hpp`, SHA-256
  `cb5e4eb4e649c1b41f4171a811fd0f8291143c0d8a86577824f2dded95a4ffc0`;
- `cpp/src/terminal_model_runtime.cpp`, SHA-256
  `546fe1c505b4d77f1ad714094881820bb5f4f49614b2afcd5ea538de070b58a8`;
- `cpp/tests/terminal_model_runtime_test.cpp`, SHA-256
  `293c4231dafcca5961ccd69a8556c0e5ee6741e270f3b71d8d49c8fa0176b751`;
- `CMakeLists.txt`, SHA-256
  `02ca2c8b99a2cc9d26b6ba79dfcbee0292c7229602cabaf81f394bf7419d24c3`.

Runtime mới tách biệt legacy F9 `ModelBundle`, tải staged terminal bundle bằng external
manifest trust hash, từ chối duplicate JSON key, symlink, member thừa/thiếu và semantic
drift của schema/profile/class order/threshold/ONNX metadata. Đường infer nhận đúng 70
feature float64 hữu hạn, chọn prefix A 0..53, cast float32 có guard và trả sáu probability
cùng quyết định threshold.

Ubuntu configure pass với GCC 13, ONNX Runtime C++ 1.27.1, Jansson 2.14,
`NIDS_BUILD_MODEL_RUNTIME=ON`, legacy T5 bundle và terminal T9.1 bundle/reference đều có
external SHA-256. Hai target `nids_model_runtime_test` và
`nids_terminal_model_runtime_test` compile/link pass. Targeted CTest:

- `nids_model.runtime`: 1/1 pass trong 16,72 giây;
- `nids_model.terminal_runtime`: 1/1 pass trong 0,45 giây.

Terminal test bao phủ tám corrupt-bundle guard và 14 vector parity production. Binary
Ubuntu có SHA-256
`ef95b3c750541259c58133a75bb9d64cb32f8febe11a7d2e69d6710dd8f64987`.
Chạy binary trực tiếp đã publish
`run_log/full-flow-v1/model/native-parity.json`, 571 byte, SHA-256
`e9f92751545c600a547b9531eeca0fd8bc3321f097c318bee93dd58e8e9a135a`.
Host và Ubuntu tính cùng hash. Receipt pass 14/14 case, tám corruption guard, quyết định
exact, maximum absolute probability error `1.2309058727844047e-07` dưới tolerance `1e-5`.
Phase 7 hoàn tất; test partition vẫn `sealed` với feature/metric/path read đều bằng 0.

### Lab control prompt và kết nối VM ngày 2026-07-28

Micro-phase lab control sửa đúng hai file sản phẩm/test:

- `tools/labctl.py`;
- `tests/test_labctl.py`.

Mỗi host result có `user_confirmation`. Câu hỏi
`Bạn đã mở VMware Workstation và bật VM ... chưa?` chỉ được phát khi address discovery
timeout, trả lỗi chung, địa chỉ không hợp lệ hoặc không phải IPv4. Discovery thành công,
`powered_off`, lỗi file local, lỗi SSH và lỗi remote command không phát câu hỏi. Status
tổng hợp thêm `user_confirmation_required`; câu hỏi nằm trong JSON thay vì gọi `input()`
để command không block automation.

Lượt smoke thật đầu tiên phát hiện stdout PowerShell CP1252 không ghi được Unicode và làm
JSON dở dang. `emit_json` được đổi sang `ensure_ascii=True`, đồng thời thêm regression test
ghi qua `TextIOWrapper(..., encoding="cp1252")`. Targeted suite cuối cùng pass 14/14 trong
0,169 giây. `py -3.13 -B tools\labctl.py status` sau đó trả đúng một JSON parseable với
`user_confirmation_required=true`; không còn `UnicodeEncodeError`.

Raw discovery hiện tại: `vmrun getGuestIPAddress` trả cùng lỗi chung
`vmrun was unable to start` cho cả ba VM dù người dùng xác nhận VMware đã mở. Không có
power action nào được thực hiện. Probe đầu tiên dùng tên `ssh` bị sandbox chuyển tới
`C:\Users\zantu\.sbx-denybin\ssh.bat`, nên output `off / exit /b 1` bị loại bỏ, không dùng
làm evidence. Lượt SSH thật dùng explicit
`C:\Windows\System32\OpenSSH\ssh.exe`, explicit
`C:\Users\zantu\.ssh\config`, `BatchMode=yes`, strict host-key và `HostKeyAlias`, rồi chỉ
dùng lease gần nhất làm probe tạm:

- Kali `192.168.100.101` trả hostname `kali`;
- Ubuntu `192.168.252.128` trả hostname `tom`;
- Windows `192.168.252.20` trả hostname `WIN-SB1364KJ9KC`.

Ba kết nối đều exit 0. Các địa chỉ này không được ghi thành endpoint bền vững. Evidence
cho thấy lỗi hiện nằm ở tầng `vmrun` discovery, không phải VM tắt hoặc SSH mất kết nối.
