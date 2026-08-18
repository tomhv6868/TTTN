# Báo cáo bàn giao MVP NIDS partial-flow

Trạng thái: **accepted_for_demo**. Hệ thống đã chạy trọn luồng packet → flow/checkpoint → native inference → decision → JSON alert trên VMware, nhưng chưa phải nghiệm thu hiệu năng production.

## Kiến trúc và quyết định

- Flow RF dùng flow features và ngưỡng `0.5`; nếu vượt ngưỡng, quyết định là `known_attack` và Known-family RF cung cấp nhãn ứng viên.
- Nếu Flow RF không vượt ngưỡng, HBOS và Isolation Forest bỏ phiếu độc lập. Hai phiếu tạo `unknown_candidate`, một phiếu tạo `uncertain`, không phiếu tạo `benign`.
- OOF anomaly meta-features chống leakage được dùng để huấn luyện RF Stacker. Stacker chỉ được giữ làm ablation vì gate cải thiện không đạt.

## Kết quả LOAFO 9-family

| Checkpoint | Flow RF known recall | Flow RF unknown recall | Flow RF FPR | Stacker unknown recall |
|---|---:|---:|---:|---:|
| F3 | 99.241% | 74.648% | 0.195% | 68.653% |
| F5 | 99.836% | 58.953% | 0.439% | 57.830% |
| F7 | 99.409% | 38.711% | 0.404% | 39.698% |
| F9 | 99.884% | 41.471% | 0.119% | 34.648% |

Unknown recall trong bảng là tỷ lệ phát hiện trên family bị giữ lại của từng model, không phải tỷ lệ quyết định runtime mang nhãn `unknown_candidate`. Với fusion đã hiệu chuẩn ở F9, macro unknown-candidate recall là 0.162%; PortScan case study là 0%.

RF Stacker minus Flow RF có delta novel-F1 `-0.023988`, CI95% `[-0.059369, 0.000949]`. Khoảng tin cậy cắt qua 0, do đó Flow RF vẫn là binary classifier chính.

## Native và live demo

- Paced sender gửi `9` frame; F9 tạo `1` alert `known_attack`, candidate `DDoS`.
- Flow RF probability live: `0.9233325720`; pacing lateness tối đa `264201 ns`.
- Adapter errors `0`, ingest errors `0`, `port_imissed=0`, `port_rx_nombuf=0`.
- Rollback retry đã pass; management connectivity được giữ.

## Kết quả T7.4–T7.6 speed-run

- T7.4 baseline: `5.000 pps` passed; `10.000 pps` failed. Chỉ được công bố bracket `[5.000, 10.000) pps`; chưa tìm chính xác maximum.
- Full pipeline passed ở `1.800 pps`, CPU `97,262%`; stability rate được khóa ở `1.000 pps`.
- T7.5 tại 1.800 pps: `195,832 flows/s`; Parse p50/p95/p99 `0,079/0,516/0,858 microsecond`; Inference p50/p95/p99 `4,771/6,358/8,317 ms`; Alert p50/p95/p99 `4,514/6,021/7,026 ms`; `imissed=0`, `rx_nombuf=0`.
- T7.6: 30 phút, `1.800.000 packet`, sender `999,982 pps`, CPU `54,296%`, max RSS `342.440 KiB`; chỉ tăng `64 KiB` so với lượt full ngắn; DPDK drop=0 và rollback passed.
- Mọi lượt dùng làm evidence đều rollback passed; NIC `ens160` đã về `vmxnet3`.

## Tái lập

Các lệnh build tạo evidence mới phải chạy trong workspace sạch vì các publisher từ chối ghi đè receipt đã tồn tại.

### environment_windows_powershell

```text
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r config\reproducibility-requirements.txt
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
```

### inventory_windows

```text
& $python scripts/inventory_cicids2017.py
& $python scripts/verify_t31_cicids2017_inventory.py validate --input run_log/t3.1/acceptance.json --rehash-sources
```

### dataset_cross_host

```text
& $python scripts/build_t32_golden_dataset.py
cd /mnt/hgfs/TTTN && bash scripts/run_t33_flow_export_ubuntu.sh
powershell -ExecutionPolicy Bypass -File scripts\run_t33_join_windows.ps1 -Mode All
powershell -ExecutionPolicy Bypass -File scripts\run_t33_join_windows.ps1 -Mode Finalize
cd /mnt/hgfs/TTTN && bash scripts/run_t35_snapshot_replay_ubuntu.sh
& $python scripts/package_t35_parquet.py
& $python scripts/verify_t35_snapshot_dataset.py --write-outputs
```

### split_windows

```text
& $python scripts/build_t36_splits.py
& $python scripts/verify_t36_splits.py run
& $python scripts/audit_t37_rare_families.py run
```

### train_windows

```text
& $python -m nids_mvp.preprocessing run
& $python -m nids_mvp.rf_baseline run
& $python -m nids_mvp.anomaly_baseline run
& $python -m nids_mvp.oof_meta_features run
& $python -m nids_mvp.rf_stacker run
& $python -m nids_mvp.known_family_rf run
$families = (Get-Content config/cicids2017-loafo-contract.json -Raw | ConvertFrom-Json).family_scope.execute_in_order
foreach ($family in $families) { & $python -m nids_mvp.loafo --contract config/cicids2017-loafo-rf300-contract.json --family $family; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
& $python -m nids_mvp.loafo_aggregate run
& $python -m nids_mvp.model_acceptance run
```

### export_windows

```text
& $python -m nids_mvp.artifact_bundle run
& $python -m nids_mvp.threshold_calibration run
```

### offline_replay_ubuntu

```text
cd /mnt/hgfs/TTTN && source "$HOME/.local/nids-toolchain/env.sh"
PYTHONPATH=/mnt/hgfs/TTTN/python python3 -m nids_mvp.model_staging --project-root /mnt/hgfs/TTTN --checkpoint F9 --output-root /home/tom/.cache/nids-partial-flow/t5.2/bundles
cmake --preset ubuntu-release -DNIDS_BUILD_DPDK=ON -DNIDS_BUILD_MODEL_RUNTIME=ON -DNIDS_T52_STAGED_BUNDLE=/home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
cmake --build --preset ubuntu-release --target nids_demo_replay nids_dpdk_live -j 2
"$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay" --input run_log/t3.2/attack-tcp-f9.pcap --bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9 --max-records 9 --expect-records 9 --expect-f9 1 --thresholds run_log/t6.1/thresholds.json --thresholds-sha256 82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4
```

### live_replay

`ubuntu_sensor`:

```text
cd /mnt/hgfs/TTTN
bash scripts/run_t85_live_sensor_ubuntu.sh --bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9
```

`kali_sender_after_ready`:

```text
cd /mnt/hgfs/TTTN
sudo python3 -B scripts/kali_t85_golden_sender.py
```


### benchmark

`accepted_for_speed_run_demo` từ receipt `run_log/t7.4-t7.6/acceptance.json` (`3066a0d56eb2fe14f8c02279cc48d6fd222b72aaed37f3fd81e3e672f38a3498`). Formal Phase 7 acceptance vẫn là `false`; không chạy lại benchmark.

```text
python tests/test_t74_t76_speedrun_acceptance.py
python scripts/build_t74_t76_speedrun_acceptance.py validate
```

## Seed đã khóa

| Thành phần | Seed/công thức | Contract |
|---|---:|---|
| `split` | `3607` | `config/cicids2017-split-contract.json` |
| `flow_rf` | `4202` | `config/cicids2017-rf-baseline-contract.json` |
| `isolation_forest` | `4303` | `config/cicids2017-anomaly-baseline-contract.json` |
| `oof_folds` | `4404` | `config/cicids2017-oof-contract.json` |
| `oof_isolation_forest` | `4404 + held_out_fold` | `config/cicids2017-oof-contract.json` |
| `rf_stacker` | `4202` | `config/cicids2017-rf-stacker-contract.json` |
| `known_family_rf` | `4202` | `config/cicids2017-known-family-contract.json` |
| `loafo_bootstrap` | `1729` | `config/cicids2017-model-acceptance-contract.json` |
| `known_validation_bootstrap` | `1729` | `config/cicids2017-model-acceptance-contract.json` |

## Giới hạn và cách diễn giải

- `unknown_candidate` chỉ có nghĩa hai anomaly detector cùng vượt ngưỡng sau khi Flow RF không báo attack. Nó không đồng nghĩa với zero-day thực tế, không chứng minh CVE mới và không tự xác định attack family.
- PortScan chưa được chứng minh ở runtime: case study sau calibration có recall 0%. Không được tuyên bố hệ thống hiện tại phát hiện được mọi lượt `nmap`.
- Speed-run chạy trên VMware, vì vậy không phải bằng chứng hiệu năng production.
- Stability dùng synthetic multi-flow TCP F9, không phải production traffic mix. Sensor thấy thêm 408 packet ngoài benchmark và có 202 parser errors, nên không được tuyên bố identity-level delivery của từng sender packet.
- Alert queue pressure chưa có vì T6.5 async queue chưa được triển khai.
- `703,99 alerts/hour` chỉ là synthetic benchmark alert rate; không thay thế alerts/hour của detection study T8.1.
- CIC sample attacker-VM replay, automated isolated flow-count equality và automated feature-hash equality vẫn được hoãn trong T7.3.

## Artifact chính

| Artifact | SHA-256 |
|---|---|
| `run_log/t3.5/acceptance.json` | `ed2cf650f862fcd102f9ba872f650da4a4c476c6198ade37def05a4b93f25042` |
| `run_log/t3.6/acceptance.json` | `9e6249d65dfc7fab7a31d411c6fd27e18e3320edde0b823776d4261e31df69ca` |
| `run_log/t4.8/acceptance.json` | `9bd14e7195c7affc8d7477939826a9fa5299f46a522cf71eecb02bdad6a3c086` |
| `run_log/t5.1/acceptance.json` | `fbd0ee96ac3a84a5f9caf8d30d80cf260cd25f3a5841b11fa2f5173c12320ace` |
| `run_log/t5.3/acceptance.json` | `1808f2ef433b0b239a5d8fca6cd829e0c42b22b971ed3b0889a5811ca834db90` |
| `run_log/t6.1/thresholds.json` | `82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4` |
| `run_log/t7.3/acceptance.json` | `da4df77a5b99efacaa5b0b228084a4d98677c29586d46fa0cb1355e80a143f26` |
| `run_log/t7.4-t7.6/acceptance.json` | `3066a0d56eb2fe14f8c02279cc48d6fd222b72aaed37f3fd81e3e672f38a3498` |
| `run_log/t8.1-t8.2/acceptance.json` | `092c8ad88586eb16dd9b216aaf9cd610e8aa2909889b05d6f5e68badb43ed36e` |
