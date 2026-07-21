# Báo cáo T3.7 — Rare-family gate CIC-IDS2017

## Trạng thái

Audit kỹ thuật đã pass. Gate đang `pending_user_decision`; T4.1 chưa được mở.

Ngưỡng đủ mẫu là ít nhất 100 distinct flow tại F9. Một danh sách family chung được dùng cho F3/F5/F7/F9. Ngưỡng tính trên toàn bộ assignment đã được T3.4R1 chấp nhận; provenance vẫn được báo cáo riêng.

## Số mẫu và quyết định

| Family | F3 | F5 | F7 | F9 | Consensus F9 | Cảnh báo provenance | Quyết định |
|---|---:|---:|---:|---:|---:|---|---|
| Bot | 736 | 736 | 736 | 736 | 100.00% | Có | Đủ mẫu macro LOAFO |
| DDoS | 58,442 | 58,442 | 58,421 | 58,410 | 99.99% | Có | Đủ mẫu macro LOAFO |
| DoS GoldenEye | 7,366 | 7,366 | 7,366 | 7,361 | 37.71% | Không | Đủ mẫu macro LOAFO |
| DoS Hulk | 150,126 | 149,932 | 149,795 | 149,689 | 100.00% | Có | Đủ mẫu macro LOAFO |
| DoS Slowhttptest | 4,467 | 4,227 | 3,249 | 259 | 35.52% | Không | Đủ mẫu macro LOAFO |
| DoS slowloris | 3,791 | 2,122 | 2,051 | 1,840 | 4.46% | Không | Đủ mẫu macro LOAFO |
| FTP-Patator | 2,467 | 2,456 | 2,456 | 2,456 | 99.59% | Có | Đủ mẫu macro LOAFO |
| Infiltration | 14 | 14 | 14 | 14 | 85.71% | Có | Chỉ case study |
| PortScan | 1,043 | 85 | 85 | 85 | 67.06% | Có | Chỉ case study |
| SSH-Patator | 2,487 | 2,486 | 2,483 | 2,483 | 99.60% | Có | Đủ mẫu macro LOAFO |
| Web Attack – Brute Force | 141 | 141 | 141 | 141 | 100.00% | Có | Đủ mẫu macro LOAFO |
| Web Attack – Sql Injection | 9 | 9 | 9 | 9 | 100.00% | Có | Chỉ case study |
| Web Attack – XSS | 21 | 21 | 21 | 21 | 100.00% | Có | Chỉ case study |
| Heartbleed | 0 | 0 | 0 | 0 | n/a | Không | Không khả dụng |

## Phạm vi macro LOAFO

Đủ mẫu: `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `SSH-Patator`, `Web Attack – Brute Force`.

Chỉ case study: `Infiltration`, `PortScan`, `Web Attack – Sql Injection`, `Web Attack – XSS`.

Không khả dụng: `Heartbleed`.

Family case study vẫn được giữ trong artifact và có thể báo cáo metric riêng, nhưng không đóng góp vào macro LOAFO. Cảnh báo provenance chỉ cho biết hơn 50% mẫu F9 đến từ `class_consensus`; nó không tự loại family vì T3.4R1 đã chấp nhận cả hai phương thức assignment.

## Cơ sở thống kê và giới hạn

Ở n=100, Wilson 95% có worst-case half-width khoảng 9,62 điểm phần trăm khi tỷ lệ thật gần 0,5. Đây là ngưỡng tối thiểu để tránh đưa family cực hiếm vào macro average; nó không chứng minh label accuracy hoặc khả năng tổng quát ngoài CIC-IDS2017.

F9 là population nhỏ nhất nên được dùng làm conservative bound. Nhờ dùng một danh sách chung, macro score giữa F3/F5/F7/F9 so sánh trên cùng tập family.

## Artifact và tái lập

- Audit: `run_log/t3.7/rare-family-audit.json`.
- Acceptance: `run_log/t3.7/acceptance.json`.
- Contract: `config/cicids2017-rare-family-contract.json`.

```powershell
python scripts/audit_t37_rare_families.py check
python -m unittest discover -s tests -p "test_t37_rare_families.py" -v
python scripts/audit_t37_rare_families.py run
python scripts/audit_t37_rare_families.py validate --input run_log/t3.7/acceptance.json
```

Các lệnh trên không chạy hook, không replay PCAP và không train model.
