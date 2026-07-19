# Báo cáo T3.4 — Audit chất lượng label join CIC-IDS2017

## Trạng thái

Auditor đã chạy thành công ở chế độ chỉ đọc. Gate vẫn `pending_user_decision`; T3.5 chưa được mở và không có nhãn nào được tự động thay đổi.

## Tolerance sweep

| Tolerance | Match | Flow match | Flow ambiguous | Flow unmatched | Flow conflict |
|---:|---:|---:|---:|---:|---:|
| 0 giây | 1,202,243 | 49.3521% | 1,229,886 | 1,705 | 2,218 |
| 1 giây | 1,202,242 | 49.3521% | 1,229,887 | 1,705 | 2,218 |
| 5 giây | 1,202,223 | 49.3513% | 1,229,909 | 1,702 | 2,218 |
| 10 giây | 1,202,126 | 49.3473% | 1,230,024 | 1,684 | 2,218 |
| 30 giây | 1,201,572 | 49.3246% | 1,230,719 | 1,543 | 2,218 |
| 60 giây | 1,200,400 | 49.2765% | 1,232,067 | 1,367 | 2,218 |

## Khuyến nghị kỹ thuật

Tolerance `0` giây cho số mutual-unique match cao nhất: 1,202,243/2,436,052 flow (49.3521%). Đây chưa phải quyết định được duyệt.

## Coverage theo lớp tại tolerance khuyến nghị

| Capture | Lớp | Tổng label | Match | Ambiguous | Unmatched | Conflict | Coverage |
|---|---|---:|---:|---:|---:|---:|---:|
| friday-working-hours | BENIGN | 413,974 | 188,337 | 225,460 | 177 | 0 | 45.4949% |
| friday-working-hours | Bot | 1,966 | 0 | 1,472 | 0 | 494 | 0.0000% |
| friday-working-hours | DDoS | 128,027 | 20 | 128,007 | 0 | 0 | 0.0156% |
| friday-working-hours | PortScan | 158,924 | 158,430 | 486 | 0 | 8 | 99.6892% |
| monday-working-hours | BENIGN | 529,586 | 223,646 | 305,781 | 159 | 0 | 42.2303% |
| thursday-working-hours | BENIGN | 456,311 | 216,078 | 240,070 | 163 | 0 | 47.3532% |
| thursday-working-hours | Infiltration | 36 | 2 | 23 | 0 | 11 | 5.5556% |
| thursday-working-hours | Web Attack – Brute Force | 1,507 | 0 | 1,498 | 0 | 9 | 0.0000% |
| thursday-working-hours | Web Attack – Sql Injection | 21 | 0 | 21 | 0 | 0 | 0.0000% |
| thursday-working-hours | Web Attack – XSS | 652 | 0 | 652 | 0 | 0 | 0.0000% |
| tuesday-working-hours | BENIGN | 431,741 | 200,421 | 231,299 | 21 | 0 | 46.4216% |
| tuesday-working-hours | FTP-Patator | 7,938 | 10 | 7,926 | 0 | 2 | 0.1260% |
| tuesday-working-hours | SSH-Patator | 5,897 | 10 | 4,983 | 0 | 904 | 0.1696% |
| wednesday-working-hours | BENIGN | 439,680 | 203,167 | 236,433 | 80 | 0 | 46.2079% |
| wednesday-working-hours | DoS GoldenEye | 10,293 | 4,663 | 5,630 | 0 | 0 | 45.3026% |
| wednesday-working-hours | DoS Hulk | 231,073 | 0 | 230,726 | 0 | 347 | 0.0000% |
| wednesday-working-hours | DoS Slowhttptest | 5,499 | 3,401 | 1,970 | 0 | 128 | 61.8476% |
| wednesday-working-hours | DoS slowloris | 5,796 | 4,058 | 1,730 | 0 | 8 | 70.0138% |
| wednesday-working-hours | Heartbleed | 11 | 0 | 11 | 0 | 0 | 0.0000% |

## Đối chiếu FlowTable với khảo sát T1.2

Production export có 2,436,052 flow; profile 60 giây T1.2 có 2,436,028, chênh +24. T1.2 là khảo sát trước production, không phải ground truth nhãn.

| Close reason | Production | T1.2 survey | Delta |
|---|---:|---:|---:|
| end_of_input | 1,154 | 2,512 | -1,358 |
| idle_timeout | 1,160,255 | 1,158,880 | +1,375 |
| maximum_age | 25 | 0 | +25 |
| tcp_fin_handshake | 380,252 | 380,265 | -13 |
| tcp_reset | 890,230 | 890,230 | +0 |
| tuple_reuse | 4,136 | 4,141 | -5 |

## Blocker trước T3.5

Các attack family có label nguồn nhưng không có mutual-unique match: `Bot`, `DoS Hulk`, `Heartbleed`, `Web Attack – Brute Force`, `Web Attack – Sql Injection`, `Web Attack – XSS`.

Người dùng phải duyệt tolerance, ngưỡng coverage và family exclusion trước khi T3.4 có thể đóng.
