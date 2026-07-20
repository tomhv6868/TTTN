# Báo cáo T3.4R1 — Audit class-consensus CIC-IDS2017

## Trạng thái

Audit kỹ thuật đã pass ở chế độ chỉ đọc. Gate vẫn `pending_user_decision`; T3.5 chưa được mở và không có nhãn, flow boundary hay family scope nào được tự động thay đổi.

## Tổng quan

- Flow nguồn: 2,436,052
- Flow được gán: 2,366,094 (97.1282%)
- Flow quarantine: 69,958 (2.8718%)
- Mutual unique: 1,202,243
- Class consensus: 1,163,851

## Theo capture

| Capture | Source flow | Assigned | Quarantine | Mutual unique | Consensus | Assignment rate |
|---|---:|---:|---:|---:|---:|---:|
| friday-working-hours | 578,024 | 541,404 | 36,620 | 346,787 | 194,617 | 93.6646% |
| monday-working-hours | 425,166 | 424,698 | 468 | 223,646 | 201,052 | 99.8899% |
| thursday-working-hours | 411,141 | 409,104 | 2,037 | 216,080 | 193,024 | 99.5045% |
| tuesday-working-hours | 357,558 | 353,676 | 3,882 | 200,441 | 153,235 | 98.9143% |
| wednesday-working-hours | 664,163 | 637,212 | 26,951 | 215,289 | 421,923 | 95.9421% |

## Theo class

Flow và CSV-row là hai đơn vị khác nhau; delta chỉ là chẩn đoán non-parity, không phải coverage hoặc bằng chứng đúng/sai. Representation chỉ cho biết tỷ lệ CSV row hợp lệ tham gia ít nhất một flow đã gán, không phải accuracy hay recall.

| Class | Source rows | Represented | Representation | Source quarantine | Assigned flow | Mutual unique | Consensus | Delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BENIGN | 2,271,292 | 2,235,981 | 98.4453% | 1,805 | 1,848,412 | 1,031,649 | 816,763 | -422,880 |
| Bot | 1,966 | 1,472 | 74.8728% | 0 | 736 | 0 | 736 | -1,230 |
| DDoS | 128,027 | 103,033 | 80.4776% | 0 | 58,807 | 20 | 58,787 | -69,220 |
| DoS GoldenEye | 10,293 | 10,238 | 99.4657% | 0 | 8,597 | 4,663 | 3,934 | -1,696 |
| DoS Hulk | 231,073 | 224,068 | 96.9685% | 0 | 271,011 | 0 | 271,011 | +39,938 |
| DoS Slowhttptest | 5,499 | 4,571 | 83.1242% | 0 | 5,304 | 3,401 | 1,903 | -195 |
| DoS slowloris | 5,796 | 5,528 | 95.3761% | 0 | 6,619 | 4,058 | 2,561 | +823 |
| FTP-Patator | 7,938 | 4,924 | 62.0307% | 0 | 4,942 | 10 | 4,932 | -2,996 |
| Heartbleed | 11 | 0 | 0.0000% | 0 | 0 | 0 | 0 | -11 |
| Infiltration | 36 | 25 | 69.4444% | 0 | 14 | 2 | 12 | -22 |
| PortScan | 158,924 | 158,788 | 99.9144% | 6 | 158,976 | 158,430 | 546 | +52 |
| SSH-Patator | 5,897 | 4,962 | 84.1445% | 0 | 2,503 | 10 | 2,493 | -3,394 |
| Web Attack – Brute Force | 1,507 | 282 | 18.7127% | 0 | 142 | 0 | 142 | -1,365 |
| Web Attack – Sql Injection | 21 | 18 | 85.7143% | 0 | 10 | 0 | 10 | -11 |
| Web Attack – XSS | 652 | 42 | 6.4417% | 0 | 21 | 0 | 21 | -631 |

## Rủi ro multiplicity

Có 2,826,421 source label_id trong toàn bộ đồ thị candidate hợp lệ; fanout lớn nhất là 190 flow/label_id và trung bình 1.4024.

Candidate agreement được tính trên tất cả candidate hợp lệ. Auditor không chọn một CSV row đại diện và các delta không được dùng để tự động relabel.

## Gate

Tolerance vẫn khóa ở `0s`. Người dùng phải duyệt ngưỡng assignment, quarantine, multiplicity và family scope trước khi T3.5 có thể được mở.
