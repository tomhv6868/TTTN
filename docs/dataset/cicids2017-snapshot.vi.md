# Báo cáo T3.5 — Dataset partial-flow CIC-IDS2017

## Trạng thái

Pipeline kỹ thuật đã hoàn tất và independent validator đã pass. Dataset gồm 20 Parquet part cho năm capture và bốn checkpoint F3/F5/F7/F9. Gate hiện là `pending_user_decision`; T3.6 chưa được mở cho tới khi người dùng chấp nhận T3.5.

## Pipeline đã chạy

1. Ubuntu 24.04 VMware replay năm PCAP bất biến qua cùng `pcap_adapter`, packet parser, `FlowTable` và feature engine của runtime C++.
2. Mỗi flow phát snapshot ngay khi đạt packet 3, 5, 7 hoặc 9. Flow ngắn không được padding và không có terminal snapshot tổng hợp.
3. Mỗi capture được stage thành SQLite ở local scratch rồi mới atomic-copy vào workspace cùng content-addressed receipt.
4. Windows Python 3.13 với PyArrow 23.0.1 đối chiếu toàn bộ close record với T3.3, join `flow_id` và nhãn T3.3R1, sau đó publish Parquet theo từng capture.
5. Independent validator tự quét toàn bộ row group, so từng metadata field và từng bit `float64` với SQLite oracle, rồi mới ghi manifest và build receipt.

Attempt replay: `run_log/t3.5/attempts/ubuntu-snapshot-replay-20260720T170954731592021Z`.

## Kết quả replay trước khi join nhãn

| Capture | Final flow | F3 | F5 | F7 | F9 | Tổng snapshot |
|---|---:|---:|---:|---:|---:|---:|
| monday-working-hours | 425,166 | 296,307 | 150,698 | 133,184 | 125,057 | 705,246 |
| tuesday-working-hours | 357,558 | 252,338 | 123,481 | 107,481 | 99,607 | 582,907 |
| wednesday-working-hours | 664,163 | 427,101 | 291,446 | 273,799 | 262,495 | 1,254,841 |
| thursday-working-hours | 411,141 | 251,145 | 111,554 | 92,262 | 85,890 | 540,851 |
| friday-working-hours | 578,024 | 325,046 | 199,705 | 183,031 | 177,090 | 884,872 |
| **Tổng** | **2,436,052** | **1,551,937** | **876,884** | **789,757** | **750,139** | **3,968,717** |

Các số trên bao gồm mọi flow runtime, kể cả flow không có assignment cuối. Đây là tầng reconciliation, không phải dataset huấn luyện.

## Dataset Parquet sau join assignment

| Checkpoint | Hàng | BENIGN | Attack | Mutual unique | Class consensus |
|---|---:|---:|---:|---:|---:|
| F3 | 1,504,210 | 1,273,100 | 231,110 | 736,231 | 767,979 |
| F5 | 829,439 | 601,402 | 228,037 | 109,260 | 720,179 |
| F7 | 744,359 | 517,532 | 226,827 | 56,982 | 687,377 |
| F9 | 705,146 | 481,642 | 223,504 | 35,091 | 670,055 |
| **Tổng** | **3,783,154** | **2,873,676** | **909,478** | **937,564** | **2,845,590** |

Có 861,884 assigned flow kết thúc trước F3: 220,398 flow một packet và 641,486 flow hai packet. Chúng không phải export loss; theo checkpoint contract, chúng không sinh snapshot.

## Phân phối class theo checkpoint

| Class | F3 | F5 | F7 | F9 |
|---|---:|---:|---:|---:|
| BENIGN | 1,273,100 | 601,402 | 517,532 | 481,642 |
| Bot | 736 | 736 | 736 | 736 |
| DDoS | 58,442 | 58,442 | 58,421 | 58,410 |
| DoS GoldenEye | 7,366 | 7,366 | 7,366 | 7,361 |
| DoS Hulk | 150,126 | 149,932 | 149,795 | 149,689 |
| DoS Slowhttptest | 4,467 | 4,227 | 3,249 | 259 |
| DoS slowloris | 3,791 | 2,122 | 2,051 | 1,840 |
| FTP-Patator | 2,467 | 2,456 | 2,456 | 2,456 |
| Infiltration | 14 | 14 | 14 | 14 |
| PortScan | 1,043 | 85 | 85 | 85 |
| SSH-Patator | 2,487 | 2,486 | 2,483 | 2,483 |
| Web Attack – Brute Force | 141 | 141 | 141 | 141 |
| Web Attack – Sql Injection | 9 | 9 | 9 | 9 |
| Web Attack – XSS | 21 | 21 | 21 | 21 |
| Heartbleed | 0 | 0 | 0 | 0 |

Không có family nào bị packager âm thầm loại. Heartbleed bằng 0 vì T3.3R1 không có assigned flow cho class này. PortScan và DoS Slowhttptest giảm mạnh ở checkpoint muộn do packet count cuối của flow, không phải do bộ lọc class.

## Schema và privacy

Mỗi hàng có đúng tám cột metadata và 54 feature `float64` không null, hữu hạn. Model input allowlist chỉ gồm 54 tên feature từ `nids.flow_features.v1`; metadata không được chọn theo vị trí.

Final Parquet không chứa generation, export ordinal, endpoint, raw IP, raw port, candidate label ID, payload, raw packet hoặc final-flow future information. `flow_id` trong Parquet luôn đến từ T3.3 SQLite, không phải runtime generation.

Layout:

`run_log/t3.5/dataset-v1/checkpoint={F3|F5|F7|F9}/capture_id={capture-id}/part-00000.parquet`

Vì tên Hive partition `checkpoint=F3` là string trong khi cột vật lý `checkpoint` là `uint8`, đọc một file riêng bằng `pyarrow.parquet.ParquetFile`, hoặc mở dataset với `partitioning=None`. Không dùng `pq.read_table(path)` với tự động suy luận Hive trên đường dẫn part.

## Bằng chứng validation

- C++ CTest: 2/2 pass (`nids_dataset.flow_export`, `nids_dataset.snapshot_export`).
- Python snapshot-shard tests trên Ubuntu: 10/10 pass.
- Independent validation: `status=passed`, 20 part, 3,783,154 hàng.
- Toàn bộ close-record được đối chiếu hai chiều với T3.3 sau chuẩn hóa protocol/IP.
- Toàn bộ row group được quét; feature được so bitwise với BLOB little-endian `<54d`.
- `flow_id` tăng nghiêm ngặt trong mỗi part; schema, sorting metadata, ZSTD, statistics, dictionary columns và absence của page index đều được kiểm.
- F9 ⊆ F7 ⊆ F5 ⊆ F3 được suy ra và kiểm bằng exact row oracle `final packet_count >= checkpoint`.

Artifact chính:

- Contract SHA-256: `5b3fef6e8539b78227810c44facb6e8583d8b7417b76a65685f1be84e0e93a08`
- Schema SHA-256: `5d64a8ab48144a405c106d32299ac5a48022ce078b2e2c5f0e7b36a79af9c241`
- Manifest: `run_log/t3.5/manifest.json`, SHA-256 `8ef8f483e4825762c724245e11c69dbf4c3e59b458dec1dab856dc9fd341c7ef`
- Build receipt: `run_log/t3.5/build.json`, SHA-256 `95f2623030ebce90bce058118c45ef5d3d4f8cb22a83c0191c431d24729bc680`
- 20 Parquet part: 324,023,969 bytes.

## Giới hạn và gate tiếp theo

Class consensus là assignment được T3.4R1 chấp nhận cho snapshot, không phải xác nhận nhãn độc lập. T3.5 chứng minh tính đúng đắn của replay, checkpoint, join và artifact; không tuyên bố label accuracy hoặc model quality.

Phạm vi model/evaluation vẫn là provisional. T3.7 giữ quyền quyết định cuối cho rare family; đặc biệt Heartbleed không có snapshot, còn Infiltration và các Web Attack có rất ít flow. T3.6 chỉ được mở sau khi người dùng chấp nhận báo cáo và artifact T3.5.
