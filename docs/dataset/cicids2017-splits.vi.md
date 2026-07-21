# Báo cáo T3.6 — Split protocol CIC-IDS2017

## Trạng thái

T3.6 đã hoàn tất validation kỹ thuật và được người dùng chấp nhận ngày 21/07/2026. Known split dùng block thời gian 60 giây với tỷ lệ mục tiêu 70/10/20; unknown split dùng LOAFO tuyệt đối theo attack family. T3.7 được phép mở nhưng vẫn giữ toàn quyền quyết định family nào đủ mẫu để tính macro LOAFO.

## Known split

Mỗi block được xác định bởi `capture_id` và `floor(flow_start_timestamp_ns / 60 giây)`. Toàn bộ flow trong cùng block nhận chung một partition. Mọi snapshot F3/F5/F7/F9 của cùng flow tra qua một flow-level map duy nhất nên không thể nằm ở các partition khác nhau.

Phân bổ dùng seed `3607`, xử lý từng capture và tối ưu đồng thời tổng flow cùng vector class. Block là đơn vị bất khả phân; pipeline không random từng hàng và không cắt block để ép tỷ lệ chính xác.

| Partition | Flow F3 | Tỷ lệ thực |
|---|---:|---:|
| Train | 1.042.365 | 69,2965% |
| Validation | 155.220 | 10,3190% |
| Test | 306.625 | 20,3845% |
| **Tổng** | **1.504.210** | **100%** |

Có 2.454 block trên năm capture. Sai lệch nhỏ so với 70/10/20 là hệ quả được chấp nhận của việc giữ nguyên block, không phải mất flow.

## Unknown split LOAFO

Manifest khai báo 13 experiment, tương ứng mọi attack family có ít nhất một snapshot T3.5. Với family holdout:

- train dùng known-train sau khi loại toàn bộ family holdout;
- validation dùng known-validation sau khi loại toàn bộ family holdout;
- test giữ nguyên known-test và nhận thêm toàn bộ holdout flow vốn ở train/validation;
- benign test membership không thay đổi.

Heartbleed có trạng thái `unavailable` vì T3.5 có 0 snapshot. T3.6 không tự quyết định family nào được đưa vào macro LOAFO; quyết định đó thuộc rare-family gate T3.7.

## Artifact

- Contract: `config/cicids2017-split-contract.json`, SHA-256 `e7e7bdb373e36062a979edd2f8fbfee766eedf3aee776feda8e3cbe815b2b6b2`.
- Known flow map: `run_log/t3.6/known-flow-split.parquet`, 1.504.210 hàng, 9.011.968 byte, SHA-256 `8137ce83b2d38424405f20ecc36f0e6227573b0f39aedf05043d4942c181d10a`.
- LOAFO manifest: `run_log/t3.6/loafo-manifest.json`, SHA-256 `3b1a4a439b9c17de4e8ef824dda49f93330859f3427d820a28fb4738d4a6ebe4`.
- Technical acceptance: `run_log/t3.6/acceptance.json`, SHA-256 `9e6249d65dfc7fab7a31d411c6fd27e18e3320edde0b823776d4261e31df69ca`.
- User acceptance: `run_log/t3.6/user-acceptance.json`.

Flow map chỉ chứa chín cột metadata phục vụ join partition. Không có feature model, raw IP, raw port, payload hoặc bản sao Parquet snapshot T3.5.

## Kiểm chứng

- 6/6 unit test T3.6 đạt.
- 328/328 regression test ngoài hook đạt; hook nằm ngoài phạm vi và không được dùng làm bằng chứng.
- Validator kiểm lại content address của toàn bộ 20 part T3.5 trước khi đọc.
- F3 coverage khớp chính xác 1.504.210 flow; không có flow trùng hoặc thiếu.
- Mỗi time block chỉ xuất hiện trong một partition.
- Toàn bộ 3.783.154 snapshot F3/F5/F7/F9 resolve qua cùng flow map.
- LOAFO arithmetic chứng minh holdout có 0 hàng train, 0 hàng validation và toàn bộ hàng ở test.
- Deterministic rebuild tạo lại flow map có cùng SHA-256.

## Lệnh tái lập

```powershell
python scripts/verify_t36_splits.py check
python -m unittest discover -s tests -p "test_t36_splits.py" -v
python scripts/build_t36_splits.py
python scripts/verify_t36_splits.py run
python scripts/verify_t36_splits.py validate --input run_log/t3.6/acceptance.json
```

Builder và validator từ chối ghi đè artifact đã phát hành. Muốn tái lập toàn bộ phải dùng workspace/output mới hoặc lưu bundle hiện tại theo quy trình bảo toàn evidence.
