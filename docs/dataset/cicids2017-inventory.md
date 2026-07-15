# Kiểm kê nguồn CIC-IDS2017

T3.1 khóa đúng bộ CIC-IDS2017 dùng cho các bước label join và tạo snapshot dataset. NF-UQ-NIDS không được dùng thay thế.

## Nguồn và điều khoản

Nguồn chính thức là trang [CIC-IDS2017 của Canadian Institute for Cybersecurity, University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html). Trang nguồn mô tả năm ngày capture từ thứ Hai đến thứ Sáu, cung cấp PCAP và labeled-flow CSV, cho phép nhà nghiên cứu truy cập và yêu cầu trích dẫn công trình liên quan.

Trang được dẫn không công bố SPDX identifier, không thể hiện rõ quyền phân phối lại và không cung cấp publisher digest. Vì vậy receipt chỉ dùng SHA-256 làm định danh nội dung cục bộ. Không được diễn giải SHA-256 này thành bằng chứng rằng file khớp bản gốc của nhà phát hành.

## Bộ dữ liệu được khóa

Inventory yêu cầu đúng năm file PCAP theo ngày và `GeneratedLabelledFlows.zip`. Archive phải chứa đúng tám labeled-flow CSV. Mỗi CSV phải có `Flow ID`, IP và port hai đầu, `Protocol`, `Timestamp` và `Label`; đây là đầu vào cho T3.3.

Các file mang đuôi `.pcap` nhưng container thực tế là PCAPNG, được xác nhận bằng magic `0a0d0d0a`. Inventory ghi đúng định dạng thực thay vì suy luận từ phần mở rộng.

`MachineLearningCSV.zip` không bắt buộc cho label join vì `GeneratedLabelledFlows.zip` đã chứa khóa tuple, thời gian và nhãn cần thiết. Quyết định này không cho phép thay archive bằng dataset dẫn xuất khác.

## Cách kiểm kê

Chương trình đọc toàn bộ file theo luồng 8 MiB để tính SHA-256. ZIP được đọc trực tiếp, không giải nén ra đĩa; từng CSV được kiểm CRC, SHA-256, kích thước, số dòng và header. Không packet hay payload nào được con người đọc thủ công.

```powershell
python scripts/inventory_cicids2017.py --self-test
python scripts/verify_t31_cicids2017_inventory.py check
python -m unittest discover -s tests -p "test_t31_cicids2017_inventory.py" -v
python scripts/inventory_cicids2017.py
python scripts/verify_t31_cicids2017_inventory.py validate --input run_log/t3.1/acceptance.json --rehash-sources
```

Lệnh inventory từ chối ghi đè receipt. Muốn chạy lại phải dùng một output mới nằm dưới `run_log/t3.1/`; acceptance đã phát hành phải được giữ nguyên làm bằng chứng. Nghiệm thu dùng `--rehash-sources` để verifier tự đọc lại năm PCAP, archive và tám CSV, nhờ đó phát hiện cả digest trong receipt bị sửa.

## Tiêu chí nghiệm thu

- Đủ đúng năm PCAP, không nhận file ngoài hợp đồng và tất cả có magic PCAPNG.
- Đủ đúng tám labeled-flow CSV, không trùng basename và có đầy đủ trường join bắt buộc.
- Có SHA-256 cho năm PCAP, archive và từng CSV sau giải nén theo luồng.
- Receipt T2.6 vẫn `passed`; danh tính năm PCAP khớp full scan T1.2.
- Bằng chứng license và giới hạn checksum khớp hợp đồng, không tuyên bố SPDX hoặc publisher digest không có thật.
- Receipt cuối có trạng thái `passed` và verifier độc lập chấp nhận.
