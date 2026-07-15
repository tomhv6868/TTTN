# Rà soát Feature Schema v1

## Kết luận cần hiểu đúng

Tài liệu này là cổng rà soát T1.5 cho `nids.flow_features.v1`. Con số 54 không được lấy nguyên từ một bài báo và chưa được chứng minh là số đặc trưng tối ưu. Đây là một tập đầu ra ứng viên được xây dựng từ đặc trưng CICFlowMeter, sau đó điều chỉnh cho ba yêu cầu của dự án:

- chỉ dùng prefix 3, 5, 7 hoặc 9 packet, không nhìn packet tương lai hay kết quả cuối flow;
- PCAPNG và DPDK đưa cùng `PacketView` vào cùng một feature engine C++;
- state được cập nhật tăng dần với bộ nhớ hữu hạn, phù hợp sensor DPDK.

Feature engine ở T2.3 bắt buộc phải xuất đúng 54 giá trị theo schema để bảo đảm khả năng tái lập. Điều này không có nghĩa mọi model cuối cùng đều phải dùng đủ 54 giá trị. Tập con dùng cho HBOS, Isolation Forest hoặc Random Forest phải được chọn và khóa riêng bằng preprocessing chỉ dựa trên training partition.

Hai schema đầu vào đã được nghiệm thu ở T1.3 và được khóa bằng SHA-256:

- `config/flow-feature-schema-v1.json`: `69241cb5069ce68f941836332cfc556d15fba00253288eb6f985155bac1bc6eb`;
- `config/packet-sequence-schema-v1.json`: `50235d3c398ff5925ff953f17dee4e433f1db15e58a8fc79f76438b602daa6d6`.

Retransmission và out-of-order chưa phải đặc trưng của Schema v1. Port category chỉ được phép xuất hiện trong một ablation có version riêng. Nếu cần đổi danh sách đầu ra, tên, thứ tự, đơn vị hoặc công thức thì phải tạo schema version mới thay vì sửa ngầm Schema v1.

## Nguồn tham khảo

Các nguồn chính dùng để xây dựng tập ứng viên:

- [CIC-IDS2017 của Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html): xác nhận dataset có PCAP, flow đã gán nhãn và hơn 80 đặc trưng do CICFlowMeter tạo;
- [danh sách đặc trưng CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt): mô tả flow duration, packet/byte theo hai chiều, packet length, IAT, rate, TCP flags, initial window, header, active/idle, bulk và subflow;
- [bài báo gốc CIC-IDS2017](https://www.scitepress.org/PublishedPapers/2018/66398/pdf/index.html): mô tả cách sinh dataset và đánh giá feature selection cho các loại tấn công;
- [RFC 9293](https://www.rfc-editor.org/info/rfc9293/): chuẩn TCP và cơ sở để hiểu sequence number, ACK, retransmission, SYN, FIN và RST;
- [RFC 6335](https://www.rfc-editor.org/info/rfc6335): định nghĩa các dải System, User và Dynamic port;
- [bài báo HBOS gốc](https://www.dfki.de/en/web/research/projects-and-publications/publication/6431): nêu giả định các chiều đặc trưng độc lập của HBOS.

Không nguồn nào ở trên công bố đúng bộ 54 đặc trưng của dự án này. Phần kế thừa và phần tự thiết kế được chỉ ra ở bảng dưới.

## Nguồn gốc theo nhóm

| Chỉ số | Nhóm | Nguồn gốc | Lý do giữ hoặc điều chỉnh |
|---:|---|---|---|
| 0–6 | Thời gian và lưu lượng | Điều chỉnh từ flow duration, total forward/backward packet và total forward/backward length của CICFlowMeter | `flow_age_us` chỉ đo prefix hiện tại; count và byte tính được tăng dần |
| 7–14 | Độ dài packet | Kế thừa ý tưởng packet-length statistics của CICFlowMeter | Giữ min/max toàn flow và mean/std toàn flow, forward, reverse để mô tả hình dạng lưu lượng sớm |
| 15–22 | IAT | Kế thừa nhóm flow/forward/backward IAT của CICFlowMeter, nhưng semantics có dấu là quyết định riêng | Giữ capture order để PCAPNG và DPDK không cần sắp xếp lại timestamp |
| 23–27 | Rate, tỷ lệ và đổi chiều | Packet/byte rate kế thừa; hai tỷ lệ điều chỉnh từ down/up ratio; `direction_change_count` tự thiết kế | Mô tả cường độ và tương tác hai chiều trong prefix ngắn |
| 28–37 | TCP | Cờ TCP và initial window kế thừa; SYN/ACK ratio và window mean/std tự thiết kế | Phân biệt bắt tay, truyền dữ liệu, đóng/reset và hành vi cửa sổ TCP |
| 38–41 | TTL | Tự thiết kế | Giữ tín hiệu biến thiên TTL mà không đưa địa chỉ IP vào model |
| 42–51 | Payload | `payload_packet_count` gần với active-data packet của CICFlowMeter; thống kê hai chiều còn lại tự thiết kế | Mô tả lượng dữ liệu ứng dụng mà không lưu payload trong `FlowState` |
| 52–53 | Header | Điều chỉnh từ header-length features của CICFlowMeter | Dùng mean/std của `payload.offset` để phản ánh VLAN, IPv4 options và TCP options |

Tổng `7 + 8 + 8 + 5 + 10 + 4 + 10 + 2` tạo thành 54. Đây là kết quả của phạm vi quan sát đã chọn, không phải một siêu tham số đã được tối ưu.

## Nguyên tắc lựa chọn

Một đặc trưng chỉ được đưa vào tập ứng viên khi đáp ứng tất cả điều kiện sau:

1. Tính được tại F3/F5/F7/F9 chỉ từ packet đã quan sát.
2. Có cùng semantics trên PCAPNG và DPDK.
3. Cập nhật được bằng counter, min/max hoặc Welford mà không giữ lịch sử raw packet trong `FlowState`.
4. Không dùng label, raw IP, raw port, timestamp tuyệt đối, capture ID hay lịch tấn công.
5. Có quy tắc xác định cho TCP và UDP, bao gồm giá trị 0 khi nhóm TCP không áp dụng cho UDP.

Các nhóm active/idle, bulk, subflow và final flow duration của CICFlowMeter bị loại vì chúng phụ thuộc timeout, phân đoạn dài hoặc thông tin cuối flow, không ổn định ở prefix 3–9 packet.

## Đầu ra schema và đầu vào model

Ba lớp phải được phân biệt:

| Lớp | Nội dung | Trạng thái |
|---|---|---|
| Feature engine | Luôn xuất vector 54 giá trị theo Schema v1 | Khóa ở T1.5, triển khai ở T2.3 |
| Preprocessing/model adapter | Chọn tập con, chuẩn hóa và lưu feature mask cùng model artifact | Chưa triển khai; chỉ được fit trên training partition |
| Model | HBOS, Isolation Forest hoặc Random Forest nhận đúng đầu vào đã khóa trong artifact | Đánh giá ở các task huấn luyện |

Các đặc trưng có quan hệ đại số và tương quan mạnh: tổng packet bằng tổng hai chiều, tổng byte bằng tổng hai chiều, rate được dẫn xuất từ count/byte và tuổi flow. Random Forest có thể tự xử lý phần nào sự dư thừa, nhưng HBOS giả định các chiều độc lập nên có nguy cơ tính lặp cùng một tín hiệu. Vì vậy không được mặc định đưa cả 54 chiều vào mọi model mà không có đánh giá trên training partition và ablation.

## Danh sách đầu ra bắt buộc

Mọi giá trị được mã hóa thành `float64` trong vector đầu ra. Cột kiểu logic giữ miền giá trị trước bước mã hóa. “Bắt buộc” trong bảng này có nghĩa feature engine phải tính và xuất; nó không khẳng định đặc trưng đó sẽ được mọi model sử dụng.

| Chỉ số | Tên | Kiểu logic | Đơn vị |
|---:|---|---|---|
| 0 | `flow_age_us` | `float64` | microsecond |
| 1 | `packet_count` | `uint64` | packet |
| 2 | `forward_packet_count` | `uint64` | packet |
| 3 | `reverse_packet_count` | `uint64` | packet |
| 4 | `wire_byte_count` | `uint64` | byte |
| 5 | `forward_wire_byte_count` | `uint64` | byte |
| 6 | `reverse_wire_byte_count` | `uint64` | byte |
| 7 | `packet_length_min` | `uint32` | byte |
| 8 | `packet_length_max` | `uint32` | byte |
| 9 | `packet_length_mean` | `float64` | byte |
| 10 | `packet_length_std` | `float64` | byte |
| 11 | `forward_packet_length_mean` | `float64` | byte |
| 12 | `forward_packet_length_std` | `float64` | byte |
| 13 | `reverse_packet_length_mean` | `float64` | byte |
| 14 | `reverse_packet_length_std` | `float64` | byte |
| 15 | `flow_iat_min_us` | `float64` | microsecond |
| 16 | `flow_iat_max_us` | `float64` | microsecond |
| 17 | `flow_iat_mean_us` | `float64` | microsecond |
| 18 | `flow_iat_std_us` | `float64` | microsecond |
| 19 | `forward_iat_mean_us` | `float64` | microsecond |
| 20 | `forward_iat_std_us` | `float64` | microsecond |
| 21 | `reverse_iat_mean_us` | `float64` | microsecond |
| 22 | `reverse_iat_std_us` | `float64` | microsecond |
| 23 | `packet_rate_per_second` | `float64` | packet/second |
| 24 | `wire_byte_rate_per_second` | `float64` | byte/second |
| 25 | `forward_reverse_packet_ratio` | `float64` | tỷ lệ |
| 26 | `forward_reverse_wire_byte_ratio` | `float64` | tỷ lệ |
| 27 | `direction_change_count` | `uint64` | lần đổi chiều |
| 28 | `tcp_syn_count` | `uint64` | cờ TCP |
| 29 | `tcp_ack_count` | `uint64` | cờ TCP |
| 30 | `tcp_fin_count` | `uint64` | cờ TCP |
| 31 | `tcp_rst_count` | `uint64` | cờ TCP |
| 32 | `tcp_psh_count` | `uint64` | cờ TCP |
| 33 | `tcp_syn_ack_ratio` | `float64` | tỷ lệ |
| 34 | `tcp_initial_forward_window` | `uint16` | byte |
| 35 | `tcp_initial_reverse_window` | `uint16` | byte |
| 36 | `tcp_window_mean` | `float64` | byte |
| 37 | `tcp_window_std` | `float64` | byte |
| 38 | `ttl_min` | `uint8` | hop |
| 39 | `ttl_max` | `uint8` | hop |
| 40 | `ttl_mean` | `float64` | hop |
| 41 | `ttl_std` | `float64` | hop |
| 42 | `payload_packet_count` | `uint64` | packet |
| 43 | `forward_payload_packet_count` | `uint64` | packet |
| 44 | `reverse_payload_packet_count` | `uint64` | packet |
| 45 | `payload_byte_count` | `uint64` | byte |
| 46 | `forward_payload_byte_count` | `uint64` | byte |
| 47 | `reverse_payload_byte_count` | `uint64` | byte |
| 48 | `payload_length_min` | `uint32` | byte |
| 49 | `payload_length_max` | `uint32` | byte |
| 50 | `payload_length_mean` | `float64` | byte |
| 51 | `payload_length_std` | `float64` | byte |
| 52 | `header_length_mean` | `float64` | byte |
| 53 | `header_length_std` | `float64` | byte |

## Quy tắc số học

- Packet luôn được xử lý theo capture order, không sắp xếp lại theo timestamp.
- IAT là hiệu timestamp có dấu. IAT âm và bằng 0 phải được giữ nguyên.
- `flow_age_us` dùng watermark timestamp không giảm trừ timestamp packet đầu. Packet có timestamp lùi không làm tuổi flow giảm.
- Mean và độ lệch chuẩn dùng Welford. Phương sai population là `M2 / n`.
- IAT được tích lũy ở nanosecond rồi chia `1000.0`; không làm tròn.
- Nhóm rỗng trả 0. Một mẫu có độ lệch chuẩn bằng 0.
- Mẫu số bằng 0 trả 0. Rate trả 0 khi tuổi flow không dương.
- NaN hoặc vô cực ở đầu vào hay đầu ra làm pipeline fail-fast.
- Độ dài payload được thống kê trên mọi packet, kể cả packet có payload dài 0.
- Độ dài header là `PacketView.payload.offset`, tức số byte từ đầu frame đến payload tầng vận chuyển.

## Thuật ngữ và các đặc trưng đang hoãn

### Retransmission và out-of-order

TCP retransmission là việc gửi lại toàn bộ hoặc một phần dải sequence number đã gửi trước đó, thường do bên gửi suy đoán packet hoặc ACK bị mất. Out-of-order là việc các segment được quan sát không theo thứ tự sequence number mong đợi. Hai hiện tượng khác nhau: segment đến muộn có thể chỉ bị đảo thứ tự chứ không phải bản truyền lại.

Sensor thụ động muốn phân loại đúng phải xử lý sequence-number wraparound, SYN/FIN chiếm sequence number, segment chồng lấn, capture loss và kết nối đã bắt đầu trước thời điểm sensor quan sát. Vì chưa có hợp đồng đầy đủ và parity test PCAPNG–DPDK cho các trường hợp này, Schema v1 không xuất retransmission count, retransmitted bytes hoặc out-of-order count. Việc hoãn không có nghĩa các tín hiệu này vô ích; chúng chỉ được phép bổ sung trong schema version mới sau khi có định nghĩa và test độc lập.

### Port category

Port category là cách biến số cổng thành nhóm thay vì đưa raw port vào model. RFC 6335 chia port thành System `0–1023`, User `1024–49151` và Dynamic `49152–65535`. Một cách khác là nhóm theo dịch vụ như web, DNS hoặc SSH, nhưng cách đó càng dễ làm model học thuộc dịch vụ của phòng lab.

CIC-IDS2017 công bố lịch tấn công, endpoint và dịch vụ cụ thể. Vì vậy raw port hoặc nhóm port có thể tạo shortcut giữa cấu hình lab và label. Schema v1 loại cả raw port lẫn port category; port category chỉ được thử như một biến độc lập trong ablation.

### Ablation

Ablation là thí nghiệm giữ nguyên dataset split, seed, preprocessing và model, chỉ thêm hoặc bỏ đúng một thành phần. Ví dụ, cấu hình A dùng tập đặc trưng nền; cấu hình B giống hệt A nhưng thêm port category. Chỉ khi B cải thiện trên split tách biệt theo ngày/capture mà không làm FPR hoặc alerts/hour xấu đi mới có cơ sở đề xuất schema version mới.

## Quan hệ với SPIN-IDS

Vector 54 đặc trưng không phải đầu vào SPIN-IDS và không tự nó tạo khả năng tương thích SPIN. Nó phục vụ nhánh flow-based của MVP.

Khả năng bổ sung SPIN nằm ở `nids.packet_sequence.v1`, nơi lưu hoặc tham chiếu raw frame, header/payload ranges, thứ tự packet, hướng forward/reverse và signed delta time. Một adapter SPIN có version riêng sẽ chọn byte, padding, ánh xạ hướng và chuẩn hóa delta time từ dữ liệu đó. Feature engine 54 chiều và packet-sequence storage là hai nhánh song song, không thay thế nhau.

## Vector TCP tính tay tại F3

Trace TCP tham chiếu có chín packet. Bảng dưới đây trình bày ba packet đầu; timestamp được đổi thành độ lệch microsecond so với packet đầu để dễ kiểm tra. Dữ liệu gốc trong fixture vẫn giữ `int64` nanosecond.

| Packet | Timestamp tương đối | Chiều | Wire | Payload | Header | TTL | Window | Cờ |
|---:|---:|---|---:|---:|---:|---:|---:|---|
| 1 | 0 | forward | 60 | 0 | 54 | 64 | 1000 | SYN |
| 2 | 1000 | reverse | 74 | 0 | 54 | 63 | 2000 | SYN, ACK |
| 3 | 500 | forward | 100 | 40 | 60 | 62 | 1500 | ACK |

Các phép tính chính:

- watermark là `max(0, 1000, 500) = 1000`, nên `flow_age_us = 1000`;
- flow IAT là `[1000, -500]`, nên min `-500`, max `1000`, mean `250`, độ lệch chuẩn population `750`;
- forward IAT là `[500]`, nên mean `500`, độ lệch chuẩn `0`; reverse chưa có IAT nên cả mean và độ lệch chuẩn bằng `0`;
- wire length là `[60, 74, 100]`, mean `78`, độ lệch chuẩn `sqrt(824/3) = 16.57307052620807`;
- packet rate là `3 × 1,000,000 / 1000 = 3000`; wire-byte rate là `234 × 1,000,000 / 1000 = 234000`;
- tỷ lệ packet hai chiều là `2/1 = 2`; tỷ lệ wire byte là `160/74 = 2.1621621621621623`;
- chuỗi chiều `forward, reverse, forward` đổi chiều hai lần;
- số cờ SYN là `2`, ACK là `2`; FIN, RST và PSH bằng `0`; tỷ lệ SYN/ACK bằng `1`;
- TCP window là `[1000, 2000, 1500]`, mean `1500`, độ lệch chuẩn `408.24829046386304`;
- TTL là `[64, 63, 62]`, mean `63`, độ lệch chuẩn `0.816496580927726`;
- payload length là `[0, 0, 40]`, mean `13.333333333333334`, độ lệch chuẩn `18.856180831641268`;
- header length là `[54, 54, 60]`, mean `56`, độ lệch chuẩn `2.8284271247461903`.

Vector đầy đủ theo đúng chỉ số Schema v1:

```text
 0– 6: [1000.0, 3, 2, 1, 234, 160, 74]
 7–14: [60, 100, 78.0, 16.57307052620807, 80.0, 20.0, 74.0, 0.0]
15–22: [-500.0, 1000.0, 250.0, 750.0, 500.0, 0.0, 0.0, 0.0]
23–27: [3000.0, 234000.0, 2.0, 2.1621621621621623, 2]
28–37: [2, 2, 0, 0, 0, 1.0, 1000, 2000, 1500.0, 408.24829046386304]
38–41: [62, 64, 63.0, 0.816496580927726]
42–51: [1, 1, 0, 40, 40, 0, 0, 40, 13.333333333333334, 18.856180831641268]
52–53: [56.0, 2.8284271247461903]
```

Packet thứ chín mang FIN và tạo F9 trước khi flow đóng theo hợp đồng T1.4. Các vector TCP F5, F7 và F9 đầy đủ nằm trong fixture.

## Trường hợp biên UDP tại F3

Trace UDP có timestamp tương đối `[0, 0, -500]` microsecond và chuỗi chiều `forward, forward, reverse`. Watermark vẫn bằng timestamp đầu, vì vậy tuổi flow, packet rate và wire-byte rate đều bằng 0. Flow IAT là `[0, -500]`, có mean `-250` và độ lệch chuẩn `250`.

UDP không có cờ hay window TCP, nên toàn bộ chỉ số 28–37 bằng 0. Trace này cũng khóa hành vi nhóm chỉ có một mẫu: reverse packet length mean bằng `80` và độ lệch chuẩn bằng `0`; reverse IAT chưa tồn tại nên mean và độ lệch chuẩn đều bằng `0`.

## Fixture và tiêu chí đối chiếu

`tests/fixtures/feature-vector-v1.json` chứa packet facts đã phân tích sẵn và năm vector cố định:

| Trace | Checkpoint | Số vector |
|---|---|---:|
| TCP hai chiều, 9 packet | F3, F5, F7, F9 | 4 |
| UDP hai chiều, 3 packet | F3 | 1 |

Fixture không phải PCAP, không triển khai parser thứ hai và không phải dữ liệu huấn luyện. Nó không mang label benign/attack. Nó là oracle số học cho bộ máy tính đặc trưng ở T2.3. Khi T2.3 được triển khai, cùng các packet facts phải tạo ra vector theo đúng thứ tự này.

Trace TCP tồn tại để kiểm tra cờ/window TCP, hai chiều, payload rỗng/không rỗng, IAT âm và FIN tại F9. Trace UDP tồn tại để khóa nhóm TCP về 0, kiểm tra một chiều chưa đủ hai mẫu và rate bằng 0 khi tuổi flow không dương. Năm vector này tuyệt đối không được trộn vào train, validation hoặc test dataset của model.

Các giá trị có kiểu logic nguyên được so sánh chính xác. Các giá trị `float64` tính từ mean, độ lệch chuẩn, rate và tỷ lệ dùng `abs_tol = 1e-12` và `rel_tol = 1e-12` khi đối chiếu với oracle độc lập. Dung sai này không nới lỏng yêu cầu đồng nhất PCAPNG–DPDK: hai adapter phải đưa cùng `PacketView` vào cùng một bộ máy C++, nên parity giữa chúng vẫn phải so sánh bit-for-bit ở task tích hợp phù hợp.

Raw frame, header, payload và delta time có dấu vẫn được giữ theo Packet Sequence Schema v1 để phục vụ adapter SPIN-IDS có version riêng. Chúng không được trộn vào vector 54 đặc trưng và cũng không bị fixture T1.5 thay thế.

## Trạng thái kiểm chứng khoa học

T1.5 chỉ chứng minh schema xác định, có thể tính lặp lại và có oracle số học. T1.5 chưa chứng minh 54 đặc trưng là tối ưu, chưa chứng minh từng đặc trưng có predictive value và chưa chứng minh khả năng tổng quát sang mạng VMware của người dùng.

Trước khi đóng băng đầu vào từng model, quy trình đánh giá phải thực hiện trên training partition và sau đó kiểm tra trên split tách biệt:

1. Phát hiện đặc trưng hằng, gần hằng, không hữu hạn hoặc phân bố lỗi tại từng checkpoint.
2. Đo tương quan và quan hệ đại số; tạo feature mask riêng cho HBOS nếu các chiều tương quan làm lặp bằng chứng.
3. So sánh tập đầy đủ với tập rút gọn cho Isolation Forest và Random Forest.
4. Chạy ablation cho nhóm TTL, payload, header, TCP window và port category nếu port category được đề xuất lại.
5. Báo cáo known recall, unknown recall, FPR, alerts/hour và độ ổn định giữa F3/F5/F7/F9 trên split theo ngày/capture.

Chỉ kết quả thực nghiệm này mới trả lời đặc trưng nào thực sự hữu ích cho model. Schema v1 hiện tại là hợp đồng quan sát tái lập để tạo dữ liệu cho quá trình đó.
