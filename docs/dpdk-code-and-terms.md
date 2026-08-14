# DPDK trong đồ án — giải thích cho người đọc báo cáo

Tài liệu này viết cho **giảng viên phản biện và người đọc không cần đọc mã nguồn**. Mục tiêu: sau khi đọc, người đọc trả lời được ba câu — DPDK làm gì trong đồ án, phần đó gồm những gì, và có bằng chứng nào cho thấy nó chạy đúng.

Chi tiết dành cho lập trình viên nằm ở [Phụ lục kỹ thuật](#phụ-lục-kỹ-thuật) cuối tài liệu. Sơ đồ kèm theo: [`docs/dpdk-architecture.mmd`](dpdk-architecture.mmd).

---

## 1. Đọc trong 60 giây

Hệ thống phát hiện xâm nhập của đồ án phải **xem được mọi gói tin đi qua card mạng, theo thời gian thực**. Cách thông thường là nhờ hệ điều hành chép gói lên cho chương trình. Cách đó đơn giản nhưng chậm, và khi lưu lượng lớn thì gói bị rơi — mà gói rơi nghĩa là cuộc tấn công có thể lọt.

DPDK giải quyết chuyện đó bằng cách **cho chương trình đọc thẳng bộ nhớ của card mạng**, bỏ qua hệ điều hành. Đổi lại, chương trình phải tự lo mọi thứ: xin bộ nhớ, cấu hình card, tự chạy vòng lặp lấy gói.

Trong đồ án, phần "tự lo mọi thứ" đó nằm gọn trong **8 tệp mã nguồn C++**, khoảng 5.400 dòng. Ba nhóm:

| Nhóm | Số tệp | Việc chính |
|------|--------|-----------|
| Bộ chuyển đổi | 2 | Dịch gói tin theo định dạng DPDK sang định dạng chung của hệ thống |
| Chương trình chạy thật | 3 | Điều khiển card mạng, chạy vòng lặp thu gói, phát cảnh báo |
| Chương trình kiểm chứng | 3 | Chứng minh đường DPDK cho kết quả giống hệt đường đọc tệp PCAP |

Điểm quan trọng nhất về mặt thiết kế: **chỉ đúng 1 tệp trong toàn bộ phần lõi biết đến sự tồn tại của DPDK**. Nhờ vậy, phần phân tích gói tin, gom luồng và trích đặc trưng dùng chung cho cả hai chế độ — chạy thật từ card mạng, và chạy lại từ tệp PCAP đã lưu. Đây không phải khẳng định suông: có hai bài kiểm thử tự động so sánh kết quả hai đường và bắt buộc phải trùng khớp.

---

## 2. DPDK là gì, và tại sao đồ án cần nó

### 2.1 Vấn đề

Bình thường, khi một gói tin tới card mạng, hệ điều hành sẽ nhận nó, chép vào bộ nhớ của mình, rồi chép thêm lần nữa sang chương trình nào đang cần. Mỗi gói tin gây một lần "ngắt" — tức là CPU đang làm việc khác phải dừng lại để xử lý. Với lưu lượng lớn, số lần dừng đó nhiều đến mức CPU dành phần lớn thời gian cho việc chuyển ngữ cảnh chứ không phải phân tích.

### 2.2 Cách DPDK làm khác

| Cách thông thường | Cách của DPDK |
|-------------------|---------------|
| Card mạng báo ngắt, CPU dừng việc để nhận gói | CPU chủ động hỏi card "có gói mới không?" liên tục — gọi là **polling** |
| Gói được chép 2 lần: card → hệ điều hành → chương trình | Card ghi thẳng vào vùng nhớ chương trình đọc được — gọi là **kernel bypass** |
| Lấy từng gói một | Lấy cả nắm gói mỗi lần hỏi — gọi là **burst** |
| Hệ điều hành cấp phát bộ nhớ khi cần | Xin sẵn một bể bộ nhớ lớn từ đầu, dùng đi dùng lại — gọi là **mempool** |

Đánh đổi rất rõ: **được tốc độ, mất tính tiện lợi**. Card mạng đã giao cho DPDK thì hệ điều hành không dùng được nữa. Vì vậy máy cảm biến trong đồ án dùng **hai card riêng biệt**: card `ens33` để quản trị (giữ cho hệ điều hành, để còn đăng nhập điều khiển từ xa được), card `ens160` giao hẳn cho DPDK để thu lưu lượng. Nếu chỉ có một card, lúc DPDK chiếm card là mất luôn kết nối tới máy.

### 2.3 Chế độ chỉ nghe, không nói

Cảm biến được cấu hình **chỉ nhận, không gửi** (RX-only, không TX). Nghĩa là nó quan sát lưu lượng chứ không nằm chắn giữa đường truyền. Hệ quả cần nêu rõ khi bảo vệ: hệ thống **phát hiện và cảnh báo**, không **chặn**. Muốn chặn thì phải đặt cảm biến ở vị trí khác và bật đường gửi — đó là hướng phát triển, không phải phạm vi đồ án hiện tại.

---

## 3. Tám tệp mã nguồn

Mỗi tệp dưới đây trình bày theo ba câu hỏi: **nó làm gì**, **vì sao cần nó**, **nếu bỏ đi thì sao**.

Lưu ý chung: toàn bộ 8 tệp chỉ được biên dịch khi bật tùy chọn `NIDS_BUILD_DPDK`. Mặc định tùy chọn này tắt, nên người muốn chạy thử phần offline (đọc tệp PCAP) không cần cài DPDK.

### Nhóm A — Bộ chuyển đổi (2 tệp, ~106 dòng)

Đây là phần nhỏ nhất nhưng quan trọng nhất về mặt kiến trúc.

#### A1. `cpp/include/nids/dpdk_adapter.hpp` — bản cam kết

**Nó làm gì.** Đây là "bản hợp đồng": ghi rõ bộ chuyển đổi nhận vào cái gì, trả ra cái gì, và hỏng thì báo lỗi ra sao. Chưa có mã thực thi.

**Vì sao cần.** Tách phần cam kết khỏi phần thực thi cho phép các tệp khác dùng bộ chuyển đổi mà không phải kéo theo toàn bộ thư viện DPDK. Tệp này khai báo kiểu dữ liệu của DPDK theo kiểu "có một thứ tên là như vậy" mà không cần biết bên trong nó ra sao.

**Điểm đáng chú ý.** Kết quả trả về bắt buộc phải là **một trong hai**: gói tin hợp lệ, hoặc mô tả lỗi. Không có trạng thái thứ ba kiểu "trả gói tin nhưng lỗi một phần". Người gọi bị ngôn ngữ lập trình ép phải xử lý cả hai nhánh, không bỏ sót lỗi được.

Hai loại lỗi được định nghĩa:

| Lỗi | Xảy ra khi | Ghi kèm gì |
|-----|-----------|-----------|
| Bộ đệm tạm quá nhỏ | Gói tin bị chia thành nhiều mảnh, mà chỗ chứa tạm không đủ để ghép lại | Cần bao nhiêu, đang có bao nhiêu |
| Chuỗi mảnh không hợp lệ | Thông tin độ dài gói tin mâu thuẫn với dữ liệu thực có | Độ dài gói tin |

Việc ghi kèm "cần bao nhiêu / đang có bao nhiêu" khiến lỗi này chẩn đoán được ngay, không phải đoán.

#### A2. `cpp/src/dpdk_adapter.cpp` — bộ chuyển đổi (65 dòng)

**Nó làm gì.** Nhận một gói tin ở định dạng riêng của DPDK, trả ra gói tin ở định dạng chung mà phần còn lại của hệ thống hiểu.

**Vì sao cần.** DPDK lưu gói tin trong cấu trúc gọi là **mbuf**. Rắc rối ở chỗ một gói tin có thể nằm gọn trong một mbuf, cũng có thể bị **chia thành nhiều mảnh nối nhau** (khi gói lớn hoặc bộ nhớ phân mảnh). Phần phân tích gói tin phía sau chỉ muốn nhận một dải byte liền mạch, không muốn biết chuyện mảnh miếc.

**Cách xử lý — hai nhánh:**

1. **Gói nằm liền một khối** → trỏ thẳng vào đó, không chép gì cả. Đây là trường hợp phổ biến và nhanh nhất, gọi là **zero-copy**.
2. **Gói bị chia mảnh** → ghép các mảnh vào một vùng nhớ tạm rồi mới trả ra. Chậm hơn, nhưng vẫn đúng. Bộ chuyển đổi đánh dấu rõ trường hợp này để thống kê được tần suất.

**Nếu bỏ đi thì sao.** Phần lõi phân tích sẽ phải tự biết về DPDK. Mà như vậy thì không thể chạy lại cùng đoạn mã đó trên tệp PCAP nữa — mất luôn khả năng so sánh đối chứng, tức mất phần lớn giá trị kiểm chứng của đồ án.

> **Đây là tệp duy nhất trong thư viện lõi có nhắc tới DPDK.** Toàn bộ phần phân tích gói tin, bảng luồng và trích đặc trưng phía sau nó không biết DPDK tồn tại. Mục 4 giải thích vì sao điều này quan trọng.

### Nhóm B — Chương trình chạy thật (3 tệp, ~3.730 dòng)

#### B1. `cpp/apps/nids_dpdk_live.cpp` — cảm biến trực tuyến (1.134 dòng)

**Nó làm gì.** Đây là chương trình chạy trên máy cảm biến khi demo. Trình tự:

1. Khởi động môi trường DPDK, xin cấp hugepage và bộ nhớ
2. Tạo bể chứa gói tin (8.192 chỗ)
3. Cấu hình card mạng, bật chế độ nghe tất cả (promiscuous)
4. Vào vòng lặp: hỏi card lấy một nắm gói → chuyển đổi → phân tích → gom vào luồng → tính đặc trưng → đến mốc F9 thì đưa mô hình chấm điểm → nếu vượt ngưỡng thì in cảnh báo JSON → trả bộ nhớ về bể
5. Khi dừng: đóng card, trả hugepage, in bảng thống kê

**Chi tiết đáng nói khi phản biện.** Chương trình đọc hai chỉ số từ card mạng sau mỗi lượt chạy:

- **`imissed`** — số gói card nhận được nhưng phải bỏ vì chương trình lấy không kịp
- **`rx_nombuf`** — số lần hết chỗ trong bể chứa

Hai chỉ số này quan trọng vì chúng **tách bạch hai loại thất bại hoàn toàn khác nhau**: mô hình đoán sai (vấn đề học máy) và gói tin không tới được mô hình (vấn đề đường thu nhận). Không có chúng thì một lần bỏ sót tấn công không quy được trách nhiệm. Trong bài chạy ổn định 30 phút với 1.800.000 gói tin, cả hai đều bằng 0.

#### B2. `cpp/apps/nids_t91_terminal_live.cpp` — cảm biến T9.1 (2.145 dòng, lớn nhất repo)

**Nó làm gì.** Cùng cơ chế thu gói như B1, nhưng phục vụ chiến dịch đo T9.1 và bổ sung một lớp **bằng chứng vận hành**.

**Vì sao cần lớp bằng chứng.** Một kết quả đo chỉ có giá trị nếu chứng minh được nó sinh ra từ đúng mô hình, đúng cấu hình, đúng lượt chạy. Chương trình này vì vậy nhận thêm mã định danh lượt chạy, mã băm SHA-256 của gói mô hình và của bản hợp đồng cấu hình, rồi ghi tất cả vào biên nhận cùng với kết quả.

**Nói ngắn gọn:** nếu ai đó thay mô hình rồi báo cáo lại con số cũ, mã băm sẽ không khớp và phát hiện được ngay. Đây là cơ chế chống nhầm lẫn, không phải chống gian lận — nhưng tác dụng thực tế là giữ cho các con số trong chương 3 truy nguyên được về đúng lượt chạy đã sinh ra chúng.

**Vì sao tệp này to.** Phần lớn 2.145 dòng là xử lý vòng đời và trạng thái lỗi: đợi tín hiệu bắt đầu, hết giờ, dừng có thời gian ân hạn, ghi biên nhận cả khi chạy hỏng. Phần logic phát hiện thực chất nhỏ hơn nhiều — nó nằm ở các tệp lõi dùng chung.

#### B3. `cpp/apps/dpdk_adapter_probe.cpp` — chương trình dò kiểm chứng (451 dòng)

**Nó làm gì.** Chạy toàn bộ đường thu nhận DPDK nhưng **thay card mạng thật bằng card ảo** do phần mềm tạo ra.

**Vì sao cần.** Kiểm thử tự động phải chạy được trên máy không có card mạng chuyên dụng, không có quyền quản trị. Card ảo cho phép bơm vào một tập gói tin đã biết trước, rồi so kết quả thu được với kỳ vọng.

Chương trình còn bật cơ chế **bắt lại gói tin ngay bên trong DPDK** (pdump) — tức là ghi lại chính những gói đã đi qua để đối chiếu. Đây là bằng chứng cho khẳng định "đường thu nhận không làm mất hoặc biến dạng gói".

### Nhóm C — Kiểm chứng (2 tệp, ~1.550 dòng)

Đây là phần trả lời câu hỏi phản biện nặng nhất: *"Làm sao biết kết quả đo trên DPDK và kết quả đo trên tệp PCAP là so sánh được với nhau?"*

#### C1. `cpp/tests/dpdk_adapter_test.cpp` — kiểm hai nhánh chuyển đổi (647 dòng)

**Nó kiểm gì.** Bộ chuyển đổi có hai nhánh: gói liền khối (nhanh, không chép) và gói chia mảnh (chậm, phải ghép). Bài kiểm thử **cố tình dựng ra gói tin bị chia mảnh** rồi khẳng định: cùng một nội dung, đi qua nhánh nào cũng phải cho ra kết quả giống hệt.

**Vì sao quan trọng.** Nhánh nhanh là nhánh chạy hầu hết thời gian nên được chú ý; nhánh chậm hiếm gặp nên dễ có lỗi âm thầm. Bài kiểm thử này ép cả hai nhánh phải đúng. Thời gian chạy: 10 giây.

#### C2. `cpp/tests/core_acceptance_test.cpp` — kiểm parity PCAP ↔ DPDK (906 dòng)

**Nó kiểm gì.** Bơm **cùng một tập gói tin** qua hai đường hoàn toàn khác nhau — một đường qua DPDK, một đường qua thư viện đọc tệp PCAP — rồi so sánh **cả 54 giá trị đặc trưng** sinh ra. Sai một giá trị là bài kiểm thử đỏ.

**Vì sao đây là bài kiểm thử quan trọng nhất trong nhóm.** Báo cáo có một khẳng định trọng yếu: *"cùng một prefix phải sinh cùng một vector bất kể nguồn thu nhận"*. Đây chính là bài kiểm thử biến khẳng định đó thành thứ máy tự kiểm được mỗi lần biên dịch. Nhờ nó mà:

- Mô hình huấn luyện trên dữ liệu offline dùng được cho suy luận online
- Kết quả offline và online so sánh trực tiếp được
- Chênh lệch giữa hai chế độ, nếu có, không thể quy cho đường thu nhận

Thời gian chạy: 15 giây.

### Tệp thứ tám

#### `cpp/include/nids/latency_samples.hpp` — đo độ trễ

**Nó làm gì.** Gom các mẫu thời gian xử lý rồi tính phân vị p50, p95, p99 — tức là "một nửa số gói xử lý nhanh hơn con số này", "95% nhanh hơn con số này".

**Vì sao dùng phân vị chứ không dùng trung bình.** Với hệ thống thời gian thực, trung bình che giấu vấn đề. Một hệ thống trung bình 1 mili-giây nghe rất tốt, nhưng nếu 1% số gói mất 500 mili-giây thì cảnh báo cho những gói đó đến quá muộn. Phân vị p99 phơi bày đúng phần đuôi đó.

**Ghi chú.** Tệp này phục vụ vòng lặp DPDK nhưng không gọi hàm DPDK nào — nên bài kiểm thử của nó chạy được trên máy không cài DPDK.

---

## 4. Điểm thiết kế đáng bảo vệ nhất

Toàn bộ phần trên có thể tóm lại thành một câu:

> **DPDK bị nhốt sau một tệp 65 dòng. Mọi thứ phía sau nó không biết DPDK tồn tại.**

Vì sao đây là điểm mạnh chứ không phải chi tiết vụn:

| Nếu không tách ranh giới | Vì có tách ranh giới |
|--------------------------|----------------------|
| Muốn kiểm thử phải có card mạng thật và quyền quản trị | Kiểm thử chạy được trên máy thường |
| Không thể chạy lại cùng đoạn mã trên tệp PCAP | Chạy lại được, nên có đối chứng |
| Không biết chênh lệch offline/online do đâu | Có bài kiểm thử chứng minh không do đường thu nhận |
| Đổi sang thư viện thu gói khác phải viết lại nhiều | Chỉ viết bộ chuyển đổi mới, ~65 dòng |

Ràng buộc kèm theo, nói cho trung thực: thêm một trường dữ liệu vào định dạng gói tin chung thì **phải sửa cả hai bộ chuyển đổi**. Nếu chỉ sửa một bên, bài kiểm thử parity sẽ đỏ. Đó là hành vi mong muốn — nó chặn việc hai đường trôi lệch nhau theo thời gian.

---

## 5. Thuật ngữ

### 5.1 Đã có trong bảng viết tắt của báo cáo

Cột cuối là thứ bảng trong Word không có: **giải thích bằng lời thường**.

| Viết tắt | Từ đầy đủ | Nói bằng lời thường |
|----------|-----------|---------------------|
| DPDK | Data Plane Development Kit | Bộ thư viện cho phép chương trình đọc thẳng card mạng, bỏ qua hệ điều hành, để xử lý gói tin nhanh hơn |
| EAL | Environment Abstraction Layer | Lớp khởi động của DPDK: xin bộ nhớ, gán CPU, dò thiết bị. Chương trình nào dùng DPDK cũng phải gọi nó trước tiên |
| NIC | Network Interface Card | Card mạng |
| DMA | Direct Memory Access | Cho phép card mạng tự ghi vào bộ nhớ máy tính, không cần CPU đứng ra chép |
| VFIO | Virtual Function I/O | Cơ chế của Linux cho phép giao một thiết bị cho chương trình người dùng điều khiển một cách an toàn |
| RX | Receive | Chiều nhận của card mạng |
| TX | Transmit | Chiều gửi. **Đồ án không dùng** — cảm biến chỉ nghe |
| PCAP | Packet Capture | Định dạng tệp lưu lại gói tin đã bắt được, để phân tích lại sau |
| pps | packets per second | Số gói tin mỗi giây — đơn vị đo tốc độ xử lý |
| RSS | Resident Set Size | Lượng bộ nhớ RAM chương trình đang thực sự chiếm |
| p50/p95/p99 | percentile | Phân vị: p99 = 99% số lần xử lý nhanh hơn con số này |

> ### ⚠ Điểm dễ bị hỏi vặn: chữ RSS
>
> Trong tài liệu DPDK nói chung, **RSS** hầu như luôn có nghĩa **Receive Side Scaling** — kỹ thuật chia gói tin ra nhiều hàng đợi để nhiều CPU cùng xử lý.
>
> Báo cáo này dùng RSS theo nghĩa **Resident Set Size** (bộ nhớ chiếm dụng), và điều đó **đúng với ngữ cảnh đo hiệu năng**.
>
> Cảm biến của đồ án chạy **một hàng đợi nhận duy nhất** và **không** dùng Receive Side Scaling. Nếu bị hỏi, đó là câu trả lời. Cân nhắc ghi rõ "RSS (bộ nhớ)" ở lần xuất hiện đầu trong chương 3 để tránh hiểu nhầm.

### 5.2 Xuất hiện trong thân báo cáo nhưng chưa có trong bảng viết tắt

Đây là danh sách **nên cân nhắc bổ sung vào bảng viết tắt hoặc chú thích lần đầu xuất hiện**. Người phản biện không chuyên về mạng tốc độ cao sẽ vấp đúng những từ này.

| Thuật ngữ | Nói bằng lời thường | Có trong báo cáo ở |
|-----------|---------------------|--------------------|
| mbuf | Hộp chứa một gói tin trong DPDK. Một gói có thể nằm trong một hộp, hoặc nhiều hộp nối nhau | Chương 2, mục thu nhận |
| mempool | Kho hộp chứa xin sẵn từ đầu, dùng xong trả lại kho thay vì cấp phát mới. Đồ án dùng 8.192 hộp | Phụ lục B |
| hugepage | Trang bộ nhớ cỡ lớn (2 MiB thay vì 4 KiB). Ít trang hơn nghĩa là máy tra địa chỉ nhanh hơn, và card mạng ghi trực tiếp vào được | Chương 2, Phụ lục B |
| PMD (Poll Mode Driver) | Trình điều khiển kiểu "hỏi liên tục" thay vì "chờ được gọi" | Chương 1 |
| polling mode | Chế độ CPU chủ động hỏi card có gói mới không, thay vì chờ card báo ngắt. Tốn CPU nhưng độ trễ thấp và ổn định | Chương 1 |
| burst | Lấy cả nắm gói mỗi lần hỏi thay vì từng gói, để chia đều chi phí gọi hàm | Chương 2 |
| zero-copy | Đọc thẳng gói tin tại chỗ nó nằm, không chép sang nơi khác | Chương 2 |
| kernel bypass | Gói tin đi thẳng từ card mạng lên chương trình, không qua hệ điều hành | Chương 1 |
| vdev | Thiết bị mạng ảo do phần mềm tạo ra, dùng để kiểm thử khi không có card thật | Kịch bản kiểm thử |
| lcore | Một nhân CPU logic mà DPDK gắn cố định luồng xử lý vào | Phụ lục B |
| memory channel | Số kênh bộ nhớ khai báo cho DPDK để nó trải dữ liệu ra cho đều | Phụ lục B |
| promiscuous | Chế độ card nhận cả gói không gửi cho mình. Bắt buộc phải bật, vì cảm biến cần nghe lưu lượng của máy khác | Phụ lục B |
| MTU | Kích thước gói tin lớn nhất card chấp nhận | Phụ lục B |
| port_imissed | Số gói card nhận được nhưng phải bỏ vì chương trình lấy không kịp | Chương 2, chương 3 |
| port_rx_nombuf | Số lần hết hộp chứa để đựng gói mới | Chương 2, chương 3 |

### 5.3 Các khối phía sau đường thu nhận

| Tên trong báo cáo | Nói bằng lời thường |
|-------------------|---------------------|
| Packet Parser | Bóc tách gói tin: đọc địa chỉ, cổng, giao thức từ chuỗi byte thô |
| Flow Table | Gom các gói cùng một cuộc trao đổi thành một "luồng" hai chiều |
| Feature Engine | Tính 54 con số mô tả đặc điểm của luồng để đưa cho mô hình |
| F3 / F5 / F7 / F9 | Các mốc chấm điểm sau khi luồng có 3, 5, 7 hoặc 9 gói — cho phép phát hiện sớm, không cần chờ luồng kết thúc |
| ONNX | Định dạng chuẩn để lưu mô hình học máy, cho phép huấn luyện bằng Python rồi chạy bằng C++ |
| HBOS | Thuật toán phát hiện bất thường dựa trên biểu đồ tần suất — dùng cho nhánh tấn công chưa biết |
| RF (Random Forest) | Mô hình cây quyết định tổ hợp — dùng cho nhánh tấn công đã biết |
| BUNDLE | Gói mô hình đóng kín: tiền xử lý, mô hình và ngưỡng khóa lại thành một khối không đổi |
| RECEIPT | Biên nhận: tệp ghi lại một lượt chạy đã dùng cấu hình gì và ra kết quả gì |
| LIVE / OFFLINE | Chạy trực tuyến từ card mạng / chạy lại từ tệp PCAP đã lưu |

---

## 6. Cấu hình thực tế

Các giá trị dưới đây lấy từ tệp cấu hình có biên nhận trong repo, không phải giá trị giả định.

| Tham số | Giá trị | Nghĩa |
|---------|---------|-------|
| Chế độ | Chỉ nhận, không gửi | Cảm biến quan sát, không chặn lưu lượng |
| Hugepage | 128 trang × 2 MiB = 256 MiB | Bộ nhớ dành riêng cho card ghi trực tiếp |
| Bộ nhớ DPDK | 256 MiB | Tổng bộ nhớ cấp cho môi trường DPDK |
| Nhân CPU | 0–1 (T9.1 dùng nhân 0) | Luồng xử lý gắn cố định vào nhân này |
| Kênh bộ nhớ | 2 | Khớp với phần cứng máy ảo |
| Số hộp chứa gói | 8.192 | Đủ đệm khi lưu lượng dồn |
| Hàng đợi nhận | 1 | Một hàng đợi duy nhất — không chia tải nhiều CPU |
| Cổng | 0 | Card dữ liệu duy nhất |
| MTU (T9.1) | 9.000 | Chấp nhận cả gói cỡ lớn |
| Nghe tất cả | Bật | Bắt buộc, để nghe lưu lượng của máy khác |
| Card dữ liệu | `ens160` (vmxnet3) → giao cho DPDK | Card bị DPDK chiếm quyền |
| Card quản trị | `ens33` → giữ cho hệ điều hành | Giữ kết nối điều khiển |

**Vì sao hai card:** khi DPDK chiếm `ens160`, hệ điều hành mất card đó. Nếu đó là card duy nhất thì mất luôn kết nối SSH tới máy cảm biến, không thao tác được nữa.

---

## 7. Bằng chứng: sáu bài kiểm thử tự động

Đây là phần trả lời cho câu "có gì chứng minh nó chạy đúng". Tất cả chạy tự động bằng một lệnh.

| Bài kiểm thử | Thời gian | Chứng minh điều gì |
|--------------|-----------|--------------------|
| Parity hai nhánh chuyển đổi | 10 giây | Gói liền khối và gói chia mảnh cho kết quả giống hệt |
| **Parity PCAP ↔ DPDK** | 15 giây | **Hai đường thu nhận sinh cùng 54 đặc trưng — bài quan trọng nhất** |
| Kiểm chứng thu nhận | 45 giây | Chương trình dò bắt lại đúng những gói đã bơm vào |
| Chạy thật trên card ảo | 300 giây | 9 gói → 1 mốc F9 → 1 cảnh báo, đúng như kỳ vọng |
| Vòng đời chạy liên tục | 60 giây | Chạy dài không rò bộ nhớ, dừng sạch |
| Vòng đời T9.1 | 120 giây | Cảm biến T9.1 khởi động, chạy, ghi biên nhận đầy đủ |

Bốn bài cuối cần có sẵn gói mô hình đã dựng. Không có gói mô hình thì hệ thống biên dịch bỏ qua chúng chứ không báo lỗi — điều này **cần nói rõ khi demo**, vì "không thấy bài kiểm thử nào đỏ" không đồng nghĩa "tất cả bài kiểm thử đã chạy".

Lệnh chạy:

```bash
cmake -S . -B build -DNIDS_BUILD_DPDK=ON -DNIDS_BUILD_MODEL_RUNTIME=ON \
      -DNIDS_T52_STAGED_BUNDLE=/duong/dan/toi/bundle
cmake --build build
ctest --test-dir build -R 'nids_dpdk|adapter_feature_parity'
```

---

## 8. Câu hỏi phản biện có thể gặp

**"Vì sao không dùng libpcap cho đơn giản?"**
libpcap đi qua hệ điều hành nên có ngắt và có sao chép; ở lưu lượng cao thì rơi gói. Đồ án vẫn giữ đường libpcap — nhưng dùng làm đường đối chứng để kiểm tra tính đúng đắn, không phải đường chạy thật. Cần nói rõ: đồ án **chưa** đo so sánh trực tiếp hai đường trên cùng phần cứng, nên chưa định lượng được ưu thế bằng số. Đây là hạn chế đã ghi trong chương kết luận.

**"Có gì chứng minh DPDK không làm sai lệch kết quả?"**
Bài kiểm thử parity PCAP ↔ DPDK: cùng gói tin vào, so đủ 54 đặc trưng, sai một giá trị là đỏ. Chạy tự động mỗi lần biên dịch.

**"Chạy trên máy ảo VMware thì con số hiệu năng có ý nghĩa gì?"**
Ý nghĩa hạn chế, và báo cáo nêu rõ điều đó. Con số chứng minh **hệ thống vận hành được và không rơi gói trong điều kiện thử nghiệm**, không chứng minh throughput đạt mức nào trên phần cứng thật.

**"Vì sao chỉ một hàng đợi nhận?"**
Vì lưu lượng thử nghiệm nằm trong khả năng của một nhân CPU, và một hàng đợi giữ cho thứ tự gói tin đơn giản — quan trọng với việc gom luồng và tính đặc trưng theo thời gian. Mở rộng nhiều hàng đợi là hướng phát triển, kèm theo phải xử lý chuyện gói cùng luồng rơi vào các hàng đợi khác nhau.

**"Hệ thống có chặn được tấn công không?"**
Không, ở phạm vi hiện tại. Cảm biến cấu hình chỉ nhận, không gửi, nên nó phát hiện và cảnh báo chứ không nằm chắn đường truyền.

---

## Phụ lục kỹ thuật

Phần này dành cho người đọc mã nguồn. Có thể bỏ qua.

### P1. Bảng tệp

| Tệp | Dòng | Đích CMake |
|-----|------|-----------|
| `cpp/include/nids/dpdk_adapter.hpp` | 41 | `nids_dpdk` (PUBLIC) |
| `cpp/src/dpdk_adapter.cpp` | 65 | `nids_dpdk` |
| `cpp/apps/dpdk_adapter_probe.cpp` | 451 | `nids_dpdk_adapter_probe` |
| `cpp/apps/nids_dpdk_live.cpp` | 1.134 | `nids_dpdk_live` |
| `cpp/apps/nids_t91_terminal_live.cpp` | 2.145 | `nids_t91_terminal_live` |
| `cpp/tests/dpdk_adapter_test.cpp` | 647 | `nids_dpdk_adapter_test` |
| `cpp/tests/core_acceptance_test.cpp` | 906 | `nids_core_acceptance_test` |
| `cpp/include/nids/latency_samples.hpp` | — | header-only |

### P2. Hợp đồng bộ chuyển đổi

```cpp
[[nodiscard]] DpdkAdapterResult adapt_mbuf(
    const rte_mbuf& mbuf,
    std::int64_t timestamp_ns,
    ClockDomain clock_domain,
    std::span<std::uint8_t> scratch) noexcept;
```

`DpdkAdapterResult = std::variant<DpdkPacketEvent, DpdkAdapterError>`. Mã lỗi: `scratch_buffer_too_small`, `invalid_mbuf_chain`. Header chỉ forward-declare `struct rte_mbuf`.

Ràng buộc vòng đời (ghi trong comment nguồn): span trong `PacketView` chỉ hợp lệ khi mbuf và scratch chưa bị thay đổi.

### P3. Header DPDK theo tệp

| Header | Dùng ở | Mục đích |
|--------|--------|----------|
| `rte_mbuf.h` | adapter, live, t91, probe, 2 test | Buffer gói tin |
| `rte_eal.h` | live, t91, probe, 2 test | Khởi tạo, dọn dẹp EAL |
| `rte_ethdev.h` | live, t91, probe, 2 test | Cấu hình port, RX queue, thống kê |
| `rte_errno.h` | live, t91, probe, adapter_test | Mã lỗi và `rte_strerror` |
| `rte_lcore.h` | live, t91, probe, adapter_test | `rte_socket_id` cho cấp phát NUMA-aware |
| `rte_ring.h` | probe, adapter_test, acceptance | Ring lockless |
| `rte_eth_ring.h` | probe, adapter_test, acceptance | Ring PMD — port ảo |
| `rte_bus_vdev.h` | adapter_test | Tạo và huỷ thiết bị ảo |
| `rte_pdump.h` | probe | Bắt lại gói làm bằng chứng |

### P4. Hàm DPDK theo nhóm

**EAL** — `rte_eal_init`, `rte_eal_cleanup`, `rte_socket_id`, `rte_errno`, `rte_strerror`

**Ethdev** — `rte_eth_dev_configure`, `rte_eth_rx_queue_setup`, `rte_eth_tx_queue_setup`, `rte_eth_dev_start`, `rte_eth_dev_stop`, `rte_eth_dev_close`, `rte_eth_dev_info_get`, `rte_eth_dev_socket_id`, `rte_eth_dev_set_mtu`, `rte_eth_dev_is_valid_port`, `rte_eth_dev_get_name_by_port`, `rte_eth_dev_get_port_by_name`, `rte_eth_promiscuous_enable`, `rte_eth_promiscuous_get`, `rte_eth_stats_get`

**Đường nóng** — `rte_eth_rx_burst`, `rte_pktmbuf_mtod`, `rte_pktmbuf_is_contiguous`, `rte_pktmbuf_free`

**mbuf / mempool** — `rte_pktmbuf_pool_create`, `rte_pktmbuf_alloc`, `rte_pktmbuf_append`, `rte_pktmbuf_chain`, `rte_pktmbuf_read`, `rte_pktmbuf_pkt_len`, `rte_pktmbuf_data_len`, `rte_mempool_free`

**Ring / vdev / pdump (chỉ dùng khi kiểm thử)** — `rte_ring_create`, `rte_ring_enqueue`, `rte_ring_dequeue`, `rte_ring_free`, `rte_eth_from_rings`, `rte_vdev_init`, `rte_vdev_uninit`, `rte_pdump_init`, `rte_pdump_uninit`

### P5. Ghi chú liên kết

```cmake
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
find_library(DPDK_NET_RING_LIBRARY NAMES rte_net_ring HINTS ${DPDK_LIBRARY_DIRS} REQUIRED)
find_library(DPDK_BUS_VDEV_LIBRARY NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} REQUIRED)
```

`rte_net_ring` và `rte_bus_vdev` phải tìm tường minh vì là plugin driver — `pkg-config libdpdk` không kéo vào. Thiếu chúng thì build qua nhưng port ảo không tồn tại lúc chạy.

### P6. Tên bài kiểm thử trong CTest

`nids_dpdk.adapter_parity` · `nids_core.adapter_feature_parity` · `nids_dpdk.capture_verification` · `nids_demo.dpdk_live_pcap` · `nids_runtime.continuous_lifecycle` · `nids_runtime.terminal_live`
