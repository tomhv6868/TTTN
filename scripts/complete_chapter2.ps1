$ErrorActionPreference = 'Stop'
$OfficeCli = 'C:\Users\xuanq\AppData\Local\OfficeCli\officecli.exe'
$File = 'E:\DATTTN\TTTN\DamMinhLinh_ A03_BCDK1_ChuongII_hoanthien.docx'
$Chapter3 = '/body/p[@paraId=46AB9237]'
$References = '/body/p[@paraId=78AB542F]'
$Appendix = '/body/p[@paraId=169112A9]'

function Add-Para([string]$Text, [string]$Style = 'Normal') {
    $args = @('add', $File, '/body', '--type', 'paragraph', '--before', $Chapter3, '--prop', "text=$Text", '--prop', "style=$Style")
    if ($Style -eq 'Heading2') {
        $args += @('--prop', 'bold=true', '--prop', 'align=justify', '--prop', 'spaceBefore=6pt', '--prop', 'spaceAfter=3pt')
    } else {
        $args += @('--prop', 'align=justify', '--prop', 'font=Times New Roman', '--prop', 'size=13pt', '--prop', 'lineSpacing=1.3x', '--prop', 'firstLineIndent=0.5cm', '--prop', 'spaceAfter=3pt')
    }
    & $OfficeCli @args | Out-Null
}

function Add-Code([string]$Text) {
    & $OfficeCli add $File /body --type paragraph --before $Chapter3 --prop "text=$Text" --prop style=Normal --prop font='Courier New' --prop size=10pt --prop lineSpacing=1x --prop indent=0.5cm --prop spaceBefore=3pt --prop spaceAfter=6pt --prop fill=F2F2F2 | Out-Null
}

function Add-Ref([string]$Text) {
    & $OfficeCli add $File /body --type paragraph --before $Appendix --prop "text=$Text" --prop style=Normal --prop font='Times New Roman' --prop size=13pt --prop lineSpacing=1.3x --prop indent=0.75cm --prop hangingIndent=0.75cm --prop spaceAfter=3pt | Out-Null
}

& $OfficeCli open $File | Out-Null

Add-Para '2.1 Kiến trúc triển khai và luồng xử lý của hệ thống' Heading2
Add-Para 'Chương này mô tả phần đã được triển khai và kiểm chứng trong workspace TTTN: máy Ubuntu đóng vai trò cảm biến DPDK, nhận lưu lượng từ mạng dữ liệu, phân tích packet, gom flow hai chiều, phát sinh các checkpoint F3/F5/F7/F9, trích xuất vector 54 đặc trưng và chuyển vector đã tiền xử lý sang mô hình học máy. Hệ thống tách riêng đường quản trị khỏi đường dữ liệu nhằm tránh mất kết nối khi card dữ liệu được tháo khỏi driver mạng của Linux và gắn với vfio-pci.'
Add-Para 'Cấu hình mẫu của dự án sử dụng VMware Workstation 17. Card quản trị của Ubuntu là ens33 trên VMnet8 (NAT, 192.168.100.0/24), còn card dữ liệu là ens160 trên VMnet1 (host-only, 192.168.252.0/24). Kali phát lưu lượng trên mạng dữ liệu; máy Windows có thể đóng vai trò đích. Chỉ card ens160 được phép binding sang DPDK. Quy tắc này xuất hiện trong config/dpdk-smoke.example.json, config/dpdk-passive.example.json và được các script kiểm tra trước khi thay đổi trạng thái thiết bị.'
Add-Para 'Luồng xử lý thực tế là: rte_eth_rx_burst nhận một burst mbuf; DpdkAdapter chuyển từng mbuf thành khung byte kèm dấu thời gian; PacketParser tạo PacketView; FlowTable chuẩn hóa khóa flow hai chiều và cập nhật trạng thái; FeatureEngine phát vector khi số packet đạt 3, 5, 7 hoặc 9; DetectionPipeline gọi runtime ONNX và ghi cảnh báo JSONL. Cùng PacketView và cùng FeatureEngine cũng được dùng cho đường PCAP, nhờ đó dự án tránh duy trì hai định nghĩa đặc trưng khác nhau.'

Add-Para '2.2 Thiết lập card mạng và môi trường DPDK trên Ubuntu' Heading2
Add-Para 'Mục đích của bước thiết lập là nhận diện chắc chắn card quản trị và card dữ liệu, kiểm tra driver gốc, địa chỉ PCI, IOMMU group và tình trạng route trước khi DPDK chiếm quyền điều khiển card. Khi một card thông thường được binding sang vfio-pci, Linux không còn quản lý giao diện đó; vì vậy binding nhầm card đang mang default route có thể làm mất kết nối quản trị. Documentation DPDK cũng lưu ý rằng phần lớn thiết bị phải rời kernel driver trước khi Poll Mode Driver sử dụng và việc binding cần đặc quyền quản trị [1].'
Add-Code "ip -br link`nip -4 route`nethtool -i ens160`nreadlink -f /sys/class/net/ens160/device`nreadlink -f /sys/class/net/ens160/device/iommu_group"
Add-Para 'Hai lệnh ip xác nhận tên giao diện, trạng thái link và default route. ethtool -i ens160 xác nhận driver gốc vmxnet3. Hai liên kết sysfs cho biết địa chỉ PCI và IOMMU group. Script dpdk_smoke.py không chấp nhận cấu hình nếu thiếu IOMMU, nếu card dữ liệu trùng card quản trị, nếu group không phù hợp chính sách an toàn hoặc nếu đường quản trị không thể được bảo toàn. Dự án không bật chế độ VFIO no-IOMMU vì config khóa require_iommu=true và allow_no_iommu=false.'
Add-Para 'DPDK dùng bộ nhớ hugepage để giảm số lượng ánh xạ trang, hỗ trợ DMA và hạn chế chi phí quản lý TLB. Cấu hình T0.3/T0.4 yêu cầu 128 trang 2 MiB, tương đương 256 MiB. Script chỉ đặt số trang tại thời điểm chạy, gắn hugetlbfs tại /dev/hugepages khi cần và lưu trạng thái ban đầu để rollback; setup_toolchain_ubuntu.sh tuyên bố rõ không tự thay đổi NIC, hugepage, IOMMU, VFIO hoặc tham số boot.'
Add-Code "sudo modprobe vfio-pci`necho 128 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`nsudo mkdir -p /dev/hugepages`nfindmnt /dev/hugepages || sudo mount -t hugetlbfs nodev /dev/hugepages"
Add-Para 'Các câu lệnh trên minh họa đúng thao tác mà workflow thực hiện có kiểm soát. Giá trị thực tế phải được đọc lại sau khi ghi; nếu kernel không cấp đủ 128 trang, script dừng thay vì tiếp tục với cấu hình khác. Documentation DPDK xác nhận /dev/hugepages là mount point thông dụng trên Linux hiện đại [1].'

Add-Para '2.3 Binding card mạng với vfio-pci' Heading2
Add-Para 'Dự án sử dụng vfio-pci, không sử dụng UIO. Lựa chọn này khớp khuyến nghị của DPDK và cho phép IOMMU cô lập DMA của thiết bị [1]. dpdk-devbind.py được dùng để xem trạng thái, binding card dữ liệu theo PCI address và trả card về vmxnet3 khi kết thúc. Script lưu driver ban đầu, địa chỉ IP, trạng thái link, route và hugepage trước mọi thay đổi.'
Add-Code "sudo python3 `$DPDK_ROOT/bin/dpdk-devbind.py --status`nsudo python3 `$DPDK_ROOT/bin/dpdk-devbind.py --bind=vfio-pci <PCI_CUA_ENS160>`npython3 `$DPDK_ROOT/bin/dpdk-devbind.py --status"
Add-Para 'Không điền cứng PCI address vì địa chỉ phụ thuộc máy ảo và phải lấy từ discovery artifact. Sau binding, workflow kiểm tra driver_for_pci trả về vfio-pci và thiết bị /dev/vfio/<IOMMU_GROUP> đã xuất hiện. Card ens33 và default route quản trị không được thay đổi. Khi kết thúc hoặc có lỗi, rollback binding lại driver gốc vmxnet3, khôi phục địa chỉ, route, link, số hugepage và gỡ mount do workflow tạo. Đây là một phần của tiêu chí nghiệm thu, không phải bước tùy chọn.'

Add-Para '2.4 Smoke test môi trường DPDK' Heading2
Add-Para 'Smoke test T0.3 nhằm chứng minh tối thiểu bốn điều: EAL khởi tạo được với hugepage và VFIO; testpmd nhận đúng một port dữ liệu; port có thể nhận/xử lý packet trong thời gian giới hạn; toàn bộ trạng thái host được rollback. Cấu hình khóa lcore 0-1, hai memory channel, 8192 mbuf, 256 MiB, file-prefix nids-t03, thời lượng 60 giây và forward mode macswap. Các giá trị này là hợp đồng kiểm thử của dự án, không phải khuyến nghị tối ưu cho mọi máy.'
Add-Code "python3 scripts/dpdk_smoke.py discover --config config/dpdk-smoke.json`nsudo python3 scripts/dpdk_smoke.py preflight --config config/dpdk-smoke.json`nsudo python3 scripts/dpdk_smoke.py apply --config config/dpdk-smoke.json`nsudo python3 scripts/dpdk_smoke.py run --config config/dpdk-smoke.json`nsudo python3 scripts/dpdk_smoke.py rollback --config config/dpdk-smoke.json"
Add-Para 'discover chỉ thu thập và ghi bằng chứng; preflight kiểm tra topology, toolchain, devbind, hugepage và IOMMU; apply mới cấp hugepage và binding; run gọi dpdk-testpmd với EAL/application arguments đã khóa; rollback phục hồi host. Công cụ kiểm tra receipt từ chối bằng chứng thiếu bước hoặc sai cấu hình. testpmd cung cấp chế độ nhận và thống kê port; các lệnh show port stats/xstats được DPDK mô tả chính thức [2].'
Add-Para 'Smoke test không chứng minh hệ thống NIDS đã phân loại đúng và cũng không phải benchmark production. Nó chỉ xác nhận đường DPDK/VFIO hoạt động lặp lại, có lưu bằng chứng và có khả năng quay về trạng thái mạng ban đầu.'

Add-Para '2.5 Live capture thụ động' Heading2
Add-Para 'Sau smoke test, T0.4 chuyển sang kiểm tra khả năng quan sát thụ động. testpmd chạy forward-mode rxonly với file-prefix nids-t04: packet được nhận và cập nhật thống kê nhưng không truyền lại. Cấu hình yêu cầu phía Kali gửi 200 UDP packet ở 10 packet/s tới máy Windows, payload nhận dạng NIDST04!, kích thước payload 12 byte. Tiêu chí tối thiểu là quan sát ít nhất 190 packet, tỷ lệ giao hàng tối thiểu 0,95, sensor TX bằng 0, error counter bằng 0 và rollback thành công.'
Add-Code "sudo python3 scripts/dpdk_passive_probe.py discover --config config/dpdk-passive.json`nsudo python3 scripts/dpdk_passive_probe.py preflight --config config/dpdk-passive.json`nsudo python3 scripts/dpdk_passive_probe.py apply --config config/dpdk-passive.json`nsudo python3 scripts/dpdk_passive_probe.py run --config config/dpdk-passive.json`nsudo python3 scripts/dpdk_passive_probe.py rollback --config config/dpdk-passive.json"
Add-Para 'Trong ứng dụng cuối nids_dpdk_live, DPDK EAL được khởi tạo trước; port được cấu hình một RX queue, mempool mbuf được tạo, promiscuous mode được bật và vòng lặp gọi rte_eth_rx_burst. API DPDK mô tả hàm này là thao tác đọc các RX descriptor đã hoàn tất và trả về tối đa số packet yêu cầu [3]. Mỗi mbuf được chuyển sang DpdkAdapter; lỗi adapter, lỗi ingest, imissed và rx_nombuf được thống kê để phân biệt packet không hợp lệ, lỗi pipeline và drop ở port.'
Add-Para 'Bằng chứng bàn giao của workspace ghi nhận live demo paced sender 9 frame tạo một checkpoint F9 và một cảnh báo known_attack với nhãn ứng viên DDoS; xác suất Flow RF là 0,9233325720; adapter errors, ingest errors, port_imissed và port_rx_nombuf đều bằng 0. Đây là kết quả của lượt demo đã lưu, không được diễn giải thành hiệu năng production hoặc khả năng phát hiện mọi kiểu tấn công.'

Add-Para '2.6 Xây dựng và trích xuất 54 đặc trưng flow' Heading2
Add-Para 'Bộ 54 đặc trưng nids.flow_features.v1 là hợp đồng nội bộ của dự án. Nó được điều chỉnh từ các nhóm đặc trưng CICFlowMeter nhưng chỉ dùng prefix 3, 5, 7 hoặc 9 packet, không dùng packet tương lai và không chờ flow kết thúc. Không có bài báo nào trong workspace công bố đúng bộ 54 này; vì vậy không được mô tả nó là bộ đặc trưng chuẩn hoặc tối ưu [4].'
Add-Para 'Flow được định danh bởi 5-tuple chuẩn hóa hai chiều. Packet đầu tiên xác lập chiều forward; packet khớp tuple đảo được tính reverse. State được cập nhật tăng dần bằng counter, min/max và thuật toán Welford cho mean/phương sai, do đó không cần giữ toàn bộ lịch sử packet. Phương sai population được tính M2/n. IAT giữ dấu theo capture order; flow_age_us dùng timestamp watermark lớn nhất trừ timestamp đầu; mẫu số bằng 0 trả 0; NaN hoặc vô cực làm pipeline fail-fast.'

& $OfficeCli add $File /body --type paragraph --before $Chapter3 --prop 'text=Bảng 2.1. Danh sách 54 đặc trưng của nids.flow_features.v1' --prop style=Caption --prop font='Times New Roman' --prop size=13pt --prop bold=true --prop align=center --prop spaceBefore=6pt --prop spaceAfter=3pt | Out-Null
& $OfficeCli add $File /body --type table --before $Chapter3 --prop rows=55 --prop cols=4 --prop width=100% --prop style=TableGrid | Out-Null
$tablePath = '/body/tbl[3]'
& $OfficeCli set $File "$tablePath/tr[1]" --prop header=true --prop c1='STT' --prop c2='Tên đặc trưng' --prop c3='Đơn vị' --prop c4='Ý nghĩa/cách tính' | Out-Null
$features = @(
@('flow_age_us','µs','watermark timestamp trừ timestamp đầu'),@('packet_count','packet','tổng packet prefix'),@('forward_packet_count','packet','packet chiều forward'),@('reverse_packet_count','packet','packet chiều reverse'),@('wire_byte_count','byte','tổng độ dài frame'),@('forward_wire_byte_count','byte','tổng byte forward'),@('reverse_wire_byte_count','byte','tổng byte reverse'),
@('packet_length_min','byte','min độ dài packet'),@('packet_length_max','byte','max độ dài packet'),@('packet_length_mean','byte','mean Welford toàn flow'),@('packet_length_std','byte','độ lệch chuẩn population'),@('forward_packet_length_mean','byte','mean độ dài forward'),@('forward_packet_length_std','byte','std forward'),@('reverse_packet_length_mean','byte','mean độ dài reverse'),@('reverse_packet_length_std','byte','std reverse'),
@('flow_iat_min_us','µs','IAT nhỏ nhất có dấu'),@('flow_iat_max_us','µs','IAT lớn nhất có dấu'),@('flow_iat_mean_us','µs','mean IAT theo capture order'),@('flow_iat_std_us','µs','std population của IAT'),@('forward_iat_mean_us','µs','mean IAT forward'),@('forward_iat_std_us','µs','std IAT forward'),@('reverse_iat_mean_us','µs','mean IAT reverse'),@('reverse_iat_std_us','µs','std IAT reverse'),
@('packet_rate_per_second','packet/s','count × 10^6 / age_us'),@('wire_byte_rate_per_second','byte/s','byte × 10^6 / age_us'),@('forward_reverse_packet_ratio','tỷ lệ','forward/reverse; mẫu 0 trả 0'),@('forward_reverse_wire_byte_ratio','tỷ lệ','byte forward/reverse'),@('direction_change_count','lần','số lần đổi hướng liên tiếp'),
@('tcp_syn_count','cờ','số cờ SYN'),@('tcp_ack_count','cờ','số cờ ACK'),@('tcp_fin_count','cờ','số cờ FIN'),@('tcp_rst_count','cờ','số cờ RST'),@('tcp_psh_count','cờ','số cờ PSH'),@('tcp_syn_ack_ratio','tỷ lệ','SYN/ACK; mẫu 0 trả 0'),@('tcp_initial_forward_window','byte','window TCP forward đầu'),@('tcp_initial_reverse_window','byte','window TCP reverse đầu'),@('tcp_window_mean','byte','mean window TCP'),@('tcp_window_std','byte','std window TCP'),
@('ttl_min','hop','TTL nhỏ nhất'),@('ttl_max','hop','TTL lớn nhất'),@('ttl_mean','hop','mean TTL'),@('ttl_std','hop','std TTL'),
@('payload_packet_count','packet','packet payload > 0'),@('forward_payload_packet_count','packet','packet payload forward'),@('reverse_payload_packet_count','packet','packet payload reverse'),@('payload_byte_count','byte','tổng byte payload'),@('forward_payload_byte_count','byte','payload byte forward'),@('reverse_payload_byte_count','byte','payload byte reverse'),@('payload_length_min','byte','min, kể cả giá trị 0'),@('payload_length_max','byte','max payload'),@('payload_length_mean','byte','mean payload mọi packet'),@('payload_length_std','byte','std payload'),@('header_length_mean','byte','mean payload.offset'),@('header_length_std','byte','std payload.offset')
)
for ($i=0; $i -lt $features.Count; $i++) {
    $r = $i + 2; $n = $i + 1; $f = $features[$i]
    & $OfficeCli set $File "$tablePath/tr[$r]" --prop "c1=$n" --prop "c2=$($f[0])" --prop "c3=$($f[1])" --prop "c4=$($f[2])" | Out-Null
}
Add-Para 'Các chỉ số 28–37 bằng 0 đối với UDP. payload length được thống kê trên mọi packet, kể cả payload bằng 0; header length bằng payload.offset, tức số byte từ đầu frame tới payload tầng vận chuyển. Retransmission, out-of-order, raw IP, raw port, timestamp tuyệt đối, active/idle, bulk, subflow và final flow duration không có trong Schema v1 vì chưa có semantics/parity test phù hợp với prefix ngắn.'
Add-Para 'Oracle kiểm thử gồm trace TCP 9 packet tại F3/F5/F7/F9 và trace UDP 3 packet tại F3. Kiểu nguyên được so sánh chính xác; giá trị float dùng abs_tol và rel_tol bằng 10^-12. Parity PCAP–DPDK vẫn yêu cầu cùng PacketView đi qua cùng engine, không dùng dung sai để che khác biệt adapter.'

Add-Para '2.7 Tiền xử lý dữ liệu và mô hình machine learning' Heading2
Add-Para 'Dữ liệu huấn luyện xuất phát từ CICIDS2017, đi qua kiểm kê PCAP/CSV, export flow từ C++, join nhãn, tạo snapshot Parquet và split tách biệt. Preprocessing chỉ fit trên training partition, phát hiện cột hằng/không hữu hạn, khóa thứ tự feature, feature mask và các tham số biến đổi vào artifact. Điều này ngăn rò rỉ thông tin từ validation/test. Bộ 54 là đầu ra của engine; model chỉ nhận đúng tập con được ghi trong bundle.'
Add-Para 'Mô hình phân loại nhị phân chính là Random Forest (Flow RF), ngưỡng runtime 0,5. Nếu xác suất vượt ngưỡng, quyết định là known_attack và Known-family RF cung cấp family ứng viên. Nếu không vượt, HBOS và Isolation Forest bỏ phiếu độc lập: hai phiếu tạo unknown_candidate, một phiếu tạo uncertain và không phiếu tạo benign. unknown_candidate không đồng nghĩa zero-day và không xác nhận một CVE mới.'
Add-Para 'OOF anomaly meta-features được tạo ngoài fold để huấn luyện RF Stacker mà không dùng dự đoán in-fold. Tuy nhiên, stacker không đạt gate cải thiện: delta novel-F1 so với Flow RF là -0,023988 với CI95% [-0,059369; 0,000949]. Do đó stacker chỉ được giữ như ablation, không thay thế Flow RF trong quyết định chính. CNN, LSTM, Transformer và các phép biến đổi ảnh được trình bày ở Chương I là nghiên cứu liên quan, không xuất hiện trong runtime flow-based hiện tại và không được gán cho dự án.'
Add-Code "python -m nids_mvp.preprocessing run`npython -m nids_mvp.rf_baseline run`npython -m nids_mvp.anomaly_baseline run`npython -m nids_mvp.oof_meta_features run`npython -m nids_mvp.rf_stacker run`npython -m nids_mvp.known_family_rf run`npython -m nids_mvp.model_acceptance run"

Add-Para '2.8 Liên kết giữa DPDK, 54 đặc trưng và suy luận thời gian thực' Heading2
Add-Para 'DPDK chỉ đảm nhiệm đường thu nhận packet tốc độ cao; nó không trực tiếp tạo nhãn hoặc dự đoán. DpdkAdapter và PacketParser biến mbuf thành PacketView; FlowTable tạo ngữ cảnh hai chiều; FeatureEngine cập nhật 54 thống kê; checkpoint manager chỉ phát vector tại F3/F5/F7/F9; model runtime áp preprocessing đã khóa và suy luận; decision fusion phát cảnh báo. Việc phân lớp rõ ràng giúp smoke test DPDK, parity feature và model acceptance được kiểm tra độc lập.'
Add-Para 'Giới hạn cần ghi nhận là các speed-run chạy trên VMware và chưa phải bằng chứng production; CIC sample attacker-VM replay, equality tự động về flow count/feature hash ở một số bước và async alert queue vẫn còn hoãn. Vì vậy Chương II chỉ kết luận hệ thống đã chạy trọn pipeline và đủ điều kiện demo theo receipt, không kết luận khả năng tổng quát cho mọi mạng hoặc mọi loại tấn công.'

# Thêm tài liệu tham khảo trước Phụ lục. Số [1]–[5] tương thích cách trích dẫn số đang dùng trong bản gốc.
Add-Ref '[1] DPDK Project, “Getting Started Guide for Linux: System Requirements, Linux Drivers and Enabling Additional Functionality,” DPDK Documentation, truy cập ngày 28/07/2026. https://doc.dpdk.org/guides/linux_gsg/'
Add-Ref '[2] DPDK Project, “Testpmd Application User Guide: Runtime Functions and Running the Application,” DPDK Documentation, truy cập ngày 28/07/2026. https://doc.dpdk.org/guides/testpmd_app_ug/'
Add-Ref '[3] DPDK Project, “rte_eth_rx_burst — Ethernet Device API,” DPDK API Documentation, truy cập ngày 28/07/2026. https://doc.dpdk.org/api/rte__ethdev_8h.html'
Add-Ref '[4] I. Sharafaldin, A. H. Lashkari và A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP, 2018.'
Add-Ref '[5] M. Ghadermazi và cộng sự, “Towards Real-Time Network Intrusion Detection with Image-Based Sequential Packets Representation,” tài liệu PDF trong workspace.'
Add-Ref '[6] Network Packet Transformation Approaches for Intrusion Detection Systems: A Survey, tài liệu PDF trong workspace. Tài liệu chỉ được dùng để tổng quan các hướng biến đổi packet/flow ở Chương I, không phải nguồn của bộ 54 đặc trưng.'

& $OfficeCli set $File /settings --prop updateFields=true | Out-Null
& $OfficeCli save $File | Out-Null
& $OfficeCli close $File | Out-Null
