# Full-Flow IDS Và Kiểm Thử Live Tối Thiểu 2/14 Nhãn

  ## Summary

  - Tạo pipeline mới nids.terminal_flow.v1, tách hoàn toàn khỏi F3/F5/F7/F9 và bundle T5 hiện tại.
  - Đơn vị dữ liệu là một flow generation quan sát được khi đóng, không khẳng định luôn là toàn bộ kết nối TCP.
  - Replay lại 5 PCAP, đối chiếu 8 CSV thông qua hai oracle bất biến hiện có:
      - run_log/t3.3/label-join.sqlite3
      - run_log/t3.3r1/class-consensus.sqlite3

  - Dataset chứa đủ 2.436.052 flow; chỉ 2.366.094 flow assigned được dùng huấn luyện. Flow quarantine vẫn được giữ để kiểm toán.
  - Train binary BENIGN/ATTACK và attack-family 13 lớp có dữ liệu. Heartbleed không có assigned flow nên không thể là output được nghiệm thu.
  - Mục tiêu live chính thức: FTP-Patator và PortScan. Harness vẫn liệt kê đủ 14 case để chạy chẩn đoán; các case thiếu tool/endpoint trả trạng thái
    skipped/unsupported, không chặn gate 2/14.

  - Giữ topology DPDK passive một cổng RX, 0 TX. Không chuyển Ubuntu thành inline bridge.

  ## Schema Và Dataset

  - Thêm schema nids.terminal_flow_features.v1 gồm 70 feature:
      - A, 54 feature hiện tại được tính tại trạng thái terminal.
      - B, thêm protocol_number, TTL mean hai chiều, wire bit-rate hai chiều, active_mean_us, idle_mean_us: 61 feature.
      - C, thêm ba counter causal trong block 60 giây: số flow cùng destination-port, số flow cùng source-destination và số destination-port phân biệt: 64
        feature.

      - D, thêm first_observed_source_port và first_observed_destination_port: 66 feature.
      - E, thêm bốn lifecycle one-hot tcp_reset, tcp_fin_handshake, tcp_other, udp: 70 feature.

  - Counter được chốt tại packet đầu, chỉ dùng flow đã quan sát trong cùng block 60 giây, gồm flow hiện tại, reset theo capture/sensor process. Cách này
    giữ train-serving parity và không nối state giữa các partition.

  - close_reason đầy đủ được giữ làm metadata; chỉ lifecycle profile E mới đưa trạng thái terminal vào model.
  - Không giả lập các feature không có semantics đáng tin cậy:
      - Loại nat_src_port, dataset-origin src, raw IP, timestamp tuyệt đối và attack schedule.
      - Không tạo ct_srv_dst giả từ port khi parser chưa có service/DPI.

  - Xuất Parquet duy nhất tại namespace mới, shard theo capture, atomic và resumable. Không xuất CSV.
  - Mỗi row giữ flow_id, capture_id, export ordinal, timestamps, endpoints, close reason, label status, nullable assigned class, assignment method và
    partition; model chỉ được đọc allowlist feature.

  - Mở rộng split hiện tại với seed 3607, block 60 giây, tỷ lệ 70/10/20:
      - Block đã có flow F3 giữ nguyên partition.
      - Flow 1-2 packet trong block đó kế thừa partition.
      - Chỉ short-only block mới được phân bổ bằng objective/ordering hiện hành, khởi tạo từ các block đã khóa.
      - Test được niêm phong đến khi thuật toán, profile và threshold đã chọn xong.

  ## Train, Chọn Model Và Bundle

  - Benchmark trên toàn bộ train partition, không row-random split, SMOTE hoặc parameter search:
      - LightGBM: 300 trees, learning rate 0,05, 31 leaves, balanced weights, deterministic, 8 threads.
      - HistGradientBoosting: 200 iterations, learning rate 0,1, 31 leaves, L2=1, balanced weights, không internal early stopping.
      - SGD: log_loss, StandardScaler, alpha 1e-4, 1.000 iterations, balanced weights, averaged weights.

  - Pin Windows task-venv với lightgbm==4.6.0 và onnxmltools==1.16.0; không sửa Python hệ thống hoặc Ubuntu toolchain. LightGBM được chuyển qua ONNXMLTools
    (https://github.com/onnx/onnxmltools) sang ONNX.

  - Fit ba binary head và ba family head trên profile D, sau đó đánh giá toàn bộ chín cặp trên validation. Binary và family được phép chọn thuật toán khác
    nhau vì cùng giao diện ONNX.

  - Binary threshold chỉ được chọn từ validation, với benign FPR <=0,01; tối ưu lần lượt min end-to-end F1 của FTP/PortScan, macro-F1, attack recall, FPR
    rồi threshold cao hơn.

  - Cặp model eligible khi:
      - Precision và recall end-to-end của cả FTP-Patator và PortScan đều >=0,90.
      - Overall attack recall không thấp hơn cặp tốt nhất quá 0,002.
      - Macro-F1 các family có ít nhất 100 flow không thấp hơn tốt nhất quá 0,01.
      - ONNX export hai lần byte-identical, checker pass, exact decision/class parity và probability error <=1e-5.

  - Chọn cặp eligible có tổng fit+export wall-time thấp nhất; chênh dưới 5% thì ưu tiên min target-F1 cao hơn, sau đó peak RSS thấp hơn.
  - Với cặp thuật toán đã chọn, chạy ablation A-E và chọn profile nhỏ nhất vẫn đạt gate, đồng thời không thấp hơn profile tốt nhất quá 0,01 ở min target-F1
    và macro-F1.

  - Mở test đúng một lần. Báo riêng toàn bộ terminal cohort, paired F9 flow IDs và các bin packet 1-2, 3-8, >=9. Nếu test fail, không tune theo test; phát
    hành model version mới.

  - Bundle nids.terminal_flow_bundle.v1 chỉ gồm schema, selected feature indices, preprocessing từng head, threshold, hai ONNX model và manifest hash.
    Không mang HBOS/IsolationForest sang runtime mới.

  ## Runtime Và Live Campaign

  - Thêm TerminalFeatureTracker dùng chung cho offline exporter và DPDK live; finalize(state, reason) trả vector terminal đúng một lần mỗi generation.
  - Thêm runtime ONNX riêng, manifest-driven, không sửa semantics bundle/runtime T5 hiện tại. Ubuntu tiếp tục chỉ cần ONNX Runtime 1.27.1.
  - App DPDK mới infer trong on_close, scope đúng cặp endpoint Kali-Windows, bỏ traffic ambient khỏi flow/context/idle accounting và phát alert exact
    family.

  - Alert phải chứa endpoint, protocol/ports, packet count, duration, close reason, binary score, family probabilities, schema/model/bundle hashes.
    unknown_candidate hoặc top-candidate không được tính là phát hiện đúng.

  - Flow đóng do end_of_input chỉ là diagnostic, không được dùng chứng minh live. FTP/PortScan acceptance bắt buộc flow đóng bằng RST hoặc FIN handshake.
  - Campaign initializer tự lấy source IP từ ip route get, ghi run contract dùng chung; không hard-code .10 hay .129. Mọi host phải từ chối chạy nếu
    source/target/run-token không khớp.

  - Script tự sinh attempt_id mới cho mỗi lần chạy. Receipt cũ không chặn rerun và không bị ghi đè.
  - FTP: Patator, 20 mật khẩu sai, concurrency 1, hard timeout 30 giây.
  - PortScan: nmap -n -Pn -sS -p 1-1024 --max-rate 100 --max-retries 0 --host-timeout 25s, bao ngoài bằng timeout 30 giây.
  - Windows tạm mở firewall TCP 1-1024 chỉ cho source IP đã khóa để closed port trả RST; rollback bắt buộc xóa rule.
  - Chạy một rehearsal cho mỗi target, sau đó freeze artifact và chạy ba attempt fresh cho mỗi target. Mỗi attempt pass khi:
      - Có ít nhất 18 flow FTP hoặc 900 flow PortScan đóng bằng RST/FIN.
      - Có alert non-EOF exact family; family chiếm nhiều alert scoped nhất phải đúng expected label.
      - Adapter/ingest errors, imissed, rx_nombuf, TX packets đều bằng 0; sender, sensor và rollback receipts hợp lệ.
      - Negative control gồm một FTP login hợp lệ và HTTP/HTTPS thông thường, không phát target-family alert.

  - Gate cuối: 3/3 FTP-Patator và 3/3 PortScan pass, ghi passed_label_count=2, taxonomy_label_count=14.
  - Sau khi đạt gate 2/14, campaign runner có thể chạy tiếp 12 case còn lại; kết quả chỉ là diagnostic cho đến khi từng case có tool, endpoint và contract
    riêng.

  ## Phases Và Verification

  1. Governance/schema, tối đa 4 file: task mới cho phép training/dependency mutation, contract, schema và requirements lock.
  2. Terminal feature tracker, tối đa 4 file: implementation, API, unit test và CMake; kiểm tra closing packet, active/idle, directional TTL/load, counter
     causal và block reset.

  3. Offline exporter, tối đa 5 file: replay app, shard builder và tests; đối chiếu tuyệt đối close records với T3.3 oracle.
  4. Parquet/split, tối đa 4 file: packager, split extender và tests; kiểm tra đủ 2.436.052 flow, 2.366.094 assigned và không đổi partition cũ.
  5. Benchmark/training, tối đa 4 file: trainer, contract receipt và tests; test partition chưa được đọc.
  6. ONNX bundle/parity, tối đa 4 file: exporter, parity runner và tests; repeatability, checker, Python-ORT-C++ parity.
  7. Native runtime, tối đa 4 file: runtime API/implementation/test/CMake; schema, dimensions, class order và corrupt-bundle failures.
  8. DPDK terminal app, tối đa 4 file: close inference, endpoint scope, bounded shutdown và tests.
  9. Host harness, tối đa 5 file: 14-case config, Windows/Kali/Ubuntu scripts và wrapper tests; auto attempt IDs, tool bounds, ready handshake và rollback.
  10. Acceptance, tối đa 4 file: verifier, tests, receipt builder và runbook; candidate-only, wrong family/source, EOF-only, missing summary hoặc stale
     hash đều phải fail.

  Mỗi phase phải re-read file trước/sau edit, hoàn tất test/receipt, dừng để người dùng duyệt rồi mới sang phase tiếp theo. Không sửa receipt T3-T8 hoặc
  run_log/receipt-index.json; toàn bộ artifact mới nằm trong run_log/full-flow-v1/.