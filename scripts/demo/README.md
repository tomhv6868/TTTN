# scripts/demo — bộ script chạy buổi demo bảo vệ

Bốn script, chạy bằng PowerShell trên máy host (Windows).

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\<script>.ps1
```

## Nguyên tắc an toàn

Mọi thứ script tạo ra nằm trong **`run_log/demo/<session>/`**.

Hai file bằng chứng của báo cáo — `run_log/full-flow-v1/live-detection-f9.jsonl`
(10.667 dòng) và `live-detection-terminal.jsonl` (28.937 dòng) — **không bao giờ bị ghi hay xoá**.
Hàm `Assert-InsideDemoRoot` trong `demo-common.ps1` ném lỗi nếu bất kỳ thao tác ghi/xoá nào
trỏ ra ngoài `run_log/demo`.

Dashboard đọc thư mục nào là do biến môi trường `NIDS_LIVE_DIR` quyết định (đã có sẵn trong
`dashboard/server/app.py`). Script chỉ đặt biến này, không sửa code dashboard.

---

## 1. `demo-up.ps1` — bật máy ảo và dashboard

Tạo session mới, bật ba máy ảo qua `vmrun`, chờ `labctl status` trả về `ok`, bật FastAPI backend
và Vite, in URL, rồi **dừng chờ lệnh**. Gõ `q` là tự tắt sạch.

```powershell
# đầy đủ
scripts\demo\demo-up.ps1

# kiểm trước, không bật gì
scripts\demo\demo-up.ps1 -DryRun

# máy ảo đã chạy sẵn, chỉ cần dashboard
scripts\demo\demo-up.ps1 -SkipVm

# tắt hẳn máy ảo thay vì suspend
scripts\demo\demo-up.ps1 -Stop poweroff
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-Hosts` | `kali,ubuntu,windows` | Máy ảo cần bật |
| `-SkipVm` / `-SkipDashboard` | tắt | Bỏ qua từng phần |
| `-BackendPort` / `-WebPort` | `8000` / `5173` | Cổng |
| `-Stop` | `suspend` | `suspend` · `poweroff` · `leave` |
| `-Gui` | tắt | Bật máy ảo có cửa sổ |
| `-DryRun` | tắt | Chỉ in ra sẽ làm gì |

Ở điểm dừng: `q` = tắt hết · `k` = thoát script nhưng giữ nguyên dashboard và máy ảo.

---

## 2. `demo-stream.ps1` — tạo luồng cho dashboard theo model

Đọc `sensor.jsonl` thật, chuyển sang định dạng dashboard, ghi vào
`<session>/live-detection-<model>.jsonl`.

```powershell
# hỏi model và file nguồn
scripts\demo\demo-stream.ps1

# chỉ định sẵn
scripts\demo\demo-stream.ps1 -Model f9 -Sensor run_log\...\sensor.jsonl

# bám đuôi file, đẩy từng sự kiện ra dashboard như đang chạy thật
scripts\demo\demo-stream.ps1 -Model terminal -Sensor ... -Follow -FollowSeconds 600
```

| Model | Bridge dùng | Ý nghĩa |
|---|---|---|
| `f9` | `bridge_sensor_to_dashboard.py` | Nhánh mốc kiểm tra F9, chín gói |
| `terminal` | `bridge_terminal_to_dashboard.py` | Nhánh Full flow toàn luồng |

Bỏ trống `-Sensor` thì script tự quét `run_log` tìm mọi `sensor.jsonl`, liệt kê 20 file mới nhất
kèm kích thước và thời gian để chọn theo số thứ tự.

`-Reset` xoá sạch stream của model đó trước khi ghi.

### Preset — chọn đúng file khớp số liệu trên slide

Không phải nhớ đường dẫn. Mỗi preset trỏ tới đúng bộ dữ liệu sinh ra con số đang in trên slide.

```powershell
scripts\demo\demo-stream.ps1 -ListPresets
scripts\demo\demo-stream.ps1 -Preset slide23-ftp
```

| Preset | Model | Ra số | Khớp slide |
|---|---|---|---|
| `slide20-dashboard` | terminal | **28.937** bản ghi (28.860 tấn công + 77 lành tính) | Slide 20 |
| `slide23-ftp` | f9 | **209/209** alert đúng nhãn, toàn bộ FTP-Patator | Slide 23 thẻ A |
| `slide23-goldeneye` | f9 | **4.127** alert, **3.175** bị nhận thành DoS Hulk | Slide 23 thẻ B |
| `slide19-latency` | f9 | **7.509** alert — lượt dùng đo p99 ba chặng | Slide 19 |
| `hulk` | f9 | **6.086** alert DoS Hulk — luồng dày nhất, đẹp để nhìn | — |

Nguồn dữ liệu lấy từ `t8.5/scenarios/rebuild-20260808/` (bản dùng cho báo cáo, cùng thư mục mà
`dashboard/server/app.py` đọc ma trận nhầm lẫn) và `full-flow-v1/live/`.

**Lưu ý:** `t8.5/scenarios/20260808-194942/` có nội dung y hệt `rebuild-20260808/`. Dùng
`rebuild-20260808` cho nhất quán với báo cáo.

---

## 3b. `demo-mail.ps1` — gửi cảnh báo qua thư

```powershell
scripts\demo\demo-mail.ps1                # chạy thử, không gửi
scripts\demo\demo-mail.ps1 -ShowConfig    # xem gửi tới đâu
scripts\demo\demo-mail.ps1 -Send          # gửi thật, hỏi xác nhận "gui"
scripts\demo\demo-mail.ps1 -MinAlerts 20 -Send   # chỉ gửi khi gom đủ 20 cảnh báo
```

**Ba tham số lọc:**

| Tham số | Mặc định | Tác dụng |
|---|---|---|
| `-MinAlerts N` | 1 | Chưa gom đủ N cảnh báo thì **không gửi và giữ nguyên con trỏ**, lần chạy sau gom tiếp. Không mất cảnh báo nào. |
| `-PerFamilyLimit N` | 5 | Tối đa N dòng mỗi họ tấn công. Chọn xoay vòng nên **mọi họ đều có mặt** — không để `DoS Hulk` (5.806 sự kiện) lấp mất `Infiltration` (1 sự kiện). `0` = bỏ giới hạn. |
| `-DedupeHours H` | 24 | Cùng một luồng đã báo thì không báo lại trong H giờ. Chỉ ghi nhớ khi **gửi thật**, chạy thử không làm bẩn bộ nhớ. `0` = tắt. |

Bản tin ghi rõ phần đã gộp, ví dụ `DoS Hulk: 5 đưa vào bản tin / 5806 sự kiện`.

Mặc định **luôn là chạy thử**. Con trỏ và biên nhận ghi vào `<session>/alert-email/`, không đụng
`run_log/full-flow-v1/alert-email/` — bốn biên nhận của báo cáo (2 dry_run + 2 sent, tổng 25 cảnh
báo) giữ nguyên.

Cần 6 biến trong `.env`: `NIDS_SMTP_HOST/PORT/USER/PASSWORD`, `NIDS_ALERT_SENDER`,
`NIDS_ALERT_RECIPIENTS`. Script kiểm đủ 6 biến trước khi chạy và không bao giờ in mật khẩu.

---

## 3. `demo-clean.ps1` — xoá log do script demo tạo

```powershell
scripts\demo\demo-clean.ps1 -List       # chỉ xem, không xoá
scripts\demo\demo-clean.ps1             # xoá session đang active, hỏi xác nhận
scripts\demo\demo-clean.ps1 -All        # xoá mọi session
scripts\demo\demo-clean.ps1 -StreamsOnly  # chỉ làm rỗng 2 file jsonl, giữ thư mục
```

Trước khi xoá, script in ra đầy đủ danh sách file kèm số dòng, **và in luôn danh sách file bằng
chứng sẽ được giữ nguyên**. Phải gõ đúng chữ `xoa` để xác nhận (`-Yes` để bỏ qua bước hỏi).

---

## 4. `demo-log.ps1` — xem và chọn thủ công file log nào đang dùng

Đổi được **giữa lúc demo**, không phải tắt đi bật lại.

```powershell
scripts\demo\demo-log.ps1                 # liệt kê session, đánh dấu cái đang dùng
scripts\demo\demo-log.ps1 -Evidence       # kèm cả file bằng chứng (chỉ đọc)
scripts\demo\demo-log.ps1 -Tail f9        # 20 dòng cuối, đã format
scripts\demo\demo-log.ps1 -Use 20260813-205928-smoke   # trỏ dashboard sang session khác
```

`-Use` **không cần khởi động lại backend.** `dashboard/server/app.py` đọc lại con trỏ
`run_log/demo/.active-session` ở **mỗi request**, nên dashboard tự đổi nguồn ở lần poll kế tiếp
(khoảng 2 giây).

Thứ tự ưu tiên khi backend chọn thư mục đọc:

1. `run_log/demo/.active-session` — do `demo-log.ps1 -Use` và `demo-up.ps1` ghi
2. biến môi trường `NIDS_LIVE_DIR`
3. `run_log/full-flow-v1` — thư mục bằng chứng

Không có con trỏ và không có biến môi trường thì hành vi y hệt như trước khi có bộ script này.

---

## Luồng chạy một buổi demo

```powershell
scripts\demo\demo-up.ps1                      # 1. bật lab + dashboard
scripts\demo\demo-stream.ps1 -Model f9 -Follow # 2. đẩy luồng F9 lên dashboard
scripts\demo\demo-log.ps1 -Tail f9            # 3. kiểm nhanh nếu dashboard trống
scripts\demo\demo-log.ps1 -Use <session-khac>  #    đổi nguồn giữa chừng, không restart
scripts\demo\demo-mail.ps1 -Send             #    gửi cảnh báo qua thư
#    ... trình bày ...
#    về cửa sổ demo-up, gõ q  -> tắt sạch
scripts\demo\demo-clean.ps1                   # 4. dọn log nếu cần chạy lại
```

---

## Đã kiểm

| Script | Trạng thái |
|---|---|
| `demo-common.ps1` | parse ok · `Assert-InsideDemoRoot` chặn đúng đường dẫn ra ngoài |
| `demo-up.ps1` | parse ok · `-DryRun` chạy hết luồng, đọc đúng 3 `.vmx` từ `config/lab-hosts.json` |
| `demo-stream.ps1` | **chạy thật** · preset `slide20-dashboard` ra đúng 28.937, `slide23-ftp` ra đúng 209 |
| `demo-clean.ps1` | **chạy thật** · xoá session, file bằng chứng nguyên vẹn (kiểm lại kích thước và thời gian) |
| `demo-log.ps1` | **chạy thật** · liệt kê, `-Tail`, `-Evidence`, `-Use` đổi nóng |
| `demo-mail.ps1` | **chạy thật** · dry-run ra đúng bản tin, biên nhận báo cáo không đổi |
| Đổi nóng stream | **chạy thật** · 209 → 6.086 → 209 sự kiện, backend chạy liên tục |

**Chưa kiểm được:** phần bật máy ảo thật và điểm dừng `Read-Host` của `demo-up.ps1` — cần chạy
tay trên máy có VMware. Chạy `-DryRun` trước để xem đường dẫn `.vmx` có đúng không.
