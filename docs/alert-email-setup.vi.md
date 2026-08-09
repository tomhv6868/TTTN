# Gửi cảnh báo NIDS qua email — hướng dẫn cài đặt

Công cụ: `scripts/alert_email_notifier.py`. Mặc định **chạy thử, không gửi**.
Chỉ khi thêm cờ `--send` thì mới gửi thật.

## 1. Tạo App Password của Gmail

Gmail không cho đăng nhập SMTP bằng mật khẩu thường. Phải dùng App Password.

1. Bật xác minh 2 bước cho tài khoản: <https://myaccount.google.com/signinoptions/two-step-verification>
2. Vào <https://myaccount.google.com/apppasswords>
3. Đặt tên bất kỳ, ví dụ `NIDS lab`, rồi bấm tạo.
4. Google trả về **16 ký tự** dạng `abcd efgh ijkl mnop`. Bỏ khoảng trắng khi dùng.

Nếu mục App passwords không hiện ra thì tài khoản chưa bật 2 bước, hoặc là tài khoản
tổ chức bị quản trị viên chặn.

**Không bao giờ dán chuỗi này vào file trong repo.** Nó chỉ nằm trong biến môi trường.

## 2. Đặt biến môi trường

PowerShell, chỉ có hiệu lực trong cửa sổ đang mở:

```powershell
$env:NIDS_SMTP_HOST       = "smtp.gmail.com"
$env:NIDS_SMTP_PORT       = "587"
$env:NIDS_SMTP_USER       = "xuanquanghhh1@gmail.com"
$env:NIDS_SMTP_PASSWORD   = "abcdefghijklmnop"
$env:NIDS_ALERT_SENDER    = "xuanquanghhh1@gmail.com"
$env:NIDS_ALERT_RECIPIENTS = "xuanquanghhh1@gmail.com"
```

Muốn giữ lại sau khi đóng cửa sổ thì dùng `setx`, nhưng như vậy mật khẩu nằm trong
registry của người dùng. Với môi trường lab thì chấp nhận được; với máy dùng chung thì không.

Nhiều người nhận: ngăn cách bằng dấu phẩy hoặc chấm phẩy.

```powershell
$env:NIDS_ALERT_RECIPIENTS = "a@example.com, b@example.com"
```

## 3. Kiểm tra thông tin đăng nhập trước

Chạy lệnh này **trong đúng cửa sổ đã đặt biến môi trường**:

```powershell
python scripts/alert_email_notifier.py --check-smtp
```

Nó chỉ mở kết nối, đăng nhập rồi thoát. Không đọc stream, không gửi thư.

In ra cấu hình đang dùng (mật khẩu chỉ hiện độ dài, không hiện nội dung) kèm cảnh báo
nếu phát hiện sai sót thường gặp:

```
Dang dung cau hinh:
  host      : smtp.gmail.com:587
  user      : ten-cua-ban@gmail.com
  password  : 16 ky tu
  sender    : ten-cua-ban@gmail.com
  recipients: ten-cua-ban@gmail.com

DANG NHAP SMTP THANH CONG. Co the chay lai voi --send.
```

Nếu dòng `password` không phải **16 ky tu**, gần như chắc chắn đang dùng mật khẩu
đăng nhập thường chứ không phải App Password, và Gmail sẽ trả lỗi 535.

## 4. Chạy thử trước khi gửi thật

```powershell
python scripts/alert_email_notifier.py `
  --stream run_log/full-flow-v1/live-detection-f9.jsonl `
  --limit 20 --from-start
```

In ra nguyên văn bản tin sẽ gửi. Không mở kết nối SMTP nào.

## 4. Gửi thật

```powershell
python scripts/alert_email_notifier.py `
  --stream run_log/full-flow-v1/live-detection-f9.jsonl `
  --limit 20 --send
```

Lần chạy đầu nên bỏ `--from-start` để chỉ gửi phần mới, tránh dội 10.667 dòng lịch sử.

## 5. Các cờ hay dùng

| Cờ | Ý nghĩa |
|---|---|
| `--stream` | file JSONL nguồn. F9 hoặc `live-detection-terminal.jsonl` |
| `--limit` | số cảnh báo tối đa mỗi bản tin, mặc định 200 |
| `--min-alerts` | chỉ gửi khi gom đủ bấy nhiêu cảnh báo, mặc định 1 |
| `--per-family-limit` | tối đa bấy nhiêu dòng mỗi họ tấn công, mặc định 5, `0` = bỏ giới hạn |
| `--dedupe-window-hours` | không báo lại cùng một luồng trong bấy nhiêu giờ, mặc định 24, `0` = tắt |
| `--from-start` | bỏ qua cursor, đọc lại từ đầu file |
| `--no-advance` | không ghi cursor, dùng khi thử nghiệm |
| `--subject-prefix` | đổi tiền tố tiêu đề, mặc định `[NIDS]` |
| `--send` | gửi thật. Thiếu cờ này là chạy thử |

## 6. Ngưỡng gửi, chống trùng và lọc đủ loại

Ba cơ chế chồng lên nhau, đọc theo thứ tự một cảnh báo đi qua:

**a. Cursor — không đọc lại dòng cũ.**
`run_log/full-flow-v1/alert-email/cursor.json` ghi số dòng đã đọc tới. Chạy lại chỉ
lấy phần mới. Xóa cursor là gửi lại từ đầu.

**b. Chống trùng trong 24 giờ — `--dedupe-window-hours`.**
Mỗi luồng đã gửi được ghi vào cursor kèm mốc thời gian, khóa theo
`(model, nguồn, đích, giao thức, nhãn)`. Trong 24 giờ sau nó không bị báo lại,
kể cả khi cảm biến vẫn tiếp tục sinh dòng cho luồng đó. Quá 24 giờ thì tính là
tin mới. Chỉ ghi nhớ khi **gửi thật**; chạy thử không làm bẩn bộ nhớ này.
Đặt `0` để tắt, khi đó chỉ còn khử trùng trong phạm vi một bản tin.

**c. Hạn mức mỗi họ — `--per-family-limit`.**
Không có cờ này thì bản tin lấy các dòng đầu theo thứ tự file, nên một họ ồn ào
lấp hết chỗ: trong stream F9 hiện tại `DoS Hulk` có **5.806** sự kiện, còn
`Infiltration` và `Web Attack – XSS` chỉ có **1**, và hai họ hiếm này sẽ không bao
giờ lọt vào. Cơ chế mới chọn xoay vòng — mỗi họ góp dòng thứ nhất trước, rồi mới
đến dòng thứ hai — nên **mọi họ đang xảy ra đều có mặt**. Phần bị cắt được ghi rõ
trong bản tin:

```
TONG HOP THEO NHAN
  - DoS Hulk: 5 dua vao ban tin / 5806 su kien
  - Infiltration: 1

DA GOP BOT (moi ho van co dai dien o tren)
  - DoS Hulk: an bot 5801 su kien cung loai
```

**d. Ngưỡng gửi — `--min-alerts`.**
Chưa gom đủ số cảnh báo yêu cầu thì **không gửi và giữ nguyên cursor**, nên lần
chạy sau gom tiếp chứ không mất cảnh báo nào. Dùng để tránh nhận thư mỗi khi có
đúng một cảnh báo lẻ.

## 7. Chạy định kỳ

Task Scheduler của Windows, mỗi 5 phút:

```powershell
schtasks /create /tn "NIDS alert email" /sc minute /mo 5 /tr `
  "powershell -NoProfile -Command \"cd E:\DATTTN\TTTN; python scripts/alert_email_notifier.py --send --min-alerts 20 --per-family-limit 5\""
```

Với `--min-alerts 20`, task chạy 5 phút một lần nhưng chỉ thực sự gửi thư khi đã
gom đủ 20 cảnh báo mới — lịch dày mà hộp thư không bị dội.

Lưu ý biến môi trường: task chạy trong phiên khác nên phải đặt bằng `setx` hoặc gói vào
một script wrapper. Kiểm tra kỹ trước khi bật lịch, tránh gửi thư liên tục.

## 8. Nội dung bản tin

Tiêu đề dạng `[NIDS] 6 tan cong, nhieu nhat: DoS Hulk`, kèm số cảnh báo chưa chắc chắn nếu có.

Thân thư gồm: thời điểm, nguồn dữ liệu, số tấn công xác nhận, số chưa chắc chắn,
số dòng benign và trùng bị loại, bảng tổng hợp theo nhãn, rồi danh sách chi tiết.

Hai điểm cố ý:

- **F9 để họ tấn công ở trường `candidate`**, còn `decision` chỉ là `known_attack`.
  Bản tin hiển thị `candidate`, nếu không thì mọi dòng đều hiện `known_attack`.
- **`uncertain` và `unknown_candidate` vẫn được báo** nhưng đánh dấu `chua chac`,
  không cộng vào số tấn công xác nhận.

## 9. Ranh giới

Bản tin là **lớp cảnh báo vận hành**, không phải nguồn số liệu.
Số đưa vào luận văn phải lấy từ receipt đã hash trong `run_log`, như mọi bảng khác.
Thân thư có sẵn một dòng ghi rõ điều này.

## 10. Lỗi thường gặp

| Triệu chứng | Nguyên nhân |
|---|---|
| `thiếu biến môi trường` | chưa đặt `NIDS_SMTP_HOST` / `NIDS_ALERT_SENDER` / `NIDS_ALERT_RECIPIENTS` |
| `Username and Password not accepted` | dùng mật khẩu thường thay vì App Password, hoặc còn khoảng trắng trong chuỗi 16 ký tự |
| `Connection unexpectedly closed` | sai cổng. Gmail STARTTLS là 587, không phải 465 |
| Gửi được nhưng không thấy thư | kiểm tra thư mục Spam; thư có header `Auto-Submitted: auto-generated` nên dễ bị lọc |
| `khong co canh bao moi` | cursor đã đọc hết file. Thêm `--from-start` để đọc lại |
