# Giải thích thuật toán và các lựa chọn triển khai

## 1. Phạm vi

Hai tiến trình Python đóng vai Alice/Bob, giao tiếp qua thư mục chung trên một máy. Phần trao đổi khóa bám công thức (1)-(11) của bài báo đính kèm. Phần vận chuyển file, định dạng JSON, lựa chọn AES-CBC/RSA cụ thể và xử lý lỗi là phần triển khai thêm để có thể chạy demo.

Không triển khai FPGA, mạng TCP, một hạ tầng chứng chỉ X.509 hay thử nghiệm hiệu năng phần cứng IoT. Không suy ra độ an toàn OTP hoặc tính bí mật chuyển tiếp hoàn hảo chỉ từ việc mỗi file có khóa mới.

## 2. Các giá trị

| Ký hiệu bài báo | Tên trong mã | Ý nghĩa |
| --- | --- | --- |
| A-word | `a_word` | Chuỗi ngẫu nhiên của Alice khi thiết lập phiên |
| B-word | `b_word` | Chuỗi ngẫu nhiên của Bob khi thiết lập phiên |
| K2 | `k2` | Bí mật chung `A-word XOR B-word` |
| IV | `protocol_iv` | IV bí mật dùng trong công thức che khóa |
| a hoặc b | `sequence` | Bộ đếm gửi riêng của Alice hoặc Bob, bắt đầu từ 2 |
| RS(IV+a) | `rs(protocol_iv, sequence)` | Cộng theo modulo rồi xoay phải vòng một bit |
| Ka hoặc Kb | `key` | Khóa AES ngẫu nhiên mới cho một gói dữ liệu |
| KA(a) hoặc KB(b) | `wrapped_key` | Khóa đã che bằng XOR, được truyền cùng bản mã |
| Ca hoặc Cb | `ciphertext` | Bản mã AES-CBC, được đưa vào JSON dưới dạng Base64 |
| hA hoặc hB | `hash` | Giá trị SHA-256 để kiểm tra trước khi giải mã |
| Không chỉ định trong bài | `cbc_iv` | IV riêng cho AES-CBC, 16 byte, sinh mới cho từng gói |

`protocol_iv` và `cbc_iv` không phải cùng một giá trị. Việc phân biệt này cần thiết vì IV bí mật của cấu trúc trao đổi khóa có vai trò khác với IV dùng khi mã hóa CBC.

## 3. Bước một - thiết lập khóa chung

Trước khi demo, `setup_demo.py` sinh khóa RSA-2048 riêng cho từng bên và đặt bản sao khóa công khai của đối tác vào `peer_public_key.pem`. Đây là **giả định cài đặt tin cậy tại máy local** thay cho triển khai đầy đủ chứng chỉ trong bài báo.

1. Alice sinh mã phiên 16 byte, A-word và IV giao thức bằng `secrets.token_bytes`.
2. Alice đóng gói mã phiên, độ dài khóa, IV, A-word và dấu băm cấu hình; mã hóa bằng **khóa công khai của Bob** với RSA-OAEP/SHA-256.
3. Alice ký phần bao gói bằng **khóa riêng của Alice** với RSA-PSS/SHA-256. Bob kiểm tra bằng khóa công khai Alice đã được cài trước, rồi giải mã bằng khóa riêng Bob.
4. Bob sinh B-word, tính `K2 = A-word XOR B-word`. Bob gửi lại mã phiên, `RS(IV+1)`, B-word và dấu băm của toàn gói hello. Gói được mã hóa bằng khóa công khai Alice và ký bằng khóa riêng Bob.
5. Alice kiểm tra chữ ký Bob, mã phiên, `RS(IV+1)` và dấu băm hello, sau đó tự tính K2. Hai bên in dấu vân tay của K2 để kiểm tra, không in K2 nguyên dạng trên màn hình.

**Khóa riêng không được truyền đi.** Cụm mô tả liên quan đến khóa riêng trong bài báo được hiện thực bằng thao tác ký số, không phải gửi khóa riêng của Bob cho Alice.

Nếu phản hồi bị mất, Alice gọi `connect` để gửi lại cùng hello. Bob trả lại cùng phản hồi đã lưu và giữ nguyên bộ đếm. Một hello khác không được tự ý thay phiên đang hoạt động. Một welcome không còn yêu cầu tương ứng bị loại.

## 4. Bước hai - gửi dữ liệu và khóa mới

Với độ rộng n = 128 bit mặc định, bên gửi thực hiện:

```text
K_file = secrets.token_bytes(16)
R      = ROTR_1((IV_protocol + sequence) mod 2^128)
K_wrap = K2 XOR R XOR K_file
IV_CBC = secrets.token_bytes(16)
C      = AES-CBC(K_file, IV_CBC, PKCS7(file_bytes))
```

Công thức che/khôi phục khóa tương ứng phương trình (2), (3), (8), (9). Hàm mã hóa `E` và giải mã `D` của bài báo được chọn là AES-CBC với đệm PKCS7.

Phần III dùng nhiều kiểu chữ khác nhau cho Ka/KA và có chỗ nhắc K1; bản demo dùng **K2** nhất quán với phương trình (1)-(3) và (8)-(9).

Bài báo mô tả dịch vòng phải nhưng không xác định rõ số bit. Bản này công khai giả định **xoay vòng phải một bit**. Không dùng đơn thuần toán tử `>>` làm mất bit thấp nhất.

### Tính hash

Bài báo viết `hash(C, K_file, R)`. Bản chạy mở rộng đầu vào để bao gồm cả thông tin phiên, tên file, hướng gửi và IV của AES-CBC:

```text
H = SHA256(
    domain
    || length(header)[4 byte big-endian]
    || header
    || length(C)[8 byte big-endian]
    || C
    || K_file
    || R
)
```

- `domain` chính xác là `b"RKE-LOCAL-DEMO-v1\x00DATA\x00"`.
- `header` là JSON của 12 trường trong `HEADER_FIELDS`, sắp xếp khóa, dấu phân cách `,` và `:`, `ensure_ascii=True`, không khoảng trắng.
- Hai trường cuối có độ dài cố định theo cấu hình. Hai phần có độ dài thay đổi được ghi kèm độ dài để tránh nối chuỗi mơ hồ.
- `header` gồm cả `wrapped_key` và `cbc_iv`. Sửa tên file hay IV sẽ làm sai hash.
- Đây là phép băm có đưa khóa vào đầu vào theo ý tưởng bài báo, **không phải HMAC**. `hmac.compare_digest` chỉ được dùng để so sánh hai giá trị; nó không biến SHA-256 ở trên thành HMAC.

Mỗi bên giữ dấu băm đầy đủ của các khóa mình đã sinh trong phiên để phát hiện va chạm trước khi gửi. Khóa được sinh độc lập ở hai bên; không có cơ chế phối hợp để bảo đảm tuyệt đối không va chạm giữa Alice và Bob. Kết quả demo chỉ xác nhận các khóa của lần chạy đó khác nhau.

### JSON dữ liệu

Các chuỗi trong ví dụ được rút gọn để đọc, không phải gói chạy được:

```json
{
  "protocol": "RKE-LOCAL-DEMO-v1",
  "kind": "data",
  "sender": "alice",
  "recipient": "bob",
  "session_id": "<32 ký tự hex>",
  "sequence": 2,
  "message_id": "<32 ký tự hex>",
  "filename": "loi_chao.txt",
  "cipher": "AES-128-CBC",
  "hash_algorithm": "sha256",
  "cbc_iv": "<32 ký tự hex>",
  "wrapped_key": "<32 ký tự hex>",
  "ciphertext": "<bản mã dạng Base64>",
  "hash": "<64 ký tự hex SHA-256>"
}
```

Với chế độ 256 bit, `cipher` là `AES-256-CBC`, `wrapped_key` dài 64 ký tự hex; `cbc_iv` vẫn dài 32 ký tự hex.

## 5. Bên nhận làm gì?

1. Kiểm tra định dạng JSON, tên trường trùng, loại gói, người gửi/nhận, mã phiên, tên file và giới hạn kích thước.
2. Kiểm tra bộ đếm. Gói cũ bị loại với `REPLAY`; gói vượt thứ tự bị loại với `OUT_OF_ORDER`.
3. Tự tính `R = RS(IV + sequence)` và khôi phục `K_file = K_wrap XOR K2 XOR R`.
4. Tính lại hash từ chính header, bản mã, khóa vừa khôi phục và R. So sánh bằng `hmac.compare_digest`.
5. Nếu hash sai: báo `HASH_MISMATCH`, không gọi AES giải mã, không ghi file, không tăng bộ đếm.
6. Nếu hash đúng: giải mã AES-CBC, bỏ đệm PKCS7, kiểm tra kích thước rồi ghi file. Sau đó tăng và lưu bộ đếm nhận.

Mã nguồn kiểm tra cả IV CBC và thông tin header để tránh trường hợp nội dung điều khiển bị sửa mà hash chỉ bao phủ phần ciphertext.

## 6. Gửi lại, lưu trạng thái và thư mục nhận

- **Gửi mới:** sinh khóa mới, tăng số thứ tự gửi.
- **Gửi lại:** dùng nguyên gói sạch đã lưu ở `sent`, cùng khóa đã che, bản mã, IV và số thứ tự. Không tạo một thông điệp khác có cùng số thứ tự.
- Khi demo `bad-hash`, `bad-data`, `bad-key`, `bad-iv`, bản gốc được lưu trước; chỉ bản đưa vào `wire` bị làm hỏng.
- Không triển khai ACK/NACK mạng, thời gian chờ tự động hay gói yêu cầu gửi lại như đoạn cuối trang 3 của bài báo. Người demo dùng `resend`; bên nhận kiểm tra tính hợp lệ và thứ tự của bản gửi lại.
- Trạng thái được lưu riêng trong `runtime/alice` và `runtime/bob`. Có khóa tiến trình để tránh hai cửa sổ cùng vai ghi đè trạng thái nhau.
- File JSON và file nhận được ghi qua file tạm rồi thay thế. Việc cập nhật file kết quả và trạng thái không phải một giao dịch nguyên tử nhiều file; không cam kết xử lý exactly-once khi máy tắt đột ngột hoặc ổ đĩa hỏng. Gửi lại có thể giúp phục hồi, nhưng đây không phải hệ thống hàng đợi sản xuất.
- Nếu chương trình dừng giữa lúc lưu gói vào `sent` và đưa gói vào `wire`, dùng `resend <số-gói>` để phát lại gói đã lưu.

Gói bị loại được chuyển vào `rejected` để xem nguyên nhân. “Hủy kết quả” nghĩa là không có plaintext được tạo từ gói lỗi, không phải xóa các file đã nhận hợp lệ từ trước.

## 7. Đối chiếu phạm vi với bài báo

| Nội dung | Mức độ bám theo |
| --- | --- |
| K2 = A-word XOR B-word | Giữ theo phương trình (1) |
| Che/khôi phục khóa bằng XOR và RS | Giữ theo (2), (3), (8), (9) |
| Hai lượt thiết lập và khóa file mới mỗi lượt gửi | Giữ cấu trúc Hình 1-2 |
| Khóa, word, IV giao thức 128 bit | Mặc định theo bài báo |
| Số bit dịch vòng | Chọn rõ 1 bit vì bài không quy định đủ |
| Hàm mã hóa cụ thể | Chọn AES-CBC + PKCS7 cho E/D |
| Hash | Chọn SHA-256; bổ sung header và IV CBC vào đầu vào |
| Chứng chỉ/PKI | Thay bằng khóa công khai đối tác đã cài tin cậy, kèm chữ ký RSA-PSS |
| Gửi lại tự động theo trao đổi điều khiển trong bài | Đơn giản thành lệnh `resend` thủ công |
| File JSON, mã phiên, mã gói, bộ đếm lưu bền | Phần triển khai thêm cho demo |
| Chế độ 256 bit | Biến thể thêm; không phải cấu hình 128 bit nguyên bản |
| Tuyên bố hiệu năng FPGA/OTP/PFS | Không tái hiện hoặc xác nhận bằng demo này |

## 8. Giới hạn bảo mật cần trình bày đúng

Việc test thấy hash sai bị loại chứng minh hành vi chương trình cho các ca đó; nó không phải chứng minh mật mã cho toàn giao thức.

**Không tuyên bố PFS:** nếu đối phương lấy được K2 và IV giao thức, họ có thể dùng `K_file = K_wrap XOR K2 XOR RS(IV+sequence)` để khôi phục khóa của các gói cũ đã ghi lại. Cặp giá trị này được giữ suốt phiên. Nếu có khóa RSA riêng và đã lưu cả hai gói thiết lập, họ cũng có thể khôi phục dữ liệu thiết lập. Thay khóa từng file không tự tạo ra bí mật chuyển tiếp hoàn hảo.

Hai bên trong demo cùng chạy dưới một tài khoản hệ điều hành và có quyền đọc thư mục chung; do đó việc tách thư mục không phải ranh giới cô lập bảo mật. Khóa riêng và trạng thái được lưu cục bộ để tiếp tục phiên; `chmod 600` chỉ được áp dụng trên hệ hỗ trợ POSIX, không phải cấu hình ACL riêng cho Windows.

Các khẳng định “an toàn tương đương OTP”, “chống mọi tấn công trung gian” hoặc “chống kênh kề” trong bài báo không được coi là đã chứng minh bởi bản Python này. Nếu phát triển thành sản phẩm thực tế, cần thay cấu trúc thử nghiệm bằng giao thức tiêu chuẩn được thẩm định và quy trình quản lý khóa phù hợp.
