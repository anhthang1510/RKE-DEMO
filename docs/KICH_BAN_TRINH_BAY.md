# Kịch bản trình bày demo khoảng 5 phút

Chuẩn bị: chạy bộ cài trước, mở hai CMD cạnh nhau, mở sẵn thư mục `received/bob`. Đợi hai bên đều báo `SESSION_READY`. Muốn demo từ số gói 2 thì dùng một thư mục giải nén mới.

## 0:00-0:45 - Giới thiệu và thiết lập phiên

“Chương trình gồm hai bên Alice và Bob chạy cục bộ, trao đổi qua file JSON. Đầu tiên, hai bên sinh A-word, B-word và một IV giao thức, rồi thiết lập khóa chung K2 bằng phép XOR. Dữ liệu thiết lập được mã hóa RSA và có chữ ký kiểm tra bằng khóa công khai đã cài trước.”

Chỉ vào hai dòng `SESSION_READY` và dấu vân tay K2 giống nhau. Có thể gõ `status` ở mỗi cửa sổ.

“Hai dấu vân tay trùng nhau cho thấy hai bên đang có cùng K2 trong lần chạy này. K2 không được truyền dưới dạng rõ trong gói dữ liệu.”

## 0:45-1:45 - Gửi đúng và đổi khóa

Tại Alice:

```text
send samples/loi_chao.txt
```

“Khi gửi, Alice sinh một khóa AES ngẫu nhiên mới bằng secrets, mã hóa file, che khóa bằng K2 và RS(IV cộng bộ đếm), rồi tính SHA-256. Bob khôi phục khóa, tính lại hash, thấy đúng mới giải mã.”

Chỉ vào `ACCEPTED` của Bob và mở file vừa nhận. Gửi cùng file lần nữa để chỉ ra dấu vân tay khóa của lần gửi mới khác lần trước.

## 1:45-2:45 - Gói sai hash

Tại Alice:

```text
bad-hash samples/loi_chao.txt
```

“Lệnh này tạo một gói đúng, lưu lại bản gốc, rồi cố ý sửa một bit của hash trên bản truyền đi. Bên nhận sẽ phát hiện sự khác biệt.”

Chỉ vào `REJECTED / HASH_MISMATCH`. Mở thư mục nhận để cho thấy không có file mới. Gõ `status` tại Bob và chỉ ra `next_receive` không tăng sau gói lỗi.

“Bộ nhận kiểm tra hash trước khi gọi hàm giải mã, nên gói lỗi không sinh file plaintext.”

## 2:45-3:30 - Gửi lại và thử phát lại

Tại Alice:

```text
resend
```

“Đây là đúng gói gốc đã lưu, giữ nguyên số thứ tự và khóa của gói đó. Lần này Bob kiểm tra thành công và lưu file.”

Sau khi Bob báo `ACCEPTED`, gõ `resend` một lần nữa.

“Gói này đã được nhận rồi nên Bob từ chối với REPLAY, không giải mã hoặc tạo thêm file.”

## 3:30-4:15 - Gửi hai chiều

Tại Bob:

```text
send samples/phan_hoi.txt
```

“Bob cũng sinh khóa mới cho file của mình. Bộ đếm gửi của hai bên hoạt động độc lập. Alice kiểm tra hash và nhận file theo cùng quy trình.”

## 4:15-5:00 - Giải thích JSON và kết quả kiểm thử

Mở một bản `runtime/alice/sent/<số-gói>/config.json`, chỉ vào `wrapped_key`, `ciphertext`, `hash`, `cbc_iv`, `sequence`.

“wrapped_key là khóa đã che, không phải khóa AES ở dạng rõ. cbc_iv thuộc bước mã hóa AES và được sinh mới cho từng file; nó khác IV bí mật đã trao đổi lúc thiết lập.”

“Bộ mã có 36 kiểm thử tự động và một kịch bản demo 13 kiểm tra. Bản này tái hiện hoạt động của cấu trúc bài báo trong môi trường local. Nó chưa phải một giao thức được chứng minh an toàn để triển khai thực tế và không khẳng định PFS.”

Nếu cần thêm tình huống, dùng `bad-data`, `bad-key`, `bad-iv`; sau mỗi tình huống dùng `resend` để khôi phục đúng thứ tự.
