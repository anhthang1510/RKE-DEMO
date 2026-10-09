# Randomized Key Exchange - demo Python chạy cục bộ

Bộ mã nguồn mô phỏng Alice/Bob trao đổi khóa và gửi file qua hai cửa sổ CMD, dựa trên yêu cầu trong ảnh và bài báo **Randomized Key Exchange Protocol Implementation for Internet of Things Application** (Pirzada và cộng sự, 2020).

**Chạy nhanh:** giải nén toàn bộ ZIP, chạy `0_CAI_DAT.cmd` một lần, sau đó mở `1_ALICE.cmd` và `2_BOB.cmd`. Đợi `SESSION_READY` ở cả hai cửa sổ rồi gửi file theo hướng dẫn dưới đây.

Đây là bản thực hành của cấu trúc trong bài báo. Nó không phải giao thức đã được thẩm định để bảo vệ dữ liệu thật. Các điểm bổ sung và giới hạn được nêu rõ trong `docs/GIAI_THICH_GIAO_THUC.md`.

## 1. Đã đáp ứng những yêu cầu nào?

| Yêu cầu trong ảnh | Cách triển khai |
| --- | --- |
| Build và chạy local | Python, không cần máy chủ hay dịch vụ bên ngoài khi chạy demo |
| Dùng hàm hash có sẵn | `hashlib.sha256`; so sánh hash bằng `hmac.compare_digest` |
| Sinh khóa mới bằng thư viện có sẵn | `secrets.token_bytes`, sinh khóa cho mỗi lần **gửi mới** |
| Hai file CMD để giao tiếp | `1_ALICE.cmd`, `2_BOB.cmd`; hai bên tự theo dõi thư mục nhận |
| JSON có hash và khóa | Mỗi gói là một `config.json` chứa `hash`, `wrapped_key`, `ciphertext`, `cbc_iv` và thông tin phiên |
| Truyền IV ở lần đầu | IV bí mật của giao thức nằm trong gói hello được mã hóa RSA và ký số |
| File đúng hash được giải mã | Kiểm tra hash trước khi gọi hàm AES giải mã và trước khi lưu file |
| File sai hash bị hủy kết quả | Không giải mã, không tạo file đầu ra, không tăng bộ đếm nhận |
| Demo tạo khóa và trao đổi hai chiều | Alice/Bob đều gửi được; dấu vân tay khóa giúp quan sát việc thay khóa |
| Gửi lại khi có lỗi | Lệnh `resend` gửi đúng bản gốc; không sinh khóa khác cho cùng số thứ tự |

**Phân biệt:** SHA-256 là hàm băm; AES-CBC là phương thức mã hóa. MD5 không được đưa vào bản này. Module đúng tên là `secrets` (có chữ **s**), và nó lấy ngẫu nhiên từ nguồn do hệ điều hành cung cấp, không có nghĩa mọi máy đều trực tiếp dùng bộ sinh số ngẫu nhiên phần cứng.

## 2. Cài và chạy trên Windows

1. Cài **Python 3.10 trở lên** nếu chưa có, bật lựa chọn **Add Python to PATH** khi cài. Bản bàn giao được kiểm tra bằng Python 3.12.14.
2. Giải nén ZIP ra thư mục ngắn, ví dụ `C:\RKE_Demo`. Không chạy trực tiếp bên trong cửa sổ ZIP.
3. Mở `0_CAI_DAT.cmd`. Script tạo môi trường `.venv`, cài `cryptography`, sinh cặp khóa RSA riêng cho Alice/Bob và chuẩn bị thư mục dữ liệu. Cần mạng cho lần cài thư viện này; phần demo sau đó chạy cục bộ.
4. Mở `1_ALICE.cmd` và `2_BOB.cmd`. Thứ tự mở hai cửa sổ không quan trọng. Alice tự gửi hello; Bob tự phản hồi.
5. Đợi **SESSION_READY** ở cả hai cửa sổ. Hai dòng “Dấu vân tay khóa” của K2 phải giống nhau.

Chạy lại `0_CAI_DAT.cmd` không xóa khóa hay đặt lại bộ đếm. Đóng rồi mở lại Alice/Bob sẽ tiếp tục phiên cũ. Không mở hai cửa sổ Alice đồng thời hoặc hai cửa sổ Bob đồng thời.

Nếu thích gõ lệnh Python trực tiếp thay vì dùng CMD:

```text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe setup_demo.py
```

Sau đó, ở hai terminal riêng:

```text
.venv\Scripts\python.exe alice.py
```

```text
.venv\Scripts\python.exe bob.py
```

Trên Linux/macOS, dùng `.venv/bin/python` thay cho `.venv\Scripts\python.exe`. Chạy lệnh tại thư mục chứa `alice.py` và `bob.py`.

## 3. Kịch bản demo cơ bản

Các lệnh sau được gõ **bên trong chương trình**, tại dấu nhắc `alice>` hoặc `bob>`. Không gõ lại chữ `alice>`/`bob>`.

### Bước A - Gửi file đúng

Tại Alice:

```text
send samples/loi_chao.txt
```

Alice báo `QUEUED` và dấu vân tay khóa mới. Bob báo `ACCEPTED: Hash đúng -> giải mã thành công -> lưu file.` Mở file theo đường dẫn Bob in ra trong thư mục `received/bob`.

`QUEUED` chỉ là đã ghi gói vào thư mục chờ. **ACCEPTED tại bên nhận mới xác nhận file đã được giải mã và lưu.**

### Bước B - Bob gửi lại cho Alice

Tại Bob:

```text
send samples/phan_hoi.txt
```

File nhận thành công nằm trong `received/alice`. Bộ đếm gửi của Bob độc lập với bộ đếm gửi của Alice.

### Bước C - Gửi file sai hash

Tại Alice:

```text
bad-hash samples/loi_chao.txt
```

Bob báo `REJECTED`, lý do `HASH_MISMATCH`. Không có file kết quả mới trong `received/bob`; bộ đếm nhận không tăng.

### Bước D - Gửi lại bản đúng

Tại Alice:

```text
resend
```

Bob nhận được đúng bản gốc của gói vừa bị lỗi, xác minh hash rồi giải mã. Sau đó có thể gửi file tiếp theo.

### Bước E - Chứng minh gói phát lại bị loại

Tại Alice, gõ `resend` lần nữa sau khi Bob đã nhận thành công. Bob báo `REPLAY`; không tạo file kết quả lần hai.

### Những tình huống khác

| Lệnh | Hành vi |
| --- | --- |
| `bad-data samples/loi_chao.txt` | Lật một bit trong bản mã, giữ nguyên hash |
| `bad-key samples/loi_chao.txt` | Sửa khóa đã che, giữ nguyên hash |
| `bad-iv samples/loi_chao.txt` | Sửa IV của AES-CBC, giữ nguyên hash |
| `resend 2` | Gửi lại gói số 2 từ bộ nhớ đệm bản gốc |
| `status` | Xem trạng thái phiên, số gói tiếp theo, hash gần nhất, khóa đã che |
| `connect` | Alice gửi lại hello nếu chưa nhận được phản hồi |
| `help` | Hiển thị danh sách lệnh |
| `quit` | Thoát chương trình |

Sau mỗi tình huống cố ý làm sai, dùng `resend` cho đến khi gói được nhận rồi mới tiếp tục gửi mới. Nếu đã gửi vượt một gói còn thiếu, xem `next_receive` của bên nhận và dùng `resend <số gói>` theo đúng thứ tự. Gói đến sớm bị từ chối, không tự lưu đợi.

## 4. Gửi file của bạn

Ví dụ:

```text
send "C:\Users\TenBan\Desktop\bai tap.pdf"
```

Chương trình xử lý file như dữ liệu nhị phân nên dùng được với TXT, PDF, PNG, DOCX, ZIP... Giới hạn mặc định **5 MiB/file**. Tên file cần tối đa 160 ký tự và 180 byte UTF-8; nếu tên quá dài hãy đổi ngắn hơn. File được đặt tiền tố số gói và mã ngẫu nhiên khi nhận để không đè file cùng tên.

Tên file và thông tin người gửi/nhận hiện trong JSON; chỉ **nội dung file** được mã hóa. Tên có khoảng trắng cần đặt trong dấu ngoặc kép.

## 5. Có những loại config.json nào?

| Vị trí | Nội dung | Có bí mật? |
| --- | --- | --- |
| `config.json` tại thư mục dự án | Thuật toán, số bit khóa, giới hạn file, chu kỳ kiểm tra thư mục | Không |
| `runtime/alice/config.json` hoặc `runtime/bob/config.json` | K2, IV giao thức, bộ đếm, hash/khóa đã che của lần gửi gần nhất | **Có**, lưu riêng theo bên |
| `wire/to_bob/<mã-gói>.packet/config.json` | Gói đang đi Alice -> Bob | Có bản mã và khóa đã che, không có K2/khóa file dạng rõ |
| `wire/to_alice/<mã-gói>.packet/config.json` | Gói đang đi Bob -> Alice | Tương tự |
| `runtime/<bên>/sent/<số-gói>/config.json` | Bản gốc đã gửi để dùng khi gửi lại | Không có khóa file dạng rõ |
| `runtime/<bên>/processed/.../config.json` | Gói đã xử lý thành công | Dùng để xem lại demo |
| `runtime/<bên>/rejected/.../config.json` | Gói bị loại, giữ làm bằng chứng kiểm tra | Không có file được giải mã từ gói lỗi |

Mỗi lần gửi dùng một thư mục riêng nhưng **chỉ có một file JSON truyền tải là `config.json`**, trong đó bản mã được biểu diễn bằng Base64. Việc ghi vào thư mục tạm rồi đổi tên giúp bên nhận không đọc nửa chừng một gói đang ghi.

Bên nhận thường lấy gói khỏi `wire` rất nhanh. Muốn xem JSON sau demo, mở bản trong `sent`, `processed` hoặc `rejected`.

**Không gửi khóa K2 hoặc khóa AES dạng rõ cùng bản mã.** Trường `wrapped_key` là kết quả XOR theo công thức bài báo. IV của giao thức là bí mật và chỉ được trao đổi ở giai đoạn thiết lập; `cbc_iv` là IV khác, dài 16 byte, được sinh mới và gửi ở mỗi gói dữ liệu.

## 6. Chạy tự động và kiểm thử

- `3_DEMO_TU_DONG.cmd`: tự chạy 13 kiểm tra gồm trao đổi khóa, gửi hai chiều, bốn kiểu sửa gói, gửi lại và chống phát lại.
- `4_KIEM_THU.cmd`: chạy bộ 36 bài kiểm thử bằng `unittest`.

Tương đương:

```text
python demo.py
python -m unittest discover -s tests -v
```

Demo tự động tạo phiên riêng tại `demos/<thời-điểm>_<mã>/`; không đụng vào phiên CMD đang dùng. File `demo_results.json` chứa kết quả, số byte và SHA-256 của các file đã nhận. Xem chứng cứ bàn giao tại `docs/KET_QUA_KIEM_THU.txt`.

Mặc định dùng 128 bit để bám kích thước trong bài báo. Để xem bản mở rộng AES-256-CBC:

```text
python demo.py --key-bits 256
```

Muốn chạy hai CMD ở chế độ 256 bit, giải nén sang **thư mục mới**, đổi `key_bits` thành `256` trong config gốc **trước khi** chạy `0_CAI_DAT.cmd`. Độ rộng XOR, A-word, B-word và IV giao thức cũng thành 256 bit; đây là điều chỉnh của demo, không phải kích thước nguyên bản trong bài báo. IV AES-CBC vẫn luôn là 128 bit.

## 7. Lỗi thường gặp

| Hiện tượng | Cách xử lý |
| --- | --- |
| Không nhận diện `python` hoặc `py` | Cài Python, bật PATH, mở lại CMD |
| `No module named cryptography` | Chạy `0_CAI_DAT.cmd`; dùng Python trong `.venv` |
| `NO_SESSION` | Mở đủ Alice/Bob, đợi `SESSION_READY`; tại Alice thử `connect` |
| `OUT_OF_ORDER` | Bên nhận đang thiếu gói; dùng `resend <next_receive>` rồi gửi lại các gói phía sau |
| `REPLAY` | Gói đó đã nhận; đây là kết quả mong đợi nếu đang demo gửi lặp |
| `LOCKED` | Đóng cửa sổ trùng vai Alice/Bob rồi mở lại |
| `CONFIG` sau khi sửa key_bits | Dùng thư mục giải nén mới; không đổi thông số mật mã giữa phiên |
| `IO_ERROR` | Kiểm tra dung lượng/quyền ghi và đường dẫn; xem log, mở lại ứng dụng sau khi khắc phục |
| Dòng thông báo nhận chen vào dấu nhắc | Đây là bộ nhận chạy nền. Nhấn Enter để hiện lại dấu nhắc; lệnh vẫn được xử lý |

Muốn một phiên hoàn toàn mới, giải nén lại sang thư mục khác. Bộ cài không tự xóa các file đã nhận hoặc khóa cũ.

## 8. Đọc mã nguồn ở đâu?

| File | Vai trò |
| --- | --- |
| `rke/crypto.py` | Công thức RS/XOR, AES-CBC, SHA-256, gói thiết lập RSA |
| `rke/peer.py` | Alice/Bob, trạng thái phiên, thư mục truyền file, gửi lại, chặn gói lặp |
| `rke/cli.py` | Lệnh tương tác và luồng nhận nền |
| `alice.py`, `bob.py` | Điểm chạy hai bên |
| `setup_demo.py` | Chuẩn bị khóa và thư mục local |
| `demo.py` | Kịch bản minh họa tự động |
| `tests/test_protocol.py` | 36 kiểm thử hành vi và biên xác minh hash |
| `docs/GIAI_THICH_GIAO_THUC.md` | Công thức, cấu trúc JSON, phần khác với bài báo |
| `docs/KICH_BAN_TRINH_BAY.md` | Kịch bản trình bày demo khoảng 5 phút |

## Tài liệu tham khảo

1. Pirzada, S. J. H., Memon, Z. W., Xu, T., & Jianwei, L. (2020). *Randomized Key Exchange Protocol Implementation for Internet of Things Application*. 2020 14th International Conference on Open Source Systems and Technologies (ICOSST). DOI: https://doi.org/10.1109/ICOSST51357.2020.9332930. Nguồn chính là PDF người dùng cung cấp, phần III và Hình 1-2, trang 2-3.
2. Python: `secrets`, https://docs.python.org/3/library/secrets.html.
3. Cryptography: AES/CBC, https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/.
4. Cryptography: RSA/OAEP/PSS, https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/.
