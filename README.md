Web Vulnerability Scanner - Phiên bản Nâng cấp Chuyên nghiệp
Đây là một ứng dụng quét lỗ hổng web được xây dựng bằng Flask và Celery, được thiết kế để tự động hóa việc phát hiện các lỗ hổng bảo mật phổ biến. Phiên bản này đã được nâng cấp với các tính năng chuyên nghiệp, bao gồm phân tích dựa trên AI, trực quan hóa dữ liệu và một bộ quét mạnh mẽ hơn.

Tính năng nổi bật
Giao diện Web Hiện đại: Giao diện người dùng trực quan được xây dựng bằng Tailwind CSS để quản lý và xem kết quả quét.

Xử lý Tác vụ Nền: Sử dụng Celery và Redis để thực hiện các tác vụ quét nặng mà không làm ảnh hưởng đến trải nghiệm người dùng.

Bộ quét Nâng cao:

Hỗ trợ quét các lỗ hổng: SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, và Directory Traversal.

Quét cả tham số GET và các form POST.

Sử dụng danh sách payload từ tệp tin, dễ dàng mở rộng.

Phân tích bằng AI: Tích hợp một module AI đơn giản để phân tích các phản hồi bất thường từ server, tăng khả năng phát hiện và cung cấp "Điểm tin cậy AI".

Trực quan hóa Dữ liệu: Kết quả quét được hiển thị dưới dạng biểu đồ (sử dụng Chart.js) giúp dễ dàng nắm bắt tình hình.

Bảo mật và Chuyên nghiệp: Quản lý thông tin nhạy cảm bằng biến môi trường (file .env).

Công nghệ sử dụng
Backend: Python, Flask, Celery

Frontend: HTML, Tailwind CSS, JavaScript, Chart.js

Cơ sở dữ liệu: SQLite (có thể dễ dàng đổi sang PostgreSQL hoặc MySQL)

Message Broker: Redis

Thư viện Python chính: requests, beautifulsoup4, sqlalchemy, redis, celery

Hướng dẫn Cài đặt và Chạy dự án
Yêu cầu tiên quyết
Python 3.8+

Redis Server đã được cài đặt và đang chạy trên máy của bạn.

Một môi trường web để thử nghiệm (ví dụ: DVWA chạy trên Docker).

Các bước cài đặt

1. Clone repository:

git clone <your-repo-url>
cd <your-repo-folder>

2. Tạo và kích hoạt môi trường ảo (khuyến khích):

python -m venv venv
source venv/bin/activate # Trên Windows: venv\Scripts\activate

3. Cài đặt các thư viện cần thiết:

pip install -r requirements.txt

4. Cấu hình biến môi trường:

Sao chép tệp .env.example thành .env:

cp .env.example .env

Mở tệp .env và chỉnh sửa các giá trị cho phù hợp với môi trường của bạn (đặc biệt là thông tin đăng nhập DVWA).

5. Khởi tạo cơ sở dữ liệu:
   Chạy lệnh sau để tạo các bảng trong file scanner.db:

python create_db.py

6. Khởi động Celery Worker:
   Mở một cửa sổ terminal mới, kích hoạt môi trường ảo và chạy lệnh sau:

celery -A task.celery worker --loglevel=info --pool=eventlet

Lưu ý: --pool=eventlet rất quan trọng để Celery hoạt động tốt với các tác vụ mạng.

7. Khởi động ứng dụng Flask:
   Mở một cửa sổ terminal khác, kích hoạt môi trường ảo và chạy:

flask run

8. Truy cập ứng dụng:
   Mở trình duyệt và truy cập vào http://127.0.0.1:5000. Bây giờ bạn có thể bắt đầu quá trình quét!
