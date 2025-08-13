import http.server
import socketserver
import urllib.parse
import subprocess
import os

# --- Cấu hình ---
HOST = "localhost"
PORT = 8000

class VulnerableTestHandler(http.server.BaseHTTPRequestHandler):
    """
    Một trình xử lý request web chứa các lỗ hổng có chủ đích để kiểm thử.
    """

    def _send_response(self, content, content_type="text/html; charset=utf-8"):
        """Hàm trợ giúp để gửi phản hồi HTTP 200."""
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(bytes(content, "utf-8"))

    def do_GET(self):
        """Xử lý các request GET."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        print(f"[INFO] Received GET request for: {self.path}")

        # === Endpoint cho Cross-Site Scripting (XSS) ===
        if path == '/xss':
            name = query_params.get('name', ['Guest'])[0]
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Test XSS</title></head>
            <body>
                <h1>Welcome, {name}</h1>
                <p>Trang này phản chiếu tham số 'name' từ URL.</p>
            </body>
            </html>
            """
            self._send_response(html_content)

        # === Endpoint cho SQL Injection (SQLi) ===
        elif path == '/sqli':
            user_id = query_params.get('id', [''])[0]
            # Mô phỏng lỗi SQL khi payload chứa dấu nháy đơn
            if "'" in user_id:
                error_message = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''"
                self._send_response(error_message, "text/plain")
            else:
                self._send_response(f"Querying data for user ID: {user_id}", "text/plain")

        # === Endpoint cho Command Injection ===
        elif path == '/cmdi':
            host = query_params.get('host', ['127.0.0.1'])[0]
            
            # Phân tách lệnh để an toàn hơn một chút trong môi trường test
            # nhưng vẫn dễ bị tấn công bởi payload như "; id"
            command = f"ping -c 1 {host}"
            
            try:
                # Thực thi lệnh và lấy kết quả
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            except subprocess.CalledProcessError as e:
                output = e.output

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Test Command Injection</title></head>
            <body>
                <h1>Ping Result:</h1>
                <pre>{output}</pre>
            </body>
            </html>
            """
            self._send_response(html_content)

        # === Endpoint cho File Inclusion / Directory Traversal ===
        elif path == '/fi':
            page = query_params.get('page', ['home.txt'])[0]
            
            # Cố gắng đọc file được yêu cầu
            try:
                # Để an toàn, chỉ cho phép đọc từ thư mục hiện tại trong môi trường test này
                # Máy quét vẫn sẽ thử các payload như ../../../etc/passwd
                with open(page, 'r') as f:
                    file_content = f.read()
                self._send_response(file_content, "text/plain")
            except FileNotFoundError:
                # Mô phỏng lỗi mà máy quét sẽ tìm kiếm
                error_message = f"Warning: include({page}): failed to open stream: No such file or directory in /var/www/html/index.php on line 10"
                self._send_response(error_message, "text/plain")
            except Exception as e:
                self._send_response(f"An error occurred: {e}", "text/plain")
        
        # === Trang chủ mặc định ===
        else:
            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Vulnerable Test Server</title></head>
            <body style="font-family: sans-serif; line-height: 1.6;">
                <h1>Chào mừng đến với Máy chủ Kiểm thử Lỗ hổng</h1>
                <p>Sử dụng các URL sau để kiểm thử máy quét của bạn:</p>
                <ul>
                    <li>
                        <strong>XSS:</strong>
                        <a href="/xss?name=<b>World</b>">/xss?name=&lt;b&gt;World&lt;/b&gt;</a>
                    </li>
                    <li>
                        <strong>SQL Injection:</strong>
                        <a href="/sqli?id=1">/sqli?id=1</a>
                    </li>
                    <li>
                        <strong>Command Injection:</strong>
                        <a href="/cmdi?host=127.0.0.1">/cmdi?host=127.0.0.1</a>
                    </li>
                    <li>
                        <strong>File Inclusion:</strong>
                        <a href="/fi?page=example.txt">/fi?page=example.txt</a>
                        <p>(Bạn cần tạo một tệp có tên <code>example.txt</code> trong cùng thư mục)</p>
                    </li>
                </ul>
            </body>
            </html>
            """
            self._send_response(html_content)

if __name__ == "__main__":
    # Tạo một tệp ví dụ để kiểm thử File Inclusion
    with open("example.txt", "w", encoding="utf-8") as f:
      f.write("Đây là nội dung của tệp ví dụ.")


    with socketserver.TCPServer((HOST, PORT), VulnerableTestHandler) as httpd:
        print(f"--- Máy chủ kiểm thử lỗ hổng đang chạy tại: http://{HOST}:{PORT} ---")
        print("Nhấn CTRL+C để dừng máy chủ.")
        httpd.serve_forever()