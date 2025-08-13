import difflib
from bs4 import BeautifulSoup

class AIAnalyzer:
    """
    Engine Phân tích được thiết kế lại, tập trung vào phương pháp so sánh
    sự khác biệt (Differential Analysis) để phát hiện các bất thường.
    """

    def __init__(self):
        # Giữ lại một số chuỗi lỗi SQL/Server rõ ràng để phát hiện nhanh
        self.quick_error_indicators = [
            # SQL Errors
            "you have an error in your sql syntax", "warning: mysql",
            "unclosed quotation mark", "syntax error", "unknown column",
            "ora-00933", "invalid sql statement", "odbc driver error",
            # Path Traversal / File Inclusion Errors
            "failed to open stream", "no such file or directory", "include(",
            # Command Injection Indicators (nếu output trực tiếp)
            "permission denied", "command not found"
        ]

    def _get_text_from_html(self, html_content):
        """Trích xuất văn bản thuần túy từ HTML để so sánh, loại bỏ script và style."""
        soup = BeautifulSoup(html_content, 'html.parser')
        for script in soup(["script", "style"]):
            script.extract()
        return " ".join(soup.get_text().split())

    def analyze_response_for_vuln(self, base_response, test_response, payload, vuln_type):
        """
        Phân tích và so sánh hai phản hồi để tìm dấu hiệu của lỗ hổng.

        :param base_response: Phản hồi HTTP gốc (không có payload).
        :param test_response: Phản hồi HTTP sau khi tiêm payload.
        :param payload: Payload đã được sử dụng.
        :param vuln_type: Loại lỗ hổng đang được kiểm tra ('xss', 'sqli', 'cmdi', etc.).
        :return: Tuple (is_vulnerable, evidence, confidence_score).
        """
        
        test_response_text = test_response.text.lower()
        
        # 1. Kiểm tra các dấu hiệu lỗi rõ ràng (phát hiện nhanh)
        for error in self.quick_error_indicators:
            if error in test_response_text:
                return (True, f"Phản hồi chứa chuỗi lỗi kinh điển: '{error}'", 0.95)

        # 2. Kiểm tra sự phản chiếu trực tiếp của payload (chủ yếu cho XSS)
        if vuln_type == 'xss':
            # Nếu payload xuất hiện nguyên vẹn trong HTML, đó là dấu hiệu XSS rất mạnh
            if payload.lower() in test_response_text:
                 return (True, f"Payload '{payload}' được phản chiếu trực tiếp trong phản hồi.", 0.90)

        # 3. Phân tích so sánh sự khác biệt (Differential Analysis)

        # So sánh mã trạng thái HTTP
        if base_response.status_code != test_response.status_code:
            # Ví dụ: trang đang hoạt động (200) bỗng dưng lỗi (500) là dấu hiệu mạnh
            if base_response.status_code == 200 and test_response.status_code >= 500:
                 return (True, f"Mã trạng thái thay đổi từ {base_response.status_code} thành {test_response.status_code}, cho thấy lỗi server.", 0.85)
            # Một số WAF (Web Application Firewall) có thể trả về 403 khi phát hiện payload
            if base_response.status_code == 200 and test_response.status_code == 403:
                 return (True, f"Mã trạng thái thay đổi thành 403 (Forbidden), có thể do WAF chặn payload.", 0.60)


        # So sánh nội dung HTML
        base_text = self._get_text_from_html(base_response.text)
        test_text = self._get_text_from_html(test_response.text)
        
        # Nếu không có sự khác biệt nào về nội dung, gần như chắc chắn không có lỗ hổng
        if base_text == test_text:
            return (False, None, 0.0)
            
        # Sử dụng difflib để tính toán tỷ lệ khác biệt
        diff_ratio = difflib.SequenceMatcher(None, base_text, test_text).ratio()

        # Nếu nội dung gần như giống hệt nhau, bỏ qua
        if diff_ratio > 0.98:
            return (False, None, 0.0)

        # Nếu có sự khác biệt đáng kể, đây là một dấu hiệu cần xem xét
        # Ngưỡng này có thể cần được tinh chỉnh sau khi thử nghiệm thực tế
        if diff_ratio < 0.95: 
            return (True, f"Nội dung phản hồi thay đổi đáng kể (tỷ lệ tương đồng: {diff_ratio:.2f}) sau khi tiêm payload.", 0.75)

        return (False, None, 0.0)