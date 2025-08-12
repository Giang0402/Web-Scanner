from bs4 import BeautifulSoup

class AIAnalyzer:
    """
    Module AI được nâng cấp toàn diện, tinh chỉnh để nhận biết các dấu hiệu
    lỗ hổng đặc trưng của môi trường DVWA mà không cần so sánh.
    """
    def __init__(self):
        self.sql_errors = [
            "you have an error in your sql syntax", "warning: mysql", 
            "unclosed quotation mark", "syntax error", "unknown column"
        ]
        self.cmd_injection_indicators = ["uid=", "gid=", "groups=", "etc/passwd", "root:x:0:0", "64 bytes from"]
        self.dir_traversal_indicators = [
            "root:x:0:0", "[boot loader]", "users on this computer", 
            "[fonts]", "for 16-bit app support"
        ]

    def analyze(self, response, payload, vuln_type):
        """
        Phân tích phản hồi và trả về (is_vulnerable, evidence, confidence_score).
        """
        content = response.text.lower()
        confidence = 0.0
        evidence = ""

        if vuln_type == 'xss':
            if payload.lower() in content:
                confidence = 0.98
                evidence = f"Payload XSS '{payload}' được phản chiếu lại trong trang."
                return True, evidence, confidence

        elif vuln_type == 'sqli':
            for error in self.sql_errors:
                if error in content:
                    confidence = 0.95
                    evidence = f"Tìm thấy thông báo lỗi SQL: '{error}'."
                    return True, evidence, confidence
            
            if '<pre>id' in content and 'surname' in content and 'first name' in content:
                confidence = 0.9
                evidence = "Phản hồi chứa bảng kết quả (ID, First name, Surname), dấu hiệu của SQLi thành công."
                return True, evidence, confidence

        elif vuln_type == 'cmdi':
            soup = BeautifulSoup(response.text, 'html.parser')
            pre_content = "".join(tag.text for tag in soup.find_all('pre')).lower()
            if pre_content:
                for indicator in self.cmd_injection_indicators:
                    if indicator in pre_content:
                        confidence = 0.9
                        evidence = f"Tìm thấy dấu hiệu thực thi lệnh '{indicator}' bên trong thẻ <pre>."
                        return True, evidence, confidence
                if 'total' in pre_content and 'drwxr-xr-x' in pre_content:
                    confidence = 0.8
                    evidence = "Phản hồi chứa cấu trúc thư mục, có thể là kết quả của lệnh 'ls'."
                    return True, evidence, confidence

        elif vuln_type == 'dirtraversal' or vuln_type == 'fi': # Hỗ trợ cả file inclusion
            for indicator in self.dir_traversal_indicators:
                if indicator in content:
                    confidence = 0.95
                    evidence = f"Tìm thấy nội dung file hệ thống nhạy cảm: '{indicator}'."
                    return True, evidence, confidence
            if "warning: include(" in content and ("failed to open stream" in content or "no such file or directory" in content):
                confidence = 0.7
                evidence = "Tìm thấy lỗi PHP 'include failed to open stream', dấu hiệu của nỗ lực tấn công File Inclusion."
                return True, evidence, confidence
            
        return False, None, 0.0
