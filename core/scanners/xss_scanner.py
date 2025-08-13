# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/core/scanners/xss_scanner.py
from .base_scanner import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import requests
import re

class XSSScanner(BaseScanner):
    @property
    def name(self):
        return 'xss'

    def _is_payload_reflected(self, content, payload):
        """Kiểm tra xem payload có thực sự được phản chiếu trong nội dung hay không."""
        normalized_content = re.sub(r'[^a-z0-9]', '', content.lower())
        normalized_payload = re.sub(r'[^a-z0-9]', '', payload.lower())
        return normalized_payload in normalized_content

    def scan(self, target):
        """
        Điều phối việc quét dựa trên loại mục tiêu.
        Giờ đây đã có thể xử lý cả URL và Form.
        """
        if target['type'] == 'url':
            return self._scan_get_url(target['value'])
        
        # === LOGIC MỚI ĐỂ XỬ LÝ FORM ===
        elif target['type'] == 'form':
            form_details = target['value']
            # Nếu là form GET, chúng ta chuyển nó thành một URL để quét
            if form_details['method'] == 'get':
                base_url = form_details['url']
                inputs = form_details['inputs']
                # Tạo một URL giả lập với các tham số từ form
                test_data = {inp['name']: 'test' for inp in inputs if inp.get('name')}
                if not test_data:
                    return []
                full_url_to_scan = f"{base_url}?{urlencode(test_data)}"
                return self._scan_get_url(full_url_to_scan)
            # Bạn có thể thêm logic cho form POST ở đây nếu cần
            # elif form_details['method'] == 'post':
            #     return self._scan_post_form(form_details)
        
        return []

    def _scan_get_url(self, url):
        found_vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []

        try:
            # Sử dụng URL gốc (không có query string) để lấy base_response
            # Điều này giúp so sánh chính xác hơn
            base_url_no_query = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""))
            base_response = self.session.get(base_url_no_query, timeout=7, allow_redirects=True)
            if "login.php" in base_response.url:
                return []
        except requests.RequestException:
            return []

        for param in list(params.keys()):
            for payload in self.payloads:
                modified_params = params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))
                
                try:
                    test_response = self.session.get(new_url, timeout=7, allow_redirects=True)
                    if "login.php" in test_response.url: continue

                    content_type = test_response.headers.get('Content-Type', '')
                    is_html = 'text/html' in content_type.lower()
                    
                    if self._is_payload_reflected(test_response.text, payload) and is_html:
                        evidence = f"Payload '{payload}' được phản chiếu trong phản hồi HTML của trang."
                        # Sử dụng URL gốc trong báo cáo để dễ đọc hơn
                        print(f"  [+] XSS VULN CONFIRMED! URL: {url}, Param: {param}")
                        found_vulnerabilities.append({
                            'url': url, 
                            'type': self.name.upper(), 
                            'payload': payload, 
                            'evidence': evidence, 
                            'ai_confidence': 0.98,
                            'method': 'GET'
                        })
                        break
                
                except requests.RequestException:
                    time.sleep(0.1)
                    continue
        return found_vulnerabilities