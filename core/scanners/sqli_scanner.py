# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/core/scanners/sqli_scanner.py
from .base_scanner import BaseScanner
from core.ai_analyzer import AIAnalyzer
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import requests

class SQLIScanner(BaseScanner):
    @property
    def name(self):
        return 'sqli'

    def __init__(self, session, payloads):
        super().__init__(session, payloads)
        self.ai_analyzer = AIAnalyzer()

    def scan(self, target):
        """Điều phối việc quét SQLi, giờ đây đã hỗ trợ cả URL và FORM."""
        if target['type'] == 'url':
            return self._scan_get_url(target['value'])
        
        elif target['type'] == 'form':
            form_details = target['value']
            if form_details['method'] == 'get':
                base_url = form_details['url']
                inputs = form_details['inputs']
                # Tạo một URL giả lập với các tham số từ form
                test_data = {inp['name']: '1' for inp in inputs if inp.get('name')} # Giả lập giá trị là '1'
                if not test_data:
                    return []
                full_url_to_scan = f"{base_url}?{urlencode(test_data)}"
                return self._scan_get_url(full_url_to_scan)
        return []

    def _scan_get_url(self, url):
        found_vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []

        print(f"  -> Bắt đầu quét SQLI trên: {url}")

        for param in list(params.keys()):
            # Bỏ qua các tham số không có khả năng bị tấn công
            if param.lower() in ['submit', 'button', 'login', 'search']:
                continue

            is_param_vulnerable = False

            # --- Phương pháp 1: Dựa trên lỗi (Error-Based) ---
            for payload in self.payloads:
                modified_params = params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))
                
                try:
                    test_response = self.session.get(new_url, timeout=7)
                    if "login.php" in test_response.url: continue

                    base_response_dummy = requests.Response()
                    base_response_dummy.status_code = 200
                    
                    is_vulnerable, evidence, confidence = self.ai_analyzer.analyze_response_for_vuln(
                        base_response_dummy, test_response, payload, self.name
                    )

                    if is_vulnerable and ("sql" in evidence.lower() or "syntax" in evidence.lower()):
                        print(f"  [+] SQLI VULN (ERROR-BASED) CONFIRMED! URL: {url}, Param: {param}")
                        found_vulnerabilities.append({
                            'url': url, 'type': self.name.upper(), 'payload': payload,
                            'evidence': evidence, 'ai_confidence': confidence, 'method': 'GET'
                        })
                        is_param_vulnerable = True
                        break 
                
                except requests.RequestException:
                    time.sleep(0.1)
                    continue
            
            if is_param_vulnerable:
                continue

            # --- Phương pháp 2: Dựa trên logic (Boolean-Based Blind) ---
            # (Phần này có thể bỏ qua để tăng tốc độ nếu phương pháp trên đã đủ tốt)

        return found_vulnerabilities