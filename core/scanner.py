import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import Config
from .ai_analyzer import AIAnalyzer
import os
import time

class Scanner:
    def __init__(self, session):
        self.session = session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        })
        self.ai_analyzer = AIAnalyzer()
        self.payloads = self._load_payloads()
        self.field_blacklist = ['submit', 'button', 'login', 'reset', 'search', 'seclev_submit', 'create_db']

    def _load_payloads(self):
        payloads = {}
        payload_dir = os.path.join(os.path.dirname(__file__), '..', 'payloads')
        if not os.path.isdir(payload_dir):
            print(f"[ERROR] Thư mục payloads không tồn tại tại: {payload_dir}")
            return {}
        for filename in os.listdir(payload_dir):
            if filename.endswith('.txt'):
                vuln_type = filename.split('.')[0]
                with open(os.path.join(payload_dir, filename), 'r', encoding='utf-8') as f:
                    payloads[vuln_type] = [line.strip() for line in f if line.strip()]
        return payloads

    def login(self):
        try:
            login_page_resp = self.session.get(Config.TARGET_LOGIN_URL, timeout=10)
            if login_page_resp.status_code != 200:
                return {'success': False, 'message': f"Không thể truy cập trang đăng nhập, status: {login_page_resp.status_code}"}
            soup = BeautifulSoup(login_page_resp.text, 'html.parser')
            user_token_tag = soup.find('input', {'name': 'user_token'})
            if not user_token_tag: return {'success': False, 'message': "Không tìm thấy user_token trên trang đăng nhập."}
            user_token = user_token_tag['value']
            
            login_data = {'username': Config.TARGET_USERNAME, 'password': Config.TARGET_PASSWORD, 'Login': 'Login', 'user_token': user_token}
            response = self.session.post(Config.TARGET_LOGIN_URL, data=login_data, allow_redirects=True, timeout=10)

            if "login.php" in response.url or "index.php" not in response.url:
                return {'success': False, 'message': "Đăng nhập thất bại. Kiểm tra lại thông tin đăng nhập hoặc logic."}

            # **BẢN VÁ QUAN TRỌNG: Thêm Referer để duy trì session**
            self.session.headers.update({'Referer': response.url})

            security_page_resp = self.session.get(Config.TARGET_SECURITY_URL, timeout=10)
            soup = BeautifulSoup(security_page_resp.text, 'html.parser')
            security_token_tag = soup.find('input', {'name': 'user_token'})
            if not security_token_tag: return {'success': False, 'message': "Không tìm thấy user_token trên trang security."}
            security_token = security_token_tag['value']
            
            security_data = {'security': 'low', 'seclev_submit': 'Submit', 'user_token': security_token}
            response_sec = self.session.post(Config.TARGET_SECURITY_URL, data=security_data, timeout=10)
            
            if "security level set to low" not in response_sec.text.lower():
                return {'success': True, 'security_set': False, 'message': "Đăng nhập thành công nhưng KHÔNG THỂ đặt security level thành 'low'."}
            
            return {'success': True, 'security_set': True, 'message': "Đăng nhập và thiết lập security thành công."}
        except requests.exceptions.RequestException as e: return {'success': False, 'message': f"Lỗi mạng khi đăng nhập: {e}"}
        except Exception as e: return {'success': False, 'message': f"Lỗi nghiêm trọng khi đăng nhập: {e}"}

    def _scan_target(self, url, method='get', data=None, vuln_type='xss'):
        found_vulnerabilities = []
        payload_list = self.payloads.get(vuln_type, [])
        
        # Đối với phương thức GET
        if method == 'get':
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if not params:
                return [] # Không có tham số để quét, trả về danh sách rỗng

            # Lặp qua TỪNG tham số
            for param in params:
                if param.lower() in self.field_blacklist:
                    continue
                
                # Lặp qua TỪNG payload cho tham số đó
                for payload in payload_list:
                    try:
                        modified_params = params.copy()
                        modified_params[param] = (payload,)
                        modified_query = urlencode(modified_params, doseq=True)
                        new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))
                        response = self.session.get(new_url, timeout=5)

                        if response and "login.php" not in response.url:
                            is_vulnerable, evidence, confidence = self.ai_analyzer.analyze(response, payload, vuln_type)
                            if is_vulnerable:
                                print(f"  [VULN FOUND!] Type: {vuln_type.upper()}, Evidence: {evidence}")
                                found_vulnerabilities.append({'url': url, 'type': vuln_type.upper(), 'payload': payload, 'evidence': evidence, 'ai_confidence': confidence, 'method': method.upper()})
                                # ĐÃ XÓA LỆNH RETURN Ở ĐÂY để vòng lặp tiếp tục
                    except requests.exceptions.RequestException:
                        time.sleep(0.1)
                        continue
        
        # Đối với phương thức POST (cần sửa tương tự)
        elif method == 'post' and data:
            for key in data.keys():
                if key.lower() in self.field_blacklist or 'token' in key.lower():
                    continue
                
                for payload in payload_list:
                    try:
                        # Lấy token mới cho mỗi lần request để tránh lỗi CSRF
                        fresh_token = ''
                        try:
                            fresh_page_resp = self.session.get(url, timeout=5)
                            soup = BeautifulSoup(fresh_page_resp.text, 'html.parser')
                            token_tag = soup.find('input', {'name': 'user_token'})
                            fresh_token = token_tag['value'] if token_tag else ''
                        except Exception:
                            pass # Bỏ qua nếu không lấy được token

                        modified_data = data.copy()
                        modified_data[key] = payload
                        if 'user_token' in modified_data and fresh_token:
                            modified_data['user_token'] = fresh_token
                        
                        response = self.session.post(url, data=modified_data, timeout=5)

                        if response and "login.php" not in response.url:
                            is_vulnerable, evidence, confidence = self.ai_analyzer.analyze(response, payload, vuln_type)
                            if is_vulnerable:
                                print(f"  [VULN FOUND!] Type: {vuln_type.upper()}, Evidence: {evidence}")
                                found_vulnerabilities.append({'url': url, 'type': vuln_type.upper(), 'payload': payload, 'evidence': evidence, 'ai_confidence': confidence, 'method': method.upper()})
                                # ĐÃ XÓA LỆNH RETURN Ở ĐÂY
                    except requests.exceptions.RequestException:
                        time.sleep(0.1)
                        continue

        # Hàm chỉ trả về kết quả ở đây, sau khi tất cả các vòng lặp đã hoàn thành
        return found_vulnerabilities

    def run_scan(self, targets):
        all_vulnerabilities = []
        url_blacklist = ['/login.php', '/logout.php', '/setup.php']

        for i, target in enumerate(targets):
            target_url = target['value']['url'] if target['type'] == 'form' else target['value']
            
            if any(blacklisted_path in target_url for blacklisted_path in url_blacklist):
                continue

            print(f"[*] Đang quét mục tiêu {i+1}/{len(targets)}: {target_url}")
            
            if target['type'] == 'url':
                for vuln_type in self.payloads.keys():
                    all_vulnerabilities.extend(self._scan_target(url=target_url, vuln_type=vuln_type, method='get'))
            
            elif target['type'] == 'form':
                form_details = target['value']
                url = form_details['url']
                method = form_details['method']
                
                if method == 'get':
                    try:
                        base_data = {inp['name']: inp.get('value', 'test') for inp in form_details['inputs']}
                        query_string = urlencode(base_data)
                        full_url_with_params = f"{url}?{query_string}"
                        for vuln_type in self.payloads.keys():
                            all_vulnerabilities.extend(self._scan_target(url=full_url_with_params, vuln_type=vuln_type, method='get'))
                    except Exception as e:
                        print(f"[SCANNER ERROR] Không thể tạo URL cho form GET: {e}")

                elif method == 'post':
                    data = {inp['name']: inp.get('value', 'test') for inp in form_details['inputs']}
                    for vuln_type in self.payloads.keys():
                        all_vulnerabilities.extend(self._scan_target(url=url, method=method, data=data, vuln_type=vuln_type))
                    
        return all_vulnerabilities
