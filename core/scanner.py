import os
import importlib
import requests
from bs4 import BeautifulSoup
from config import Config
from core.scanners.base_scanner import BaseScanner

class Scanner:
    """
    Lớp điều phối chính. Tải tất cả các plugin quét và điều phối việc quét.
    """
    def __init__(self, session, scan_config=None):
        self.session = session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        })
        
        # Áp dụng cấu hình xác thực nếu có
        if scan_config and 'auth' in scan_config:
            auth_config = scan_config['auth']
            if auth_config.get('cookie'):
                self.session.headers.update({'Cookie': auth_config['cookie']})
                print("[INFO] Đã áp dụng Session Cookie vào header.")
            if auth_config.get('header'):
                self.session.headers.update({'Authorization': auth_config['header']})
                print("[INFO] Đã áp dụng Authorization Header.")

        self.payloads = self._load_payloads()
        
        # Chỉ tải các plugin được yêu cầu trong chính sách
        enabled_plugins = scan_config.get('policy', {}).get('plugins') if scan_config else None
        self.scanners = self._load_scanners(enabled_plugins)
        
        if not hasattr(self, 'already_printed_info'): # Tránh in nhiều lần
            print(f"[INFO] Đã tải thành công {len(self.scanners)} plugin quét: {[s.name for s in self.scanners]}")
            self.already_printed_info = True


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

    def _load_scanners(self, enabled_plugins=None):
        """Tải các plugin, có thể lọc theo danh sách cho phép."""
        scanners = []
        scanner_dir = os.path.join(os.path.dirname(__file__), 'scanners')
        for filename in os.listdir(scanner_dir):
            if filename.endswith('.py') and not filename.startswith('__') and not filename.startswith('base'):
                # Tên plugin được suy ra từ tên file, ví dụ: 'xss_scanner.py' -> 'xss'
                plugin_name = filename.replace('_scanner.py', '')
                
                # Nếu có danh sách cho phép và plugin không nằm trong đó, bỏ qua
                if enabled_plugins is not None and plugin_name not in enabled_plugins:
                    continue
                
                module_name = f"core.scanners.{filename[:-3]}"
                try:
                    module = importlib.import_module(module_name)
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if isinstance(item, type) and issubclass(item, BaseScanner) and item is not BaseScanner:
                            scanners.append(item(self.session, self.payloads))
                except Exception as e:
                    print(f"[ERROR] Không thể tải plugin từ {filename}: {e}")
        return scanners

    def run_scan(self, targets):
        """
        Lặp qua tất cả các mục tiêu và áp dụng tất cả các plugin quét.
        """
        all_vulnerabilities = []
        url_blacklist = ['/login.php', '/logout.php', '/setup.php']

        print(f"[*] Bắt đầu quét {len(targets)} mục tiêu với {len(self.scanners)} plugin...")
        for i, target in enumerate(targets):
            target_url_display = target['value'] if target['type'] == 'url' else target['value']['url']
            
            if any(blacklisted_path in target_url_display for blacklisted_path in url_blacklist):
                continue

            print(f"  -> Đang quét mục tiêu {i+1}/{len(targets)}: {target_url_display[:80]}...")
            
            # Áp dụng từng plugin cho mục tiêu
            for scanner_plugin in self.scanners:
                try:
                    results = scanner_plugin.scan(target)
                    if results:
                        all_vulnerabilities.extend(results)
                except Exception as e:
                    print(f"  [!] Lỗi khi chạy plugin '{scanner_plugin.name}' trên mục tiêu {target_url_display}: {e}")
                    
        return all_vulnerabilities

    def login(self):
        """Logic đăng nhập DVWA. Sẽ ít được dùng hơn khi có tùy chọn xác thực."""
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