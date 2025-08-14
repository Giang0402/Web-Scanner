import os
import importlib
import requests
from bs4 import BeautifulSoup
from config import Config
from core.scanners.base_scanner import BaseScanner

class Scanner:
    """
    Main orchestrator class. Loads all scanner plugins and coordinates the scan.
    """
    def __init__(self, session, scan_config=None):
        self.session = session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        })
        
        # Apply authentication configuration if provided
        if scan_config and 'auth' in scan_config:
            auth_config = scan_config['auth']
            if auth_config.get('cookie'):
                self.session.headers.update({'Cookie': auth_config['cookie']})
                print("[INFO] Applied Session Cookie to headers.")
            if auth_config.get('header'):
                self.session.headers.update({'Authorization': auth_config['header']})
                print("[INFO] Applied Authorization Header.")

        self.payloads = self._load_payloads()
        
        # Load only the plugins requested in the policy
        enabled_plugins = scan_config.get('policy', {}).get('plugins') if scan_config else None
        self.scanners = self._load_scanners(enabled_plugins)
        
        if not hasattr(self, 'already_printed_info'): # Avoid printing multiple times
            print(f"[INFO] Successfully loaded {len(self.scanners)} scanner plugins: {[s.name for s in self.scanners]}")
            self.already_printed_info = True


    def _load_payloads(self):
        payloads = {}
        payload_dir = os.path.join(os.path.dirname(__file__), '..', 'payloads')
        if not os.path.isdir(payload_dir):
            print(f"[ERROR] Payloads directory does not exist at: {payload_dir}")
            return {}
        for filename in os.listdir(payload_dir):
            if filename.endswith('.txt'):
                vuln_type = filename.split('.')[0]
                with open(os.path.join(payload_dir, filename), 'r', encoding='utf-8') as f:
                    payloads[vuln_type] = [line.strip() for line in f if line.strip()]
        return payloads

    def _load_scanners(self, enabled_plugins=None):
        """Loads scanner plugins, optionally filtering by an allowed list."""
        scanners = []
        scanner_dir = os.path.join(os.path.dirname(__file__), 'scanners')
        for filename in os.listdir(scanner_dir):
            if filename.endswith('.py') and not filename.startswith('__') and not filename.startswith('base'):
                # Plugin name is inferred from the filename, e.g., 'xss_scanner.py' -> 'xss'
                plugin_name = filename.replace('_scanner.py', '')
                
                # If an allowed list is provided and the plugin is not in it, skip
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
                    print(f"[ERROR] Failed to load plugin from {filename}: {e}")
        return scanners

    def run_scan(self, targets):
        """
        Iterates through all targets and applies all scanner plugins.
        """
        all_vulnerabilities = []
        url_blacklist = ['/login.php', '/logout.php', '/setup.php']

        print(f"[*] Starting scan on {len(targets)} targets with {len(self.scanners)} plugins...")
        for i, target in enumerate(targets):
            target_url_display = target['value'] if target['type'] == 'url' else target['value']['url']
            
            if any(blacklisted_path in target_url_display for blacklisted_path in url_blacklist):
                continue

            print(f"  -> Scanning target {i+1}/{len(targets)}: {target_url_display[:80]}...")
            
            # Apply each plugin to the target
            for scanner_plugin in self.scanners:
                try:
                    results = scanner_plugin.scan(target)
                    if results:
                        all_vulnerabilities.extend(results)
                except Exception as e:
                    print(f"  [!] Error running plugin '{scanner_plugin.name}' on target {target_url_display}: {e}")
                    
        return all_vulnerabilities

    def login(self):
        """DVWA login logic. Will be used less with the new authentication options."""
        try:
            login_page_resp = self.session.get(Config.TARGET_LOGIN_URL, timeout=10)
            if login_page_resp.status_code != 200:
                return {'success': False, 'message': f"Could not access login page, status: {login_page_resp.status_code}"}
            soup = BeautifulSoup(login_page_resp.text, 'html.parser')
            user_token_tag = soup.find('input', {'name': 'user_token'})
            if not user_token_tag: return {'success': False, 'message': "user_token not found on login page."}
            user_token = user_token_tag['value']
            
            login_data = {'username': Config.TARGET_USERNAME, 'password': Config.TARGET_PASSWORD, 'Login': 'Login', 'user_token': user_token}
            response = self.session.post(Config.TARGET_LOGIN_URL, data=login_data, allow_redirects=True, timeout=10)

            if "login.php" in response.url or "index.php" not in response.url:
                return {'success': False, 'message': "Login failed. Check credentials or logic."}

            self.session.headers.update({'Referer': response.url})

            security_page_resp = self.session.get(Config.TARGET_SECURITY_URL, timeout=10)
            soup = BeautifulSoup(security_page_resp.text, 'html.parser')
            security_token_tag = soup.find('input', {'name': 'user_token'})
            if not security_token_tag: return {'success': False, 'message': "user_token not found on security page."}
            security_token = security_token_tag['value']
            
            security_data = {'security': 'low', 'seclev_submit': 'Submit', 'user_token': security_token}
            response_sec = self.session.post(Config.TARGET_SECURITY_URL, data=security_data, timeout=10)
            
            if "security level set to low" not in response_sec.text.lower():
                return {'success': True, 'security_set': False, 'message': "Login successful but FAILED to set security level to 'low'."}
            
            return {'success': True, 'security_set': True, 'message': "Login and security setup successful."}
        except requests.exceptions.RequestException as e: return {'success': False, 'message': f"Network error during login: {e}"}
        except Exception as e: return {'success': False, 'message': f"Critical error during login: {e}"}