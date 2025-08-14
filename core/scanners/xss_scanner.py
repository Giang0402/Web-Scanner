# core/scanners/xss_scanner.py

from .base_scanner import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

class XSSScanner(BaseScanner):

    @property
    def name(self):
        return 'xss'

    def scan(self, target):
        """
        The main dispatcher. It intelligently routes targets to the correct
        scanning logic based on their type and method.
        """
        target_type = target.get('type')
        target_value = target.get('value')

        if target_type == 'url' and parse_qs(urlparse(target_value).query):
            # A direct URL with params, always a GET request
            return self._scan_get_request(target_value)
        
        elif target_type == 'form':
            # A form was discovered
            form_method = target_value.get('method', 'get').lower()
            if form_method == 'get':
                # A GET form is functionally equivalent to a URL with parameters
                return self._scan_get_form(target_value)
            else: # post
                # A POST form, typically for Stored XSS
                return self._scan_post_form(target_value)
        
        return []

    def _confirm_with_playwright(self, html_content):
        """Renders HTML in a headless browser to confirm JS execution."""
        if not html_content: return False
        vulnerable = False
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                def handle_dialog(dialog):
                    nonlocal vulnerable
                    if 'XSS_SUCCESS' in dialog.message: vulnerable = True
                    dialog.dismiss()

                page.on('dialog', handle_dialog)
                page.set_content(html_content, wait_until='domcontentloaded')
                page.wait_for_timeout(500)
                browser.close()
                return vulnerable
        except Exception:
            return False

    def _scan_get_request(self, url):
        """Scan a raw URL that already has GET parameters."""
        vulnerabilities = []
        print(f"    -> Scanning [XSS on GET URL]: {url[:80]}")
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        for param in list(params.keys()):
            for payload in self.payloads:
                modified_params = params.copy()
                modified_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(modified_params, doseq=True)))
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.ok and self._confirm_with_playwright(response.text):
                        print(f"      [+] VULN (Reflected XSS) CONFIRMED! Param: {param}")
                        vulnerabilities.append({
                            'url': url, 'type': 'XSS_REFLECTED_URL', 'payload': payload,
                            'evidence': "Execution confirmed via headless browser.", 'method': 'GET', 'parameter': param
                        })
                        return vulnerabilities
                except Exception: continue
        return vulnerabilities

    def _scan_get_form(self, form_details):
        """Scan a form that submits via GET (Reflected XSS)."""
        vulnerabilities = []
        url = form_details['url']
        print(f"    -> Scanning [XSS on GET Form]: {url[:80]}")
        
        base_url = urlunparse(urlparse(url)._replace(query=""))
        
        for input_field in form_details['inputs']:
            param_name = input_field.get('name')
            if not param_name or input_field.get('type') not in ['text', 'search', 'textarea']: continue
                
            for payload in self.payloads:
                form_data = {i['name']: 'test' for i in form_details['inputs'] if i.get('name')}
                form_data[param_name] = payload
                test_url = f"{base_url}?{urlencode(form_data, doseq=True)}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.ok and self._confirm_with_playwright(response.text):
                        print(f"      [+] VULN (Reflected XSS) CONFIRMED! Param: {param_name}")
                        vulnerabilities.append({
                            'url': url, 'type': 'XSS_REFLECTED_FORM', 'payload': payload,
                            'evidence': "Execution confirmed via headless browser.", 'method': 'GET', 'parameter': param_name
                        })
                        return vulnerabilities
                except Exception: continue
        return vulnerabilities

    def _scan_post_form(self, form_details):
        """Scan a form that submits via POST (Stored XSS)."""
        vulnerabilities = []
        url = form_details['url']
        print(f"    -> Scanning [XSS on POST Form]: {url[:80]}")

        for input_field in form_details['inputs']:
            param_name = input_field.get('name')
            if not param_name or input_field.get('type') not in ['text', 'textarea', 'search']: continue

            for payload in self.payloads:
                form_data = {i['name']: 'test' for i in form_details['inputs'] if i.get('name')}
                form_data[param_name] = payload
                try:
                    self.session.post(url, data=form_data, timeout=10)
                    response = self.session.get(url, timeout=10)
                    if response.ok and self._confirm_with_playwright(response.text):
                        print(f"      [+] VULN (Stored XSS) CONFIRMED! Param: {param_name}")
                        vulnerabilities.append({
                            'url': url, 'type': 'XSS_STORED', 'payload': payload,
                            'evidence': "Execution confirmed via headless browser.", 'method': 'POST', 'parameter': param_name
                        })
                        return vulnerabilities
                except Exception: continue
        return vulnerabilities