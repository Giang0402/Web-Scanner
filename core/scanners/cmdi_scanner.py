from .base_scanner import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import requests
import uuid

class CMDiScanner(BaseScanner):

    @property
    def name(self):
        return 'cmdi'

    def scan(self, target):
        """Orchestrates the Command Injection scan for both URL and FORM targets."""
        if target['type'] == 'url':
            return self._scan_url(target['value'])
        
        elif target['type'] == 'form':
            form_details = target['value']
            # This scanner will now properly handle both GET and POST forms
            return self._scan_form(form_details)
        
        return []

    def _generate_test_cases(self, original_value=""):
        """Generates both output-based and time-based test cases."""
        unique_marker = uuid.uuid4().hex[:10]
        sleep_time = 7
        
        test_cases = {
            "output_based": {
                "type": "CMDI_OUTPUT_BASED",
                "command": f"echo {unique_marker}",
                "marker": unique_marker,
                "evidence_template": f"The unique marker '{unique_marker}' was found in the server's response."
            },
            "time_based": {
                "type": "CMDI_TIME_BASED",
                "command": f"sleep {sleep_time}",
                "sleep_time": sleep_time,
                "evidence_template": f"Server response was delayed by {{response_time:.2f}} seconds, indicating the sleep command was executed."
            }
        }
        
        payloads = []
        for case in test_cases.values():
            for payload_template in self.payloads:
                # Append payload to original value to support cases like ping
                full_payload = f"{original_value}{payload_template.format(command=case['command'])}"
                payloads.append({**case, "payload": full_payload})

        return payloads

    def _execute_scan(self, method, url, data=None, param_name=None):
        """A generic function to execute scan logic for GET or POST."""
        original_value = data.get(param_name) if data and param_name else "127.0.0.1"
        test_payloads = self._generate_test_cases(original_value)

        for test in test_payloads:
            try:
                # Prepare request
                current_data = data.copy() if data else {}
                if param_name:
                    current_data[param_name] = test['payload']

                start_time = time.time()
                
                if method.lower() == 'get':
                    # For GET, we need to reconstruct the URL with the payload
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    if param_name:
                        query_params[param_name] = test['payload']
                    
                    final_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, urlencode(query_params, doseq=True), parsed_url.fragment))
                    response = self.session.get(final_url, timeout=test.get('sleep_time', 10) + 5)
                else: # POST
                    response = self.session.post(url, data=current_data, timeout=test.get('sleep_time', 10) + 5)
                
                end_time = time.time()
                response_time = end_time - start_time

                # Analyze response
                if test['type'] == "CMDI_OUTPUT_BASED":
                    if test['marker'] in response.text:
                        print(f"      [+] VULN ({test['type']}) found! Param: {param_name}, Payload: {test['payload']}")
                        return {
                            'url': url, 'type': test['type'], 'payload': test['payload'],
                            'evidence': test['evidence_template'], 'method': method.upper(), 'parameter': param_name
                        }
                
                elif test['type'] == "CMDI_TIME_BASED":
                    if response_time >= test['sleep_time']:
                        print(f"      [+] VULN ({test['type']}) found! Param: {param_name}, Payload: {test['payload']}")
                        return {
                            'url': url, 'type': test['type'], 'payload': test['payload'],
                            'evidence': test['evidence_template'].format(response_time=response_time),
                            'method': method.upper(), 'parameter': param_name
                        }

            except requests.exceptions.Timeout:
                 if test['type'] == "CMDI_TIME_BASED":
                    print(f"      [+] VULN ({test['type']}) found via timeout! Param: {param_name}")
                    return {
                        'url': url, 'type': test['type'], 'payload': test['payload'],
                        'evidence': "Request timed out, a strong indicator of a time-based vulnerability.",
                        'method': method.upper(), 'parameter': param_name
                    }
            except requests.RequestException:
                continue
        return None


    def _scan_url(self, url):
        """Scans a URL with GET parameters for Command Injection."""
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []

        print(f"    -> Scanning [CMDI] on URL: {url[:80]}")
        
        for param in list(params.keys()):
            result = self._execute_scan('get', url, data=params, param_name=param)
            if result:
                vulnerabilities.append(result)
                # Found a vulnerability in this parameter, no need to test further payloads on it
                break 
        
        return vulnerabilities

    def _scan_form(self, form_details):
        """Scans a form for Command Injection (handles GET and POST)."""
        vulnerabilities = []
        url = form_details['url']
        method = form_details['method'].lower()
        inputs = form_details['inputs']
        
        print(f"    -> Scanning [CMDI] on FORM at: {url[:80]}")

        # Create a base data dictionary for the form
        form_data = {}
        for i in inputs:
            if i.get('name'):
                form_data[i['name']] = i.get('value', '127.0.0.1') # Default value

        for input_field in inputs:
            param_name = input_field.get('name')
            # Skip non-injectable fields
            if not param_name or input_field.get('type') in ['submit', 'button', 'hidden', 'checkbox', 'radio']:
                continue
            
            # The _execute_scan function will handle both GET and POST
            result = self._execute_scan(method, url, data=form_data, param_name=param_name)
            if result:
                vulnerabilities.append(result)
                # Found a vulnerability in this input, move to the next form
                return vulnerabilities 

        return vulnerabilities