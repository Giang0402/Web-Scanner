# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/core/scanners/cmdi_scanner.py
from .base_scanner import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import requests

class CMDiScanner(BaseScanner):
    @property
    def name(self):
        return 'cmdi'

    def scan(self, target):
        """Điều phối việc quét CMDi, giờ đây đã hỗ trợ cả GET và POST."""
        if target['type'] == 'url':
            return self._scan_get_url(target['value'])
        
        elif target['type'] == 'form':
            form_details = target['value']
            if form_details['method'] == 'get':
                base_url = form_details['url']
                inputs = form_details['inputs']
                test_data = {inp['name']: '127.0.0.1' for inp in inputs if inp.get('name')}
                if not test_data: return []
                full_url_to_scan = f"{base_url}?{urlencode(test_data)}"
                return self._scan_get_url(full_url_to_scan)
            
            # === LOGIC MỚI ĐỂ XỬ LÝ FORM POST ===
            elif form_details['method'] == 'post':
                return self._scan_post_form(form_details)
        return []

    def _perform_time_based_test(self, request_func):
        """Hàm chung để thực hiện kiểm tra dựa trên thời gian."""
        sleep_time = 7 
        normal_threshold = 5

        try:
            start_time = time.time()
            request_func(timeout=sleep_time + normal_threshold)
            end_time = time.time()
            response_time = end_time - start_time

            if response_time >= sleep_time:
                return True, f"Phản hồi của máy chủ bị trễ {response_time:.2f} giây, cho thấy lệnh 'sleep' đã được thực thi."
        
        except requests.exceptions.Timeout:
            return True, f"Request bị timeout sau khi tiêm payload 'sleep', dấu hiệu mạnh cho thấy lệnh đã được thực thi."

        except requests.RequestException:
            pass

        return False, None

    def _scan_get_url(self, url):
        found_vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return []
        
        print(f"  -> Bắt đầu quét CMDI (GET) trên: {url}")

        for param in list(params.keys()):
            if param.lower() in ['submit', 'button']:
                continue

            for payload_template in self.payloads:
                payload = f"| sleep 7" # Sử dụng payload POST phổ biến

                modified_params = params.copy()
                original_value = params.get(param, [''])[0]
                modified_params[param] = f"{original_value}{payload}"
                modified_query = urlencode(modified_params, doseq=True)
                new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, ""))

                is_vulnerable, evidence = self._perform_time_based_test(
                    lambda timeout: self.session.get(new_url, timeout=timeout)
                )

                if is_vulnerable:
                    print(f"  [+] CMDI VULN (TIME-BASED) CONFIRMED! URL: {url}, Param: {param}")
                    found_vulnerabilities.append({
                        'url': url, 'type': 'CMDI_BLIND', 'payload': payload,
                        'evidence': evidence, 'ai_confidence': 0.98, 'method': 'GET'
                    })
                    return found_vulnerabilities

        return found_vulnerabilities


    def _scan_post_form(self, form_details):
        found_vulnerabilities = []
        url = form_details['url']
        inputs = form_details['inputs']
        
        print(f"  -> Bắt đầu quét CMDI (POST) trên: {url}")

        for input_tag in inputs:
            param = input_tag.get('name')
            if not param or param.lower() in ['submit', 'button']:
                continue

            for payload_template in self.payloads:
                payload = f"| sleep 7" # Sử dụng payload POST phổ biến

                # Tạo dữ liệu POST
                data = {inp['name']: '127.0.0.1' for inp in inputs if inp.get('name')}
                data[param] = payload

                is_vulnerable, evidence = self._perform_time_based_test(
                    lambda timeout: self.session.post(url, data=data, timeout=timeout)
                )

                if is_vulnerable:
                    print(f"  [+] CMDI VULN (TIME-BASED) CONFIRMED! URL: {url}, Param: {param}")
                    found_vulnerabilities.append({
                        'url': url, 'type': 'CMDI_BLIND', 'payload': payload,
                        'evidence': evidence, 'ai_confidence': 0.98, 'method': 'POST'
                    })
                    return found_vulnerabilities # Tìm thấy là dừng

        return found_vulnerabilities