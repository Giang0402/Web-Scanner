# scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import config # Import các cấu hình từ file config.py

def login_and_set_security(session):
    """Thực hiện đăng nhập và thiết lập mức độ bảo mật xuống 'low'."""
    try:
        login_page_content = session.get(config.LOGIN_URL).text
        soup = BeautifulSoup(login_page_content, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']

        login_data = {
            'username': config.USERNAME,
            'password': config.PASSWORD,
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post(config.LOGIN_URL, data=login_data)

        if "welcome.php" not in response.url and "index.php" not in response.url:
            return False, "Đăng nhập thất bại"

        security_page_content = session.get(config.SECURITY_URL).text
        soup = BeautifulSoup(security_page_content, 'html.parser')
        security_token = soup.find('input', {'name': 'user_token'})['value']

        security_data = {'security': 'low', 'seclev_submit': 'Submit', 'user_token': security_token}
        response_sec = session.post(config.SECURITY_URL, data=security_data)
        
        if "Security level set to low" not in response_sec.text:
            return True, "Đăng nhập thành công nhưng không thể đặt security level"
        
        return True, "Đăng nhập và thiết lập security thành công"
    except Exception as e:
        return False, f"Lỗi nghiêm trọng: {e}"

def crawl(session, target_url):
    """Bò qua URL để thu thập các liên kết."""
    try:
        response = session.get(target_url)
        if response.status_code != 200: return []
    except requests.exceptions.RequestException as e:
        print(f"(!) Lỗi kết nối khi crawl: {e}")
        return []

    soup = BeautifulSoup(response.content, 'html.parser')
    links = [urljoin(target_url, a['href']) for a in soup.find_all('a', href=True)]
    return list(set(links))

def scan_sql_injection(session, url):
    """Quét lỗ hổng SQL Injection."""
    sql_payload = "'"
    sql_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "syntax error"]
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for param in params:
        original_value = params.get(param, [''])[0]
        modified_params = params.copy()
        modified_params[param] = (original_value + sql_payload,)
        modified_query = urlencode(modified_params, doseq=True)
        new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, modified_query, parsed_url.fragment))
        try:
            response = session.get(new_url, timeout=5)
            for error in sql_errors:
                if error in response.content.decode('utf-8', errors='ignore').lower():
                    return {'vulnerable': True, 'type': 'SQL Injection', 'url': url, 'parameter': param}
        except requests.exceptions.RequestException:
            continue
    return {'vulnerable': False}

def scan_xss(session, url):
    """Quét lỗ hổng XSS."""
    xss_payload = "<script>alert('xss')</script>"
    try:
        response = session.get(url, params={'name': xss_payload}, timeout=5)
        if xss_payload in response.content.decode('utf-8', errors='ignore'):
            return {'vulnerable': True, 'type': 'XSS', 'url': url, 'parameter': 'name'}
    except requests.exceptions.RequestException:
        pass
    return {'vulnerable': False}