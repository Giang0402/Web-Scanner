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

# scanner.py (thay thế hàm crawl cũ)
def crawl(session, target_url, max_depth=1):
    """Bò qua URL một cách đệ quy để thu thập các liên kết."""
    crawled_links = set()
    
    def _crawl_recursive(url, depth):
        if depth > max_depth or url in crawled_links or not url.startswith(config.DVWA_BASE_URL):
            return
        
        print(f"[CRAWL] Đang crawl ở độ sâu {depth}: {url}")
        crawled_links.add(url)
        
        try:
            response = session.get(url)
            if response.status_code != 200: return
        except requests.exceptions.RequestException:
            return

        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(url, a_tag['href'])
            _crawl_recursive(link, depth + 1)
            
    _crawl_recursive(target_url, 0)
    return list(crawled_links)

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
    """
    Quét lỗ hổng XSS bằng cách chèn payload vào từng tham số của URL.
    Phiên bản nâng cấp và tổng quát.
    """
    xss_payload = "<script>alert('xss')</script>"
    
    # Phân tích URL và lấy các tham số
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    # Lặp qua từng tham số để kiểm tra
    for param in params:
        original_value = params.get(param, [''])[0]
        modified_params = params.copy()
        
        # Chèn payload XSS vào giá trị của tham số hiện tại
        modified_params[param] = (original_value + xss_payload,)
        
        # Xây dựng lại query string và URL mới
        modified_query = urlencode(modified_params, doseq=True)
        new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, modified_query, parsed_url.fragment))

        try:
            # Gửi yêu cầu với URL đã bị thay đổi
            response = session.get(new_url, timeout=5)
            # Kiểm tra xem payload có bị phản hồi lại trong nội dung không
            if xss_payload in response.content.decode('utf-8', errors='ignore'):
                return {'vulnerable': True, 'type': 'XSS', 'url': url, 'parameter': param}
        except requests.exceptions.RequestException:
            continue # Thử với tham số tiếp theo nếu có lỗi

    return {'vulnerable': False}

# Thêm hàm này vào cuối file scanner.py
def scan_url(session, url):
    """Quét một URL cho tất cả các loại lỗ hổng đã biết."""
    found = []
    result_sqli = scan_sql_injection(session, url)
    if result_sqli.get('vulnerable'):
        found.append(result_sqli)

    result_xss = scan_xss(session, url)
    if result_xss.get('vulnerable'):
        found.append(result_xss)
    return found