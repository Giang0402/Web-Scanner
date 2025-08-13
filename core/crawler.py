# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/core/crawler.py
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

class Crawler:
    """
    Crawler được nâng cấp sử dụng Playwright để xử lý các trang web dựa trên JavaScript (SPA).
    """
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.crawled_links = set()
        self.crawled_forms = set()
        self.url_blacklist = ['logout', 'signout', 'exit', 'logoff', 'dangxuat']

    def _parse_cookie_string(self, cookie_string):
        """Hàm trợ giúp để chuyển đổi chuỗi cookie thành định dạng mà Playwright yêu cầu."""
        cookies = []
        if not cookie_string:
            return cookies
        
        parts = cookie_string.split(';')
        for part in parts:
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies.append({
                    'name': name,
                    'value': value,
                    'domain': self.domain_name,
                    'path': '/'
                })
        return cookies

    def _get_links_and_forms(self, page):
        """Hàm này xử lý action của form một cách chính xác."""
        links = set()
        forms = []
        time.sleep(1)
        content = page.content()
        soup = BeautifulSoup(content, 'html.parser')

        # Lấy links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.attrs['href']
            if not href or href.startswith(('mailto:', 'tel:')):
                continue
            full_url = urljoin(page.url, href)
            if urlparse(full_url).netloc == self.domain_name and '#' not in full_url:
                links.add(full_url)

        # Lấy forms
        for form in soup.find_all('form'):
            action = form.attrs.get('action', '').strip()
            
            # === LOGIC QUAN TRỌNG NHẤT: Xử lý action của form ===
            # Nếu action rỗng hoặc là '#', form sẽ submit đến chính trang hiện tại.
            if not action or action == '#':
                form_url = page.url
            # Ngược lại, kết hợp action với URL của trang hiện tại.
            else:
                form_url = urljoin(page.url, action)

            method = form.attrs.get('method', 'get').lower()
            
            form_details = {'url': form_url, 'method': method, 'inputs': []}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.attrs.get('name')
                if input_name:
                    form_details['inputs'].append({'name': input_name, 'type': input_tag.attrs.get('type', 'text'), 'value': input_tag.attrs.get('value', '')})
            
            forms.append(form_details)
        return links, forms

    def crawl(self, max_depth=2, auth_cookie=None):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
            
            if auth_cookie:
                parsed_cookies = self._parse_cookie_string(auth_cookie)
                context.add_cookies(parsed_cookies)
                print("[CRAWLER INFO] Đã áp dụng Session Cookie cho trình duyệt của Crawler.")

            page = context.new_page()
            to_crawl = {self.base_url}
            targets = []
            
            for depth in range(max_depth):
                new_links = set()
                if not to_crawl:
                    break
                
                print(f"[CRAWLER] Bắt đầu crawl ở độ sâu {depth+1} với {len(to_crawl)} links...")
                for url in list(to_crawl):
                    if any(blacklisted_word in url.lower() for blacklisted_word in self.url_blacklist):
                        print(f"[CRAWLER INFO] Bỏ qua URL trong danh sách đen: {url}")
                        continue
                    if url in self.crawled_links:
                        continue
                    
                    self.crawled_links.add(url)
                    targets.append({'type': 'url', 'value': url})

                    try:
                        page.goto(url, wait_until='load', timeout=20000)
                        
                        if "login.php" in page.url and urlparse(url).path not in ('/login.php', '/dvwa/login.php'):
                             print(f"[CRAWLER WARNING] Bị chuyển hướng về trang đăng nhập khi truy cập: {url}.")
                             continue

                        links, forms = self._get_links_and_forms(page)
                        new_links.update(links)
                        
                        for form in forms:
                            form_key = (form['url'], form['method'], tuple(sorted(d['name'] for d in form['inputs'])))
                            if form_key not in self.crawled_forms:
                                targets.append({'type': 'form', 'value': form})
                                self.crawled_forms.add(form_key)

                    except PlaywrightTimeoutError:
                        print(f"[CRAWLER WARNING] Timeout khi truy cập: {url}")
                    except Exception as e:
                        print(f"[CRAWLER ERROR] Lỗi khi xử lý {url}: {e}")

                to_crawl = new_links - self.crawled_links
            
            browser.close()
            return targets