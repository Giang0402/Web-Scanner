from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.crawled_links = set()
        self.crawled_forms = set()

    def _get_links_and_forms(self, url):
        links = set()
        forms = []
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Lấy tất cả các link
            for a_tag in soup.find_all('a', href=True):
                href = a_tag.attrs['href']
                full_url = urljoin(self.base_url, href)
                # Chỉ crawl các link trong cùng domain và chưa được crawl
                if urlparse(full_url).netloc == self.domain_name and '#' not in full_url:
                    links.add(full_url)

            # Lấy tất cả các form
            for form in soup.find_all('form'):
                action = form.attrs.get('action', url)
                method = form.attrs.get('method', 'get').lower()
                form_url = urljoin(self.base_url, action)
                
                form_details = {'url': form_url, 'method': method, 'inputs': []}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.attrs.get('name')
                    input_type = input_tag.attrs.get('type', 'text')
                    input_value = input_tag.attrs.get('value', '')
                    if input_name:
                        form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_value})
                
                # Tránh crawl form lặp lại
                form_key = (form_details['url'], form_details['method'], tuple(d['name'] for d in form_details['inputs']))
                if form_key not in self.crawled_forms:
                    forms.append(form_details)
                    self.crawled_forms.add(form_key)

        except Exception as e:
            print(f"[CRAWLER ERROR] Lỗi khi xử lý {url}: {e}")
        
        return links, forms

    def crawl(self, max_depth=2):
        to_crawl = {self.base_url}
        targets = []
        
        for depth in range(max_depth):
            new_links = set()
            if not to_crawl:
                break
            
            print(f"[CRAWLER] Bắt đầu crawl ở độ sâu {depth+1} với {len(to_crawl)} links...")
            for url in to_crawl:
                if url in self.crawled_links:
                    continue
                
                self.crawled_links.add(url)
                targets.append({'type': 'url', 'value': url})

                links, forms = self._get_links_and_forms(url)
                new_links.update(links)
                
                for form in forms:
                    targets.append({'type': 'form', 'value': form})

            to_crawl = new_links - self.crawled_links
            
        return targets