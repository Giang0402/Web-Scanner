# tasks.py (Phiên bản nâng cấp với CSDL)
from celery import Celery
import requests
import scanner
# MỚI: Import app và db để tác vụ có thể tương tác với CSDL
from app import app, db, Scan, Vulnerability
from concurrent.futures import ThreadPoolExecutor

celery = Celery('tasks', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')

@celery.task
def run_scan_task(scan_id):
    """Tác vụ chạy nền cuối cùng: có CSDL, crawl đệ quy và quét song song."""
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan: return

        scan.status = 'RUNNING'
        db.session.commit()

        session = requests.Session()
        success, _ = scanner.login_and_set_security(session)
        if not success:
            scan.status = 'FAILED'
            db.session.commit()
            return

        # 1. Crawl đệ quy để lấy danh sách link
        links_to_scan = scanner.crawl(session, scan.target_url, max_depth=1) # Giới hạn độ sâu
        print(f"[*] Tìm thấy {len(links_to_scan)} link để quét song song.")

        # 2. Quét các link song song bằng ThreadPoolExecutor
        def scan_and_save(link):
            results = scanner.scan_url(session, link)
            for vuln_data in results:
                # Cần app_context ở đây vì mỗi thread là một môi trường riêng
                with app.app_context():
                    vulnerability = Vulnerability(
                        scan_id=scan.id,
                        url=vuln_data['url'],
                        vuln_type=vuln_data['type'],
                        parameter=vuln_data.get('parameter')
                    )
                    db.session.add(vulnerability)

        # Chạy tối đa 5 thread cùng lúc
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(scan_and_save, links_to_scan)
        
        db.session.commit() # Commit tất cả các lỗ hổng đã tìm thấy
        scan.status = 'COMPLETED'
        db.session.commit()