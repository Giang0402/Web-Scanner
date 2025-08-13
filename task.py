# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/task.py
# SỬA LỖI ModuleNotFoundError: Thêm thư mục gốc của dự án vào PYTHONPATH
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Thực hiện Monkey-patching LÀ ĐIỀU ĐẦU TIÊN, trước mọi import khác.
import gevent.monkey
gevent.monkey.patch_all()

from celery import Celery

celery = Celery('tasks')

@celery.task(bind=True)
def run_scan_task(self, scan_id):
    from app import app, db, Scan, Vulnerability
    from core.scanner import Scanner
    from core.crawler import Crawler
    import requests

    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            print(f"[ERROR] Không tìm thấy Scan với ID: {scan_id}")
            return

        try:
            scan.status = 'INITIALIZING'
            db.session.commit()

            session = requests.Session()
            scanner = Scanner(session, scan_config=scan.scan_config)
            
            scan.status = 'CRAWLING'
            db.session.commit()
            print(f"[INFO] Bắt đầu crawl trang: {scan.target_url}")
            crawler = Crawler(scan.target_url)

            # === THAY ĐỔI QUAN TRỌNG ===
            # Lấy cookie từ cấu hình và truyền nó vào cho crawler
            auth_cookie = scan.scan_config.get('auth', {}).get('cookie')
            max_crawl_depth = 2
            
            targets_to_scan = crawler.crawl(max_depth=max_crawl_depth, auth_cookie=auth_cookie)
            print(f"[INFO] Crawl hoàn tất. Tìm thấy {len(targets_to_scan)} mục tiêu.")

            scan.status = 'SCANNING'
            db.session.commit()
            print(f"[INFO] Bắt đầu quét các lỗ hổng...")
            vulnerabilities = scanner.run_scan(targets_to_scan)
            print(f"[INFO] Quét hoàn tất. Tìm thấy {len(vulnerabilities)} lỗ hổng.")

            if vulnerabilities:
                for vuln in vulnerabilities:
                    new_vuln = Vulnerability(
                        scan_id=scan.id,
                        url=vuln.get('url', 'N/A'),
                        vuln_type=vuln.get('type', 'N/A'),
                        payload=vuln.get('payload', 'N/A'),
                        evidence=vuln.get('evidence'),
                        ai_confidence=vuln.get('ai_confidence'),
                        method=vuln.get('method', 'GET'),
                        details=vuln.get('details')
                    )
                    db.session.add(new_vuln)

            scan.status = 'COMPLETED'
            db.session.commit()
            print(f"[SUCCESS] Hoàn thành quét cho Scan ID: {scan_id}")

        except Exception as e:
            print(f"[FATAL ERROR] Đã xảy ra lỗi không mong muốn trong tác vụ quét: {e}")
            if 'scan' in locals() and scan:
                scan.status = 'FAILED: Lỗi hệ thống'
                db.session.commit()
            import traceback
            traceback.print_exc()