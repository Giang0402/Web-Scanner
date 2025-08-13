import eventlet
eventlet.monkey_patch()

from celery import Celery
from app import app, db, Scan, Vulnerability
from core.scanner import Scanner
from core.crawler import Crawler
import requests

celery = Celery(
    app.import_name,
    backend=app.config['CELERY_RESULT_BACKEND'],
    broker=app.config['CELERY_BROKER_URL']
)
celery.conf.update(app.config)

class ContextTask(celery.Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)

celery.Task = ContextTask

@celery.task(bind=True)
def run_scan_task(self, scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        print(f"[ERROR] Không tìm thấy Scan với ID: {scan_id}")
        return

    try:
        scan.status = 'INITIALIZING'
        db.session.commit()

        session = requests.Session()
        scanner = Scanner(session)

        # --- LOGIC MỚI: KIỂM TRA MỤC TIÊU ---
        is_dvwa_target = 'dvwa' in scan.target_url.lower()

        if is_dvwa_target:
            print("[INFO] Mục tiêu được xác định là DVWA. Bắt đầu quá trình đăng nhập...")
            login_result = scanner.login()
            if not login_result.get('success') or not login_result.get('security_set'):
                error_message = login_result.get('message', 'Lỗi không xác định khi đăng nhập DVWA.')
                print(f"[CRITICAL] {error_message}")
                scan.status = f'FAILED: {error_message}'
                db.session.commit()
                return
            print("[SUCCESS] Đăng nhập và thiết lập security cho DVWA thành công.")
        else:
            print(f"[INFO] Mục tiêu là trang web đơn giản ({scan.target_url}). Bỏ qua bước đăng nhập.")

        scan.status = 'CRAWLING'
        db.session.commit()
        print(f"[INFO] Bắt đầu crawl trang: {scan.target_url}")
        crawler = Crawler(session, scan.target_url)
        # Giảm độ sâu crawl cho các trang đơn giản để quét nhanh hơn
        max_crawl_depth = 2 if is_dvwa_target else 1
        targets_to_scan = crawler.crawl(max_depth=max_crawl_depth)
        print(f"[INFO] Crawl hoàn tất. Tìm thấy {len(targets_to_scan)} mục tiêu.")

        # Tái xác thực chỉ cần thiết cho DVWA
        if is_dvwa_target:
            print("[INFO] Tái xác thực phiên làm việc DVWA trước khi quét...")
            relogin_result = scanner.login()
            if not relogin_result.get('success') or not relogin_result.get('security_set'):
                print("[CRITICAL] Tái xác thực thất bại. Dừng quá trình quét.")
                scan.status = 'FAILED: Mất phiên làm việc'
                db.session.commit()
                return

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
                    method=vuln.get('method', 'GET')
                )
                db.session.add(new_vuln)

        scan.status = 'COMPLETED'
        db.session.commit()
        print(f"[SUCCESS] Hoàn thành quét cho Scan ID: {scan_id}")

    except Exception as e:
        print(f"[FATAL ERROR] Đã xảy ra lỗi không mong muốn trong tác vụ quét: {e}")
        scan.status = 'FAILED: Lỗi hệ thống'
        db.session.commit()
        import traceback
        traceback.print_exc()
