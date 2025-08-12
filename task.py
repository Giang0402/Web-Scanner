# QUAN TRỌNG: Dòng này phải được thực thi ĐẦU TIÊN để Celery worker hoạt động với eventlet
import eventlet
eventlet.monkey_patch()

from celery import Celery
from app import app, db, Scan, Vulnerability # Import chính
from core.scanner import Scanner
from core.crawler import Crawler
import requests

# Khởi tạo Celery với context của ứng dụng Flask
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
    """
    Tác vụ Celery chính để chạy quá trình quét.
    """
    scan = Scan.query.get(scan_id)
    if not scan:
        print(f"[ERROR] Không tìm thấy Scan với ID: {scan_id}")
        return

    try:
        # Cập nhật trạng thái ban đầu
        scan.status = 'INITIALIZING'
        db.session.commit()

        session = requests.Session()
        scanner = Scanner(session)

        # --- BƯỚC KIỂM TRA QUAN TRỌNG NHẤT ---
        print("[INFO] Bắt đầu đăng nhập và thiết lập security level...")
        login_result = scanner.login()

        # Kiểm tra chặt chẽ cả 'success' và 'security_set'
        if not login_result.get('success') or not login_result.get('security_set'):
            error_message = login_result.get('message', 'Lỗi không xác định khi đăng nhập hoặc thiết lập security.')
            print(f"[CRITICAL] {error_message}")
            scan.status = f'FAILED: {error_message}'
            db.session.commit()
            return # Dừng tác vụ ngay lập tức

        print(f"[SUCCESS] {login_result.get('message')}")

        # --- Bắt đầu Crawl ---
        scan.status = 'CRAWLING'
        db.session.commit()
        print(f"[INFO] Bắt đầu crawl trang: {scan.target_url}")
        crawler = Crawler(session, scan.target_url)
        targets_to_scan = crawler.crawl(max_depth=2)
        print(f"[INFO] Crawl hoàn tất. Tìm thấy {len(targets_to_scan)} mục tiêu.")

        # --- Bắt đầu Scan ---
        scan.status = 'SCANNING'
        db.session.commit()
        print(f"[INFO] Bắt đầu quét các lỗ hổng...")
        vulnerabilities = scanner.run_scan(targets_to_scan)
        print(f"[INFO] Quét hoàn tất. Tìm thấy {len(vulnerabilities)} lỗ hổng.")

        # --- Lưu kết quả ---
        if vulnerabilities:
            for vuln in vulnerabilities:
                new_vuln = Vulnerability(
                    scan_id=scan.id,
                    url=vuln['url'],
                    vuln_type=vuln['type'],
                    payload=vuln['payload'],
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
