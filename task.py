import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Perform gevent monkey-patching at the very beginning to enable async I/O.
import gevent.monkey
gevent.monkey.patch_all()

from celery import Celery

# Initialize the Celery application.
celery = Celery('tasks')

@celery.task(bind=True)
def run_scan_task(self, scan_id):
    """
    Celery task to run a complete web scan.

    Args:
        scan_id (int): The ID of the scan to be processed.
    """
    # Imports are placed inside the function to avoid circular dependencies with the app.
    from app import app, db, Scan, Vulnerability
    from core.scanner import Scanner
    from core.crawler import Crawler
    import requests

    # Use Flask's application context to access the database.
    with app.app_context():
        # Retrieve the scan from the database.
        scan = Scan.query.get(scan_id)
        if not scan:
            print(f"[ERROR] Scan not found with ID: {scan_id}")
            return

        try:
            # Update the scan status to 'INITIALIZING'.
            scan.status = 'INITIALIZING'
            db.session.commit()

            # Set up the HTTP session and scanner.
            session = requests.Session()
            scanner = Scanner(session, scan_config=scan.scan_config)
            
            # Start the crawling phase.
            scan.status = 'CRAWLING'
            db.session.commit()
            print(f"[INFO] Starting to crawl target URL: {scan.target_url}")
            
            # Initialize and run the crawler.
            crawler = Crawler(scan.target_url)
            
            # Retrieve authentication cookies from the scan configuration.
            auth_cookie = scan.scan_config.get('auth', {}).get('cookie')
            max_crawl_depth = 2
            
            # Execute the crawl and get a list of targets.
            targets_to_scan = crawler.crawl(max_depth=max_crawl_depth, auth_cookie=auth_cookie)
            print(f"[INFO] Crawl complete. Found {len(targets_to_scan)} targets.")

            # Start the vulnerability scanning phase.
            scan.status = 'SCANNING'
            db.session.commit()
            print(f"[INFO] Starting vulnerability scan...")
            
            # Run the scanner on the crawled targets.
            vulnerabilities = scanner.run_scan(targets_to_scan)
            print(f"[INFO] Scan complete. Found {len(vulnerabilities)} vulnerabilities.")

            # Save any discovered vulnerabilities to the database.
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

            # Update the scan status to 'COMPLETED' after a successful run.
            scan.status = 'COMPLETED'
            db.session.commit()
            print(f"[SUCCESS] Scan completed for Scan ID: {scan_id}")

        except Exception as e:
            # Handle unexpected errors and update the scan status to 'FAILED'.
            print(f"[FATAL ERROR] An unexpected error occurred during the scan task: {e}")
            if 'scan' in locals() and scan:
                scan.status = 'FAILED: System Error'
                db.session.commit()
            
            # Print the traceback for debugging purposes.
            import traceback
            traceback.print_exc()
