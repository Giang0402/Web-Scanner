# main.py
import requests
import scanner  # Import module scanner của chúng ta
import config   # Import module config

def run_scanner():
    """Hàm chính để điều phối toàn bộ quá trình quét."""
    print("===== BẮT ĐẦU CHƯƠNG TRÌNH QUÉT LỖ HỔNG WEB =====")
    
    session = requests.Session()
    
    # Bước 1: Đăng nhập và thiết lập môi trường
    success, message = scanner.login_and_set_security(session)
    print(f"[INFO] {message}")
    if not success:
        print("===== DỪNG CHƯƠNG TRÌNH =====")
        return

    # Bước 2: Bò qua trang chủ để lấy danh sách link (ví dụ)
    # Trong dự án thực tế, bạn sẽ cho người dùng nhập URL
    print(f"\n[*] Bắt đầu crawl từ trang chủ: {config.DVWA_BASE_URL}")
    links_to_scan = scanner.crawl(session, config.DVWA_BASE_URL)
    print(f"[*] Tìm thấy tổng cộng {len(links_to_scan)} link để quét.")

    # Thêm các URL test cụ thể vào danh sách quét
    links_to_scan.extend([config.SQLI_TEST_URL, config.XSS_TEST_URL])
    links_to_scan = list(set(links_to_scan)) # Loại bỏ trùng lặp

    # Bước 3: Lặp qua từng link và quét
    print("\n[*] Bắt đầu quét các lỗ hổng...")
    vulnerabilities_found = []
    for link in links_to_scan:
        # Quét SQLi
        result_sqli = scanner.scan_sql_injection(session, link)
        if result_sqli['vulnerable']:
            vulnerabilities_found.append(result_sqli)
        
        # Quét XSS
        result_xss = scanner.scan_xss(session, link)
        if result_xss['vulnerable']:
            vulnerabilities_found.append(result_xss)

    # Bước 4: In kết quả
    print("\n===== KẾT THÚC QUÁ TRÌNH QUÉT =====")
    if not vulnerabilities_found:
        print("Không tìm thấy lỗ hổng nào.")
    else:
        print(f"Phát hiện tổng cộng {len(vulnerabilities_found)} lỗ hổng:")
        for vuln in vulnerabilities_found:
            print(f"  - Loại: {vuln['type']}, URL: {vuln['url']}, Tham số: {vuln.get('parameter', 'N/A')}")

if __name__ == '__main__':
    run_scanner()