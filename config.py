# config.py

# --- THÔNG TIN CẤU HÌNH DVWA ---
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = f"{DVWA_BASE_URL}login.php"
SECURITY_URL = f"{DVWA_BASE_URL}security.php"
USERNAME = "admin"
PASSWORD = "password"

# --- URL MỤC TIÊU ĐỂ KIỂM THỬ ---
SQLI_TEST_URL = f"{DVWA_BASE_URL}vulnerabilities/sqli/?id=1&Submit=Submit#"
XSS_TEST_URL = f"{DVWA_BASE_URL}vulnerabilities/xss_r/?name=test"