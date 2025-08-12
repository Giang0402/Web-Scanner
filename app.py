from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os # MỚI

# Lấy đường dẫn thư mục hiện tại
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Cấu hình đường dẫn đến file CSDL SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Khởi tạo đối tượng CSDL
db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # Tạo mối quan hệ với bảng Vulnerability
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    parameter = db.Column(db.String(100), nullable=True)

# app.py (thay thế các route cũ)

@app.route('/')
def index():
    # Lấy lịch sử các lần quét để hiển thị
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('url')
    if not target_url:
        return "URL is required", 400

    # 1. Tạo một bản ghi mới trong CSDL cho lần quét này
    new_scan = Scan(target_url=target_url, status='PENDING')
    db.session.add(new_scan)
    db.session.commit()

    # 2. Giao việc cho Celery với ID của lần quét
    run_scan_task.delay(new_scan.id)

    return jsonify({'scan_id': new_scan.id})

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    # Lấy thông tin chi tiết của một lần quét từ CSDL
    scan = Scan.query.get_or_404(scan_id)
    return render_template('results.html', scan=scan)

@app.route('/status/<int:scan_id>')
def scan_status(scan_id):
    # API để frontend hỏi trạng thái, lấy trực tiếp từ CSDL
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({'status': scan.status})


from task import run_scan_task # Import tác vụ chạy nền từ tasks.py
