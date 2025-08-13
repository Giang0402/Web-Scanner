# giang0402/web-scanner/Web-Scanner-e94e379f950bc97333bfe721b328412df3aa10ea/app.py
import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
import json

# BƯỚC 1: Khởi tạo Flask App và các extension
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# BƯỚC 2: Import và cấu hình Celery
# Instance celery này được tạo trong task.py nhưng chưa có config
from task import celery
# Cập nhật config của Celery với config của Flask app
celery.config_from_object('config:Config')


# --- DATABASE MODELS ---
# (Các model không thay đổi, chỉ chuyển xuống dưới để code mạch lạc hơn)
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(255), default='PENDING', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    scan_config = db.Column(db.JSON, nullable=True)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return { 'id': self.id, 'target_url': self.target_url, 'status': self.status,
                 'created_at': self.created_at.isoformat(), 'vuln_count': self.vulnerabilities.count() }

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id', ondelete='CASCADE'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.String(500), nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    ai_confidence = db.Column(db.Float, nullable=True)
    method = db.Column(db.String(10), nullable=False, default='GET')
    details = db.Column(db.JSON, nullable=True)

# --- HELPERS ---
def get_remediation_advice(vuln_type):
    #... (Giữ nguyên hàm này)
    advice = {
        'XSS': "Sử dụng kỹ thuật Output Encoding cho tất cả dữ liệu do người dùng cung cấp...",
        'SQLI': "Luôn sử dụng Prepared Statements...",
        'CMDI': "Tránh gọi các lệnh hệ điều hành trực tiếp...",
        'SSRF_BLIND': "Cấu hình tường lửa để chặn các kết nối ra ngoài..."
    }
    return advice.get(vuln_type.upper(), "Không có gợi ý cụ thể. Hãy tham khảo các tài liệu bảo mật từ OWASP.")

# --- FLASK ROUTES ---
@app.route('/')
def index():
    import requests # Hoãn import requests vào bên trong hàm
    from core.scanner import Scanner
    scanner_instance = Scanner(requests.Session())
    available_plugins = [s.name for s in scanner_instance.scanners]
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('index.html', scans=scans, available_plugins=available_plugins)

@app.route('/scan', methods=['POST'])
def start_scan():
    # Giờ đây không cần import task nữa, vì celery đã được cấu hình
    from task import run_scan_task
    target_url = request.form.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    config = {
        'auth': { 'cookie': request.form.get('auth_cookie'), 'header': request.form.get('auth_header') },
        'policy': { 'plugins': request.form.getlist('plugins') }
    }

    with app.app_context():
        new_scan = Scan(target_url=target_url, status='PENDING', scan_config=config)
        db.session.add(new_scan)
        db.session.commit()
        scan_id = new_scan.id

    run_scan_task.delay(scan_id)
    return jsonify({'message': 'Scan started successfully', 'scan_id': scan_id})

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = scan.vulnerabilities.all()
    return render_template('results.html', scan=scan, vulnerabilities=vulnerabilities, get_remediation_advice=get_remediation_advice)

@app.route('/status/<int:scan_id>')
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({'status': scan.status})
    
@app.route('/scan/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/data/vulnerability_types/<int:scan_id>')
def vulnerability_types_data(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vuln_counts = db.session.query(Vulnerability.vuln_type, db.func.count(Vulnerability.vuln_type)).filter_by(scan_id=scan.id).group_by(Vulnerability.vuln_type).all()
    data = { 'labels': [item[0] for item in vuln_counts], 'counts': [item[1] for item in vuln_counts] }
    return jsonify(data)