from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(255), default='PENDING', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'vuln_count': self.vulnerabilities.count()
        }

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id', ondelete='CASCADE'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.String(500), nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    ai_confidence = db.Column(db.Float, nullable=True)
    method = db.Column(db.String(10), nullable=False, default='GET')

# --- FLASK ROUTES ---
@app.route('/')
def index():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    # SỬA LỖI: Import tác vụ Celery BÊN TRONG hàm để tránh import vòng
    from task import run_scan_task
    
    target_url = request.form.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    new_scan = Scan(target_url=target_url, status='PENDING')
    db.session.add(new_scan)
    db.session.commit()

    run_scan_task.delay(new_scan.id)
    
    return jsonify({'message': 'Scan started successfully', 'scan_id': new_scan.id})

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = scan.vulnerabilities.all()
    return render_template('results.html', scan=scan, vulnerabilities=vulnerabilities)

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
    data = {
        'labels': [item[0] for item in vuln_counts],
        'counts': [item[1] for item in vuln_counts]
    }
    return jsonify(data)
