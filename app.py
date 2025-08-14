import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
import json

# STEP 1: Initialize the Flask App and extensions
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# STEP 2: Import and configure Celery
# This Celery instance is created in task.py but has no configuration yet.
from task import celery
# Update the Celery configuration with the Flask app's config.
celery.config_from_object('config:Config')


# --- DATABASE MODELS ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(255), default='PENDING', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    scan_config = db.Column(db.JSON, nullable=True)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        """Returns a dictionary representation of the Scan object."""
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
    details = db.Column(db.JSON, nullable=True)

# --- HELPERS ---
def get_remediation_advice(vuln_type):
    """
    Returns remediation advice for a given vulnerability type.
    """
    advice = {
        'XSS': "Use Output Encoding for all user-provided data...",
        'SQLI': "Always use Prepared Statements...",
        'CMDI': "Avoid calling operating system commands directly...",
        'SSRF_BLIND': "Configure a firewall to block outbound connections..."
    }
    return advice.get(vuln_type.upper(), "No specific advice available. Refer to OWASP security documents.")

# --- FLASK ROUTES ---
@app.route('/')
def index():
    """Renders the main page with a list of all scans."""
    import requests
    from core.scanner import Scanner
    scanner_instance = Scanner(requests.Session())
    available_plugins = [s.name for s in scanner_instance.scanners]
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('index.html', scans=scans, available_plugins=available_plugins)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Starts a new web scan task via Celery."""
    from task import run_scan_task
    target_url = request.form.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    config = {
        'auth': {
            'cookie': request.form.get('auth_cookie'),
            'header': request.form.get('auth_header')
        },
        'policy': {
            'plugins': request.form.getlist('plugins')
        }
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
    """Displays the details and vulnerabilities for a specific scan."""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = scan.vulnerabilities.all()
    return render_template('results.html', scan=scan, vulnerabilities=vulnerabilities, get_remediation_advice=get_remediation_advice)

@app.route('/status/<int:scan_id>')
def scan_status(scan_id):
    """Returns the current status of a scan."""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({'status': scan.status})
    
@app.route('/scan/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Deletes a scan and all its associated vulnerabilities."""
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/data/vulnerability_types/<int:scan_id>')
def vulnerability_types_data(scan_id):
    """Returns data for a chart showing the count of each vulnerability type."""
    scan = Scan.query.get_or_404(scan_id)
    vuln_counts = db.session.query(Vulnerability.vuln_type, db.func.count(Vulnerability.vuln_type)).filter_by(scan_id=scan.id).group_by(Vulnerability.vuln_type).all()
    data = {'labels': [item[0] for item in vuln_counts], 'counts': [item[1] for item in vuln_counts]}
    return jsonify(data)
