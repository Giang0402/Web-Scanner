import os
from dotenv import load_dotenv

# Tải các biến từ file .env
load_dotenv()

class Config:
    """Lớp cấu hình, tải thông tin từ biến môi trường."""
    # Flask & SQLAlchemy
    # THAY THẾ CẤU HÌNH SQLITE BẰNG POSTGRESQL
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:giang123@localhost:5432/scanner_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

    # Target Application (giữ nguyên)
    TARGET_BASE_URL = os.getenv('TARGET_BASE_URL')
    TARGET_LOGIN_URL = os.getenv('TARGET_LOGIN_URL')
    TARGET_SECURITY_URL = os.getenv('TARGET_SECURITY_URL')
    TARGET_USERNAME = os.getenv('TARGET_USERNAME')
    TARGET_PASSWORD = os.getenv('TARGET_PASSWORD')