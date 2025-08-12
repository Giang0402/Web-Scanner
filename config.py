import os
from dotenv import load_dotenv
from sqlalchemy.pool import NullPool # FIX: Import NullPool

# Tải các biến từ file .env
load_dotenv()

class Config:
    """Lớp cấu hình, tải thông tin từ biến môi trường."""
    # Flask & SQLAlchemy
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'scanner.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # FIX: Thêm engine options để vô hiệu hóa connection pooling cho SQLite
    # Điều này rất quan trọng để tránh lỗi lock khi dùng eventlet/gevent
    SQLALCHEMY_ENGINE_OPTIONS = {
        'poolclass': NullPool,
    }

    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

    # Target Application
    TARGET_BASE_URL = os.getenv('TARGET_BASE_URL')
    TARGET_LOGIN_URL = os.getenv('TARGET_LOGIN_URL')
    TARGET_SECURITY_URL = os.getenv('TARGET_SECURITY_URL')
    TARGET_USERNAME = os.getenv('TARGET_USERNAME')
    TARGET_PASSWORD = os.getenv('TARGET_PASSWORD')