import os
from dotenv import load_dotenv

# Load environment variables from a .env file.
load_dotenv()

class Config:
    """
    Configuration class that loads settings from environment variables.
    """
    # Use PostgreSQL as the database.
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:giang123@localhost:5432/scanner_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

    # Target Application
    TARGET_BASE_URL = os.getenv('TARGET_BASE_URL')
    TARGET_LOGIN_URL = os.getenv('TARGET_LOGIN_URL')
    TARGET_SECURITY_URL = os.getenv('TARGET_SECURITY_URL')
    TARGET_USERNAME = os.getenv('TARGET_USERNAME')
    TARGET_PASSWORD = os.getenv('TARGET_PASSWORD')
