import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "webscanpro-super-secret-key-cyber-2026")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'webscanpro.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Reports directory
    REPORTS_DIR = BASE_DIR / "instance" / "reports"
    
    # Security boundaries & safety limits
    ALLOWED_TARGET_HOSTS = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "testserver",
    ]
    # Allow local lab domains if explicitly enabled
    ALLOW_PRIVATE_IPS = True
    
    # Crawler and scan budget defaults
    DEFAULT_MAX_DEPTH = 3
    DEFAULT_MAX_PAGES = 30
    DEFAULT_REQUEST_TIMEOUT = 5  # seconds
    DEFAULT_REQUEST_DELAY = 0.05  # polite crawl delay in seconds
    DEFAULT_MAX_REQUESTS_PER_SCAN = 150
    
    # Health check ports for common local security labs
    LAB_PRESETS = {
        "juice_shop": {
            "name": "OWASP Juice Shop",
            "url": "http://localhost:3000",
            "description": "Intentionally insecure web app for security training",
        },
        "dvwa": {
            "name": "Damn Vulnerable Web App (DVWA)",
            "url": "http://localhost:4280",
            "description": "PHP/MySQL web application to test security skills",
        },
        "mock_lab": {
            "name": "WebScanPro Mock Target Lab",
            "url": "http://127.0.0.1:5001/mock-lab/",
            "description": "Safe, built-in testing bench for instant verification",
        }
    }


class DevelopmentConfig(Config):
    DEBUG = True


import tempfile

class TestingConfig(Config):
    TESTING = True
    _test_db_file = tempfile.NamedTemporaryFile(suffix="_wsp_test.db", delete=False).name
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{_test_db_file}"
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "prod-security-key-change-me")


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
