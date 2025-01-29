# config.py

import os

class Config:
    """Base configuration with default settings."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    FERNET_KEY = os.getenv('FERNET_KEY', 'default_fernet_key')
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./easemyvote.db')
    EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
    EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', 'easemyvote@gmail.com')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'default_email_password')
    SESSION_COOKIE = 'session'
    SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', 1800))
    HTTPS_ONLY = False
    SAME_SITE = 'lax'
    TESTING = False
    DEBUG = False

class ProductionConfig(Config):
    """Production configuration settings."""
    SECRET_KEY = os.getenv('SECRET_KEY')
    FERNET_KEY = os.getenv('FERNET_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
    HTTPS_ONLY = True  # Ensure cookies are only sent over HTTPS
    DEBUG = False

class TestingConfig(Config):
    """Testing configuration settings."""
    SECRET_KEY = os.getenv('TEST_SECRET_KEY', 'test_secret_key')
    FERNET_KEY = os.getenv('TEST_FERNET_KEY', 'test_fernet_key')
    DATABASE_URL = os.getenv('TEST_DATABASE_URL', 'sqlite:///./test_easemyvote.db')
    EMAIL_PASSWORD = os.getenv('TEST_EMAIL_PASSWORD', 'test_email_password')
    SESSION_COOKIE = 'test_session'
    TESTING = True
    DEBUG = True
