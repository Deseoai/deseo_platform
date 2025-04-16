import os
from dotenv import load_dotenv

load_dotenv()  # Lädt lokale .env Variablen

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'unsicherer_key'
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL ist nicht definiert!")

    # Flask-Mail Konfiguration
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 'on']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ['true', '1', 'on']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'Deseo <noreply@example.com>'

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')  # z. B. admin@example.com

    # Gültigkeitsdauer für Passwort-Reset
    PASSWORD_RESET_TOKEN_MAX_AGE = 3600  # 1 Stunde

    # Sicherheit (Cookies)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ['true', '1', 'on']
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

config = Config()
