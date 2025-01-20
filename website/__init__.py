from flask import Flask
from datetime import timedelta
import secrets

def create_app():
    app = Flask(__name__)
    
    # Generate a secure secret key if none exists
    try:
        with open('instance/secret_key.txt', 'r') as f:
            secret_key = f.read().strip()
    except FileNotFoundError:
        # Generate a new secret key
        secret_key = secrets.token_hex(32)
        # Save it for future use
        import os
        os.makedirs('instance', exist_ok=True)
        with open('instance/secret_key.txt', 'w') as f:
            f.write(secret_key)

    app.config.update(
        SECRET_KEY=secret_key,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        SESSION_COOKIE_SECURE=False,  # HTTP setting
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
    
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    return app
