from flask import Flask, session
from flask_session import Session
from datetime import timedelta
import secrets
import os

def create_app():
    app = Flask(__name__)

    # Generate or retrieve a secure secret key
    secret_key_path = 'instance/secret_key.txt'
    os.makedirs('instance', exist_ok=True)

    if os.path.exists(secret_key_path):
        with open(secret_key_path, 'r') as f:
            secret_key = f.read().strip()
    else:
        secret_key = secrets.token_hex(32)
        with open(secret_key_path, 'w') as f:
            f.write(secret_key)

    # Flask Configuration
    app.config.update(
        SECRET_KEY=secret_key,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_TYPE="filesystem",  # Store sessions on the server
    )

    # Initialize Flask-Session
    Session(app)

    # Import and register Blueprints
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    return app
