from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import hashlib
import random
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from db_manager import Database
from functools import wraps

auth = Blueprint('auth', __name__)

# Load Configuration
with open('password_config.json', 'r') as f:
    CONFIG = json.load(f)

SMTP_PROVIDERS = CONFIG['smtp_providers']

def send_email(recipient: str, subject: str, body: str) -> bool:
    try:
        smtp_provider = SMTP_PROVIDERS.get('gmail')
        if not smtp_provider:
            flash("SMTP configuration not found.", "error")
            return False

        msg = MIMEMultipart()
        msg['From'] = smtp_provider['email_address']
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(smtp_provider['smtp_server'], smtp_provider['smtp_port']) as server:
            server.starttls()
            server.login(smtp_provider['email_address'], smtp_provider['email_password'])
            server.sendmail(smtp_provider['email_address'], recipient, msg.as_string())
        return True
    except smtplib.SMTPAuthenticationError:
        flash("Authentication error. Please check your email credentials.", "error")
        return False
    except Exception as e:
        flash("An unexpected error occurred while sending the email.", "error")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = Database()
        try:
            data = db.fetch_user_data_from_register_page()
            if not data:
                return redirect(url_for('auth.register'))

            db.create_table('employees')
            db.insert_user_to_table('employees', data)
            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash('An error occurred during registration.', 'error')
        finally:
            db.close()
    return render_template("register.html")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_email' in session:
        return redirect(url_for('views.system'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('auth.login'))

        db = Database()
        try:
            if db.validate_user_login(email, password):
                session['user_email'] = email
                flash('Logged in successfully!', 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Invalid email or password.', 'error')
        finally:
            db.close()
    return render_template("login.html")

@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('auth.forgotpass'))

        db = Database()
        try:
            db.cursor.execute("SELECT email FROM employees WHERE email = ?", (email,))
            if not db.cursor.fetchone():
                flash('Email not found.', 'error')
                return redirect(url_for('auth.forgotpass'))

            random_value = str(random.randint(100000, 999999))
            sha1_hash = hashlib.sha1(random_value.encode()).hexdigest()

            session['reset_token'] = sha1_hash
            session['reset_email'] = email

            email_body = f"Your password reset token is: {random_value}"
            if send_email(email, "Password Reset Request", email_body):
                flash('A password reset token has been sent to your email.', 'success')
                return redirect(url_for('auth.verify_reset'))
        finally:
            db.close()
    return render_template("forgotpass.html")

@auth.route('/verify_reset', methods=['GET', 'POST'])
def verify_reset():
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        if not token:
            flash('Token is required.', 'error')
            return redirect(url_for('auth.verify_reset'))

        sha1_hash = hashlib.sha1(token.encode()).hexdigest()
        if session.get('reset_token') == sha1_hash:
            return redirect(url_for('auth.reset_password'))
        else:
            flash('Invalid or expired token.', 'error')
            return redirect(url_for('auth.verify_reset'))
    return render_template("verify_reset.html")

@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('newPassword', '').strip()
        confirm_password = request.form.get('confirmPassword', '').strip()

        if not new_password or not confirm_password:
            flash('Both fields are required.', 'error')
            return redirect(url_for('auth.reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('auth.reset_password'))

        db = Database()
        try:
            email = session.get('reset_email')
            hashed_password = db._hash_password(new_password)
            db._execute_query("UPDATE employees SET password = ? WHERE email = ?", (hashed_password, email))

            session.pop('reset_email', None)
            session.pop('reset_token', None)

            flash('Password reset successfully!', 'success')
            return redirect(url_for('auth.login'))
        finally:
            db.close()
    return render_template("reset_password.html")

@auth.route('/changepass', methods=['GET', 'POST'])
@login_required
def changepass():
    if request.method == 'POST':
        current_password = request.form.get('oldPassword', '').strip()  # Changed 'currentPassword' to 'oldPassword'
        new_password = request.form.get('newPassword', '').strip()
        confirm_password = request.form.get('confirmPassword', '').strip()

        # Check if any field is empty
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.changepass'))

        # Check if the new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('auth.changepass'))

        db = Database()
        try:
            email = session.get('user_email')
            db.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = db.cursor.fetchone()

            # Check if the current password matches the stored password
            if result and db._verify_password(current_password, result[0]):
                hashed_password = db._hash_password(new_password)
                db._execute_query("UPDATE employees SET password = ? WHERE email = ?", (hashed_password, email))
                flash('Password changed successfully!', 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('auth.changepass'))
        finally:
            db.close()
    return render_template("changepass.html")

