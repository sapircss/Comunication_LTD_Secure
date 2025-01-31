from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import hashlib
import random
import smtplib
import json
import re
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
        domain = recipient.split('@')[-1].lower()
        smtp_provider = None

        if "gmail.com" in domain:
            smtp_provider = SMTP_PROVIDERS.get("gmail")
        elif "hotmail.com" in domain:
            smtp_provider = SMTP_PROVIDERS.get("hotmail")

        if not smtp_provider:
            flash("SMTP configuration not found for this domain.", "error")
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
    except smtplib.SMTPAuthenticationError as e:
        flash(f"SMTP Authentication error: {e}", "error")
        return False
    except Exception as e:
        flash(f"An unexpected error occurred while sending the email: {e}", "error")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_email'):
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_password(password: str, email: str = None) -> str:
    """
    Validate the password based on the configuration file.
    
    Args:
        password (str): The password to validate.
        email (str): User email for password history check (optional).

    Returns:
        str: Error message if validation fails, otherwise None.
    """
    if len(password) < CONFIG["password_length"]:
        return f"Password must be at least {CONFIG['password_length']} characters long."

    if CONFIG["complexity"]["uppercase"] and not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."

    if CONFIG["complexity"]["lowercase"] and not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."

    if CONFIG["complexity"]["numbers"] and not any(c.isdigit() for c in password):
        return "Password must contain at least one number."

    if CONFIG["complexity"]["special_characters"] and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."

    for word in CONFIG["dictionary_words"]:
        if word.lower() in password.lower():
            return "Password is too weak. Do not use common words or phrases."

    # Password history check
    if email:
        db = Database()
        try:
            db.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            password_history = [row[0] for row in db.cursor.fetchall()]
            if any(db._verify_password(password, old_password) for old_password in password_history[-CONFIG["password_history_limit"]:]):
                return f"Password must not match the last {CONFIG['password_history_limit']} passwords."
        finally:
            db.close()

    return None

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = Database()
        try:
            data = {
                'email': request.form.get('email', '').strip(),
                'id': request.form.get('id', '').strip(),
                'first_name': request.form.get('firstName', '').strip(),
                'last_name': request.form.get('lastName', '').strip(),
                'password': request.form.get('password1', '').strip()
            }

            if data['password'] != request.form.get('password2', '').strip():
                flash('Passwords do not match.', 'error')
                return render_template("register.html", **data)

            # Validate password
            password_error = is_valid_password(data['password'])
            if password_error:
                flash(password_error, 'error')
                return render_template("register.html", **data)

            db.create_table('employees')
            db.insert_user_to_table('employees', data)
            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))
        except ValueError as ve:
            flash(str(ve), 'error')
            return render_template("register.html", **data)
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')
        finally:
            db.close()
    return render_template("register.html")

@auth.route('/changepass', methods=['GET', 'POST'])
@login_required
def changepass():
    if request.method == 'POST':
        current_password = request.form.get('oldPassword', '').strip()
        new_password = request.form.get('newPassword', '').strip()
        confirm_password = request.form.get('confirmPassword', '').strip()

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.changepass'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('auth.changepass'))

        db = Database()
        try:
            email = session.get('user_email')
            db.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = db.cursor.fetchone()

            if result and db._verify_password(current_password, result[0]):
                password_error = is_valid_password(new_password, email)
                if password_error:
                    flash(password_error, 'error')
                    return redirect(url_for('auth.changepass'))

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

@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Email is required.', 'error')  
            return redirect(url_for('auth.forgotpass'))

        db = Database()
        try:
            # Vulnerable SQL query - directly concatenates user input into query
            db.cursor.execute(f"SELECT email FROM employees WHERE email = '{email}'")
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
    """Handles password reset after verifying the token."""
    if 'reset_email' not in session:
        flash("Session expired. Please request a new password reset.", "error")
        return redirect(url_for('auth.forgotpass'))

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
            email = session.pop('reset_email')  # Remove from session for security
            hashed_password = db._hash_password(new_password)

            # Use parameterized query to prevent SQL injection
            db._execute_query("UPDATE employees SET password = ? WHERE email = ?", (hashed_password, email))

            flash("Password reset successfully! Please log in.", "success")
            return redirect(url_for('auth.login'))  
        finally:
            db.close()

    return render_template("reset_password.html")


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
