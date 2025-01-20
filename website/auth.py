from flask import Blueprint, render_template, request, redirect, url_for,flash,session
from db_manager import Database
from functools import wraps  # Added for login_required decorator
import sqlite3

auth = Blueprint('auth', __name__)


def login_required(f):
    """Ensures user is logged in before accessing protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

#Login Page
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_email' in session:
        return redirect(url_for('views.system'))  # Redirect to system if already logged in

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('auth.login'))

        db = Database()
        try:
            if db.validate_user_login(email, password):
                session['user_email'] = email  # Set session for logged-in user
                flash('Logged in successfully!', 'success')
                return redirect(url_for('views.system'))  # Redirect to the system page
            else:
                flash('Invalid email or password.', 'error')
        except Exception as e:
            print(f"Error during login: {e}")
            flash('An error occurred during login.', 'error')
        finally:
            db.close()

    return render_template("login.html")



#Logout Page
@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'POST':
        session.pop('user_email', None)
        flash('Logged out successfully!', 'success')
        return redirect(url_for('auth.login'))
    return redirect(url_for('views.home'))


#Register Page
@auth.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        db = Database()
        try:
            data = db.fetch_data_from_a_page(page="register")
            if not data:
                flash('Please fill in all fields correctly.', 'error')
                return redirect(url_for('auth.register'))

            db.create_table('employees')
            db.insert_user_to_table('employees', data)
            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
        finally:
            db.close()
            
    return render_template("register.html")
#change password Page
@auth.route('/changepass', methods=['GET','POST'])
def changepass():

    if request.method == 'POST':
        email = request.form.get('email')
        old_password = request.form.get('oldPassword')
        new_password = request.form.get('newPassword')

        if not all([email, old_password, new_password]):
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('auth.changepass'))

        if email != session.get('user_email'):
            flash('You can only change your own password.', 'error')
            return redirect(url_for('auth.changepass'))

        db = Database()
        try:
            if db.change_password(email, old_password, new_password):
                flash('Password changed successfully!', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid current password.', 'error')
        except Exception as e:
            flash('An error occurred while changing password.', 'error')
        finally:
            db.close()

    return render_template("changepass.html")

#change password Page
@auth.route('/randval')
def randval():
    return render_template("randval.html")


@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    return render_template("forgotpass.html")
