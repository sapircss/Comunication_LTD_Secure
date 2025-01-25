from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db_manager import Database
from .auth import login_required

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template("home.html", user_email=session.get('user_email'))

@views.route('/system', methods=['GET'])
@login_required
def system():
    db = Database()
    clients = []

    try:
        db.create_table('clients')  # Ensure the `clients` table exists
        filter_id = request.args.get('filter_id')  # Optional filter

        if filter_id:
            db.cursor.execute("SELECT id, first_name, last_name FROM clients WHERE id = ?", (filter_id,))
        else:
            db.cursor.execute("SELECT id, first_name, last_name FROM clients")
        
        clients = [{'id': row[0], 'first_name': row[1], 'last_name': row[2]} for row in db.cursor.fetchall()]
    finally:
        db.close()

    return render_template("system.html", user_email=session.get('user_email'), clients=clients)

@views.route('/addclient', methods=['POST'])
@login_required
def add_client():
    db = Database()
    try:
        client_id = request.form.get('id', '').strip()
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()

        if not all([client_id, first_name, last_name]):
            flash('All fields are required.', 'error')
            return redirect(url_for('views.system'))

        client_data = {
            'id': client_id,
            'first_name': first_name,
            'last_name': last_name,
        }

        db.create_table('clients')
        db.insert_user_to_table('clients', client_data)

        flash(f"Client {first_name} {last_name} added successfully!", 'success')
    finally:
        db.close()

    return redirect(url_for('views.system'))