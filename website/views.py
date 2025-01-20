from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db_manager import Database
from .auth import login_required  # Added for route protection

views = Blueprint('views', __name__)

@views.route('/')
#@login_required  
# # SECURITY: Protect home page from unauthorized access
def home():
    return render_template("home.html", user_email=session.get('user_email')) #Passes user email from session to template

@views.route('/system', methods=['GET', 'POST'])
@login_required
def system():
    db = Database()
    filter_id = request.args.get('filter_id')  # Get the filter ID from the query parameters
    clients = []

    try:
        db.create_table('clients')  # Ensure the `clients` table exists

        if filter_id:  # If a filter ID is provided
            db.cursor.execute("SELECT id, first_name, last_name FROM clients WHERE id = ?", (filter_id,))
        else:
            db.cursor.execute("SELECT id, first_name, last_name FROM clients")
        
        clients = [{'id': row[0], 'first_name': row[1], 'last_name': row[2]} for row in db.cursor.fetchall()]
    except Exception as e:
        print(f"Error fetching clients: {e}")
        flash('An error occurred while fetching client data.', 'error')
    finally:
        db.close()

    return render_template("system.html", user_email=session.get('user_email'), clients=clients)



@views.route('/addclient', methods=['POST'])
@login_required
def add_client():
    db = Database()
    try:
        # Fetch and validate form data
        client_data = db.fetch_user_data_from_add_clients_page()
        if not client_data:
            flash('Invalid input. Please check your entries.', 'error')
            return redirect(url_for('views.system'))

        # Add the client to the database
        db.create_table('clients')  # Ensure the `clients` table exists
        db.insert_user_to_table('clients', client_data)

        flash(f"Client {client_data['first_name']} {client_data['last_name']} added successfully!", 'success')
    except Exception as e:
        print(f"Error adding client: {e}")
        flash('An error occurred while adding the client.', 'error')
    finally:
        db.close()

    return redirect(url_for('views.system'))
