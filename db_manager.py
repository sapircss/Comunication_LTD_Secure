import sqlite3
from flask import request, flash, url_for, redirect
from prettytable import PrettyTable
import bcrypt  # Added for secure password hashing
import html  # Added for XSS prevention
from typing import Dict, Any  # Added for type hints

class Database:
    EMPLOYEES_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
        'password': 'TEXT NOT NULL', # Will store hashed passwords instead of plaintext
        'email': 'TEXT NOT NULL UNIQUE',
    }

    CLIENTS_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
    }

    TABLES_COLUMNS = {
        'employees': EMPLOYEES_COLUMNS,
        'clients': CLIENTS_COLUMNS
    }

    def __init__(self, db_name='company.db'): # The location of where the db is can be changed.
        """Establish a single connection during object initialization"""
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.conn.execute("PRAGMA foreign_keys = ON") # SECURITY: Enable foreign key support to maintain data integrity - Guy
        self.cursor = self.conn.cursor()
        print("Database Connection establish")

    def _execute_query(self, query: str, params = ()):
        """
        SECURITY IMPROVEMENT:
           Uses parameterized queries instead of string formatting
        - Prevents SQL injection attacks
        """
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during query execution: {e}")
            raise

    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) #ues bcrypt for password hashing,Automatically handles salt generation and storage

    def _verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed) #securely compares hashed passwords

    def _sanitize_input(self, data):
        return {k: html.escape(str(v)) if isinstance(v, str) else v  #escapes html special charachers in user input and prevens script injection
                for k, v in data.items()}


    def create_table(self, table_name: str) -> None:
        if table_name.lower() not in self.TABLES_COLUMNS:
            print(f"Invalid table name '{table_name}'")
            return

        self.cursor.execute("SELECT name FROM sqlite_master WHERE type=? AND name=?", ('table', table_name))

        if not self.cursor.fetchone():
            columns = self.TABLES_COLUMNS[table_name.lower()]
            columns_definition = ', '.join(f'{col} {dtype}' for col, dtype in columns.items())
            create_table_query = f"CREATE TABLE {table_name} ({columns_definition});"
            self._execute_query(create_table_query)
            print(f"Table '{table_name}' created successfully.")

    def insert_user_to_table(self, table_name, user_data):
        try:
            clean_data = self._sanitize_input(user_data) #Sanitizes input to prevent XSS
            
            if 'password' in clean_data:
                clean_data['password'] = self._hash_password(clean_data['password']) #Hashes passwords before storage

            columns = ', '.join(clean_data.keys())
            placeholders = ', '.join(['?' for _ in clean_data])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})" #Uses parameterized queries to prevent SQL injection
            
            self._execute_query(query, tuple(clean_data.values()))
            
        except sqlite3.IntegrityError as e: #Properly handles exceptions
            print(f"Error inserting user into '{table_name}': {e}")
            raise


    def print_table(self, table_name):
        """Print all rows from a specified table"""
        try:
            self.cursor.execute(f"SELECT * FROM {table_name}")
            rows = self.cursor.fetchall()
            if rows:
                self.cursor.execute(f"PRAGMA table_info('{table_name}')") #returns metadata about the columns in the table
                columns_name = [info[1] for info in self.cursor.fetchall()]
                table = PrettyTable()
                table.field_names = columns_name
                for row in rows:
                    table.add_row(row)
                print(f"\nContents of table '{table_name}':")
                print(table)
            else:
                print(f"Table '{table_name}' is empty.")
        except sqlite3.Error as e:
            print(f"Error reading table '{table_name}': {e}")

    def change_password(self, email: str, old_password: str, new_password: str, table_name='employees') -> bool:
        try:
            self.cursor.execute(f"SELECT password FROM {table_name} WHERE email = ?", (email,)) #Uses parameterized queries
            stored_password = self.cursor.fetchone()
            
            if stored_password and self._verify_password(old_password, stored_password[0]): #Verifies old password before allowing change
                new_password_hash = self._hash_password(new_password) #Hashes new password before storage
                self._execute_query(
                    f"UPDATE {table_name} SET password = ? WHERE email = ?",
                    (new_password_hash, email)
                )
                return True
            return False
        except sqlite3.Error as e: #Proper error handling
            print(f"Error updating password: {e}")
            return False
        

    def validate_user_login(self, email, password):
        try:
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,)) #Uses parameterized query to prevent SQL injection
            result = self.cursor.fetchone()
            
            if result and self._verify_password(password, result[0]): #Securely verifies hashed passwords
                return True
            return False
            
        except sqlite3.Error as e: #Proper error handling
            print(f"Database error during login validation: {e}")
            return False
        




    def fetch_user_data_from_register_page(self):
        try:
            email = request.form.get('email', '').strip()
            user_id = request.form.get('id', '').strip()
            first_name = request.form.get('firstName', '').strip()
            last_name = request.form.get('lastName', '').strip()
            password1 = request.form.get('password1', '')
            password2 = request.form.get('password2', '')

            # Validate all required fields are present
            if not all([email, user_id, first_name, last_name, password1, password2]):
                flash('All fields are required.', 'error')
                return None

            # Validate email format
            if not '@' in email or not '.' in email:
                flash('Please enter a valid email address.', 'error')
                return None

            # Validate ID is numeric
            if not user_id.isdigit():
                flash('ID must contain only numbers.', 'error')
                return None

            # Validate name lengths
            if len(first_name) > 50 or len(last_name) > 50:
                flash('Names must be less than 50 characters.', 'error')
                return None

            # Validate passwords match
            if password1 != password2:
                flash('Passwords do not match.', 'error')
                return None

            # Create user data dictionary with sanitized inputs
            user_data = {
                'id': self._sanitize_input({'id': user_id})['id'],
                'first_name': self._sanitize_input({'first_name': first_name})['first_name'],
                'last_name': self._sanitize_input({'last_name': last_name})['last_name'],
                'password': password1,  # Will be hashed later in insert_user_to_table
                'email': self._sanitize_input({'email': email})['email'],
            }

            return user_data

        except Exception as e:
            print(f"Error processing registration data: {e}")
            flash('An error occurred while processing your registration.', 'error')
            return None
 
    def fetch_user_data_from_add_clients_page(self):
        try:
            user_id = request.form.get('id', '').strip()
            first_name = request.form.get('firstName', '').strip()
            last_name = request.form.get('lastName', '').strip()

            # Validate all required fields are present
            if not all([user_id, first_name, last_name]):
                flash('All fields are required.', 'error')
                return None

            # Validate ID is numeric
            if not user_id.isdigit():
                flash('ID must contain only numbers.', 'error')
                return None

             #Validate name lengths
            if len(first_name) > 50 or len(last_name) > 50:
                flash('Names must be less than 50 characters.', 'error')
                return None
            #Input validation for all fields above,Length checks on inputs above,

            # Create client data dictionary with sanitized inputs
            client_data = {
                'id': self._sanitize_input({'id': user_id})['id'],
                'first_name': self._sanitize_input({'first_name': first_name})['first_name'],
                'last_name': self._sanitize_input({'last_name': last_name})['last_name'], #Sanitization of all inputs
            }

            return client_data

        except Exception as e:
            print(f"Error processing client data: {e}")
            flash('An error occurred while processing client data.', 'error')
            return None

    def fetch_data_from_a_page(self, page):
        allowed_pages = {'register', 'addClients'} #Limited to specific allowed pages
    
        try:
            if page not in allowed_pages:
                print(f"Invalid page requested: {page}") #Input validation for page parameter
                return None
            
            if page == 'register':
                return self.fetch_user_data_from_register_page()
            elif page == 'addClients':
                return self.fetch_user_data_from_add_clients_page()
            
        except Exception as e: #Proper error handling
            print(f"Error fetching data from page {page}: {e}")
            return None


    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.conn:
                self.conn.close()
            print("Database Connection closed")
        except Exception as e:
            print(f"Error closing database connection: {e}")
