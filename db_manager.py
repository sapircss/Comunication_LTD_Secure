import json
import sqlite3
from flask import request, flash
from prettytable import PrettyTable
import bcrypt
import html
import re


class Database:
    EMPLOYEES_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
        'password': 'TEXT NOT NULL',
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

    def __init__(self, db_name='company.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.conn.cursor()
        print("Database connection established.")

    def _execute_query(self, query: str, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during query execution: {e}")
            raise

    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def _verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    def _sanitize_input(self, data):
        return {k: html.escape(str(v)) if isinstance(v, str) else v for k, v in data.items()}

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
            clean_data = self._sanitize_input(user_data)
            if 'password' in clean_data:
                clean_data['password'] = self._hash_password(clean_data['password'])

            columns = ', '.join(clean_data.keys())
            placeholders = ', '.join(['?' for _ in clean_data])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            self._execute_query(query, tuple(clean_data.values()))
        except sqlite3.IntegrityError as e:
            print(f"Error inserting user into '{table_name}': {e}")
            raise

    def print_table(self, table_name):
        try:
            self.cursor.execute(f"SELECT * FROM {table_name}")
            rows = self.cursor.fetchall()
            if rows:
                self.cursor.execute(f"PRAGMA table_info('{table_name}')")
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
            self.cursor.execute(f"SELECT password FROM {table_name} WHERE email = ?", (email,))
            stored_password = self.cursor.fetchone()

            if stored_password and self._verify_password(old_password, stored_password[0]):
                new_password_hash = self._hash_password(new_password)
                self._execute_query(
                    f"UPDATE {table_name} SET password = ? WHERE email = ?",
                    (new_password_hash, email)
                )
                return True
            return False
        except sqlite3.Error as e:
            print(f"Error updating password: {e}")
            return False

    def validate_user_login(self, email, password):
        try:
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = self.cursor.fetchone()
            if result and self._verify_password(password, result[0]):
                return True
            return False
        except sqlite3.Error as e:
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

            if not all([email, user_id, first_name, last_name, password1, password2]):
                flash('All fields are required.', 'error')
                return None

            if not '@' in email or not '.' in email:
                flash('Please enter a valid email address.', 'error')
                return None

            if not user_id.isdigit():
                flash('ID must contain only numbers.', 'error')
                return None

            if password1 != password2:
                flash('Passwords do not match.', 'error')
                return None

            with open('password_config.json', 'r') as f:
                config = json.load(f)
            min_length = config['password_length']
            complexity = config['complexity']
            dictionary_words = config['dictionary_words']

            if len(password1) < min_length:
                flash(f'Password must be at least {min_length} characters long.', 'error')
                return None

            if complexity.get('uppercase') and not re.search(r'[A-Z]', password1):
                flash('Password must contain at least one uppercase letter.', 'error')
                return None
            if complexity.get('lowercase') and not re.search(r'[a-z]', password1):
                flash('Password must contain at least one lowercase letter.', 'error')
                return None
            if complexity.get('numbers') and not re.search(r'[0-9]', password1):
                flash('Password must contain at least one number.', 'error')
                return None
            if complexity.get('special_characters') and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password1):
                flash('Password must contain at least one special character.', 'error')
                return None

            for word in dictionary_words:
                if word.lower() in password1.lower():
                    flash(f'Password cannot contain the dictionary word: {word}', 'error')
                    return None

            user_data = {
                'id': user_id,
                'first_name': first_name,
                'last_name': last_name,
                'password': password1,
                'email': email,
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

            if not all([user_id, first_name, last_name]):
                flash('All fields are required.', 'error')
                return None

            if not user_id.isdigit():
                flash('ID must contain only numbers.', 'error')
                return None

            if len(first_name) > 50 or len(last_name) > 50:
                flash('Names must be less than 50 characters.', 'error')
                return None

            client_data = {
                'id': self._sanitize_input({'id': user_id})['id'],
                'first_name': self._sanitize_input({'first_name': first_name})['first_name'],
                'last_name': self._sanitize_input({'last_name': last_name})['last_name'],
            }

            return client_data

        except Exception as e:
            print(f"Error processing client data: {e}")
            flash('An error occurred while processing client data.', 'error')
            return None

    def fetch_data_from_a_page(self, page):
        allowed_pages = {'register', 'addClients'}

        try:
            if page not in allowed_pages:
                print(f"Invalid page requested: {page}")
                return None

            if page == 'register':
                return self.fetch_user_data_from_register_page()
            elif page == 'addClients':
                return self.fetch_user_data_from_add_clients_page()

        except Exception as e:
            print(f"Error fetching data from page {page}: {e}")
            return None

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.conn:
                self.conn.close()
            print("Database connection closed.")
        except Exception as e:
            print(f"Error closing database connection: {e}")
