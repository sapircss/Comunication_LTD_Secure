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

    TABLES_COLUMNS = {
        'employees': EMPLOYEES_COLUMNS,
    }

    def __init__(self, db_name='company.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.conn.cursor()

    def _execute_query(self, query: str, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during query execution: {e}")
            raise

    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

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

            # Validate passwords match
            if password1 != password2:
                flash('Passwords do not match.', 'error')
                return None

            # Load password configuration
            with open('password_config.json', 'r') as f:
                config = json.load(f)
            min_length = config['password_length']
            complexity = config['complexity']
            dictionary_words = config['dictionary_words']

            # Validate password length
            if len(password1) < min_length:
                flash(f'Password must be at least {min_length} characters long.', 'error')
                return None

            # Validate password complexity
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

            # Check password against dictionary words (substring match)
            for word in dictionary_words:
                if word.lower() in password1.lower():
                    flash(f'Password cannot contain the dictionary word: {word}', 'error')
                    return None

            # Create user data dictionary
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

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.conn:
                self.conn.close()
        except Exception as e:
            print(f"Error closing database connection: {e}")
