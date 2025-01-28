import json
import sqlite3
from flask import request, flash
from prettytable import PrettyTable
import bcrypt
import bleach  # For input sanitization
from markupsafe import escape
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
        'clients': CLIENTS_COLUMNS,
    }

    def __init__(self, db_name='company.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.conn.cursor()
        print("Database connection established.")

    def _execute_query(self, query: str, params=()):
        """Executes a query using parameterized SQL to prevent SQL injection."""
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during query execution: {escape(str(e))}")
            raise

    def _hash_password(self, password: str) -> str:
        """Hashes a password securely using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verifies a password against its hashed version."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def _sanitize_input(self, data: dict) -> dict:
        """Sanitizes input using bleach and blocks SQL injection patterns."""
        forbidden_patterns = ["SELECT", "UNION", "INSERT", "DELETE", "UPDATE", "DROP", "--", ";", "'", '"']
        sanitized_data = {}
        for k, v in data.items():
            if isinstance(v, str):
                if any(pattern in v.lower() for pattern in forbidden_patterns):
                    raise ValueError("Invalid input detected. Possible SQL Injection.")
                sanitized_data[k] = escape(bleach.clean(v))
            else:
                sanitized_data[k] = v
        return sanitized_data

    def create_table(self, table_name: str) -> None:
        """Creates a table if it doesn't already exist."""
        if table_name.lower() not in self.TABLES_COLUMNS:
            print(f"Invalid table name '{escape(table_name)}'")
            return

        columns = self.TABLES_COLUMNS[table_name.lower()]
        columns_definition = ', '.join(f'{col} {dtype}' for col, dtype in columns.items())
        create_table_query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_definition});"
        self._execute_query(create_table_query)
        print(f"Table '{table_name}' created successfully.")

    def insert_user_to_table(self, table_name: str, user_data: dict) -> None:
        """Inserts a user securely into the specified table."""
        try:
            sanitized_data = self._sanitize_input(user_data)
            if 'password' in sanitized_data:
                sanitized_data['password'] = self._hash_password(sanitized_data['password'])

            columns = ', '.join(sanitized_data.keys())
            placeholders = ', '.join(['?' for _ in sanitized_data])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            self._execute_query(query, tuple(sanitized_data.values()))
        except sqlite3.IntegrityError as e:
            print(f"Error inserting user into '{table_name}': {escape(str(e))}")
            raise
        except ValueError as ve:
            print(f"Input validation error: {escape(str(ve))}")
            raise

    def print_table(self, table_name: str) -> None:
        """Prints the contents of a table."""
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
            print(f"Error reading table '{table_name}': {escape(str(e))}")

    def change_password(self, email: str, old_password: str, new_password: str, table_name='employees') -> bool:
        """Changes a user's password securely."""
        try:
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            stored_password = self.cursor.fetchone()

            if stored_password and self._verify_password(old_password, stored_password[0]):
                new_password_hash = self._hash_password(new_password)
                self._execute_query("UPDATE employees SET password = ? WHERE email = ?", (new_password_hash, email))
                return True
            return False
        except sqlite3.Error as e:
            print(f"Error updating password: {escape(str(e))}")
            return False

    def validate_user_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials securely."""
        try:
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = self.cursor.fetchone()
            if result and self._verify_password(password, result[0]):
                return True
            return False
        except sqlite3.Error as e:
            print(f"Database error during login validation: {escape(str(e))}")
            return False

    def fetch_user_data_from_register_page(self) -> dict:
        """Fetches and validates user data securely from the registration page."""
        try:
            email = bleach.clean(request.form.get('email', '').strip())
            user_id = bleach.clean(request.form.get('id', '').strip())
            first_name = bleach.clean(request.form.get('firstName', '').strip())
            last_name = bleach.clean(request.form.get('lastName', '').strip())
            password1 = request.form.get('password1', '').strip()
            password2 = request.form.get('password2', '').strip()

            if not all([email, user_id, first_name, last_name, password1, password2]):
                flash('All fields are required.', 'error')
                return None

            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash('Invalid email format.', 'error')
                return None

            if not user_id.isdigit():
                flash('ID must contain only numbers.', 'error')
                return None

            if password1 != password2:
                flash('Passwords do not match.', 'error')
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
            print(f"Error processing registration data: {escape(str(e))}")
            flash('An error occurred during registration.', 'error')
            return None

    def close(self) -> None:
        """Closes the database connection safely."""
        try:
            if self.cursor:
                self.cursor.close()
            if self.conn:
                self.conn.close()
            print("Database connection closed.")
        except Exception as e:
            print(f"Error closing database connection: {escape(str(e))}")
