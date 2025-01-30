import json
import sqlite3
from flask import request, flash
from prettytable import PrettyTable
import bcrypt
from markupsafe import escape
import re


class Database:
    # Define columns for the `employees` table
    EMPLOYEES_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
        'password': 'TEXT NOT NULL',
        'email': 'TEXT NOT NULL UNIQUE',
    }

    # Define columns for the `clients` table
    CLIENTS_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
    }

    # Map table names to their respective column definitions
    TABLES_COLUMNS = {
        'employees': EMPLOYEES_COLUMNS,
        'clients': CLIENTS_COLUMNS,
    }

    def __init__(self, db_name='company.db'):
        """
        Initializes the database connection and sets up foreign key enforcement.
        """
        try:
            self.db_name = db_name
            self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support
            self.cursor = self.conn.cursor()
            print("Database connection established.")
        except sqlite3.Error as e:
            print(f"# Error initializing database connection: {escape(str(e))}")

    def _execute_query(self, query: str, params=()):
        """
        Executes a query using parameterized SQL to prevent SQL injection.
        """
        try:
            print(f"Executing query: {query} with params: {params}")
            self.cursor.execute(query, params)  # Use parameterized queries
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"# Database error during query execution: {escape(str(e))}")
            raise

    def _hash_password(self, password: str) -> str:
        """
        Hashes a password securely using bcrypt.
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def _verify_password(self, password: str, hashed: str) -> bool:
        """
        Verifies a password against its hashed version.
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def _validate_input(self, input_value: str) -> str:
        """
        Validates input to prevent SQL injection and XSS attacks.
        """
        if not input_value:
            raise ValueError("# Error: Input cannot be empty.")
        
        # Escape potential HTML tags to prevent XSS
        safe_input = escape(input_value)

        # Block common SQL injection attack patterns
        forbidden_patterns = [
            r";--",  # Prevents inline comment-based injection
            r"/\*", r"\*/",  # Prevents block comment injection
            r"\b(xp_|union|select|insert|delete|update|drop|alter)\b"
        ]

        if any(re.search(pattern, safe_input, re.IGNORECASE) for pattern in forbidden_patterns):
            raise ValueError("# Error: Input contains invalid keywords or patterns.")

        return safe_input  # Return escaped input for safe processing

    def create_table(self, table_name: str) -> None:
        """
        Creates a table if it doesn't already exist.
        """
        if table_name.lower() not in self.TABLES_COLUMNS:
            print(f"# Error: Invalid table name '{escape(table_name)}'")
            return

        try:
            columns = self.TABLES_COLUMNS[table_name.lower()]
            columns_definition = ', '.join(f'{col} {dtype}' for col, dtype in columns.items())
            create_table_query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_definition});"
            self._execute_query(create_table_query)
            print(f"Table '{table_name}' created successfully.")
        except sqlite3.Error as e:
            print(f"# Error creating table '{table_name}': {escape(str(e))}")

    def insert_user_to_table(self, table_name: str, user_data: dict) -> None:
        """
        Inserts a user securely into the specified table.
        """
        try:
            # Validate input
            for key, value in user_data.items():
                if isinstance(value, str):
                    user_data[key] = self._validate_input(value)

            # Hash password if needed
            if 'password' in user_data:
                user_data['password'] = self._hash_password(user_data['password'])

            # Use parameterized queries
            columns = ', '.join(user_data.keys())
            placeholders = ', '.join(['?' for _ in user_data])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            self._execute_query(query, tuple(user_data.values()))
        except sqlite3.IntegrityError as e:
            print(f"# Integrity error inserting into '{table_name}': {escape(str(e))}")
            raise

    def validate_user_login(self, email: str, password: str) -> bool:
        """
        Validates a user's login credentials securely.
        """
        try:
            email = self._validate_input(email)
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = self.cursor.fetchone()
            if result and self._verify_password(password, result[0]):
                return True
            return False
        except sqlite3.Error as e:
            print(f"# Error during login validation: {escape(str(e))}")
            return False

    def change_password(self, email: str, old_password: str, new_password: str) -> bool:
        """
        Changes a user's password securely.
        """
        try:
            email = self._validate_input(email)
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            stored_password = self.cursor.fetchone()

            if stored_password and self._verify_password(old_password, stored_password[0]):
                new_password_hash = self._hash_password(new_password)
                self._execute_query("UPDATE employees SET password = ? WHERE email = ?", (new_password_hash, email))
                return True
            return False
        except sqlite3.Error as e:
            print(f"# Error updating password: {escape(str(e))}")
            return False

    def delete_user(self, table_name: str, user_id: int) -> None:
        """
        Deletes a user from a specified table.
        """
        try:
            query = f"DELETE FROM {table_name} WHERE id = ?"
            self._execute_query(query, (user_id,))
            print(f"User with ID {user_id} deleted from '{table_name}'.")
        except sqlite3.Error as e:
            print(f"# Error deleting user from '{table_name}': {escape(str(e))}")

    def get_user_by_id(self, table_name: str, user_id: int):
        """
        Retrieves user details by ID.
        """
        try:
            query = f"SELECT * FROM {table_name} WHERE id = ?"
            self.cursor.execute(query, (user_id,))
            return self.cursor.fetchone()
        except sqlite3.Error as e:
            print(f"# Error retrieving user from '{table_name}': {escape(str(e))}")
            return None

    def print_table(self, table_name: str) -> None:
        """
        Prints the contents of a table.
        """
        try:
            query = f"SELECT * FROM {table_name}"
            self.cursor.execute(query)
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
                print(f"# Warning: Table '{table_name}' is empty.")
        except sqlite3.Error as e:
            print(f"# Error reading table '{table_name}': {escape(str(e))}")

    def close(self) -> None:
        """
        Closes the database connection safely.
        """
        try:
            if self.cursor:
                self.cursor.close()
            if self.conn:
                self.conn.close()
            print("Database connection closed.")
        except sqlite3.Error as e:
            print(f"# Error closing database connection: {escape(str(e))}")
