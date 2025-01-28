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
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support
        self.cursor = self.conn.cursor()
        print("Database connection established.")

    def _execute_query(self, query: str, params=()):
        """
        Executes a query using parameterized SQL to prevent SQL injection.
        """
        try:
            print(f"Executing query: {query} with params: {params}")
            self.cursor.execute(query, params)  # Use parameterized queries
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during query execution: {escape(str(e))}")
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

    def _validate_input(self, input_value: str) -> None:
        """
        Validates input to prevent SQL injection and XSS attacks.
        """
        if not input_value:
            raise ValueError("Input cannot be empty.")
        
        # Check for HTML tags to prevent XSS
        if re.search(r"<.*?>", input_value):
            raise ValueError("Input contains invalid HTML tags.")
        
        # Check for forbidden SQL patterns to prevent SQL injection
        forbidden_patterns = ["--", ";--", "/*", "*/", "xp_", "union", "select", "insert", "delete", "update", "drop", "alter"]
        if any(pattern in input_value.lower() for pattern in forbidden_patterns):
            raise ValueError("Input contains invalid SQL keywords or patterns.")

    def create_table(self, table_name: str) -> None:
        """
        Creates a table if it doesn't already exist.
        """
        if table_name.lower() not in self.TABLES_COLUMNS:
            print(f"Invalid table name '{escape(table_name)}'")
            return

        columns = self.TABLES_COLUMNS[table_name.lower()]
        columns_definition = ', '.join(f'{col} {dtype}' for col, dtype in columns.items())
        create_table_query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_definition});"
        self._execute_query(create_table_query)
        print(f"Table '{table_name}' created successfully.")

    def insert_user_to_table(self, table_name: str, user_data: dict) -> None:
        """
        Inserts a user securely into the specified table.
        """
        try:
            # Validate all user data fields before saving
            for key, value in user_data.items():
                if isinstance(value, str):
                    self._validate_input(value)
            
            # Hash the password if it exists in the user data
            if 'password' in user_data:
                user_data['password'] = self._hash_password(user_data['password'])

            # Prepare SQL for parameterized execution
            columns = ', '.join(user_data.keys())
            placeholders = ', '.join(['?' for _ in user_data])
            query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            self._execute_query(query, tuple(user_data.values()))
        except sqlite3.IntegrityError as e:
            print(f"Error inserting user into '{table_name}': {escape(str(e))}")
            raise

    def print_table(self, table_name: str) -> None:
        """
        Prints the contents of a table.
        """
        try:
            query = f"SELECT * FROM {table_name}"
            print(f"Printing table with query: {query}")
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
                print(f"Table '{table_name}' is empty.")
        except sqlite3.Error as e:
            print(f"Error reading table '{table_name}': {escape(str(e))}")

    def change_password(self, email: str, old_password: str, new_password: str, table_name='employees') -> bool:
        """
        Changes a user's password securely.
        """
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
        """
        Validates a user's login credentials securely.
        """
        try:
            self._validate_input(email)
            self.cursor.execute("SELECT password FROM employees WHERE email = ?", (email,))
            result = self.cursor.fetchone()
            if result and self._verify_password(password, result[0]):
                return True
            return False
        except sqlite3.Error as e:
            print(f"Database error during login validation: {escape(str(e))}")
            return False

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
        except Exception as e:
            print(f"Error closing database connection: {escape(str(e))}")
