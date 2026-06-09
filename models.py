import os
import sqlite3
from datetime import datetime

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash


# ---------------- LOAD ENVIRONMENT VARIABLES ----------------
load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///inventory.db")


# ---------------- DATABASE TYPE CHECK ----------------
def is_postgres():
    return DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")


def get_sqlite_db_name():
    if DATABASE_URL.startswith("sqlite:///"):
        return DATABASE_URL.replace("sqlite:///", "")
    return "inventory.db"


# ---------------- DATABASE CONNECTION ----------------
def get_db_connection():
    if is_postgres():
        conn = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        return conn

    db_name = get_sqlite_db_name()
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- SQL PLACEHOLDER HELPER ----------------
def convert_placeholders(sql):
    if is_postgres():
        return sql.replace("?", "%s")
    return sql


# ---------------- FETCH HELPERS ----------------
def fetch_one(sql, params=()):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders(sql), params)
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    return row


def fetch_all(sql, params=()):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders(sql), params)
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows


def execute_query(sql, params=()):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders(sql), params)

    conn.commit()
    cursor.close()
    conn.close()


# ---------------- COLUMN CHECK HELPERS ----------------
def column_exists(cursor, table_name, column_name):
    if is_postgres():
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        """, (table_name, column_name))

        return cursor.fetchone() is not None

    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    for column in columns:
        if column["name"] == column_name:
            return True

    return False


def add_column_if_missing(cursor, table_name, column_name, column_definition):
    if not column_exists(cursor, table_name, column_name):
        cursor.execute(f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
        """)


# ---------------- PASSWORD HELPERS ----------------
def hash_password(password):
    return generate_password_hash(password)


def verify_password(stored_password, entered_password):
    if stored_password is None:
        return False

    if stored_password.startswith("scrypt:") or stored_password.startswith("pbkdf2:"):
        return check_password_hash(stored_password, entered_password)

    return stored_password == entered_password


def upgrade_user_password_to_hash(username, plain_password):
    hashed = hash_password(plain_password)

    execute_query("""
        UPDATE users
        SET password = ?
        WHERE username = ?
    """, (hashed, username))


# ---------------- INITIALIZE DATABASE ----------------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    if is_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suppliers (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                address TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                sku TEXT NOT NULL,
                category TEXT DEFAULT 'Others',
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                supplier_id INTEGER REFERENCES suppliers(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stock_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
                product_name TEXT,
                sku TEXT,
                movement_type TEXT,
                quantity INTEGER,
                date TEXT
            )
        """)

    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suppliers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                sku TEXT NOT NULL,
                category TEXT DEFAULT 'Others',
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                supplier_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stock_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                product_id INTEGER,
                product_name TEXT,
                sku TEXT,
                movement_type TEXT,
                quantity INTEGER,
                date TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            )
        """)

    # ---------------- SAFE DATABASE UPGRADES ----------------
    add_column_if_missing(cursor, "suppliers", "user_id", "INTEGER")

    add_column_if_missing(cursor, "products", "user_id", "INTEGER")
    add_column_if_missing(cursor, "products", "category", "TEXT DEFAULT 'Others'")
    add_column_if_missing(cursor, "products", "supplier_id", "INTEGER")

    add_column_if_missing(cursor, "stock_history", "user_id", "INTEGER")
    add_column_if_missing(cursor, "stock_history", "product_id", "INTEGER")
    add_column_if_missing(cursor, "stock_history", "product_name", "TEXT")
    add_column_if_missing(cursor, "stock_history", "sku", "TEXT")
    add_column_if_missing(cursor, "stock_history", "movement_type", "TEXT")
    add_column_if_missing(cursor, "stock_history", "quantity", "INTEGER")
    add_column_if_missing(cursor, "stock_history", "date", "TEXT")

    # Create default admin account if no admin exists
    cursor.execute(convert_placeholders("""
        SELECT *
        FROM users
        WHERE username = ?
    """), ("admin",))

    admin_user = cursor.fetchone()

    if admin_user is None:
        cursor.execute(convert_placeholders("""
            INSERT INTO users (username, password)
            VALUES (?, ?)
        """), ("admin", hash_password("1234")))

    # Get admin id for old existing data migration
    cursor.execute(convert_placeholders("""
        SELECT id
        FROM users
        WHERE username = ?
    """), ("admin",))

    admin_user = cursor.fetchone()
    admin_id = admin_user["id"] if admin_user else 1

    # Assign old global data to admin so new users start clean
    cursor.execute(convert_placeholders("""
        UPDATE suppliers
        SET user_id = ?
        WHERE user_id IS NULL
    """), (admin_id,))

    cursor.execute(convert_placeholders("""
        UPDATE products
        SET user_id = ?
        WHERE user_id IS NULL
    """), (admin_id,))

    cursor.execute(convert_placeholders("""
        UPDATE stock_history
        SET user_id = ?
        WHERE user_id IS NULL
    """), (admin_id,))

    # Fix old products where category is empty or NULL
    cursor.execute("""
        UPDATE products
        SET category = 'Others'
        WHERE category IS NULL OR category = ''
    """)

    conn.commit()
    cursor.close()
    conn.close()


# ---------------- USER FUNCTIONS ----------------
def add_user(username, password):
    hashed_password = hash_password(password)

    execute_query("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
    """, (username, hashed_password))


def get_user_by_username(username):
    return fetch_one("""
        SELECT *
        FROM users
        WHERE username = ?
    """, (username,))


# ---------------- PRODUCT FUNCTIONS ----------------
def add_product(user_id, name, sku, category, quantity, price, supplier_id=None):
    if supplier_id == "":
        supplier_id = None

    if category == "" or category is None:
        category = "Others"

    execute_query("""
        INSERT INTO products (user_id, name, sku, category, quantity, price, supplier_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, name, sku, category, quantity, price, supplier_id))


def get_all_products(user_id):
    return fetch_all("""
        SELECT 
            products.*,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers 
            ON products.supplier_id = suppliers.id
            AND suppliers.user_id = products.user_id
        WHERE products.user_id = ?
        ORDER BY products.id DESC
    """, (user_id,))


def get_product_by_id(user_id, pid):
    return fetch_one("""
        SELECT 
            products.*,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers 
            ON products.supplier_id = suppliers.id
            AND suppliers.user_id = products.user_id
        WHERE products.id = ?
        AND products.user_id = ?
    """, (pid, user_id))


def get_product_by_sku(user_id, sku):
    return fetch_one("""
        SELECT 
            products.*,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers 
            ON products.supplier_id = suppliers.id
            AND suppliers.user_id = products.user_id
        WHERE products.sku = ?
        AND products.user_id = ?
    """, (sku, user_id))


def update_product(user_id, pid, name, sku, category, quantity, price, supplier_id=None):
    if supplier_id == "":
        supplier_id = None

    if category == "" or category is None:
        category = "Others"

    execute_query("""
        UPDATE products
        SET name = ?, sku = ?, category = ?, quantity = ?, price = ?, supplier_id = ?
        WHERE id = ?
        AND user_id = ?
    """, (name, sku, category, quantity, price, supplier_id, pid, user_id))


def delete_product(user_id, pid):
    execute_query("""
        DELETE FROM products
        WHERE id = ?
        AND user_id = ?
    """, (pid, user_id))


# ---------------- STOCK HISTORY FUNCTIONS ----------------
def add_stock_history(user_id, product_id, product_name, sku, movement_type, quantity):
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_query("""
        INSERT INTO stock_history (user_id, product_id, product_name, sku, movement_type, quantity, date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, product_id, product_name, sku, movement_type, quantity, date))


def get_stock_history(user_id):
    return fetch_all("""
        SELECT *
        FROM stock_history
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))


def get_product_stock_history(user_id, sku):
    return fetch_all("""
        SELECT *
        FROM stock_history
        WHERE user_id = ?
        AND sku = ?
        ORDER BY id DESC
    """, (user_id, sku))


def get_recent_stock_movements(user_id):
    return fetch_all("""
        SELECT *
        FROM stock_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (user_id,))


# ---------------- REPORT FUNCTIONS ----------------
def get_report_data(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count 
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_products = row["count"] if is_postgres() else row[0]

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total 
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_stock = row["total"] if is_postgres() else row[0]
    if total_stock is None:
        total_stock = 0

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity * price) AS total 
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_value = row["total"] if is_postgres() else row[0]
    if total_value is None:
        total_value = 0

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count 
        FROM products 
        WHERE quantity <= 5
        AND user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    low_stock_count = row["count"] if is_postgres() else row[0]

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM stock_history
        WHERE movement_type = 'Stock In'
        AND user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_stock_in = row["total"] if is_postgres() else row[0]
    if total_stock_in is None:
        total_stock_in = 0

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM stock_history
        WHERE movement_type = 'Stock Out'
        AND user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_stock_out = row["total"] if is_postgres() else row[0]
    if total_stock_out is None:
        total_stock_out = 0

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count 
        FROM stock_history
        WHERE user_id = ?
    """), (user_id,))
    row = cursor.fetchone()
    total_movements = row["count"] if is_postgres() else row[0]

    cursor.close()
    conn.close()

    return {
        "total_products": total_products,
        "total_stock": total_stock,
        "total_value": total_value,
        "low_stock_count": low_stock_count,
        "total_stock_in": total_stock_in,
        "total_stock_out": total_stock_out,
        "total_movements": total_movements
    }


def get_top_stock_products(user_id):
    return fetch_all("""
        SELECT *
        FROM products
        WHERE user_id = ?
        ORDER BY quantity DESC
        LIMIT 5
    """, (user_id,))


# ---------------- SUPPLIER FUNCTIONS ----------------
def add_supplier(user_id, name, phone, email, address):
    execute_query("""
        INSERT INTO suppliers (user_id, name, phone, email, address)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, name, phone, email, address))


def get_all_suppliers(user_id):
    return fetch_all("""
        SELECT *
        FROM suppliers
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))


def get_supplier_by_id(user_id, sid):
    return fetch_one("""
        SELECT *
        FROM suppliers
        WHERE id = ?
        AND user_id = ?
    """, (sid, user_id))


def update_supplier(user_id, sid, name, phone, email, address):
    execute_query("""
        UPDATE suppliers
        SET name = ?, phone = ?, email = ?, address = ?
        WHERE id = ?
        AND user_id = ?
    """, (name, phone, email, address, sid, user_id))


def delete_supplier(user_id, sid):
    execute_query("""
        UPDATE products
        SET supplier_id = NULL
        WHERE supplier_id = ?
        AND user_id = ?
    """, (sid, user_id))

    execute_query("""
        DELETE FROM suppliers
        WHERE id = ?
        AND user_id = ?
    """, (sid, user_id))