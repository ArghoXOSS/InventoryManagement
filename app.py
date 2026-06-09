import os
import csv
import io
import sqlite3

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, Response, flash

from models import *
from auth import login_required


# ---------------- LOAD ENVIRONMENT VARIABLES ----------------
load_dotenv()


# ---------------- APP SETUP ----------------
app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-change-this")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"


# Initialize database
init_db()


# ---------------- HELPER FUNCTIONS ----------------
def get_current_user_id():
    """
    Returns logged-in user's ID from session.
    Also supports older sessions that only had session['user'].
    """
    if "user_id" in session:
        return session["user_id"]

    if "user" in session:
        user = get_user_by_username(session["user"])
        if user:
            session["user_id"] = user["id"]
            return user["id"]

    session.clear()
    return None


def scalar_value(row, key, index=0, default=0):
    """
    Works with both:
    - SQLite row access by index
    - PostgreSQL RealDictCursor access by key
    """
    if row is None:
        return default

    try:
        value = row[key]
    except Exception:
        value = row[index]

    if value is None:
        return default

    return value


# ---------------- ROOT ----------------
@app.route("/")
def home():
    if "user" in session:
        return redirect("/dashboard")
    return redirect("/login")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user_by_username(username)

        if user and verify_password(user["password"], password):
            session.clear()
            session["user"] = username
            session["user_id"] = user["id"]

            # Upgrade old plain-text passwords to hashed passwords after successful login
            if not user["password"].startswith("scrypt:") and not user["password"].startswith("pbkdf2:"):
                upgrade_user_password_to_hash(username, password)

            flash("Login successful! Welcome back.", "success")
            return redirect("/dashboard")

        flash("Invalid username or password.", "error")
        return redirect("/login")

    return render_template("login.html")


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if username == "":
            flash("Username cannot be empty.", "error")
            return redirect("/signup")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return redirect("/signup")

        if len(password) < 4:
            flash("Password must be at least 4 characters.", "error")
            return redirect("/signup")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect("/signup")

        existing_user = get_user_by_username(username)

        if existing_user:
            flash("Username already exists.", "error")
            return redirect("/signup")

        try:
            add_user(username, password)
        except Exception:
            flash("Username already exists.", "error")
            return redirect("/signup")

        flash("Account created successfully! Please login.", "success")
        return redirect("/login")

    return render_template("signup.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/login")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_products = scalar_value(cursor.fetchone(), "count")

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_stock = scalar_value(cursor.fetchone(), "total")

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
        AND quantity <= 5
    """), (user_id,))
    low_stock_count = scalar_value(cursor.fetchone(), "count")

    cursor.execute(convert_placeholders("""
        SELECT SUM(price * quantity) AS total
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_stock_value = scalar_value(cursor.fetchone(), "total")

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM suppliers
        WHERE user_id = ?
    """), (user_id,))
    total_suppliers = scalar_value(cursor.fetchone(), "count")

    cursor.execute(convert_placeholders("""
        SELECT name, quantity
        FROM products
        WHERE user_id = ?
        ORDER BY quantity DESC
        LIMIT 8
    """), (user_id,))
    chart_products = cursor.fetchall()

    product_names = [row["name"] for row in chart_products]
    product_quantities = [row["quantity"] for row in chart_products]

    cursor.execute(convert_placeholders("""
        SELECT 
            COALESCE(NULLIF(category, ''), 'Others') AS category_name,
            COUNT(*) AS product_count
        FROM products
        WHERE user_id = ?
        GROUP BY COALESCE(NULLIF(category, ''), 'Others')
        ORDER BY product_count DESC
    """), (user_id,))
    category_rows = cursor.fetchall()

    category_names = [row["category_name"] for row in category_rows]
    category_counts = [row["product_count"] for row in category_rows]

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM stock_history
        WHERE user_id = ?
        AND movement_type = 'Stock In'
    """), (user_id,))
    total_stock_in = scalar_value(cursor.fetchone(), "total")

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM stock_history
        WHERE user_id = ?
        AND movement_type = 'Stock Out'
    """), (user_id,))
    total_stock_out = scalar_value(cursor.fetchone(), "total")

    stock_movement_labels = ["Stock In", "Stock Out"]
    stock_movement_values = [total_stock_in, total_stock_out]

    cursor.execute(convert_placeholders("""
        SELECT *
        FROM stock_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """), (user_id,))
    recent_movements = cursor.fetchall()

    cursor.execute(convert_placeholders("""
        SELECT *
        FROM products
        WHERE user_id = ?
        AND quantity <= 5
        ORDER BY quantity ASC
        LIMIT 5
    """), (user_id,))
    low_stock_products = cursor.fetchall()

    cursor.execute(convert_placeholders("""
        SELECT name, quantity
        FROM products
        WHERE user_id = ?
        ORDER BY quantity DESC
        LIMIT 1
    """), (user_id,))
    most_stocked_product = cursor.fetchone()

    if most_stocked_product:
        most_stocked_name = most_stocked_product["name"]
        most_stocked_quantity = most_stocked_product["quantity"]
    else:
        most_stocked_name = "N/A"
        most_stocked_quantity = 0

    cursor.execute(convert_placeholders("""
        SELECT name, quantity, price, (quantity * price) AS total_value
        FROM products
        WHERE user_id = ?
        ORDER BY total_value DESC
        LIMIT 1
    """), (user_id,))
    most_valuable_product = cursor.fetchone()

    if most_valuable_product:
        most_valuable_name = most_valuable_product["name"]
        most_valuable_value = most_valuable_product["total_value"]
    else:
        most_valuable_name = "N/A"
        most_valuable_value = 0

    if total_products == 0:
        inventory_health = "No Data"
        inventory_health_message = "No products have been added yet."
    elif low_stock_count == 0:
        inventory_health = "Excellent"
        inventory_health_message = "All products have healthy stock levels."
    elif low_stock_count <= 3:
        inventory_health = "Good"
        inventory_health_message = "Only a few products are running low."
    else:
        inventory_health = "Needs Attention"
        inventory_health_message = "Several products are low in stock."

    cursor.close()
    conn.close()

    return render_template(
        "dashboard.html",
        total_products=total_products,
        total_stock=total_stock,
        low_stock_count=low_stock_count,
        total_stock_value=total_stock_value,
        total_suppliers=total_suppliers,
        product_names=product_names,
        product_quantities=product_quantities,
        category_names=category_names,
        category_counts=category_counts,
        stock_movement_labels=stock_movement_labels,
        stock_movement_values=stock_movement_values,
        total_stock_in=total_stock_in,
        total_stock_out=total_stock_out,
        recent_movements=recent_movements,
        low_stock_products=low_stock_products,
        most_stocked_name=most_stocked_name,
        most_stocked_quantity=most_stocked_quantity,
        most_valuable_name=most_valuable_name,
        most_valuable_value=most_valuable_value,
        inventory_health=inventory_health,
        inventory_health_message=inventory_health_message
    )


# ---------------- PRODUCT DETAILS ----------------
@app.route("/product/<sku>")
@login_required
def product_details(sku):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_sku(user_id, sku)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    history = get_product_stock_history(user_id, sku)

    total_value = product["price"] * product["quantity"]

    return render_template(
        "product_details.html",
        product=product,
        history=history,
        total_value=total_value
    )


# ---------------- PRODUCTS PAGE ----------------
@app.route("/products")
@login_required
def products():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    search_query = request.args.get("search", "").strip().lower()
    sort_by = request.args.get("sort", "")
    category_filter = request.args.get("category", "")

    items = get_all_products(user_id)
    suppliers = get_all_suppliers(user_id)

    if search_query:
        items = [
            item for item in items
            if search_query in item["name"].lower()
            or search_query in item["sku"].lower()
            or search_query in (item["category"] or "Others").lower()
            or search_query in (item["supplier_name"] or "").lower()
        ]

    if category_filter:
        items = [
            item for item in items
            if (item["category"] or "Others") == category_filter
        ]

    if sort_by == "name_az":
        items = sorted(items, key=lambda item: item["name"].lower())
    elif sort_by == "name_za":
        items = sorted(items, key=lambda item: item["name"].lower(), reverse=True)
    elif sort_by == "category_az":
        items = sorted(items, key=lambda item: (item["category"] or "Others").lower())
    elif sort_by == "category_za":
        items = sorted(items, key=lambda item: (item["category"] or "Others").lower(), reverse=True)
    elif sort_by == "quantity_low":
        items = sorted(items, key=lambda item: item["quantity"])
    elif sort_by == "quantity_high":
        items = sorted(items, key=lambda item: item["quantity"], reverse=True)
    elif sort_by == "price_low":
        items = sorted(items, key=lambda item: item["price"])
    elif sort_by == "price_high":
        items = sorted(items, key=lambda item: item["price"], reverse=True)

    total_products = len(items)
    total_stock = sum(item["quantity"] for item in items)
    low_stock = len([item for item in items if item["quantity"] <= 5])

    names = [item["name"] for item in items]
    quantities = [item["quantity"] for item in items]

    categories = [
        "Others",
        "Electronics",
        "Grocery",
        "Stationery",
        "Medicine",
        "Clothing",
        "Cosmetics",
        "Food",
        "Accessories"
    ]

    return render_template(
        "products.html",
        products=items,
        suppliers=suppliers,
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        names=names,
        quantities=quantities,
        search_query=search_query,
        sort_by=sort_by,
        category_filter=category_filter,
        categories=categories
    )


# ---------------- ADD PRODUCT ----------------
@app.route("/add", methods=["POST"])
@login_required
def add():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    name = request.form.get("name", "").strip()
    sku = request.form.get("sku", "").strip()
    category = request.form.get("category", "Others").strip()
    quantity_text = request.form.get("quantity", "0")
    price_text = request.form.get("price", "0")
    supplier_id = request.form.get("supplier_id")

    if name == "" or sku == "":
        flash("Product name and SKU cannot be empty.", "error")
        return redirect("/products")

    if category == "":
        category = "Others"

    try:
        quantity = int(quantity_text)
        price = float(price_text)
    except ValueError:
        flash("Quantity and price must be valid numbers.", "error")
        return redirect("/products")

    if quantity < 0:
        flash("Quantity cannot be negative.", "error")
        return redirect("/products")

    if price < 0:
        flash("Price cannot be negative.", "error")
        return redirect("/products")

    if supplier_id == "":
        supplier_id = None

    if supplier_id is not None:
        supplier = get_supplier_by_id(user_id, supplier_id)
        if supplier is None:
            flash("Invalid supplier selected.", "error")
            return redirect("/products")

    try:
        add_product(user_id, name, sku, category, quantity, price, supplier_id)
    except Exception:
        flash("SKU already exists. Please use a unique SKU.", "error")
        return redirect("/products")

    flash("Product added successfully!", "success")
    return redirect("/products")


# ---------------- DELETE PRODUCT ----------------
@app.route("/delete/<int:pid>")
@login_required
def delete(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    delete_product(user_id, pid)

    flash("Product deleted successfully!", "success")
    return redirect("/products")


# ---------------- EDIT PRODUCT PAGE ----------------
@app.route("/edit/<int:pid>")
@login_required
def edit(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)
    suppliers = get_all_suppliers(user_id)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    return render_template(
        "edit_product.html",
        product=product,
        suppliers=suppliers
    )


# ---------------- UPDATE PRODUCT ----------------
@app.route("/update/<int:pid>", methods=["POST"])
@login_required
def update(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    name = request.form.get("name", "").strip()
    sku = request.form.get("sku", "").strip()
    category = request.form.get("category", "Others").strip()
    quantity_text = request.form.get("quantity", "0")
    price_text = request.form.get("price", "0")
    supplier_id = request.form.get("supplier_id")

    if name == "" or sku == "":
        flash("Product name and SKU cannot be empty.", "error")
        return redirect(f"/edit/{pid}")

    if category == "":
        category = "Others"

    try:
        quantity = int(quantity_text)
        price = float(price_text)
    except ValueError:
        flash("Quantity and price must be valid numbers.", "error")
        return redirect(f"/edit/{pid}")

    if quantity < 0:
        flash("Quantity cannot be negative.", "error")
        return redirect(f"/edit/{pid}")

    if price < 0:
        flash("Price cannot be negative.", "error")
        return redirect(f"/edit/{pid}")

    if supplier_id == "":
        supplier_id = None

    if supplier_id is not None:
        supplier = get_supplier_by_id(user_id, supplier_id)
        if supplier is None:
            flash("Invalid supplier selected.", "error")
            return redirect(f"/edit/{pid}")

    try:
        update_product(user_id, pid, name, sku, category, quantity, price, supplier_id)
    except Exception:
        flash("SKU already exists. Please use a unique SKU.", "error")
        return redirect(f"/edit/{pid}")

    flash("Product updated successfully!", "success")
    return redirect("/products")


# ---------------- LOW STOCK PAGE ----------------
@app.route("/low-stock")
@login_required
def low_stock_page():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    items = get_all_products(user_id)
    low_stock_items = [item for item in items if item["quantity"] <= 5]

    total_low_stock = len(low_stock_items)
    total_low_stock_value = sum(item["quantity"] * item["price"] for item in low_stock_items)

    return render_template(
        "low_stock.html",
        low_stock_items=low_stock_items,
        total_low_stock=total_low_stock,
        total_low_stock_value=total_low_stock_value
    )


# ---------------- STOCK IN PAGE ----------------
@app.route("/stock-in/<int:pid>")
@login_required
def stock_in_page(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    return render_template("stock_in.html", product=product)


# ---------------- STOCK IN ACTION ----------------
@app.route("/stock-in/<int:pid>", methods=["POST"])
@login_required
def stock_in(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        error = "Stock in amount must be a valid number."
        return render_template("stock_in.html", product=product, error=error)

    if amount <= 0:
        error = "Stock in amount must be greater than 0."
        return render_template("stock_in.html", product=product, error=error)

    new_quantity = product["quantity"] + amount

    update_product(
        user_id,
        pid,
        product["name"],
        product["sku"],
        product["category"],
        new_quantity,
        product["price"],
        product["supplier_id"]
    )

    add_stock_history(
        user_id,
        pid,
        product["name"],
        product["sku"],
        "Stock In",
        amount
    )

    flash("Stock added successfully!", "success")
    return redirect("/products")


# ---------------- STOCK OUT PAGE ----------------
@app.route("/stock-out/<int:pid>")
@login_required
def stock_out_page(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    return render_template("stock_out.html", product=product)


# ---------------- STOCK OUT ACTION ----------------
@app.route("/stock-out/<int:pid>", methods=["POST"])
@login_required
def stock_out(pid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    product = get_product_by_id(user_id, pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        error = "Stock out amount must be a valid number."
        return render_template("stock_out.html", product=product, error=error)

    if amount <= 0:
        error = "Stock out amount must be greater than 0."
        return render_template("stock_out.html", product=product, error=error)

    if amount > product["quantity"]:
        error = "Stock out amount cannot be greater than current quantity."
        return render_template("stock_out.html", product=product, error=error)

    new_quantity = product["quantity"] - amount

    update_product(
        user_id,
        pid,
        product["name"],
        product["sku"],
        product["category"],
        new_quantity,
        product["price"],
        product["supplier_id"]
    )

    add_stock_history(
        user_id,
        pid,
        product["name"],
        product["sku"],
        "Stock Out",
        amount
    )

    flash("Stock removed successfully!", "success")
    return redirect("/products")


# ---------------- STOCK HISTORY PAGE ----------------
@app.route("/stock-history")
@login_required
def stock_history():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    history = get_stock_history(user_id)
    return render_template("stock_history.html", history=history)


# ---------------- REPORTS PAGE ----------------
@app.route("/reports")
@login_required
def reports():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    report = get_report_data(user_id)
    top_products = get_top_stock_products(user_id)
    recent_movements = get_recent_stock_movements(user_id)

    return render_template(
        "reports.html",
        report=report,
        top_products=top_products,
        recent_movements=recent_movements
    )


# ---------------- PRINT REPORT ----------------
@app.route("/print-report")
@login_required
def print_report():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(convert_placeholders("""
        SELECT 
            products.*,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers 
            ON products.supplier_id = suppliers.id
            AND suppliers.user_id = products.user_id
        WHERE products.user_id = ?
        ORDER BY products.id DESC
    """), (user_id,))
    products = cursor.fetchall()

    cursor.execute(convert_placeholders("""
        SELECT *
        FROM suppliers
        WHERE user_id = ?
        ORDER BY id DESC
    """), (user_id,))
    suppliers = cursor.fetchall()

    cursor.execute(convert_placeholders("""
        SELECT *
        FROM stock_history
        WHERE user_id = ?
        ORDER BY id DESC
    """), (user_id,))
    stock_history_data = cursor.fetchall()

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_products = scalar_value(cursor.fetchone(), "count")

    cursor.execute(convert_placeholders("""
        SELECT SUM(quantity) AS total
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_stock = scalar_value(cursor.fetchone(), "total")

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
        AND quantity <= 5
    """), (user_id,))
    low_stock = scalar_value(cursor.fetchone(), "count")

    cursor.execute(convert_placeholders("""
        SELECT SUM(price * quantity) AS total
        FROM products
        WHERE user_id = ?
    """), (user_id,))
    total_stock_value = scalar_value(cursor.fetchone(), "total")

    cursor.execute(convert_placeholders("""
        SELECT COUNT(*) AS count
        FROM suppliers
        WHERE user_id = ?
    """), (user_id,))
    total_suppliers = scalar_value(cursor.fetchone(), "count")

    cursor.close()
    conn.close()

    return render_template(
        "print_report.html",
        products=products,
        suppliers=suppliers,
        stock_history=stock_history_data,
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        total_stock_value=total_stock_value,
        total_suppliers=total_suppliers
    )


# ---------------- EXPORT PRODUCTS CSV ----------------
@app.route("/export-products")
@login_required
def export_products():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    products = get_all_products(user_id)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Product Name",
        "SKU",
        "Category",
        "Supplier",
        "Quantity",
        "Price",
        "Total Value"
    ])

    for product in products:
        total_value = product["quantity"] * product["price"]

        writer.writerow([
            product["id"],
            product["name"],
            product["sku"],
            product["category"] if product["category"] else "Others",
            product["supplier_name"] if product["supplier_name"] else "N/A",
            product["quantity"],
            product["price"],
            total_value
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=products_report.csv"
        }
    )


# ---------------- SUPPLIERS PAGE ----------------
@app.route("/suppliers")
@login_required
def suppliers():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    suppliers_data = get_all_suppliers(user_id)
    return render_template("suppliers.html", suppliers=suppliers_data)


# ---------------- ADD SUPPLIER ----------------
@app.route("/add-supplier", methods=["POST"])
@login_required
def add_supplier_route():
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if name == "":
        flash("Supplier name cannot be empty.", "error")
        return redirect("/suppliers")

    add_supplier(user_id, name, phone, email, address)

    flash("Supplier added successfully!", "success")
    return redirect("/suppliers")


# ---------------- EDIT SUPPLIER PAGE ----------------
@app.route("/edit-supplier/<int:sid>")
@login_required
def edit_supplier_page(sid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    supplier = get_supplier_by_id(user_id, sid)

    if supplier is None:
        flash("Supplier not found.", "error")
        return redirect("/suppliers")

    return render_template("edit_supplier.html", supplier=supplier)


# ---------------- UPDATE SUPPLIER ----------------
@app.route("/update-supplier/<int:sid>", methods=["POST"])
@login_required
def update_supplier_route(sid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    supplier = get_supplier_by_id(user_id, sid)

    if supplier is None:
        flash("Supplier not found.", "error")
        return redirect("/suppliers")

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if name == "":
        flash("Supplier name cannot be empty.", "error")
        return redirect(f"/edit-supplier/{sid}")

    update_supplier(user_id, sid, name, phone, email, address)

    flash("Supplier updated successfully!", "success")
    return redirect("/suppliers")


# ---------------- DELETE SUPPLIER ----------------
@app.route("/delete-supplier/<int:sid>")
@login_required
def delete_supplier_route(sid):
    user_id = get_current_user_id()
    if user_id is None:
        return redirect("/login")

    supplier = get_supplier_by_id(user_id, sid)

    if supplier is None:
        flash("Supplier not found.", "error")
        return redirect("/suppliers")

    delete_supplier(user_id, sid)

    flash("Supplier deleted successfully!", "success")
    return redirect("/suppliers")


# ---------------- ERROR PAGES ----------------
@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV") != "production"
    app.run(debug=debug_mode)