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


# Initialize database
init_db()


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
            session["user"] = username

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
        except sqlite3.IntegrityError:
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
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(quantity) FROM products")
    total_stock = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM products WHERE quantity <= 5")
    low_stock_count = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(price * quantity) FROM products")
    total_stock_value = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM suppliers")
    total_suppliers = cursor.fetchone()[0]

    cursor.execute("""
        SELECT name, quantity
        FROM products
        ORDER BY quantity DESC
        LIMIT 8
    """)
    chart_products = cursor.fetchall()

    product_names = [row["name"] for row in chart_products]
    product_quantities = [row["quantity"] for row in chart_products]

    cursor.execute("""
        SELECT 
            COALESCE(NULLIF(category, ''), 'Others') AS category_name,
            COUNT(*) AS product_count
        FROM products
        GROUP BY COALESCE(NULLIF(category, ''), 'Others')
        ORDER BY product_count DESC
    """)
    category_rows = cursor.fetchall()

    category_names = [row["category_name"] for row in category_rows]
    category_counts = [row["product_count"] for row in category_rows]

    cursor.execute("""
        SELECT SUM(quantity)
        FROM stock_history
        WHERE movement_type = 'Stock In'
    """)
    total_stock_in = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT SUM(quantity)
        FROM stock_history
        WHERE movement_type = 'Stock Out'
    """)
    total_stock_out = cursor.fetchone()[0] or 0

    stock_movement_labels = ["Stock In", "Stock Out"]
    stock_movement_values = [total_stock_in, total_stock_out]

    cursor.execute("""
        SELECT *
        FROM stock_history
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_movements = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM products
        WHERE quantity <= 5
        ORDER BY quantity ASC
        LIMIT 5
    """)
    low_stock_products = cursor.fetchall()

    cursor.execute("""
        SELECT name, quantity
        FROM products
        ORDER BY quantity DESC
        LIMIT 1
    """)
    most_stocked_product = cursor.fetchone()

    if most_stocked_product:
        most_stocked_name = most_stocked_product["name"]
        most_stocked_quantity = most_stocked_product["quantity"]
    else:
        most_stocked_name = "N/A"
        most_stocked_quantity = 0

    cursor.execute("""
        SELECT name, quantity, price, (quantity * price) AS total_value
        FROM products
        ORDER BY total_value DESC
        LIMIT 1
    """)
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
    product = get_product_by_sku(sku)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM stock_history
        WHERE sku = ?
        ORDER BY id DESC
    """, (sku,))

    history = cursor.fetchall()
    conn.close()

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
    search_query = request.args.get("search", "").strip().lower()
    sort_by = request.args.get("sort", "")
    category_filter = request.args.get("category", "")

    items = get_all_products()
    suppliers = get_all_suppliers()

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

    try:
        add_product(name, sku, category, quantity, price, supplier_id)
    except sqlite3.IntegrityError:
        flash("SKU already exists. Please use a unique SKU.", "error")
        return redirect("/products")

    flash("Product added successfully!", "success")
    return redirect("/products")


# ---------------- DELETE PRODUCT ----------------
@app.route("/delete/<int:pid>")
@login_required
def delete(pid):
    delete_product(pid)
    flash("Product deleted successfully!", "success")
    return redirect("/products")


# ---------------- EDIT PRODUCT PAGE ----------------
@app.route("/edit/<int:pid>")
@login_required
def edit(pid):
    product = get_product_by_id(pid)
    suppliers = get_all_suppliers()

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
    product = get_product_by_id(pid)

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

    try:
        update_product(pid, name, sku, category, quantity, price, supplier_id)
    except sqlite3.IntegrityError:
        flash("SKU already exists. Please use a unique SKU.", "error")
        return redirect(f"/edit/{pid}")

    flash("Product updated successfully!", "success")
    return redirect("/products")


# ---------------- LOW STOCK PAGE ----------------
@app.route("/low-stock")
@login_required
def low_stock_page():
    items = get_all_products()
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
    product = get_product_by_id(pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    return render_template("stock_in.html", product=product)


# ---------------- STOCK IN ACTION ----------------
@app.route("/stock-in/<int:pid>", methods=["POST"])
@login_required
def stock_in(pid):
    product = get_product_by_id(pid)

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
        pid,
        product["name"],
        product["sku"],
        product["category"],
        new_quantity,
        product["price"],
        product["supplier_id"]
    )

    add_stock_history(
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
    product = get_product_by_id(pid)

    if product is None:
        flash("Product not found.", "error")
        return redirect("/products")

    return render_template("stock_out.html", product=product)


# ---------------- STOCK OUT ACTION ----------------
@app.route("/stock-out/<int:pid>", methods=["POST"])
@login_required
def stock_out(pid):
    product = get_product_by_id(pid)

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
        pid,
        product["name"],
        product["sku"],
        product["category"],
        new_quantity,
        product["price"],
        product["supplier_id"]
    )

    add_stock_history(
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
    history = get_stock_history()
    return render_template("stock_history.html", history=history)


# ---------------- REPORTS PAGE ----------------
@app.route("/reports")
@login_required
def reports():
    report = get_report_data()
    top_products = get_top_stock_products()
    recent_movements = get_recent_stock_movements()

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
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            products.*,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers ON products.supplier_id = suppliers.id
        ORDER BY products.id DESC
    """)
    products = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM suppliers
        ORDER BY id DESC
    """)
    suppliers = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM stock_history
        ORDER BY id DESC
    """)
    stock_history_data = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(quantity) FROM products")
    total_stock = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM products WHERE quantity <= 5")
    low_stock = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(price * quantity) FROM products")
    total_stock_value = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM suppliers")
    total_suppliers = cursor.fetchone()[0]

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
    products = get_all_products()

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
    suppliers_data = get_all_suppliers()
    return render_template("suppliers.html", suppliers=suppliers_data)


# ---------------- ADD SUPPLIER ----------------
@app.route("/add-supplier", methods=["POST"])
@login_required
def add_supplier_route():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if name == "":
        flash("Supplier name cannot be empty.", "error")
        return redirect("/suppliers")

    add_supplier(name, phone, email, address)

    flash("Supplier added successfully!", "success")
    return redirect("/suppliers")


# ---------------- EDIT SUPPLIER PAGE ----------------
@app.route("/edit-supplier/<int:sid>")
@login_required
def edit_supplier_page(sid):
    supplier = get_supplier_by_id(sid)

    if supplier is None:
        flash("Supplier not found.", "error")
        return redirect("/suppliers")

    return render_template("edit_supplier.html", supplier=supplier)


# ---------------- UPDATE SUPPLIER ----------------
@app.route("/update-supplier/<int:sid>", methods=["POST"])
@login_required
def update_supplier_route(sid):
    supplier = get_supplier_by_id(sid)

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

    update_supplier(sid, name, phone, email, address)

    flash("Supplier updated successfully!", "success")
    return redirect("/suppliers")


# ---------------- DELETE SUPPLIER ----------------
@app.route("/delete-supplier/<int:sid>")
@login_required
def delete_supplier_route(sid):
    delete_supplier(sid)
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