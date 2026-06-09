# Inventory Management System

## Project Overview

Inventory Management System is a web-based application developed using Flask and SQLite. It helps users manage products, suppliers, stock movement, low-stock alerts, and inventory reports from one centralized dashboard.

This project was developed for the Advanced Programming course.

## Main Features

- User Signup and Login
- Session-based Authentication
- Flash Messages for User Feedback
- Dashboard with Inventory Summary
- Product Management
- Add, Edit, Delete Products
- Search and Sort Products
- Supplier Management
- Supplier-Product Linking
- Stock In Management
- Stock Out Management
- Stock Movement History
- Low Stock Alert
- Reports Page
- Printable Inventory Report
- CSV Export

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Jinja2 Template Engine

## Database Tables

### Users Table
Stores registered user information for login and authentication.

### Products Table
Stores product details such as name, SKU, category, quantity, price, and supplier.

### Suppliers Table
Stores supplier information such as name, phone, email, and address.

### Stock History Table
Stores all stock in and stock out records.

## How the System Works

1. A user signs up or logs in.
2. After login, the user reaches the dashboard.
3. The user can add products and suppliers.
4. Products can be linked with suppliers.
5. Stock can be increased using Stock In.
6. Stock can be reduced using Stock Out.
7. Every stock movement is saved in stock history.
8. Low-stock products are shown separately.
9. Reports can be viewed, printed, or exported as CSV.

## Default Admin Account

Username: admin  
Password: 1234

## How to Run the Project

1. Open the project folder in VS Code.
2. Activate the virtual environment.
3. Run the Flask app:

```bash
python app.py