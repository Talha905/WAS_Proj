import sqlite3
import click
from flask import current_app, g

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            'instance/app.db',
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS users;
        
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            category TEXT DEFAULT 'General',
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            image_url TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            amount REAL NOT NULL,
            shipping_address TEXT DEFAULT '',
            tracking_number TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
    ''')

@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    import os
    os.makedirs('instance', exist_ok=True)
    init_db()
    click.echo('Initialized the database.')

@click.command('seed-db')
def seed_db_command():
    """Seed the database with initial ShopLite marketplace data."""
    import os
    os.makedirs('instance', exist_ok=True)
    init_db()
    db = get_db()
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt()
    
    users = [
        ('alice', 'alice@shoplite.dev', bcrypt.generate_password_hash('password123').decode('utf-8'), 'Alice Walker', '+1-555-0101', 'user'),
        ('bob', 'bob@shoplite.dev', bcrypt.generate_password_hash('password123').decode('utf-8'), 'Bob Martinez', '+1-555-0102', 'user'),
        ('admin', 'admin@shoplite.dev', bcrypt.generate_password_hash('admin123').decode('utf-8'), 'System Administrator', '+1-555-0199', 'admin')
    ]
    db.executemany(
        'INSERT INTO users (username, email, password_hash, full_name, phone, role) VALUES (?, ?, ?, ?, ?, ?)',
        users
    )

    products = [
        (1, 1, 'Wireless Noise-Cancelling Headphones', 'Over-ear Bluetooth headphones with active noise cancellation and 30h battery life.', 'Electronics', 149.99, 8, 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500'),
        (2, 1, 'Leather Laptop Messenger Bag', 'Handcrafted full-grain leather bag with padded sleeve for up to 15.6 inch laptops.', 'Accessories', 59.99, 15, 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=500'),
        (3, 2, 'Mechanical Gaming Keyboard', 'Tenkeyless compact layout with hot-swappable tactile blue switches and RGB backlight.', 'Electronics', 89.99, 12, 'https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=500'),
        (4, 2, 'Ergonomic Vertical Mouse', 'Wireless 2.4G optical vertical mouse designed to reduce wrist strain and RSI.', 'Electronics', 45.99, 20, 'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=500')
    ]
    db.executemany(
        'INSERT INTO products (id, owner_id, name, description, category, price, stock, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        products
    )
    
    orders = [
        (1, 1, 1, 'Wireless Noise-Cancelling Headphones', 'Express 2-day delivery. Gift wrapping requested.', 'delivered', 149.99, '742 Evergreen Terrace, Springfield OR 97477', 'SL-EXP-8472910'),
        (2, 1, 2, 'Leather Laptop Messenger Bag', 'Standard courier delivery to residential address.', 'processing', 59.99, '742 Evergreen Terrace, Springfield OR 97477', 'SL-STD-1938472'),
        (3, 2, 3, 'Mechanical Gaming Keyboard', 'Signature required upon delivery.', 'shipped', 89.99, '1042 Elm Street, Suite 4B, Dallas TX 75201', 'SL-EXP-6629103'),
        (4, 2, 4, 'Ergonomic Vertical Mouse', 'Deliver to front desk reception if unavailable.', 'pending', 45.99, '1042 Elm Street, Suite 4B, Dallas TX 75201', 'SL-STD-5510294')
    ]
    db.executemany(
        'INSERT INTO orders (id, user_id, product_id, title, description, status, amount, shipping_address, tracking_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        orders
    )
    
    db.commit()
    click.echo('Seeded the database with ShopLite marketplace data.')

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_db_command)
