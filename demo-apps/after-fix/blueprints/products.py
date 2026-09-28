from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import get_db

products_bp = Blueprint('products', __name__)

@products_bp.route('', methods=['GET'])
def list_products():
    db = get_db()
    products = db.execute('SELECT * FROM products').fetchall()
    return jsonify([dict(product) for product in products]), 200

@products_bp.route('', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    if not data or not data.get('name') or not data.get('price'):
        return jsonify({'error': 'Invalid request'}), 400
        
    current_user_id = int(get_jwt_identity())
    
    db = get_db()
    cursor = db.execute(
        '''INSERT INTO products (owner_id, name, description, category, price, stock, image_url)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (
            current_user_id,
            data['name'],
            data.get('description', ''),
            data.get('category', 'General'),
            data['price'],
            data.get('stock', 0),
            data.get('image_url', '')
        )
    )
    db.commit()
    
    return jsonify({'id': cursor.lastrowid, 'message': 'Product created successfully'}), 201

@products_bp.route('/<int:id>', methods=['GET'])
def get_product(id):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()
    if not product:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(product)), 200

@products_bp.route('/<int:id>', methods=['PUT'])
@jwt_required()
def update_product(id):
    # FIX: Check owner_id matches current_user_id
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
        
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()
    
    if not product or product['owner_id'] != current_user_id:
        return jsonify({'error': 'Not found'}), 404
        
    name = data.get('name', product['name'])
    description = data.get('description', product['description'])
    category = data.get('category', product['category'])
    price = data.get('price', product['price'])
    stock = data.get('stock', product['stock'])
    image_url = data.get('image_url', product['image_url'])
    
    db.execute(
        '''UPDATE products 
           SET name = ?, description = ?, category = ?, price = ?, stock = ?, image_url = ?
           WHERE id = ?''',
        (name, description, category, price, stock, image_url, id)
    )
    db.commit()
    
    return jsonify({'message': 'Product updated successfully'}), 200

@products_bp.route('/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_product(id):
    # FIX: Check owner_id matches current_user_id
    current_user_id = int(get_jwt_identity())
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()
    
    if not product or product['owner_id'] != current_user_id:
        return jsonify({'error': 'Not found'}), 404
        
    db.execute('DELETE FROM products WHERE id = ?', (id,))
    db.commit()
    
    return jsonify({'message': 'Product deleted successfully'}), 200
