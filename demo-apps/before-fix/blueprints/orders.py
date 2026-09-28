from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import get_db

orders_bp = Blueprint('orders', __name__)

@orders_bp.route('', methods=['GET'])
@jwt_required()
def list_orders():
    # GAP 5: Query parameter BOLA
    user_id_param = request.args.get('user_id')
    current_user_id = int(get_jwt_identity())
    
    user_id_to_fetch = int(user_id_param) if user_id_param else current_user_id
    
    db = get_db()
    orders = db.execute('SELECT * FROM orders WHERE user_id = ?', (user_id_to_fetch,)).fetchall()
    return jsonify([dict(order) for order in orders]), 200

@orders_bp.route('', methods=['POST'])
@jwt_required()
def create_order():
    # GAP 3: Mass assignment - accepts user_id from payload instead of deriving from JWT
    data = request.get_json()
    if not data or not data.get('title') or not data.get('amount'):
        return jsonify({'error': 'Invalid request'}), 400
        
    current_user_id = int(get_jwt_identity())
    user_id = data.get('user_id', current_user_id)
    
    db = get_db()
    cursor = db.execute(
        '''INSERT INTO orders (user_id, product_id, title, description, status, amount, shipping_address, tracking_number)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            user_id,
            data.get('product_id'),
            data['title'],
            data.get('description', ''),
            data.get('status', 'pending'),
            data['amount'],
            data.get('shipping_address', '742 Evergreen Terrace, Springfield OR 97477'),
            data.get('tracking_number', f'SL-TRK-{cursor_id}' if 'cursor_id' in locals() else 'SL-TRK-PENDING')
        )
    )
    db.commit()
    
    return jsonify({'id': cursor.lastrowid, 'message': 'Order created successfully'}), 201

@orders_bp.route('/<int:id>', methods=['GET'])
@jwt_required()
def get_order(id):
    # GAP 2: No ownership check
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id = ?', (id,)).fetchone()
    if not order:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(order)), 200

@orders_bp.route('/<int:id>', methods=['PUT'])
@jwt_required()
def update_order(id):
    # GAP 2: No ownership check
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
        
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id = ?', (id,)).fetchone()
    if not order:
        return jsonify({'error': 'Not found'}), 404
        
    title = data.get('title', order['title'])
    description = data.get('description', order['description'])
    status = data.get('status', order['status'])
    amount = data.get('amount', order['amount'])
    shipping_address = data.get('shipping_address', order['shipping_address'])
    tracking_number = data.get('tracking_number', order['tracking_number'])
    
    db.execute(
        '''UPDATE orders 
           SET title = ?, description = ?, status = ?, amount = ?, shipping_address = ?, tracking_number = ?
           WHERE id = ?''',
        (title, description, status, amount, shipping_address, tracking_number, id)
    )
    db.commit()
    
    return jsonify({'message': 'Order updated successfully'}), 200

@orders_bp.route('/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_order(id):
    # GAP 2: No ownership check
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id = ?', (id,)).fetchone()
    if not order:
        return jsonify({'error': 'Not found'}), 404
        
    db.execute('DELETE FROM orders WHERE id = ?', (id,))
    db.commit()
    
    return jsonify({'message': 'Order deleted successfully'}), 200
