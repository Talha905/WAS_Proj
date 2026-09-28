from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import get_db

users_bp = Blueprint('users', __name__)

@users_bp.route('/<int:id>', methods=['GET'])
@jwt_required()
def get_user(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({'error': 'Not found'}), 404

    db = get_db()
    user = db.execute('SELECT id, username, email, full_name, phone, role, created_at FROM users WHERE id = ?', (id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(user)), 200

@users_bp.route('/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
        
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
        
    username = data.get('username', user['username'])
    email = data.get('email', user['email'])
    full_name = data.get('full_name', user['full_name'])
    phone = data.get('phone', user['phone'])
    
    db.execute(
        'UPDATE users SET username = ?, email = ?, full_name = ?, phone = ? WHERE id = ?',
        (username, email, full_name, phone, id)
    )
    db.commit()
    
    return jsonify({'message': 'User updated successfully'}), 200
