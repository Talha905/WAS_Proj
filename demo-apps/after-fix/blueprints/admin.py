from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from functools import wraps
from database import get_db

admin_bp = Blueprint('admin', __name__)

def require_admin(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'admin':
            return jsonify({'error': 'Not found'}), 404
        return fn(*args, **kwargs)
    return wrapper

@admin_bp.route('/users', methods=['GET'])
@require_admin
def list_users():
    db = get_db()
    users = db.execute('SELECT id, username, email, full_name, phone, role, created_at FROM users').fetchall()
    return jsonify([dict(user) for user in users]), 200

@admin_bp.route('/reports', methods=['GET'])
@require_admin
def get_reports():
    db = get_db()
    users_count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    orders_count = db.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
    revenue = db.execute('SELECT SUM(amount) FROM orders').fetchone()[0] or 0.0
    
    return jsonify({
        'total_users': users_count,
        'total_orders': orders_count,
        'total_revenue': revenue
    }), 200

@admin_bp.route('/users/<int:id>', methods=['DELETE'])
@require_admin
def delete_user(id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
        
    db.execute('DELETE FROM users WHERE id = ?', (id,))
    db.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200
