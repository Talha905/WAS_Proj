from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from database import get_db

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    # GAP 4: No role check
    db = get_db()
    users = db.execute('SELECT id, username, email, full_name, phone, role, created_at FROM users').fetchall()
    return jsonify([dict(user) for user in users]), 200

@admin_bp.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    # GAP 4: No role check
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
@jwt_required()
def delete_user(id):
    # GAP 4: No role check
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
        
    db.execute('DELETE FROM users WHERE id = ?', (id,))
    db.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200
