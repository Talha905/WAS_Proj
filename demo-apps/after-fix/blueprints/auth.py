import re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from app import bcrypt, limiter
from database import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
        
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not re.match(r'^\w{3,30}$', username):
        return jsonify({'error': 'Invalid username'}), 400
    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400
    if not password or len(password) < 8:
        return jsonify({'error': 'Invalid password'}), 400
        
    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
    if existing:
        return jsonify({'error': 'User already exists'}), 409
        
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    cursor = db.execute(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        (username, email, password_hash)
    )
    db.commit()
    
    user_id = cursor.lastrowid
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    additional_claims = {'role': user['role'], 'username': user['username']}
    access_token = create_access_token(identity=str(user_id), additional_claims=additional_claims)
    
    return jsonify({'token': access_token}), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400
        
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
    
    if user and bcrypt.check_password_hash(user['password_hash'], data['password']):
        additional_claims = {'role': user['role'], 'username': user['username']}
        access_token = create_access_token(identity=str(user['id']), additional_claims=additional_claims)
        return jsonify({'token': access_token}), 200
        
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
@limiter.limit("10 per minute")
def me():
    current_user_id = int(get_jwt_identity())
    db = get_db()
    user = db.execute('SELECT id, username, email, full_name, phone, role, created_at FROM users WHERE id = ?', (current_user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(user)), 200
