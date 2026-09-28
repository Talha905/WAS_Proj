import os
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from database import init_app

bcrypt = Bcrypt()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, origins=["http://localhost:3000"])
    bcrypt.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    init_app(app)

    from blueprints.auth import auth_bp
    from blueprints.users import users_bp
    from blueprints.orders import orders_bp
    from blueprints.products import products_bp
    from blueprints.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(orders_bp, url_prefix='/api/orders')
    app.register_blueprint(products_bp, url_prefix='/api/products')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({"error": "Rate limit exceeded", "description": str(e.description)}), 429
        
    @app.errorhandler(Exception)
    def handle_exception(e):
        return jsonify({"error": "An unexpected error occurred"}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(port=app.config['PORT'], debug=app.config['DEBUG'])
