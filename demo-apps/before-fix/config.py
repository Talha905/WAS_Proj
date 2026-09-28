import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-secret-change-in-prod')
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    PROPAGATE_EXCEPTIONS = False
    PORT = int(os.environ.get('PORT', 5001))
