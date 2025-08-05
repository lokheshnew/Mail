import jwt
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
import os

# Secret key for JWT - in production, use environment variable
SECRET_KEY = '3ad1d0cd507ef604c1c42b89aa985b56f82b5d74c18a3e573d88eb0c66c049a6'

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed_password):
    """Verify a password against its hash"""
    return hash_password(password) == hashed_password

def generate_token(user_data):
    """Generate JWT token for user"""
    try:
        payload = {
            'user_id': user_data.get('user_id'),
            'email': user_data.get('email'),
            'username': user_data.get('username'),
            'exp': datetime.utcnow() + timedelta(hours=24),  # Token expires in 24 hours
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
        
    except Exception as e:
        print(f"Error generating token: {e}")
        return None

def verify_token(token):
    """Verify JWT token and return user data"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return {
            'user_id': payload.get('user_id'),
            'email': payload.get('email'),
            'username': payload.get('username')
        }
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def token_required(f):
    """Decorator to require valid token for route access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from header
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Also check for custom header
        if not token:
            token = request.headers.get('MAIL-KEY')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Pass user data to the route
        return f(user_data, *args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """Decorator to require admin access for route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from header
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            token = request.headers.get('MAIL-KEY')
        
        if not token:
            return jsonify({'error': 'Admin authentication required'}), 401
        
        # Verify token
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Check if user is admin (assuming admin emails start with 'admin@')
        user_email = user_data.get('email', '')
        if not user_email.startswith('admin@'):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Pass user data to the route
        return f(user_data, *args, **kwargs)
    
    return decorated_function

def is_domain_admin(user_email, domain):
    """Check if user is admin for a specific domain"""
    return user_email == f'admin@{domain}'

def get_user_domain(email):
    """Extract domain from email address"""
    if '@' in email:
        return email.split('@')[1]
    return None