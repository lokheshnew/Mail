from flask import Blueprint, request, jsonify
from models.user import register_user, authenticate_user, update_user_last_login, get_client_secret
from utils.auth import generate_token, verify_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user with client secret generation"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Register user
        user, error = register_user(username, email, password)
        
        if error:
            return jsonify({'error': error}), 400
        
        # Return user data including client secret for initial setup
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'user_id': user.get('user_id'),
                'username': user.get('username'),
                'email': user.get('email'),
                'status': user.get('status'),
                'created_at': user.get('created_at')
            },
            'client_secret': user.get('client_secret'),  # Include client secret
            'security_note': 'Store your client secret securely. It will be used for encrypted API calls.'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return token with client secret"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Authenticate user
        user, error = authenticate_user(email, password)
        
        if error:
            return jsonify({'error': error}), 401
        
        # Update last login
        update_user_last_login(email)
        
        # Generate token
        token = generate_token(user)
        
        if not token:
            return jsonify({'error': 'Failed to generate token'}), 500
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user_id': user.get('user_id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'client_secret': user.get('client_secret'),  # Include client secret for API calls
            'encryption_enabled': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@auth_bp.route('/verify', methods=['POST'])
def verify_token_route():
    """Verify if token is valid"""
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            token = request.headers.get('MAIL-KEY')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return jsonify({
            'valid': True,
            'user': user_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Token verification failed: {str(e)}'}), 500

@auth_bp.route('/get_client_secret', methods=['POST'])
def get_user_client_secret():
    """Get client secret for authenticated user"""
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            token = request.headers.get('MAIL-KEY')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user_email = user_data.get('email')
        if not user_email:
            return jsonify({'error': 'User email not found in token'}), 400
        
        # Get client secret
        client_secret = get_client_secret(user_email)
        
        if not client_secret:
            return jsonify({'error': 'Failed to retrieve client secret'}), 500
        
        return jsonify({
            'client_secret': client_secret,
            'email': user_email,
            'note': 'Use this client secret as X-CLIENT-SECRET header for encrypted API calls'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get client secret: {str(e)}'}), 500

@auth_bp.route('/refresh_client_secret', methods=['POST'])
def refresh_client_secret():
    """Generate a new client secret for authenticated user"""
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            token = request.headers.get('MAIL-KEY')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user_email = user_data.get('email')
        if not user_email:
            return jsonify({'error': 'User email not found in token'}), 400
        
        # Generate new client secret
        from models.user import load_users, save_users, generate_client_secret
        from utils.encryption import Encryption
        
        users = load_users()
        if user_email not in users:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate new client secret
        new_client_secret = generate_client_secret(32)
        encryption = Encryption()
        encrypted_client_secret = encryption.encrypt(new_client_secret)
        
        # Update user record
        users[user_email]['client_secret'] = encrypted_client_secret
        users[user_email]['client_secret_updated'] = datetime.now().isoformat()
        
        if not save_users(users):
            return jsonify({'error': 'Failed to save new client secret'}), 500
        
        return jsonify({
            'message': 'Client secret refreshed successfully',
            'client_secret': new_client_secret,
            'email': user_email,
            'warning': 'Previous client secret is now invalid. Update your applications.'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to refresh client secret: {str(e)}'}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user (client-side token removal)"""
    try:
        # In a stateless JWT system, logout is typically handled client-side
        # by removing the token from storage
        return jsonify({
            'message': 'Logout successful',
            'note': 'Remove token and client secret from client storage'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500