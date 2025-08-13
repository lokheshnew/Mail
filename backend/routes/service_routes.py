# routes/service_routes.py - Fixed syntax error around line 491

from flask import Blueprint, request, jsonify
from models.user import load_users, is_supported_email, authenticate_user, get_client_secret
from models.company import get_company_by_domain
from utils.auth import verify_token, generate_token
# from utils.encryption import encrypt_data, decrypt_data
from services.mail_service import MailService
from utils.encryption import EncryptionService
from config import API_KEY
from datetime import datetime,timedelta
import re
import json
import jwt
import secrets
service_bp = Blueprint('service', __name__)
REFRESH_TOKENS = {}
# Initialize encryption service
encryption_service = EncryptionService()


# API Key validation
def validate_api_key():
    """Validate API key from request headers"""
    api_key = request.headers.get('X-API-KEY')
    
    if not api_key or api_key != API_KEY:
        return False, "Invalid or missing API key"
    
    return True, None

def get_client_secret_from_request():
    """Get client-specific secret from headers with user lookup"""
    # Try to get from header first
    client_secret = request.headers.get('X-CLIENT-SECRET')
    
    if client_secret:
        return client_secret
    
    # Try to get from user identification
    user_email = request.headers.get('X-USER-EMAIL')
    if user_email:
        return get_client_secret(user_email)
    
    return None

def is_encrypted_request():
    """Check if request contains encrypted data"""
    data = request.get_json()
    return data and 'encrypted_data' in data

def authenticate_api_user(email=None):
    """Authenticate user for API access and get their client secret"""
    if not email:
        # Try to get from headers
        email = request.headers.get('X-USER-EMAIL')
    
    if not email:
        return None, None, "User email required for API access"
    
    # Validate user exists and is active
    users = load_users()
    if email not in users:
        return None, None, "User not found"
    
    user_data = users[email]
    if user_data.get('status') != 'active':
        return None, None, "User account is inactive"
    
    # Get client secret
    client_secret = get_client_secret(email)
    if not client_secret:
        return None, None, "Client secret not available for user"
    
    return user_data, client_secret, None

# ========== ENHANCED VERIFY EMAIL API ==========

@service_bp.route('/verify_email', methods=['POST'])
def verify_email_enhanced():
    """
    Enhanced verify email endpoint supporting both plain and encrypted payloads
    
    Plain Text Request:
    {
        "email": "user@domain.com"
    }
    
    Encrypted Request:
    {
        "encrypted_data": "base64-encoded-encrypted-json",
        "encryption_type": "aes256gcm"  // optional
    }
    """
    try:
        data = request.get_json()
        client_secret = None
        
        # Check if this is an encrypted request
        if is_encrypted_request():
            # Validate API key for encrypted requests
            valid, error = validate_api_key()
            if not valid:
                return jsonify({'error': error}), 401
            
            client_secret = get_client_secret_from_request()
            encrypted_payload = data.get('encrypted_data')
            
            if not encrypted_payload:
                return jsonify({'error': 'Encrypted data is required'}), 400
            
            try:
                # Decrypt the payload
                decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
                email = decrypted_data.get('email', '').strip().lower()
            except Exception as e:
                return jsonify({
                    'error': f'Decryption failed: {str(e)}',
                    'verified': False
                }), 400
            
        else:
            # Handle plain text request (backward compatibility)
            email = data.get('email', '').strip().lower() if data else ''
            
            # Also check query parameter for plain requests
            if not email:
                email = request.args.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email parameter is required'}), 400
        
        # Load users and check if email exists
        users = load_users()
        
        if email in users:
            # Email exists - prepare response
            user_data = users[email]
            response_data = {
                'email': email,
                'exists': True,
                'username': user_data.get('username'),
                'status': user_data.get('status', 'active'),
                'verified': True,
                'has_client_secret': 'client_secret' in user_data
            }
            
            # If encrypted request, encrypt the response
            if is_encrypted_request():
                encrypted_response = encryption_service.prepare_api_response(response_data, client_secret)
                return jsonify({
                    'encrypted_response': encrypted_response
                }), 200
            else:
                return jsonify(response_data), 200
        else:
            # Email doesn't exist - prepare error response
            error_response = {
                'email': email,
                'exists': False,
                'verified': False,
                'error': 'Email not found'
            }
            
            # If encrypted request, encrypt the error response
            if is_encrypted_request():
                encrypted_response = encryption_service.prepare_api_response(error_response, client_secret)
                return jsonify({
                    'encrypted_response': encrypted_response
                }), 404
            else:
                return jsonify(error_response), 404
        
    except Exception as e:
        error_response = {
            'error': f'Verification failed: {str(e)}',
            'verified': False
        }
        
        # If encrypted request, encrypt the error response
        if is_encrypted_request():
            try:
                client_secret = get_client_secret_from_request()
                encrypted_response = encryption_service.prepare_api_response(error_response, client_secret)
                return jsonify({
                    'encrypted_response': encrypted_response
                }), 500
            except:
                pass
        
        return jsonify(error_response), 500

# ========== ENHANCED SEND EMAIL API ==========

@service_bp.route('/h', methods=['POST'])
def check():
    """Check if the service is running"""
    return jsonify({'status': 'Service is running'}), 200

@service_bp.route('/send_email', methods=['POST'])
def send_email_enhanced():
    """
    Enhanced send email endpoint supporting both plain and encrypted payloads
    """
    try:
        # Validate API key (required for all send_email requests)
        print('hello')
        import pdb;
        pdb.set_trace()
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        client_secret = None
        # Check if this is an encrypted request
        if is_encrypted_request():
            # Get user email for client secret lookup
            user_email = data.get('user_email') or request.headers.get('X-USER-EMAIL')
            
            if not user_email:
                return jsonify({'error': 'User email required for encrypted requests'}), 400
            
            # Authenticate user and get client secret
            user_data, client_secret, auth_error = authenticate_api_user(user_email)
            if auth_error:
                return jsonify({'error': auth_error}), 401
            
            encrypted_payload = data.get('encrypted_data')
            
            if not encrypted_payload:
                return jsonify({'error': 'Encrypted data is required'}), 400
            
            try:
                # Decrypt the payload
                decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
            except Exception as e:
                return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
            
            # Extract email data from decrypted payload
            sender = decrypted_data.get('from')
            recipient = decrypted_data.get('to')
            subject = decrypted_data.get('subject', '')
            body = decrypted_data.get('body', '')
            attachment = decrypted_data.get('attachment')
            
            # Verify sender matches authenticated user
            if sender != user_email:
                return jsonify({'error': 'Sender must match authenticated user'}), 403
        else:
            # Handle plain text request (backward compatibility)
            sender = data.get('from')
            recipient = data.get('to')
            subject = data.get('subject', '')
            body = data.get('body', '')
            attachment = data.get('attachment')
            
            # For plain requests, authenticate the sender
            if sender:
                user_data, client_secret, auth_error = authenticate_api_user(sender)
                if auth_error:
                    return jsonify({'error': auth_error}), 401
        
        if not all([sender, recipient]):
            return jsonify({'error': 'Sender and recipient are required'}), 400
        
        # Send email using existing service
        success, error = MailService.send_mail(sender, recipient, subject, body, attachment)
        
        if not success:
            error_response = {'error': error}
            
            # If encrypted request, encrypt the error response
            if is_encrypted_request():
                encrypted_response = encryption_service.prepare_api_response(error_response, client_secret)
                return jsonify({
                    'encrypted_response': encrypted_response
                }), 400
            else:
                return jsonify(error_response), 400
        
        # Prepare success response
        success_response = {
            'success': True,
            'message': 'Email sent successfully',
            'timestamp': datetime.now().isoformat(),
            'from': sender,
            'to': recipient
        }
        
        # If encrypted request, encrypt the response
        if is_encrypted_request():
            encrypted_response = encryption_service.prepare_api_response(success_response, client_secret)
            return jsonify({
                'encrypted_response': encrypted_response
            }), 200
        else:
            return jsonify(success_response), 200
        
    except Exception as e:
        error_response = {'error': f'Email sending failed: {str(e)}'}
        
        # If encrypted request, encrypt the error response
        if is_encrypted_request():
            try:
                client_secret = get_client_secret_from_request()
                encrypted_response = encryption_service.prepare_api_response(error_response, client_secret)
                return jsonify({
                    'encrypted_response': encrypted_response
                }), 500
            except:
                pass
        
        return jsonify(error_response), 500

# ========== USER AUTHENTICATION API ==========

@service_bp.route('/authenticate_user', methods=['POST'])
def authenticate_user_api():
    """
    Authenticate user and return client secret for API usage
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Authenticate user
        user, error = authenticate_user(email, password)
        
        if error:
            return jsonify({
                'authenticated': False,
                'error': error
            }), 401
        
        return jsonify({
            'authenticated': True,
            'client_secret': user.get('client_secret'),
            'user_info': {
                'user_id': user.get('user_id'),
                'email': user.get('email'),
                'username': user.get('username'),
                'status': user.get('status')
            },
            'api_usage': {
                'include_client_secret_header': 'X-CLIENT-SECRET: your-client-secret',
                'include_user_email_header': 'X-USER-EMAIL: your-email@domain.com',
                'encrypted_endpoints': ['/service/send_email', '/service/verify_email']
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'authenticated': False,
            'error': f'Authentication failed: {str(e)}'
        }), 500

# ========== ENCRYPTION INFO API ==========

@service_bp.route('/encryption_info', methods=['GET'])
def get_encryption_info():
    """Get encryption algorithm information for external applications"""
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        info = {
            'service': 'Mail Service Encryption API',
            'version': '1.0.0',
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'key_derivation': 'PBKDF2-HMAC-SHA256',
                'iterations': 100000,
                'key_length_bits': 256,
                'nonce_length_bits': 96,
                'salt_length_bits': 128,
                'encoding': 'Base64',
                'data_format': 'JSON'
            },
            'client_secret_usage': {
                'purpose': 'User-specific encryption key for enhanced security',
                'generation': 'Automatically generated during user registration',
                'storage': 'Encrypted in user database',
                'usage': 'Include as X-CLIENT-SECRET header in encrypted requests',
                'retrieval': 'Available through /auth/login or /auth/get_client_secret endpoints'
            },
            'encrypted_request_format': {
                'description': 'Send encrypted data in request body',
                'required_fields': ['encrypted_data'],
                'required_headers': {
                    'X-API-KEY': 'API key for service access',
                    'X-CLIENT-SECRET': 'User-specific client secret',
                    'X-USER-EMAIL': 'User email for authentication (encrypted requests)',
                    'Content-Type': 'application/json'
                }
            },
            'supported_endpoints': {
                'verify_email': {
                    'url': '/service/verify_email',
                    'method': 'POST',
                    'supports_encryption': True,
                    'backward_compatible': True
                },
                'send_email': {
                    'url': '/service/send_email',
                    'method': 'POST',
                    'supports_encryption': True,
                    'backward_compatible': True,
                    'requires_authentication': True
                },
                'authenticate_user': {
                    'url': '/service/authenticate_user',
                    'method': 'POST',
                    'supports_encryption': False,
                    'purpose': 'Get client secret for API usage'
                }
            }
        }
        
        return jsonify(info), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get encryption info: {str(e)}'}), 500

# ========== EXISTING APIS ==========

@service_bp.route('/validate_email', methods=['POST'])
def validate_email():
    """Validate if an email format is correct and domain is supported"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Check email format
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, email):
            return jsonify({
                'valid': False,
                'error': 'Invalid email format'
            }), 200
        
        # Check if domain is supported
        domain_supported = is_supported_email(email)
        
        if not domain_supported:
            return jsonify({
                'valid': False,
                'error': 'Domain not supported'
            }), 200
        
        return jsonify({
            'valid': True,
            'email': email,
            'domain': email.split('@')[1]
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Validation failed: {str(e)}'}), 500

@service_bp.route('/user_exists', methods=['POST'])
def check_user_exists():
    """Check if a user exists in the system"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        users = load_users()
        exists = email in users
        
        response_data = {
            'exists': exists,
            'email': email
        }
        
        if exists:
            user_data = users[email]
            response_data.update({
                'username': user_data.get('username'),
                'status': user_data.get('status', 'active'),
                'created_at': user_data.get('created_at'),
                'has_client_secret': 'client_secret' in user_data
            })
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Check failed: {str(e)}'}), 500

@service_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for service monitoring"""
    try:
        from pathlib import Path
        from config import DATA_DIR, USERS_FILE
        
        checks = {
            'service': 'running',
            'database': 'connected' if Path(USERS_FILE).exists() else 'disconnected',
            'storage': 'available' if Path(DATA_DIR).exists() else 'unavailable',
            'encryption': 'enabled',
            'client_secrets': 'supported',
            'timestamp': datetime.now().isoformat()
        }
        
        all_healthy = all(status in ['running', 'connected', 'available', 'enabled', 'supported'] 
                         for status in checks.values() if status != checks['timestamp'])
        
        return jsonify({
            'status': 'healthy' if all_healthy else 'unhealthy',
            'checks': checks
        }), 200 if all_healthy else 503
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503

@service_bp.route('/api/docs', methods=['GET'])
def api_documentation():
    """API documentation for Mail as a Service"""
    docs = {
        'service': 'Mail as a Service API',
        'version': '1.0.0',
        'encryption_support': 'AES-256-GCM with user-specific client secrets',
        'authentication': {
            'user_registration': 'POST /auth/register - Returns client secret',
            'user_login': 'POST /auth/login - Returns client secret',
            'api_authentication': 'POST /service/authenticate_user - Returns client secret',
            'get_client_secret': 'POST /auth/get_client_secret - Requires valid token'
        },
        'endpoints': {
            'User Management': {
                'POST /auth/register': 'Register a new user (returns client secret)',
                'POST /auth/login': 'Authenticate user (returns client secret)',
                'POST /auth/verify': 'Verify user token',
                'POST /service/validate_email': 'Validate email format and domain',
                'POST /service/user_exists': 'Check if user exists',
                'POST /service/authenticate_user': 'API authentication (returns client secret)'
            },
            'Mail Operations (Enhanced with Encryption)': {
                'POST /service/send_email': 'Send email (supports encryption, requires API key + client secret)',
                'POST /service/verify_email': 'Verify email exists (supports encryption)',
                'GET /mail/inbox/<email>': 'Get user inbox (requires auth token)',
                'GET /mail/sent/<email>': 'Get sent emails (requires auth token)',
                'POST /mail/search': 'Search emails (requires auth token)'
            },
            'Encryption': {
                'GET /service/encryption_info': 'Get encryption algorithm details (requires API key)'
            },
            'Service': {
                'GET /service/health': 'Service health check',
                'GET /service/api/docs': 'This documentation'
            }
        },
        'client_secret_usage': {
            'generation': 'Automatically generated during user registration',
            'retrieval': 'Available through login/authentication endpoints',
            'usage': 'Include as X-CLIENT-SECRET header for encrypted API calls',
            'security': 'User-specific secrets enhance encryption security'
        },
        'encryption_headers': {
            'X-API-KEY': 'Required for all encrypted endpoints',
            'X-CLIENT-SECRET': 'User-specific secret for encryption',
            'X-USER-EMAIL': 'User email for authentication verification',
            'Content-Type': 'application/json'
        }
    }
    
    return jsonify(docs), 200

def generate_access_token(user_data, expires_in_minutes=60):
    """Generate JWT access token with expiration"""
    try:
        payload = {
            'user_id': user_data.get('user_id'),
            'email': user_data.get('email'),
            'username': user_data.get('username'),
            'token_type': 'access',
            'exp': datetime.utcnow() + timedelta(minutes=expires_in_minutes),
            'iat': datetime.utcnow(),
            'nbf': datetime.utcnow()  # Not valid before
        }
        
        # Use the same secret key as existing auth system
        from utils.auth import SECRET_KEY
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
        
    except Exception as e:
        print(f"Error generating access token: {e}")
        return None

def generate_refresh_token(user_email):
    """Generate secure refresh token"""
    refresh_token = secrets.token_urlsafe(64)
    
    # Store refresh token with expiration (30 days)
    REFRESH_TOKENS[refresh_token] = {
        'email': user_email,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(days=30),
        'used': False
    }
    
    return refresh_token

def validate_refresh_token(refresh_token):
    """Validate refresh token"""
    if refresh_token not in REFRESH_TOKENS:
        return None, "Invalid refresh token"
    
    token_data = REFRESH_TOKENS[refresh_token]
    
    if token_data['used']:
        return None, "Refresh token already used"
    
    if datetime.utcnow() > token_data['expires_at']:
        # Clean up expired token
        del REFRESH_TOKENS[refresh_token]
        return None, "Refresh token expired"
    
    return token_data, None

def revoke_refresh_token(refresh_token):
    """Revoke a refresh token"""
    if refresh_token in REFRESH_TOKENS:
        del REFRESH_TOKENS[refresh_token]
        return True
    return False

@service_bp.route('/pure_auth', methods=['POST'])
def pure_authentication():
    print("arrives")
    """
    Pure authentication API - only validates credentials and returns tokens
    
    Request:
    {
        "email": "user@domain.com",
        "password": "userpassword",
        "token_expiry_minutes": 60  // optional, default 60 minutes
    }
    
    Headers:
    - X-API-KEY: Required API key
    
    Response:
    {
        "authenticated": true,
        "access_token": "jwt_token_here",
        "refresh_token": "secure_refresh_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expires_at": "2025-08-13T15:30:00Z",
        "user_info": {
            "user_id": "user123",
            "email": "user@domain.com",
            "username": "John Doe"
        }
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        token_expiry_minutes = data.get('token_expiry_minutes', 60)
        
        # Validate input
        if not all([email, password]):
            return jsonify({
                'authenticated': False,
                'error': 'Email and password are required'
            }), 400
        
        # Validate token expiry (max 24 hours)
        if not isinstance(token_expiry_minutes, int) or token_expiry_minutes < 5 or token_expiry_minutes > 1440:
            return jsonify({
                'authenticated': False,
                'error': 'Token expiry must be between 5 and 1440 minutes'
            }), 400
        
        # Authenticate user using existing system
        user, error = authenticate_user(email, password)
        
        if error:
            return jsonify({
                'authenticated': False,
                'error': error,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 401
        
        # Generate access token
        access_token = generate_access_token(user, token_expiry_minutes)
        
        if not access_token:
            return jsonify({
                'authenticated': False,
                'error': 'Failed to generate access token'
            }), 500
        
        # Generate refresh token
        refresh_token = generate_refresh_token(email)
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=token_expiry_minutes)
        expires_in_seconds = token_expiry_minutes * 60
        
        return jsonify({
            'authenticated': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': expires_in_seconds,
            'expires_at': expires_at.isoformat() + 'Z',
            'user_info': {
                'user_id': user.get('user_id'),
                'email': user.get('email'),
                'username': user.get('username')
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
        
    except Exception as e:
        return jsonify({
            'authenticated': False,
            'error': f'Authentication failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@service_bp.route('/refresh_token', methods=['POST'])
def refresh_access_token():
    """
    Refresh access token using refresh token
    
    Request:
    {
        "refresh_token": "secure_refresh_token_here",
        "token_expiry_minutes": 60  // optional, default 60 minutes
    }
    
    Headers:
    - X-API-KEY: Required API key
    
    Response:
    {
        "success": true,
        "access_token": "new_jwt_token_here",
        "refresh_token": "new_refresh_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expires_at": "2025-08-13T16:30:00Z"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        refresh_token = data.get('refresh_token', '')
        token_expiry_minutes = data.get('token_expiry_minutes', 60)
        
        if not refresh_token:
            return jsonify({
                'success': False,
                'error': 'Refresh token is required'
            }), 400
        
        # Validate token expiry
        if not isinstance(token_expiry_minutes, int) or token_expiry_minutes < 5 or token_expiry_minutes > 1440:
            return jsonify({
                'success': False,
                'error': 'Token expiry must be between 5 and 1440 minutes'
            }), 400
        
        # Validate refresh token
        token_data, error = validate_refresh_token(refresh_token)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            }), 401
        
        user_email = token_data['email']
        
        # Get user data for new token
        users = load_users()
        if user_email not in users:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        user_data = users[user_email]
        
        # Check if user is still active
        if user_data.get('status') != 'active':
            return jsonify({
                'success': False,
                'error': 'User account is inactive'
            }), 403
        
        # Mark old refresh token as used
        REFRESH_TOKENS[refresh_token]['used'] = True
        
        # Generate new tokens
        new_access_token = generate_access_token(user_data, token_expiry_minutes)
        new_refresh_token = generate_refresh_token(user_email)
        
        if not new_access_token:
            return jsonify({
                'success': False,
                'error': 'Failed to generate new access token'
            }), 500
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=token_expiry_minutes)
        expires_in_seconds = token_expiry_minutes * 60
        
        # Clean up old refresh token
        del REFRESH_TOKENS[refresh_token]
        
        return jsonify({
            'success': True,
            'access_token': new_access_token,
            'refresh_token': new_refresh_token,
            'token_type': 'Bearer',
            'expires_in': expires_in_seconds,
            'expires_at': expires_at.isoformat() + 'Z',
            'user_info': {
                'user_id': user_data.get('user_id'),
                'email': user_data.get('email'),
                'username': user_data.get('username')
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Token refresh failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@service_bp.route('/verify_token', methods=['POST'])
def verify_access_token():
    """
    Verify if an access token is valid
    
    Request:
    {
        "access_token": "jwt_token_here"
    }
    
    OR send token in Authorization header: Bearer jwt_token_here
    
    Headers:
    - X-API-KEY: Required API key
    - Authorization: Bearer jwt_token_here (optional, can use request body instead)
    
    Response:
    {
        "valid": true,
        "user_info": {
            "user_id": "user123",
            "email": "user@domain.com",
            "username": "John Doe"
        },
        "expires_at": "2025-08-13T15:30:00Z",
        "time_remaining_seconds": 1800
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get token from header or body
        auth_header = request.headers.get('Authorization')
        access_token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            access_token = auth_header.split(' ')[1]
        else:
            data = request.get_json()
            if data:
                access_token = data.get('access_token')
        
        if not access_token:
            return jsonify({
                'valid': False,
                'error': 'Access token is required (in body or Authorization header)'
            }), 400
        
        # Verify token using existing system
        from utils.auth import verify_token, SECRET_KEY
        
        try:
            # Use PyJWT directly for more detailed error handling
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
            
            # Check token type
            if payload.get('token_type') != 'access':
                return jsonify({
                    'valid': False,
                    'error': 'Invalid token type'
                }), 400
            
            # Calculate time remaining
            exp = payload.get('exp')
            time_remaining = exp - datetime.utcnow().timestamp() if exp else 0
            
            return jsonify({
                'valid': True,
                'user_info': {
                    'user_id': payload.get('user_id'),
                    'email': payload.get('email'),
                    'username': payload.get('username')
                },
                'expires_at': datetime.fromtimestamp(exp).isoformat() + 'Z' if exp else None,
                'time_remaining_seconds': max(0, int(time_remaining)),
                'token_type': payload.get('token_type'),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'valid': False,
                'error': 'Token has expired',
                'expired': True
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'valid': False,
                'error': 'Invalid token'
            }), 401
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'error': f'Token verification failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@service_bp.route('/revoke_token', methods=['POST'])
def revoke_token():
    """
    Revoke a refresh token (logout)
    
    Request:
    {
        "refresh_token": "refresh_token_to_revoke"
    }
    
    Headers:
    - X-API-KEY: Required API key
    
    Response:
    {
        "success": true,
        "message": "Token revoked successfully"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        refresh_token = data.get('refresh_token', '')
        
        if not refresh_token:
            return jsonify({
                'success': False,
                'error': 'Refresh token is required'
            }), 400
        
        # Revoke the refresh token
        revoked = revoke_refresh_token(refresh_token)
        
        if revoked:
            return jsonify({
                'success': True,
                'message': 'Token revoked successfully',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Token not found or already revoked',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 404
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Token revocation failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@service_bp.route('/auth_info', methods=['GET'])
def auth_service_info():
    """
    Get information about the authentication service
    
    Headers:
    - X-API-KEY: Required API key
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Clean up expired refresh tokens
        current_time = datetime.utcnow()
        expired_tokens = [
            token for token, data in REFRESH_TOKENS.items() 
            if current_time > data['expires_at']
        ]
        
        for token in expired_tokens:
            del REFRESH_TOKENS[token]
        
        return jsonify({
            'service': 'Pure Authentication API',
            'version': '1.0.0',
            'description': 'Generic authentication service for external applications',
            'features': [
                'JWT access tokens with configurable expiry',
                'Secure refresh tokens',
                'Token verification',
                'Token revocation (logout)',
                'User authentication without application-specific logic'
            ],
            'endpoints': {
                'authenticate': {
                    'url': '/service/pure_auth',
                    'method': 'POST',
                    'description': 'Authenticate user and get tokens'
                },
                'refresh': {
                    'url': '/service/refresh_token',
                    'method': 'POST',
                    'description': 'Refresh access token using refresh token'
                },
                'verify': {
                    'url': '/service/verify_token',
                    'method': 'POST',
                    'description': 'Verify if access token is valid'
                },
                'revoke': {
                    'url': '/service/revoke_token',
                    'method': 'POST',
                    'description': 'Revoke refresh token (logout)'
                },
                'info': {
                    'url': '/service/auth_info',
                    'method': 'GET',
                    'description': 'Get service information'
                }
            },
            'token_info': {
                'access_token': {
                    'type': 'JWT',
                    'algorithm': 'HS256',
                    'default_expiry_minutes': 60,
                    'max_expiry_minutes': 1440,
                    'min_expiry_minutes': 5
                },
                'refresh_token': {
                    'type': 'Secure random token',
                    'expiry_days': 30,
                    'single_use': True
                }
            },
            'usage': {
                'authentication_header': 'X-API-KEY: your-api-key',
                'token_usage': 'Authorization: Bearer access-token-here',
                'token_refresh': 'Use refresh_token endpoint before access token expires'
            },
            'stats': {
                'active_refresh_tokens': len(REFRESH_TOKENS),
                'server_time': datetime.utcnow().isoformat() + 'Z'
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get auth info: {str(e)}'}), 500
    

#encrypted authentication service
# Add these encrypted authentication endpoints to your service_routes.py

@service_bp.route('/encrypted_pure_auth', methods=['POST'])
def encrypted_pure_authentication():
    """
    Pure authentication API with encrypted payload support
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_payload",
        "client_secret": "optional_user_specific_secret"
    }
    
    Encrypted Payload Structure:
    {
        "email": "user@domain.com",
        "password": "userpassword",
        "token_expiry_minutes": 60,
        "encryption_password": "optional_custom_password"
    }
    
    Headers:
    - X-API-KEY: Required API key
    - X-CLIENT-SECRET: Optional user-specific encryption password
    - X-ENCRYPTION-PASSWORD: Optional custom encryption password
    
    Response (Encrypted):
    {
        "encrypted_response": "base64_encoded_encrypted_response"
    }
    
    Decrypted Response Structure:
    {
        "authenticated": true,
        "access_token": "jwt_token_here",
        "refresh_token": "secure_refresh_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expires_at": "2025-08-13T15:30:00Z",
        "user_info": {
            "user_id": "user123",
            "email": "user@domain.com",
            "username": "John Doe"
        },
        "encryption_info": {
            "response_encrypted": true,
            "algorithm": "AES-256-GCM"
        }
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password from multiple sources
        decryption_password = (
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            # Handle decryption error
            if isinstance(decrypted_data, str) and decrypted_data.startswith("Decryption failed"):
                return jsonify({
                    'authenticated': False,
                    'error': 'Failed to decrypt payload',
                    'details': decrypted_data
                }), 400
            
            # Ensure decrypted_data is a dictionary
            if isinstance(decrypted_data, str):
                try:
                    decrypted_data = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    return jsonify({
                        'authenticated': False,
                        'error': 'Invalid encrypted payload format'
                    }), 400
                    
        except Exception as e:
            return jsonify({
                'authenticated': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
        
        # Extract authentication data
        email = decrypted_data.get('email', '').strip().lower()
        password = decrypted_data.get('password', '')
        token_expiry_minutes = decrypted_data.get('token_expiry_minutes', 60)
        response_encryption_password = decrypted_data.get('encryption_password', decryption_password)
        
        # Validate input
        if not all([email, password]):
            error_response = {
                'authenticated': False,
                'error': 'Email and password are required',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Validate token expiry (max 24 hours)
        if not isinstance(token_expiry_minutes, int) or token_expiry_minutes < 5 or token_expiry_minutes > 1440:
            error_response = {
                'authenticated': False,
                'error': 'Token expiry must be between 5 and 1440 minutes',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Authenticate user using existing system
        user, auth_error = authenticate_user(email, password)
        
        if auth_error:
            error_response = {
                'authenticated': False,
                'error': auth_error,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 401
        
        # Generate access token
        access_token = generate_access_token(user, token_expiry_minutes)
        
        if not access_token:
            error_response = {
                'authenticated': False,
                'error': 'Failed to generate access token',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        
        # Generate refresh token
        refresh_token = generate_refresh_token(email)
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=token_expiry_minutes)
        expires_in_seconds = token_expiry_minutes * 60
        
        # Prepare success response
        success_response = {
            'authenticated': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': expires_in_seconds,
            'expires_at': expires_at.isoformat() + 'Z',
            'user_info': {
                'user_id': user.get('user_id'),
                'email': user.get('email'),
                'username': user.get('username')
            },
            'encryption_info': {
                'response_encrypted': True,
                'algorithm': 'AES-256-GCM',
                'decryption_password_used': 'client_secret' if decryption_password != 'default_password' else 'default'
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Encrypt the response
        encrypted_response = encrypt_data(success_response, response_encryption_password)
        
        return jsonify({
            'encrypted_response': encrypted_response,
            'encryption_note': 'Response is encrypted with the same password used for request decryption'
        }), 200
        
    except Exception as e:
        error_response = {
            'authenticated': False,
            'error': f'Authentication failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Try to encrypt error response if possible
        try:
            decryption_password = (
                data.get('client_secret') or
                request.headers.get('X-CLIENT-SECRET') or
                request.headers.get('X-ENCRYPTION-PASSWORD') or
                "default_password"
            )
            encrypted_error = encrypt_data(error_response, decryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        except:
            return jsonify(error_response), 500

@service_bp.route('/encrypted_refresh_token', methods=['POST'])
def encrypted_refresh_access_token():
    """
    Refresh access token using encrypted refresh token payload
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_payload",
        "client_secret": "optional_user_specific_secret"
    }
    
    Encrypted Payload Structure:
    {
        "refresh_token": "secure_refresh_token_here",
        "token_expiry_minutes": 60,
        "encryption_password": "optional_custom_password"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password
        decryption_password = (
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            if isinstance(decrypted_data, str) and decrypted_data.startswith("Decryption failed"):
                return jsonify({
                    'success': False,
                    'error': 'Failed to decrypt payload',
                    'details': decrypted_data
                }), 400
            
            if isinstance(decrypted_data, str):
                try:
                    decrypted_data = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid encrypted payload format'
                    }), 400
                    
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
        
        refresh_token = decrypted_data.get('refresh_token', '')
        token_expiry_minutes = decrypted_data.get('token_expiry_minutes', 60)
        response_encryption_password = decrypted_data.get('encryption_password', decryption_password)
        
        if not refresh_token:
            error_response = {
                'success': False,
                'error': 'Refresh token is required'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Validate token expiry
        if not isinstance(token_expiry_minutes, int) or token_expiry_minutes < 5 or token_expiry_minutes > 1440:
            error_response = {
                'success': False,
                'error': 'Token expiry must be between 5 and 1440 minutes'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Validate refresh token (using existing function)
        token_data, error = validate_refresh_token(refresh_token)
        
        if error:
            error_response = {
                'success': False,
                'error': error
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 401
        
        user_email = token_data['email']
        
        # Get user data for new token
        users = load_users()
        if user_email not in users:
            error_response = {
                'success': False,
                'error': 'User not found'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 404
        
        user_data = users[user_email]
        
        # Check if user is still active
        if user_data.get('status') != 'active':
            error_response = {
                'success': False,
                'error': 'User account is inactive'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 403
        
        # Mark old refresh token as used
        REFRESH_TOKENS[refresh_token]['used'] = True
        
        # Generate new tokens
        new_access_token = generate_access_token(user_data, token_expiry_minutes)
        new_refresh_token = generate_refresh_token(user_email)
        
        if not new_access_token:
            error_response = {
                'success': False,
                'error': 'Failed to generate new access token'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=token_expiry_minutes)
        expires_in_seconds = token_expiry_minutes * 60
        
        # Clean up old refresh token
        del REFRESH_TOKENS[refresh_token]
        
        # Prepare success response
        success_response = {
            'success': True,
            'access_token': new_access_token,
            'refresh_token': new_refresh_token,
            'token_type': 'Bearer',
            'expires_in': expires_in_seconds,
            'expires_at': expires_at.isoformat() + 'Z',
            'user_info': {
                'user_id': user_data.get('user_id'),
                'email': user_data.get('email'),
                'username': user_data.get('username')
            },
            'encryption_info': {
                'response_encrypted': True,
                'algorithm': 'AES-256-GCM'
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Encrypt the response
        encrypted_response = encrypt_data(success_response, response_encryption_password)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        error_response = {
            'success': False,
            'error': f'Token refresh failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        try:
            decryption_password = (
                data.get('client_secret') or
                request.headers.get('X-CLIENT-SECRET') or
                request.headers.get('X-ENCRYPTION-PASSWORD') or
                "default_password"
            )
            encrypted_error = encrypt_data(error_response, decryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        except:
            return jsonify(error_response), 500

@service_bp.route('/encrypted_verify_token', methods=['POST'])
def encrypted_verify_access_token():
    """
    Verify if an access token is valid using encrypted payload
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_payload",
        "client_secret": "optional_user_specific_secret"
    }
    
    Encrypted Payload Structure:
    {
        "access_token": "jwt_token_here",
        "encryption_password": "optional_custom_password"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password
        decryption_password = (
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            if isinstance(decrypted_data, str) and decrypted_data.startswith("Decryption failed"):
                return jsonify({
                    'valid': False,
                    'error': 'Failed to decrypt payload'
                }), 400
            
            if isinstance(decrypted_data, str):
                try:
                    decrypted_data = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    return jsonify({
                        'valid': False,
                        'error': 'Invalid encrypted payload format'
                    }), 400
                    
        except Exception as e:
            return jsonify({
                'valid': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
        
        access_token = decrypted_data.get('access_token')
        response_encryption_password = decrypted_data.get('encryption_password', decryption_password)
        
        if not access_token:
            error_response = {
                'valid': False,
                'error': 'Access token is required'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Verify token using existing system
        from utils.auth import SECRET_KEY
        
        try:
            # Use PyJWT directly for more detailed error handling
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
            
            # Check token type
            if payload.get('token_type') != 'access':
                error_response = {
                    'valid': False,
                    'error': 'Invalid token type'
                }
                encrypted_error = encrypt_data(error_response, response_encryption_password)
                return jsonify({'encrypted_response': encrypted_error}), 400
            
            # Calculate time remaining
            exp = payload.get('exp')
            time_remaining = exp - datetime.utcnow().timestamp() if exp else 0
            
            success_response = {
                'valid': True,
                'user_info': {
                    'user_id': payload.get('user_id'),
                    'email': payload.get('email'),
                    'username': payload.get('username')
                },
                'expires_at': datetime.fromtimestamp(exp).isoformat() + 'Z' if exp else None,
                'time_remaining_seconds': max(0, int(time_remaining)),
                'token_type': payload.get('token_type'),
                'encryption_info': {
                    'response_encrypted': True,
                    'algorithm': 'AES-256-GCM'
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            encrypted_response = encrypt_data(success_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_response}), 200
            
        except jwt.ExpiredSignatureError:
            error_response = {
                'valid': False,
                'error': 'Token has expired',
                'expired': True
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 401
            
        except jwt.InvalidTokenError:
            error_response = {
                'valid': False,
                'error': 'Invalid token'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 401
        
    except Exception as e:
        error_response = {
            'valid': False,
            'error': f'Token verification failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        try:
            decryption_password = (
                data.get('client_secret') or
                request.headers.get('X-CLIENT-SECRET') or
                request.headers.get('X-ENCRYPTION-PASSWORD') or
                "default_password"
            )
            encrypted_error = encrypt_data(error_response, decryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        except:
            return jsonify(error_response), 500

@service_bp.route('/encrypted_revoke_token', methods=['POST'])
def encrypted_revoke_token():
    """
    Revoke a refresh token using encrypted payload (logout)
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_payload",
        "client_secret": "optional_user_specific_secret"
    }
    
    Encrypted Payload Structure:
    {
        "refresh_token": "refresh_token_to_revoke",
        "encryption_password": "optional_custom_password"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password
        decryption_password = (
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            if isinstance(decrypted_data, str) and decrypted_data.startswith("Decryption failed"):
                return jsonify({
                    'success': False,
                    'error': 'Failed to decrypt payload'
                }), 400
            
            if isinstance(decrypted_data, str):
                try:
                    decrypted_data = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid encrypted payload format'
                    }), 400
                    
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
        
        refresh_token = decrypted_data.get('refresh_token', '')
        response_encryption_password = decrypted_data.get('encryption_password', decryption_password)
        
        if not refresh_token:
            error_response = {
                'success': False,
                'error': 'Refresh token is required'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 400
        
        # Revoke the refresh token (using existing function)
        revoked = revoke_refresh_token(refresh_token)
        
        if revoked:
            success_response = {
                'success': True,
                'message': 'Token revoked successfully',
                'encryption_info': {
                    'response_encrypted': True,
                    'algorithm': 'AES-256-GCM'
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_response = encrypt_data(success_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_response}), 200
        else:
            error_response = {
                'success': False,
                'error': 'Token not found or already revoked',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            encrypted_error = encrypt_data(error_response, response_encryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 404
        
    except Exception as e:
        error_response = {
            'success': False,
            'error': f'Token revocation failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        try:
            decryption_password = (
                data.get('client_secret') or
                request.headers.get('X-CLIENT-SECRET') or
                request.headers.get('X-ENCRYPTION-PASSWORD') or
                "default_password"
            )
            encrypted_error = encrypt_data(error_response, decryption_password)
            return jsonify({'encrypted_response': encrypted_error}), 500
        except:
            return jsonify(error_response), 500

@service_bp.route('/encrypted_auth_info', methods=['POST'])
def encrypted_auth_service_info():
    """
    Get information about the encrypted authentication service
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_payload",
        "client_secret": "optional_user_specific_secret"
    }
    
    Encrypted Payload Structure:
    {
        "request_info": true,
        "encryption_password": "optional_custom_password"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password
        decryption_password = (
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            if isinstance(decrypted_data, str):
                try:
                    decrypted_data = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    decrypted_data = {'request_info': True}
                    
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        response_encryption_password = decrypted_data.get('encryption_password', decryption_password)
        
        # Clean up expired refresh tokens
        current_time = datetime.utcnow()
        expired_tokens = [
            token for token, data in REFRESH_TOKENS.items() 
            if current_time > data['expires_at']
        ]
        
        for token in expired_tokens:
            del REFRESH_TOKENS[token]
        
        info_response = {
            'service': 'Encrypted Pure Authentication API',
            'version': '1.0.0',
            'description': 'Encrypted authentication service for external applications with enhanced security',
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'key_derivation': 'PBKDF2-HMAC-SHA256',
                'iterations': 100000,
                'encoding': 'Base64'
            },
            'features': [
                'End-to-end encrypted payloads',
                'JWT access tokens with configurable expiry',
                'Secure refresh tokens',
                'Encrypted token verification',
                'Encrypted token revocation (logout)',
                'Multiple encryption password sources',
                'Backward compatible with plain auth'
            ],
            'encrypted_endpoints': {
                'authenticate': {
                    'url': '/service/encrypted_pure_auth',
                    'method': 'POST',
                    'description': 'Authenticate user with encrypted payload'
                },
                'refresh': {
                    'url': '/service/encrypted_refresh_token',
                    'method': 'POST',
                    'description': 'Refresh access token with encrypted payload'
                },
                'verify': {
                    'url': '/service/encrypted_verify_token',
                    'method': 'POST',
                    'description': 'Verify access token with encrypted payload'
                },
                'revoke': {
                    'url': '/service/encrypted_revoke_token',
                    'method': 'POST',
                    'description': 'Revoke refresh token with encrypted payload'
                },
                'info': {
                    'url': '/service/encrypted_auth_info',
                    'method': 'POST',
                    'description': 'Get encrypted service information'
                }
            },
            'encryption_password_sources': [
                'Request body: client_secret field',
                'Header: X-CLIENT-SECRET',
                'Header: X-ENCRYPTION-PASSWORD',
                'Default: default_password'
            ],
            'payload_structure': {
                'request': {
                    'encrypted_data': 'Base64 encoded encrypted JSON payload',
                    'client_secret': 'Optional encryption password'
                },
                'response': {
                    'encrypted_response': 'Base64 encoded encrypted JSON response'
                }
            },
            'token_info': {
                'access_token': {
                    'type': 'JWT',
                    'algorithm': 'HS256',
                    'default_expiry_minutes': 60,
                    'max_expiry_minutes': 1440,
                    'min_expiry_minutes': 5
                },
                'refresh_token': {
                    'type': 'Secure random token',
                    'expiry_days': 30,
                    'single_use': True
                }
            },
            'security_features': {
                'encrypted_payloads': 'All request/response data encrypted',
                'flexible_encryption_passwords': 'Multiple password source options',
                'secure_token_generation': 'Cryptographically secure tokens',
                'automatic_cleanup': 'Expired tokens automatically removed'
            },
            'stats': {
                'active_refresh_tokens': len(REFRESH_TOKENS),
                'server_time': datetime.utcnow().isoformat() + 'Z'
            },
            'encryption_info': {
                'response_encrypted': True,
                'algorithm': 'AES-256-GCM'
            }
        }
        
        # Encrypt the response
        encrypted_response = encrypt_data(info_response, response_encryption_password)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get encrypted auth info: {str(e)}'}), 500

# ========== ENCRYPTION UTILITY ENDPOINTS ==========

@service_bp.route('/encrypt_data', methods=['POST'])
def encrypt_data_endpoint():
    """
    Utility endpoint to encrypt data using the same algorithm
    
    Request:
    {
        "data": "data_to_encrypt_or_json_object",
        "password": "encryption_password",
        "client_secret": "optional_user_specific_secret"
    }
    
    Headers:
    - X-API-KEY: Required API key
    - X-CLIENT-SECRET: Optional encryption password
    - X-ENCRYPTION-PASSWORD: Optional encryption password
    
    Response:
    {
        "encrypted_data": "base64_encoded_encrypted_data",
        "algorithm": "AES-256-GCM",
        "success": true
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        data_to_encrypt = data.get('data')
        if data_to_encrypt is None:
            return jsonify({'error': 'Data to encrypt is required'}), 400
        
        # Get encryption password from multiple sources
        encryption_password = (
            data.get('password') or
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Encrypt the data
        try:
            encrypted_data = encrypt_data(data_to_encrypt, encryption_password)
            
            return jsonify({
                'encrypted_data': encrypted_data,
                'algorithm': 'AES-256-GCM',
                'success': True,
                'original_data_type': type(data_to_encrypt).__name__,
                'encrypted_length': len(encrypted_data),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Encryption failed: {str(e)}'
            }), 400
        
    except Exception as e:
        return jsonify({'error': f'Encryption endpoint failed: {str(e)}'}), 500

@service_bp.route('/decrypt_data', methods=['POST'])
def decrypt_data_endpoint():
    """
    Utility endpoint to decrypt data using the same algorithm
    
    Request:
    {
        "encrypted_data": "base64_encoded_encrypted_data",
        "password": "decryption_password",
        "client_secret": "optional_user_specific_secret"
    }
    
    Headers:
    - X-API-KEY: Required API key
    - X-CLIENT-SECRET: Optional decryption password
    - X-ENCRYPTION-PASSWORD: Optional decryption password
    
    Response:
    {
        "decrypted_data": "original_data_or_json_object",
        "algorithm": "AES-256-GCM",
        "success": true
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        encrypted_payload = data.get('encrypted_data')
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Get decryption password from multiple sources
        decryption_password = (
            data.get('password') or
            data.get('client_secret') or
            request.headers.get('X-CLIENT-SECRET') or
            request.headers.get('X-ENCRYPTION-PASSWORD') or
            "default_password"
        )
        
        # Decrypt the data
        try:
            decrypted_data = decrypt_data(encrypted_payload, decryption_password)
            
            # Check if decryption failed
            if isinstance(decrypted_data, str) and decrypted_data.startswith("Decryption failed"):
                return jsonify({
                    'success': False,
                    'error': decrypted_data
                }), 400
            
            return jsonify({
                'decrypted_data': decrypted_data,
                'algorithm': 'AES-256-GCM',
                'success': True,
                'decrypted_data_type': type(decrypted_data).__name__,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
        
    except Exception as e:
        return jsonify({'error': f'Decryption endpoint failed: {str(e)}'}), 500

# ========== EXAMPLE USAGE AND TESTING ==========

@service_bp.route('/encrypted_auth_example', methods=['GET'])
def encrypted_auth_example():
    """
    Get example requests and responses for encrypted authentication
    
    Headers:
    - X-API-KEY: Required API key
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        examples = {
            'service': 'Encrypted Authentication Examples',
            'encryption_password_note': 'Use "default_password" for testing or your own secure password',
            'examples': {
                'authentication': {
                    'endpoint': '/service/encrypted_pure_auth',
                    'method': 'POST',
                    'description': 'Authenticate user with encrypted credentials',
                    'headers': {
                        'X-API-KEY': 'your-api-key',
                        'X-CLIENT-SECRET': 'your-encryption-password (optional)',
                        'Content-Type': 'application/json'
                    },
                    'request_body': {
                        'encrypted_data': 'base64_encoded_encrypted_payload',
                        'client_secret': 'optional_encryption_password'
                    },
                    'encrypted_payload_structure': {
                        'email': 'user@domain.com',
                        'password': 'userpassword',
                        'token_expiry_minutes': 60,
                        'encryption_password': 'response_encryption_password'
                    },
                    'sample_payload_to_encrypt': {
                        'email': 'test@example.com',
                        'password': 'testpassword123',
                        'token_expiry_minutes': 120
                    }
                },
                'token_refresh': {
                    'endpoint': '/service/encrypted_refresh_token',
                    'method': 'POST',
                    'description': 'Refresh access token with encrypted refresh token',
                    'encrypted_payload_structure': {
                        'refresh_token': 'your_refresh_token_here',
                        'token_expiry_minutes': 60,
                        'encryption_password': 'response_encryption_password'
                    }
                },
                'token_verification': {
                    'endpoint': '/service/encrypted_verify_token',
                    'method': 'POST',
                    'description': 'Verify access token with encrypted payload',
                    'encrypted_payload_structure': {
                        'access_token': 'your_jwt_access_token_here',
                        'encryption_password': 'response_encryption_password'
                    }
                },
                'token_revocation': {
                    'endpoint': '/service/encrypted_revoke_token',
                    'method': 'POST',
                    'description': 'Revoke refresh token with encrypted payload',
                    'encrypted_payload_structure': {
                        'refresh_token': 'refresh_token_to_revoke',
                        'encryption_password': 'response_encryption_password'
                    }
                }
            },
            'utility_endpoints': {
                'encrypt_data': {
                    'endpoint': '/service/encrypt_data',
                    'method': 'POST',
                    'description': 'Encrypt any data using the same algorithm',
                    'request_body': {
                        'data': 'data_to_encrypt_or_json_object',
                        'password': 'encryption_password'
                    }
                },
                'decrypt_data': {
                    'endpoint': '/service/decrypt_data',
                    'method': 'POST',
                    'description': 'Decrypt data using the same algorithm',
                    'request_body': {
                        'encrypted_data': 'base64_encoded_encrypted_data',
                        'password': 'decryption_password'
                    }
                }
            },
            'workflow': [
                '1. Use /service/encrypt_data to encrypt your authentication payload',
                '2. Send encrypted payload to /service/encrypted_pure_auth',
                '3. Receive encrypted response with access_token and refresh_token',
                '4. Use /service/decrypt_data to decrypt the response',
                '5. Use access_token for API calls, refresh_token for token renewal',
                '6. Use encrypted endpoints for secure token operations'
            ],
            'security_tips': [
                'Use unique passwords for different users/applications',
                'Store encryption passwords securely',
                'Use client secrets from headers when possible',
                'Always validate decrypted responses',
                'Implement proper error handling for decryption failures'
            ],
            'integration_steps': {
                'step1': 'Generate or obtain API key',
                'step2': 'Choose encryption password (user-specific recommended)',
                'step3': 'Encrypt authentication payload using /service/encrypt_data',
                'step4': 'Send encrypted request to authentication endpoint',
                'step5': 'Decrypt response to get tokens',
                'step6': 'Use tokens for subsequent encrypted API calls'
            }
        }
        
        return jsonify(examples), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get examples: {str(e)}'}), 500