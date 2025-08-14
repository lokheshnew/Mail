from flask import Blueprint, request, jsonify
from models.user import load_users, is_supported_email, authenticate_user, get_client_secret
from models.company import get_company_by_domain
from utils.auth import verify_token, generate_token
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

@service_bp.route('/send_email', methods=['POST'])
def send_email_enhanced():
    """
    Enhanced send email endpoint supporting both plain and encrypted payloads
    """
    try:
        # Validate API key (required for all send_email requests)
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