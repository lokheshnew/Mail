# routes/service_routes.py - Fixed syntax error around line 491

from flask import Blueprint, request, jsonify
from models.user import load_users, is_supported_email, authenticate_user, get_client_secret
from models.company import get_company_by_domain
from utils.auth import verify_token, generate_token
from services.mail_service import MailService
from utils.encryption import EncryptionService
from config import API_KEY
from datetime import datetime
import re
import json

service_bp = Blueprint('service', __name__)

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