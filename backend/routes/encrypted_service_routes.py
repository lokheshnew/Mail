# routes/encrypted_service_routes.py - Enhanced with Client Secret Integration
from flask import Blueprint, request, jsonify
from models.user import load_users, register_user, authenticate_user, get_client_secret
from models.company import get_company_by_domain
from utils.encryption import EncryptionService
from services.mail_service import MailService
from config import API_KEY
from datetime import datetime
import json
import re

encrypted_service_bp = Blueprint('encrypted_service', __name__, url_prefix='/api/v1/encrypted')

# Initialize encryption service
encryption_service = EncryptionService()

# API Key validation
def validate_api_key():
    """Validate API key from request headers"""
    api_key = request.headers.get('X-API-KEY')
    
    if not api_key or api_key != API_KEY:
        return False, "Invalid or missing API key"
    
    return True, None

def get_client_password_from_request():
    """Get client-specific password from headers with user lookup"""
    # Try to get from header first
    client_secret = request.headers.get('X-CLIENT-SECRET')
    
    if client_secret:
        return client_secret
    
    # Try to get from user identification
    user_email = request.headers.get('X-USER-EMAIL')
    if user_email:
        return get_client_secret(user_email)
    
    # Try to extract from request data for registration/auth endpoints
    data = request.get_json()
    if data:
        # For registration endpoint
        if 'user_email' in data:
            return get_client_secret(data['user_email'])
        
        # For authentication with encrypted payload
        if 'encrypted_data' in data:
            try:
                # Try to decrypt with no client secret first to get user info
                decrypted = encryption_service.process_api_request(data['encrypted_data'], None)
                user_email = decrypted.get('email')
                if user_email:
                    return get_client_secret(user_email)
            except:
                pass
    
    return None

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

# ========== ENCRYPTED EMAIL OPERATIONS ==========

@encrypted_service_bp.route('/send_email', methods=['POST'])
def send_encrypted_email():
    """
    Send email with encrypted payload using user-specific client secret
    
    Headers:
    - X-API-KEY: API key
    - X-CLIENT-SECRET: User-specific client secret (optional if X-USER-EMAIL provided)
    - X-USER-EMAIL: User email for client secret lookup
    
    Expected encrypted payload structure:
    {
        "from": "sender@domain.com",
        "to": "recipient@domain.com", 
        "subject": "Email subject",
        "body": "Email body content",
        "attachment": null (optional)
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get user email for authentication
        user_email = request.headers.get('X-USER-EMAIL')
        if not user_email:
            data = request.get_json()
            user_email = data.get('user_email')
        
        if not user_email:
            return jsonify({'error': 'User email required (X-USER-EMAIL header or user_email in body)'}), 400
        
        # Authenticate user and get client secret
        user_data, client_secret, auth_error = authenticate_api_user(user_email)
        if auth_error:
            return jsonify({'error': auth_error}), 401
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Decrypt the payload using user's client secret
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        # Extract email data
        sender = decrypted_data.get('from')
        recipient = decrypted_data.get('to')
        subject = decrypted_data.get('subject', '')
        body = decrypted_data.get('body', '')
        attachment = decrypted_data.get('attachment')
        
        if not all([sender, recipient]):
            return jsonify({'error': 'Sender and recipient are required'}), 400
        
        # Verify sender matches authenticated user
        if sender != user_email:
            return jsonify({'error': 'Sender must match authenticated user'}), 403
        
        # Send email using existing service
        success, error = MailService.send_mail(sender, recipient, subject, body, attachment)
        
        if not success:
            return jsonify({'error': error}), 400
        
        # Prepare encrypted response
        response_data = {
            'success': True,
            'message': 'Email sent successfully',
            'timestamp': datetime.now().isoformat(),
            'from': sender,
            'to': recipient
        }
        
        encrypted_response = encryption_service.prepare_api_response(response_data, client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Email sending failed: {str(e)}'}), 500

@encrypted_service_bp.route('/get_inbox', methods=['POST'])
def get_encrypted_inbox():
    """
    Get user's inbox with encrypted response using user-specific client secret
    
    Headers:
    - X-API-KEY: API key
    - X-CLIENT-SECRET: User-specific client secret (optional if X-USER-EMAIL provided)
    - X-USER-EMAIL: User email for authentication
    
    Expected encrypted payload:
    {
        "email": "user@domain.com"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get user email for authentication
        user_email = request.headers.get('X-USER-EMAIL')
        if not user_email:
            data = request.get_json()
            user_email = data.get('user_email')
        
        if not user_email:
            return jsonify({'error': 'User email required for authentication'}), 400
        
        # Authenticate user and get client secret
        user_data, client_secret, auth_error = authenticate_api_user(user_email)
        if auth_error:
            return jsonify({'error': auth_error}), 401
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Decrypt the payload
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        email = decrypted_data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required in encrypted payload'}), 400
        
        # Verify email matches authenticated user
        if email != user_email:
            return jsonify({'error': 'Email must match authenticated user'}), 403
        
        # Get inbox
        inbox, error = MailService.get_inbox(email)
        
        if error:
            return jsonify({'error': error}), 404
        
        # Prepare encrypted response
        response_data = {
            'inbox': inbox,
            'count': len(inbox),
            'email': email,
            'timestamp': datetime.now().isoformat()
        }
        
        encrypted_response = encryption_service.prepare_api_response(response_data, client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Inbox retrieval failed: {str(e)}'}), 500

@encrypted_service_bp.route('/register_user', methods=['POST'])
def register_encrypted_user():
    """
    Register user with encrypted payload
    
    Expected encrypted payload:
    {
        "username": "John Doe",
        "email": "john@domain.com",
        "password": "securepassword"
    }
    
    Note: Client secret will be generated and returned for the new user
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # For registration, we might not have a user-specific client secret yet
        # Try to get from header or use None for initial decryption
        client_password = request.headers.get('X-CLIENT-SECRET')
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Decrypt the payload (might not have client secret for new users)
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_password)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        username = decrypted_data.get('username')
        email = decrypted_data.get('email')
        password = decrypted_data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Register user (this will generate a client secret)
        user, error = register_user(username, email, password)
        
        if error:
            return jsonify({'error': error}), 400
        
        # Get the newly generated client secret for encrypted response
        new_client_secret = user.get('client_secret')
        
        # Prepare encrypted response using the new user's client secret
        response_data = {
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'user_id': user.get('user_id'),
                'username': user.get('username'),
                'email': user.get('email'),
                'status': user.get('status'),
                'created_at': user.get('created_at')
            },
            'client_secret_generated': True,
            'note': 'Store your client secret securely for future encrypted API calls'
        }
        
        # Use the new client secret for response encryption
        encrypted_response = encryption_service.prepare_api_response(response_data, new_client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response,
            'client_secret': new_client_secret,  # Also return in plain for initial setup
            'security_note': 'Client secret is included for initial setup. Store securely.'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'User registration failed: {str(e)}'}), 500

@encrypted_service_bp.route('/authenticate_user', methods=['POST'])
def authenticate_encrypted_user():
    """
    Authenticate user with encrypted payload and return client secret
    
    Expected encrypted payload:
    {
        "email": "user@domain.com",
        "password": "userpassword"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # For authentication, we might need to try without client secret first
        client_password = request.headers.get('X-CLIENT-SECRET')
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # If no client secret provided, try to get user email and then their secret
        if not client_password:
            # Try to extract email from unencrypted or minimally encrypted data
            try:
                # First try with no password
                decrypted_data = encryption_service.process_api_request(encrypted_payload, None)
                user_email = decrypted_data.get('email')
                if user_email:
                    client_password = get_client_secret(user_email)
            except:
                pass
        
        # Decrypt the payload
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_password)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        email = decrypted_data.get('email')
        password = decrypted_data.get('password')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Authenticate user
        user, error = authenticate_user(email, password)
        
        if error:
            return jsonify({'error': error}), 401
        
        # Get client secret for response encryption
        user_client_secret = user.get('client_secret')
        
        # Prepare encrypted response
        response_data = {
            'authenticated': True,
            'message': 'Authentication successful',
            'user': {
                'user_id': user.get('user_id'),
                'username': user.get('username'),
                'email': user.get('email'),
                'status': user.get('status'),
                'last_login': user.get('last_login')
            },
            'api_access': {
                'client_secret_header': 'X-CLIENT-SECRET',
                'user_email_header': 'X-USER-EMAIL',
                'encrypted_endpoints_available': True
            }
        }
        
        encrypted_response = encryption_service.prepare_api_response(response_data, user_client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response,
            'client_secret': user_client_secret,  # Return for API usage
            'api_usage_note': 'Include client_secret in X-CLIENT-SECRET header for encrypted API calls'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 500

@encrypted_service_bp.route('/bulk_send', methods=['POST'])
def bulk_send_encrypted():
    """
    Send multiple emails with encrypted payload using user-specific client secret
    
    Headers:
    - X-API-KEY: API key
    - X-CLIENT-SECRET: User-specific client secret
    - X-USER-EMAIL: User email for authentication
    
    Expected encrypted payload:
    {
        "emails": [
            {
                "from": "sender@domain.com",
                "to": "recipient1@domain.com",
                "subject": "Subject 1",
                "body": "Body 1"
            },
            {
                "from": "sender@domain.com", 
                "to": "recipient2@domain.com",
                "subject": "Subject 2", 
                "body": "Body 2"
            }
        ]
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get user email for authentication
        user_email = request.headers.get('X-USER-EMAIL')
        if not user_email:
            data = request.get_json()
            user_email = data.get('user_email')
        
        if not user_email:
            return jsonify({'error': 'User email required for authentication'}), 400
        
        # Authenticate user and get client secret
        user_data, client_secret, auth_error = authenticate_api_user(user_email)
        if auth_error:
            return jsonify({'error': auth_error}), 401
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Decrypt the payload
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        emails = decrypted_data.get('emails', [])
        
        if not emails:
            return jsonify({'error': 'Email list is required'}), 400
        
        results = []
        successful = 0
        failed = 0
        
        for email_data in emails:
            try:
                sender = email_data.get('from')
                recipient = email_data.get('to')
                subject = email_data.get('subject', '')
                body = email_data.get('body', '')
                attachment = email_data.get('attachment')
                
                if not all([sender, recipient]):
                    results.append({
                        'to': recipient,
                        'success': False,
                        'error': 'Sender and recipient are required'
                    })
                    failed += 1
                    continue
                
                # Verify sender matches authenticated user
                if sender != user_email:
                    results.append({
                        'to': recipient,
                        'success': False,
                        'error': 'Sender must match authenticated user'
                    })
                    failed += 1
                    continue
                
                success, error = MailService.send_mail(sender, recipient, subject, body, attachment)
                
                if success:
                    results.append({
                        'to': recipient,
                        'success': True,
                        'message': 'Email sent successfully'
                    })
                    successful += 1
                else:
                    results.append({
                        'to': recipient,
                        'success': False,
                        'error': error
                    })
                    failed += 1
                    
            except Exception as e:
                results.append({
                    'to': email_data.get('to', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
                failed += 1
        
        # Prepare encrypted response
        response_data = {
            'total': len(emails),
            'successful': successful,
            'failed': failed,
            'results': results,
            'timestamp': datetime.now().isoformat(),
            'authenticated_user': user_email
        }
        
        encrypted_response = encryption_service.prepare_api_response(response_data, client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Bulk email sending failed: {str(e)}'}), 500

@encrypted_service_bp.route('/get_user_info', methods=['POST'])
def get_encrypted_user_info():
    """
    Get user information with encrypted response
    
    Headers:
    - X-API-KEY: API key
    - X-CLIENT-SECRET: User-specific client secret
    - X-USER-EMAIL: User email for authentication
    
    Expected encrypted payload:
    {
        "email": "user@domain.com"
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get user email for authentication
        user_email = request.headers.get('X-USER-EMAIL')
        if not user_email:
            data = request.get_json()
            user_email = data.get('user_email')
        
        if not user_email:
            return jsonify({'error': 'User email required for authentication'}), 400
        
        # Authenticate user and get client secret
        user_data, client_secret, auth_error = authenticate_api_user(user_email)
        if auth_error:
            return jsonify({'error': auth_error}), 401
        
        # Get encrypted payload
        data = request.get_json()
        encrypted_payload = data.get('encrypted_data')
        
        if not encrypted_payload:
            return jsonify({'error': 'Encrypted data is required'}), 400
        
        # Decrypt the payload
        try:
            decrypted_data = encryption_service.process_api_request(encrypted_payload, client_secret)
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
        
        email = decrypted_data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required in encrypted payload'}), 400
        
        # Verify email matches authenticated user
        if email != user_email:
            return jsonify({'error': 'Email must match authenticated user'}), 403
        
        # Get user stats
        stats, stats_error = MailService.get_stats(email)
        if stats_error:
            stats = None
        
        # Prepare encrypted response
        response_data = {
            'user_info': {
                'user_id': user_data.get('user_id'),
                'username': user_data.get('username'),
                'email': email,
                'status': user_data.get('status', 'active'),
                'created_at': user_data.get('created_at'),
                'last_login': user_data.get('last_login'),
                'login_count': user_data.get('login_count', 0)
            },
            'email_stats': stats,
            'encryption_info': {
                'has_client_secret': True,
                'encryption_enabled': True
            },
            'timestamp': datetime.now().isoformat()
        }
        
        encrypted_response = encryption_service.prepare_api_response(response_data, client_secret)
        
        return jsonify({
            'encrypted_response': encrypted_response
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'User info retrieval failed: {str(e)}'}), 500

# ========== ENCRYPTION UTILITY ENDPOINTS ==========

@encrypted_service_bp.route('/test_encryption', methods=['POST'])
def test_encryption():
    """Test endpoint for encryption/decryption with user-specific client secret"""
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get user email for authentication
        user_email = request.headers.get('X-USER-EMAIL')
        if not user_email:
            return jsonify({'error': 'User email required for testing'}), 400
        
        # Authenticate user and get client secret
        user_data, client_secret, auth_error = authenticate_api_user(user_email)
        if auth_error:
            return jsonify({'error': auth_error}), 401
        
        data = request.get_json()
        test_data = data.get('test_data', 'Hello, World!')
        
        # Encrypt test data with user's client secret
        encrypted = encryption_service.encryption.encrypt_for_api(test_data, client_secret)
        
        # Decrypt it back
        decrypted = encryption_service.encryption.decrypt_from_api(encrypted, client_secret)
        
        return jsonify({
            'test_successful': test_data == decrypted,
            'original': test_data,
            'decrypted': decrypted,
            'encrypted_data_length': len(encrypted),
            'user_email': user_email,
            'encryption_algorithm': 'AES-256-GCM',
            'client_secret_used': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Encryption test failed: {str(e)}'}), 500

@encrypted_service_bp.route('/encryption_info', methods=['GET'])
def get_encryption_info():
    """Get information about the encryption algorithm with client secret details"""
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        info = {
            'algorithm': 'AES-256-GCM',
            'key_derivation': 'PBKDF2-HMAC-SHA256',
            'iterations': 100000,
            'key_length': 256,
            'nonce_length': 96,
            'salt_length': 128,
            'encoding': 'Base64',
            'data_format': 'JSON',
            'client_secret_integration': {
                'purpose': 'User-specific encryption for enhanced security',
                'generation': 'Automatic during user registration',
                'storage': 'Encrypted in user database',
                'retrieval': 'Available through authentication endpoints',
                'usage': 'Include as X-CLIENT-SECRET header or use X-USER-EMAIL for lookup'
            },
            'required_fields': ['ciphertext', 'nonce', 'tag', 'algorithm'],
            'optional_fields': ['salt', 'iterations'],
            'authentication_headers': {
                'X-API-KEY': 'Required API key for service access',
                'X-CLIENT-SECRET': 'User-specific client secret (optional if X-USER-EMAIL provided)',
                'X-USER-EMAIL': 'User email for client secret lookup and authentication'
            },
            'example_usage': {
                'registration': {
                    'endpoint': '/api/v1/encrypted/register_user',
                    'note': 'Returns client secret for new user'
                },
                'authentication': {
                    'endpoint': '/api/v1/encrypted/authenticate_user',
                    'note': 'Returns client secret for existing user'
                },
                'encrypted_operations': {
                    'endpoints': [
                        '/api/v1/encrypted/send_email',
                        '/api/v1/encrypted/get_inbox',
                        '/api/v1/encrypted/bulk_send'
                    ],
                    'note': 'Require authenticated user and client secret'
                }
            },
            'security_features': {
                'user_specific_encryption': 'Each user has unique client secret',
                'automatic_secret_generation': 'Generated during registration',
                'encrypted_secret_storage': 'Client secrets stored encrypted in database',
                'authentication_required': 'Most endpoints require user authentication',
                'sender_verification': 'Email sender must match authenticated user'
            }
        }
        
        return jsonify(info), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get encryption info: {str(e)}'}), 500

# ========== ERROR HANDLERS ==========

@encrypted_service_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@encrypted_service_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': 'Invalid API key or authentication required'}), 401

@encrypted_service_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403

@encrypted_service_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500