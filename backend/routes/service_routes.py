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

encryption_service = EncryptionService()

def validate_api_key():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != API_KEY:
        return False, "Invalid or missing API key"
    return True, None

def get_client_secret_from_request():
    client_secret = request.headers.get('X-CLIENT-SECRET')
    if client_secret:
        return client_secret
    user_email = request.headers.get('X-USER-EMAIL')
    if user_email:
        return get_client_secret(user_email)
    return None

def is_encrypted_request():
    data = request.get_json()
    return data and 'encrypted_data' in data

def authenticate_api_user(email=None):
    if not email:
        email = request.headers.get('X-USER-EMAIL')
    if not email:
        return None, None, "User email required for API access"
    users = load_users()
    if email not in users:
        return None, None, "User not found"
    user_data = users[email]
    if user_data.get('status') != 'active':
        return None, None, "User account is inactive"
    client_secret = get_client_secret(email)
    if not client_secret:
        return None, None, "Client secret not available for user"
    
    return user_data, client_secret, None

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
# Add this function to your service_routes.py

def process_api_attachment(attachment_data):
    """
    Process attachment data from API requests to match expected format
    """
    if not attachment_data:
        return None
    
    # Case 1: Already in correct format (dict with content and filename)
    if isinstance(attachment_data, dict) and 'content' in attachment_data and 'filename' in attachment_data:
        return attachment_data
    
    # Case 2: Raw base64 string (your current case)
    if isinstance(attachment_data, str):
        # Check if it's base64 data
        if attachment_data.startswith('/9j/') or attachment_data.startswith('iVBORw0KGgo') or len(attachment_data) > 100:
            return {
                "filename": "attachment.pdf",  # Default filename - you might want to make this configurable
                "content": attachment_data,
                "type": "base64"
            }
    
    return None

# Update your send_email_enhanced function in service_routes.py
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
        
        # FIXED: Process attachment to match expected format
        processed_attachment = process_api_attachment(attachment) if attachment else None
        
        # Send email using existing service
        success, error = MailService.send_mail(sender, recipient, subject, body, processed_attachment)
        
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
            'to': recipient,
            'attachment_processed': processed_attachment is not None
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
# Add this to your service_routes.py file

@service_bp.route('/bulk_send', methods=['POST'])
def bulk_send_email():
    """
    Bulk send emails to multiple recipients with validation
    
    Headers:
    - X-API-KEY: API key for authentication
    - Authorization: Bearer token (optional, for user authentication)
    
    Payload:
    {
        "from": "sender@domain.com",
        "to": ["recipient1@domain.com", "recipient2@domain.com", "recipient3@domain.com"],
        "subject": "Email subject",
        "body": "Email body content",
        "attachment": null (optional)
    }
    
    Response:
    {
        "total_requested": 3,
        "total_valid": 2,
        "total_sent": 2,
        "total_failed": 0,
        "valid_emails": ["recipient1@domain.com", "recipient2@domain.com"],
        "invalid_emails": ["recipient3@domain.com"],
        "sent_results": [
            {
                "to": "recipient1@domain.com",
                "success": true,
                "message": "Email sent successfully"
            },
            {
                "to": "recipient2@domain.com", 
                "success": true,
                "message": "Email sent successfully"
            }
        ],
        "summary": {
            "success_rate": "100%",
            "processing_time": "2.3s"
        }
    }
    """
    start_time = datetime.now()
    
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        # Extract required fields
        sender = data.get('from')
        recipients = data.get('to', [])
        subject = data.get('subject', '')
        body = data.get('body', '')
        attachment = data.get('attachment')
        
        # Validation
        if not sender:
            return jsonify({'error': 'Sender (from) is required'}), 400
        
        if not recipients or not isinstance(recipients, list):
            return jsonify({'error': 'Recipients (to) must be a non-empty array'}), 400
        
        if len(recipients) == 0:
            return jsonify({'error': 'At least one recipient is required'}), 400
        
        if len(recipients) > 100:  # Limit to prevent abuse
            return jsonify({'error': 'Maximum 100 recipients allowed per request'}), 400
        
        # Authenticate sender (optional - can be skipped if not needed)
        sender_authenticated = False
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user_data = verify_token(token)
            if user_data and user_data.get('email') == sender:
                sender_authenticated = True
        
        # If not authenticated via token, try API-based authentication
        if not sender_authenticated:
            user_data, client_secret, auth_error = authenticate_api_user(sender)
            if not auth_error:
                sender_authenticated = True
        
        # For now, we'll proceed without strict authentication but log it
        if not sender_authenticated:
            print(f"Warning: Bulk send from {sender} without authentication")
        
        # Step 1: Validate all email addresses
        valid_emails = []
        invalid_emails = []
        
        print(f"Starting bulk validation for {len(recipients)} recipients")
        
        for recipient in recipients:
            if not recipient or not isinstance(recipient, str):
                invalid_emails.append({
                    'email': recipient,
                    'reason': 'Invalid email format'
                })
                continue
            
            recipient = recipient.strip().lower()
            
            # Use existing email verification logic
            try:
                # Check if email exists using your existing verify_email logic
                users = load_users()
                if recipient in users:
                    valid_emails.append(recipient)
                    print(f"✓ Validated: {recipient}")
                else:
                    invalid_emails.append({
                        'email': recipient,
                        'reason': 'Email not found in system'
                    })
                    print(f"✗ Invalid: {recipient} - not found")
            except Exception as e:
                invalid_emails.append({
                    'email': recipient,
                    'reason': f'Validation error: {str(e)}'
                })
                print(f"✗ Error validating {recipient}: {e}")
        
        print(f"Validation complete: {len(valid_emails)} valid, {len(invalid_emails)} invalid")
        
        # Step 2: Send emails to valid recipients
        sent_results = []
        successful_sends = 0
        failed_sends = 0
        
        if valid_emails:
            print(f"Starting bulk send to {len(valid_emails)} valid recipients")
            
            for recipient in valid_emails:
                try:
                    # Use existing MailService to send email
                    success, error = MailService.send_mail(sender, recipient, subject, body, attachment)
                    
                    if success:
                        sent_results.append({
                            'to': recipient,
                            'success': True,
                            'message': 'Email sent successfully'
                        })
                        successful_sends += 1
                        print(f"✓ Sent to: {recipient}")
                    else:
                        sent_results.append({
                            'to': recipient,
                            'success': False,
                            'error': error or 'Unknown error'
                        })
                        failed_sends += 1
                        print(f"✗ Failed to send to {recipient}: {error}")
                        
                except Exception as e:
                    sent_results.append({
                        'to': recipient,
                        'success': False,
                        'error': f'Send error: {str(e)}'
                    })
                    failed_sends += 1
                    print(f"✗ Exception sending to {recipient}: {e}")
        
        # Calculate processing time
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Calculate success rate
        success_rate = "0%"
        if len(valid_emails) > 0:
            success_rate = f"{(successful_sends / len(valid_emails) * 100):.1f}%"
        
        # Prepare response
        response_data = {
            'status': 'completed',
            'total_requested': len(recipients),
            'total_valid': len(valid_emails),
            'total_sent': successful_sends,
            'total_failed': failed_sends,
            'sender': sender,
            'subject': subject,
            'valid_emails': valid_emails,
            'invalid_emails': invalid_emails,
            'sent_results': sent_results,
            'summary': {
                'success_rate': success_rate,
                'processing_time': f"{processing_time:.1f}s",
                'timestamp': end_time.isoformat()
            }
        }
        
        # Return appropriate status code based on results
        if successful_sends == len(valid_emails) and len(valid_emails) > 0:
            # All valid emails sent successfully
            status_code = 200
        elif successful_sends > 0:
            # Partial success
            status_code = 207  # Multi-status
        else:
            # No emails sent successfully
            status_code = 400
        
        print(f"Bulk send completed: {successful_sends}/{len(valid_emails)} sent successfully")
        
        return jsonify(response_data), status_code
        
    except Exception as e:
        error_response = {
            'status': 'error',
            'error': f'Bulk send failed: {str(e)}',
            'total_requested': len(recipients) if 'recipients' in locals() else 0,
            'total_sent': 0,
            'timestamp': datetime.now().isoformat()
        }
        print(f"Bulk send error: {e}")
        return jsonify(error_response), 500

@service_bp.route('/cache/stats')
def cache_stats():
    from utils.json_cache import get_cache_instance
    cache = get_cache_instance()
    return jsonify(cache.get_cache_stats())

@service_bp.route('/bulk_verify_emails', methods=['POST'])
def bulk_verify_emails():
    """
    Bulk verify multiple email addresses
    
    Headers:
    - X-API-KEY: API key for authentication
    
    Payload:
    {
        "emails": ["email1@domain.com", "email2@domain.com", "email3@domain.com"]
    }
    
    Response:
    {
        "total_checked": 3,
        "valid_count": 2,
        "invalid_count": 1,
        "valid_emails": ["email1@domain.com", "email2@domain.com"],
        "invalid_emails": [
            {
                "email": "email3@domain.com",
                "reason": "Email not found in system"
            }
        ]
    }
    """
    try:
        # Validate API key
        valid, error = validate_api_key()
        if not valid:
            return jsonify({'error': error}), 401
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        emails = data.get('emails', [])
        
        if not emails or not isinstance(emails, list):
            return jsonify({'error': 'Emails array is required'}), 400
        
        if len(emails) > 500:  # Reasonable limit for bulk verification
            return jsonify({'error': 'Maximum 500 emails allowed per verification request'}), 400
        
        valid_emails = []
        invalid_emails = []
        
        # Load users once for efficiency
        users = load_users()
        
        for email in emails:
            if not email or not isinstance(email, str):
                invalid_emails.append({
                    'email': email,
                    'reason': 'Invalid email format'
                })
                continue
            
            email = email.strip().lower()
            
            # Basic email format validation
            email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
            if not re.match(email_regex, email):
                invalid_emails.append({
                    'email': email,
                    'reason': 'Invalid email format'
                })
                continue
            
            # Check if email exists in system
            if email in users:
                user_data = users[email]
                if user_data.get('status') == 'active':
                    valid_emails.append(email)
                else:
                    invalid_emails.append({
                        'email': email,
                        'reason': f'User account is {user_data.get("status", "inactive")}'
                    })
            else:
                invalid_emails.append({
                    'email': email,
                    'reason': 'Email not found in system'
                })
        
        response_data = {
            'total_checked': len(emails),
            'valid_count': len(valid_emails),
            'invalid_count': len(invalid_emails),
            'valid_emails': valid_emails,
            'invalid_emails': invalid_emails,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Bulk verification failed: {str(e)}',
            'total_checked': 0,
            'valid_count': 0,
            'invalid_count': 0
        }), 500


# Add this helper function for better email validation if needed
def validate_email_advanced(email):
    """
    Advanced email validation with domain checking
    """
    try:
        if not email or not isinstance(email, str):
            return False, "Invalid email format"
        
        email = email.strip().lower()
        
        # Basic format validation
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, email):
            return False, "Invalid email format"
        
        # Check domain is supported
        if not is_supported_email(email):
            return False, "Domain not supported"
        
        # Check if user exists
        users = load_users()
        if email not in users:
            return False, "Email not found"
        
        # Check if user is active
        user_data = users[email]
        if user_data.get('status') != 'active':
            return False, f"User account is {user_data.get('status', 'inactive')}"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"
