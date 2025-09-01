from flask import Blueprint, request, jsonify, redirect, render_template_string
from models.user import authenticate_user, get_user_by_email, load_users
from models.company import get_company_by_domain
from utils.auth import verify_token, generate_token
from utils.encryption import Encryption
from config import API_KEY
from datetime import datetime, timedelta
import secrets
import json
import re
import base64

oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

# In-memory storage for authorization codes and client registrations
# In production, these should be stored in a database
authorization_codes = {}
registered_clients = {}
access_tokens = {}

# Initialize encryption service
encryption = Encryption()

# ========== CLIENT REGISTRATION ==========

@oauth_bp.route('/register_client', methods=['POST'])
def register_client():
    """
    Register a third-party application to use authentication service
    
    Request:
    {
        "client_name": "My Application",
        "redirect_uris": ["https://myapp.com/callback", "http://localhost:3000/callback"],
        "description": "My application description",
        "website": "https://myapp.com",
        "scopes": ["email", "profile"]
    }
    
    Response:
    {
        "client_id": "abc123",
        "client_secret": "def456",
        "client_name": "My Application",
        "redirect_uris": [...],
        "created_at": "2025-01-01T00:00:00Z"
    }
    """
    try:
        print("arives")
        data = request.get_json()
        print(data)
        # Validate required fields
        client_name = data.get('client_name', '').strip()
        redirect_uris = data.get('redirect_uris', [])
        description = data.get('description', '').strip()
        website = data.get('website', '').strip()
        scopes = data.get('scopes', ['email', 'profile'])
        
        if not client_name:
            return jsonify({'error': 'Client name is required'}), 400
        
        if not redirect_uris or not isinstance(redirect_uris, list):
            return jsonify({'error': 'At least one redirect URI is required'}), 400
        
        # Validate redirect URIs
        for uri in redirect_uris:
            if not uri.startswith(('http://', 'https://')):
                return jsonify({'error': f'Invalid redirect URI: {uri}'}), 400
        
        # Validate scopes
        valid_scopes = ['email', 'profile', 'read', 'write']
        for scope in scopes:
            if scope not in valid_scopes:
                return jsonify({'error': f'Invalid scope: {scope}'}), 400
        
        # Generate client credentials
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(64)
        
        # Store client registration
        client_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'client_name': client_name,
            'redirect_uris': redirect_uris,
            'description': description,
            'website': website,
            'scopes': scopes,
            'created_at': datetime.now().isoformat(),
            'status': 'active'
        }
        
        registered_clients[client_id] = client_data
        
        return jsonify({
            'client_id': client_id,
            'client_secret': client_secret,
            'client_name': client_name,
            'redirect_uris': redirect_uris,
            'scopes': scopes,
            'created_at': client_data['created_at'],
            'message': 'Client registered successfully'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Client registration failed: {str(e)}'}), 500

@oauth_bp.route('/clients', methods=['GET'])
def list_clients():
    """List all registered clients (for admin purposes)"""
    try:
        # This should require admin authentication in production
        clients = []
        for client_id, client_data in registered_clients.items():
            # Don't expose client_secret in listings
            client_info = client_data.copy()
            client_info.pop('client_secret', None)
            clients.append(client_info)
        
        return jsonify({
            'clients': clients,
            'count': len(clients)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to list clients: {str(e)}'}), 500

# ========== OAUTH AUTHORIZATION FLOW ==========

@oauth_bp.route('/authorize', methods=['GET'])
def authorize():
    """
    OAuth authorization endpoint - Step 1 of OAuth flow
    
    Query Parameters:
    - response_type: "code" (required)
    - client_id: registered client ID (required)
    - redirect_uri: callback URI (required)
    - scope: requested permissions (optional, defaults to "email profile")
    - state: CSRF protection token (recommended)
    
    Example:
    GET /oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://myapp.com/callback&scope=email%20profile&state=xyz789
    """
    try:
        # Get query parameters
        response_type = request.args.get('response_type')
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope', 'email profile')
        state = request.args.get('state', '')
        
        # Validate required parameters
        if response_type != 'code':
            return jsonify({'error': 'Invalid response_type. Must be "code"'}), 400
        
        if not client_id:
            return jsonify({'error': 'client_id is required'}), 400
        
        if not redirect_uri:
            return jsonify({'error': 'redirect_uri is required'}), 400
        
        # Validate client
        if client_id not in registered_clients:
            return jsonify({'error': 'Invalid client_id'}), 400
        
        client = registered_clients[client_id]
        
        # Validate redirect URI
        if redirect_uri not in client['redirect_uris']:
            return jsonify({'error': 'Invalid redirect_uri'}), 400
        
        # Validate scope
        requested_scopes = scope.split()
        for s in requested_scopes:
            if s not in client['scopes']:
                return jsonify({'error': f'Scope "{s}" not allowed for this client'}), 400
        
        # Return authorization page HTML (in production, this would be a proper template)
        auth_page = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize {client['client_name']}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .auth-container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .app-info {{ background: #f8f9fa; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
                .permissions {{ margin: 20px 0; }}
                .permission-item {{ margin: 10px 0; padding: 10px; background: #e9ecef; border-radius: 4px; }}
                .form-group {{ margin: 15px 0; }}
                input[type="email"], input[type="password"] {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; }}
                .btn {{ padding: 12px 24px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                .error {{ color: #dc3545; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="auth-container">
                <h2>Authorize Application</h2>
                <div class="app-info">
                    <h3>{client['client_name']}</h3>
                    <p>{client.get('description', 'No description provided')}</p>
                    {f'<p><strong>Website:</strong> <a href="{client["website"]}" target="_blank">{client["website"]}</a></p>' if client.get('website') else ''}
                </div>
                
                <p><strong>{client['client_name']}</strong> would like permission to:</p>
                <div class="permissions">
                    {''.join([f'<div class="permission-item">Access your {s}</div>' for s in requested_scopes])}
                </div>
                
                <form action="/oauth/authorize" method="post">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="scope" value="{scope}">
                    <input type="hidden" name="state" value="{state}">
                    
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" name="action" value="authorize" class="btn btn-primary">
                        Authorize {client['client_name']}
                    </button>
                    <button type="submit" name="action" value="deny" class="btn btn-secondary">
                        Deny Access
                    </button>
                </form>
            </div>
        </body>
        </html>
        """
        
        return auth_page, 200
        
    except Exception as e:
        return jsonify({'error': f'Authorization failed: {str(e)}'}), 500

@oauth_bp.route('/authorize', methods=['POST'])
def process_authorization():
    """
    Process user authorization - Step 2 of OAuth flow
    """
    try:
        # Get form data
        action = request.form.get('action')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        scope = request.form.get('scope')
        state = request.form.get('state', '')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate client
        if client_id not in registered_clients:
            return jsonify({'error': 'Invalid client'}), 400
        
        client = registered_clients[client_id]
        
        # Handle denial
        if action == 'deny':
            error_params = f"error=access_denied&error_description=User%20denied%20authorization"
            if state:
                error_params += f"&state={state}"
            return redirect(f"{redirect_uri}?{error_params}")
        
        # Handle authorization
        if action == 'authorize':
            # Authenticate user
            user, auth_error = authenticate_user(email, password)
            
            if auth_error:
                # Return to authorization page with error
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Generate authorization code
            auth_code = secrets.token_urlsafe(32)
            
            # Store authorization code with expiration (10 minutes)
            authorization_codes[auth_code] = {
                'client_id': client_id,
                'user_email': email,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(minutes=10)
            }
            
            # Redirect back to client with authorization code
            callback_params = f"code={auth_code}"
            if state:
                callback_params += f"&state={state}"
            
            return redirect(f"{redirect_uri}?{callback_params}")
        
        return jsonify({'error': 'Invalid action'}), 400
        
    except Exception as e:
        return jsonify({'error': f'Authorization processing failed: {str(e)}'}), 500

# ========== TOKEN EXCHANGE ==========

@oauth_bp.route('/token', methods=['POST'])
def exchange_token():
    """
    Exchange authorization code for access token - Step 3 of OAuth flow
    
    Request (application/x-www-form-urlencoded or JSON):
    {
        "grant_type": "authorization_code",
        "code": "authorization_code_from_step_2",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
        "redirect_uri": "your_redirect_uri"
    }
    
    Response:
    {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh_token_value",
        "scope": "email profile"
    }
    """
    try:
        # Handle both JSON and form data
        if request.content_type == 'application/json':
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Extract parameters
        grant_type = data.get('grant_type')
        code = data.get('code')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        redirect_uri = data.get('redirect_uri')
        
        # Validate grant type
        if grant_type != 'authorization_code':
            return jsonify({
                'error': 'unsupported_grant_type',
                'error_description': 'Only authorization_code grant type is supported'
            }), 400
        
        # Validate required parameters
        if not all([code, client_id, client_secret, redirect_uri]):
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Missing required parameters'
            }), 400
        
        # Validate client credentials
        if client_id not in registered_clients:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client_id'
            }), 401
        
        client = registered_clients[client_id]
        
        if client['client_secret'] != client_secret:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client_secret'
            }), 401
        
        # Validate authorization code
        if code not in authorization_codes:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Invalid or expired authorization code'
            }), 400
        
        auth_data = authorization_codes[code]
        
        # Check if code has expired
        if datetime.now() > auth_data['expires_at']:
            del authorization_codes[code]
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Authorization code has expired'
            }), 400
        
        # Validate that the code was issued to this client and redirect URI
        if (auth_data['client_id'] != client_id or 
            auth_data['redirect_uri'] != redirect_uri):
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Authorization code mismatch'
            }), 400
        
        # Generate access token and refresh token
        user_email = auth_data['user_email']
        users = load_users()
        user_data = users.get(user_email)
        
        if not user_data:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'User not found'
            }), 400
        
        # Create token payload
        token_payload = {
            'user_id': user_data.get('user_id'),
            'email': user_email,
            'username': user_data.get('username'),
            'client_id': client_id,
            'scope': auth_data['scope'],
            'iat': datetime.now().timestamp(),
            'exp': (datetime.now() + timedelta(hours=1)).timestamp(),
            'token_type': 'oauth_access'
        }
        
        # Generate tokens
        access_token = generate_token(token_payload)
        refresh_token = secrets.token_urlsafe(64)
        
        # Store access token info
        access_tokens[access_token] = {
            'user_email': user_email,
            'client_id': client_id,
            'scope': auth_data['scope'],
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=1),
            'refresh_token': refresh_token
        }
        
        # Clean up authorization code (one-time use)
        del authorization_codes[code]
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'scope': auth_data['scope']
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'server_error',
            'error_description': f'Token exchange failed: {str(e)}'
        }), 500

@oauth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Refresh access token using refresh token
    
    Request:
    {
        "grant_type": "refresh_token",
        "refresh_token": "your_refresh_token",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
    """
    try:
        data = request.get_json() if request.content_type == 'application/json' else request.form.to_dict()
        
        grant_type = data.get('grant_type')
        refresh_token_value = data.get('refresh_token')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if grant_type != 'refresh_token':
            return jsonify({
                'error': 'unsupported_grant_type',
                'error_description': 'Only refresh_token grant type is supported'
            }), 400
        
        # Validate client
        if (client_id not in registered_clients or 
            registered_clients[client_id]['client_secret'] != client_secret):
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client credentials'
            }), 401
        
        # Find access token by refresh token
        token_info = None
        old_access_token = None
        
        for access_token, info in access_tokens.items():
            if info.get('refresh_token') == refresh_token_value:
                token_info = info
                old_access_token = access_token
                break
        
        if not token_info:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Invalid refresh token'
            }), 400
        
        # Generate new access token
        users = load_users()
        user_data = users.get(token_info['user_email'])
        
        new_token_payload = {
            'user_id': user_data.get('user_id'),
            'email': token_info['user_email'],
            'username': user_data.get('username'),
            'client_id': client_id,
            'scope': token_info['scope'],
            'iat': datetime.now().timestamp(),
            'exp': (datetime.now() + timedelta(hours=1)).timestamp(),
            'token_type': 'oauth_access'
        }
        
        new_access_token = generate_token(new_token_payload)
        new_refresh_token = secrets.token_urlsafe(64)
        
        # Update token storage
        access_tokens[new_access_token] = {
            'user_email': token_info['user_email'],
            'client_id': client_id,
            'scope': token_info['scope'],
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=1),
            'refresh_token': new_refresh_token
        }
        
        # Remove old token
        if old_access_token:
            del access_tokens[old_access_token]
        
        return jsonify({
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': new_refresh_token,
            'scope': token_info['scope']
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'server_error',
            'error_description': f'Token refresh failed: {str(e)}'
        }), 500

# ========== USER INFO ENDPOINT ==========

@oauth_bp.route('/userinfo', methods=['GET'])
def get_user_info():
    """
    Get user information using access token
    
    Headers:
    - Authorization: Bearer {access_token}
    
    Response:
    {
        "sub": "user_id",
        "email": "user@domain.com",
        "name": "User Name",
        "username": "username",
        "email_verified": true,
        "created_at": "2025-01-01T00:00:00Z",
        "last_login": "2025-01-01T12:00:00Z"
    }
    """
    try:
        # Get access token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Missing or invalid authorization header'
            }), 401
        
        access_token = auth_header.split(' ')[1]
        
        # Validate access token
        if access_token not in access_tokens:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Invalid access token'
            }), 401
        
        token_info = access_tokens[access_token]
        
        # Check token expiration
        if datetime.now() > token_info['expires_at']:
            del access_tokens[access_token]
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Access token has expired'
            }), 401
        
        # Get user data
        users = load_users()
        user_data = users.get(token_info['user_email'])
        
        if not user_data:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'User not found'
            }), 401
        
        # Check scope and return appropriate user info
        scopes = token_info['scope'].split()
        user_info = {}
        
        if 'profile' in scopes:
            user_info.update({
                'sub': user_data.get('user_id'),
                'name': user_data.get('username'),
                'username': user_data.get('username'),
                'created_at': user_data.get('created_at'),
                'last_login': user_data.get('last_login')
            })
        
        if 'email' in scopes:
            user_info.update({
                'email': token_info['user_email'],
                'email_verified': True  # All emails in your system are considered verified
            })
        
        return jsonify(user_info), 200
        
    except Exception as e:
        return jsonify({
            'error': 'server_error',
            'error_description': f'Failed to get user info: {str(e)}'
        }), 500

# ========== TOKEN REVOCATION ==========

@oauth_bp.route('/revoke', methods=['POST'])
def revoke_token():
    """
    Revoke an access token or refresh token
    
    Request:
    {
        "token": "token_to_revoke",
        "token_type_hint": "access_token|refresh_token",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
    """
    try:
        data = request.get_json() if request.content_type == 'application/json' else request.form.to_dict()
        
        token = data.get('token')
        token_type_hint = data.get('token_type_hint', 'access_token')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not token:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Token is required'
            }), 400
        
        # Validate client credentials
        if (client_id not in registered_clients or 
            registered_clients[client_id]['client_secret'] != client_secret):
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client credentials'
            }), 401
        
        # Revoke token
        revoked = False
        
        # Check if it's an access token
        if token in access_tokens:
            del access_tokens[token]
            revoked = True
        
        # Check if it's a refresh token
        for access_token, info in list(access_tokens.items()):
            if info.get('refresh_token') == token:
                del access_tokens[access_token]
                revoked = True
        
        # OAuth spec says to return 200 even if token wasn't found
        return jsonify({'message': 'Token revoked successfully'}), 200
        
    except Exception as e:
        return jsonify({
            'error': 'server_error',
            'error_description': f'Token revocation failed: {str(e)}'
        }), 500

# ========== INTROSPECTION ENDPOINT ==========

@oauth_bp.route('/introspect', methods=['POST'])
def introspect_token():
    """
    Token introspection endpoint (RFC 7662)
    
    Request:
    {
        "token": "token_to_introspect",
        "token_type_hint": "access_token",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
    
    Response:
    {
        "active": true,
        "scope": "email profile",
        "client_id": "client123",
        "username": "john_doe",
        "email": "john@example.com",
        "exp": 1609459200,
        "iat": 1609455600,
        "sub": "user123"
    }
    """
    try:
        data = request.get_json() if request.content_type == 'application/json' else request.form.to_dict()
        
        token = data.get('token')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not token:
            return jsonify({'active': False}), 200
        
        # Validate client credentials
        if (client_id not in registered_clients or 
            registered_clients[client_id]['client_secret'] != client_secret):
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client credentials'
            }), 401
        
        # Check if token exists and is valid
        if token not in access_tokens:
            return jsonify({'active': False}), 200
        
        token_info = access_tokens[token]
        
        # Check expiration
        if datetime.now() > token_info['expires_at']:
            del access_tokens[token]
            return jsonify({'active': False}), 200
        
        # Get user data
        users = load_users()
        user_data = users.get(token_info['user_email'])
        
        if not user_data:
            return jsonify({'active': False}), 200
        
        # Return token introspection data
        introspection_data = {
            'active': True,
            'scope': token_info['scope'],
            'client_id': token_info['client_id'],
            'username': user_data.get('username'),
            'email': token_info['user_email'],
            'exp': int(token_info['expires_at'].timestamp()),
            'iat': int(token_info['created_at'].timestamp()),
            'sub': user_data.get('user_id'),
            'token_type': 'Bearer'
        }
        
        return jsonify(introspection_data), 200
        
    except Exception as e:
        return jsonify({
            'error': 'server_error',
            'error_description': f'Token introspection failed: {str(e)}'
        }), 500

# ========== DISCOVERY ENDPOINTS ==========

@oauth_bp.route('/.well-known/oauth-authorization-server', methods=['GET'])
def oauth_discovery():
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    """
    try:
        base_url = request.host_url.rstrip('/')
        
        metadata = {
            'issuer': base_url,
            'authorization_endpoint': f'{base_url}/oauth/authorize',
            'token_endpoint': f'{base_url}/oauth/token',
            'userinfo_endpoint': f'{base_url}/oauth/userinfo',
            'revocation_endpoint': f'{base_url}/oauth/revoke',
            'introspection_endpoint': f'{base_url}/oauth/introspect',
            'registration_endpoint': f'{base_url}/oauth/register_client',
            'jwks_uri': f'{base_url}/oauth/.well-known/jwks.json',
            'scopes_supported': ['email', 'profile', 'read', 'write'],
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic'],
            'service_documentation': f'{base_url}/oauth/docs',
            'ui_locales_supported': ['en'],
            'claims_supported': ['sub', 'email', 'name', 'username', 'email_verified', 'created_at'],
            'code_challenge_methods_supported': ['plain', 'S256']
        }
        
        return jsonify(metadata), 200
        
    except Exception as e:
        return jsonify({'error': f'Discovery failed: {str(e)}'}), 500
    