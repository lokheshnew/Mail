import json
import hashlib
import re
import secrets
import string
from config import SUPPORTED_SERVICES, MONGO_URI, DB_NAME
from utils.encryption import Encryption
from datetime import datetime, timedelta
from pymongo import MongoClient, ReturnDocument

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_col = db['users']

print(">>> Importing models.user")


def validate_email_format(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False, "Email must be a non-empty string"
    
    email = email.strip().lower()
    
    # Basic email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Check email length
    if len(email) > 254:  # RFC 5321 limit
        return False, "Email address too long"
    
    local_part, domain = email.split('@')
    if len(local_part) > 64:  # RFC 5321 limit
        return False, "Email local part too long"
    
    return True, email

def validate_username(username):
    """Validate username"""
    if not username or not isinstance(username, str):
        return False, "Username must be a non-empty string"
    
    username = username.strip()
    
    if len(username) < 2:
        return False, "Username must be at least 2 characters"
    
    if len(username) > 100:
        return False, "Username too long (max 100 characters)"
    
    # Check for valid characters (letters, numbers, spaces, basic punctuation)
    if not re.match(r'^[a-zA-Z0-9\s\.\-\_]+$', username):
        return False, "Username contains invalid characters"
    
    return True, username

def validate_password(password):
    """Validate password strength"""
    if not password or not isinstance(password, str):
        return False, "Password must be a non-empty string"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    if len(password) > 128:
        return False, "Password too long (max 128 characters)"
    
    # Check for at least one letter and one number
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    return True, password

def generate_client_secret(length=32):
    """Generate a cryptographically secure client secret"""
    # Use a mix of letters, numbers, and special characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_user_id(username, password):
    """Generate a user ID based on username and password"""
    if not username or not password:
        raise ValueError("Username and password are required")
    
    combined = f"{username}:{password}:{datetime.now().isoformat()}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]

def get_user_id(username, password):
    """Get a user ID (for backward compatibility)"""
    return generate_user_id(username, password)

def load_users():
    """Load all users from MongoDB as a dictionary keyed by email"""
    try:
        users = {}
        cursor = users_col.find({})
        for doc in cursor:
            email = doc.get("email")
            if email:
                users[email] = doc
        return users
    except Exception as e:
        print(f"❌ Error loading users from MongoDB: {e}")
        return {}

def save_users(users):
    """Save users into MongoDB with upsert (keep same API as old JSON version)"""
    try:
        if not isinstance(users, dict):
            raise ValueError("Users data must be a dictionary")

        for email, user_data in users.items():
            if not isinstance(user_data, dict):
                continue
            users_col.update_one(
                {"email": email},       # match by email
                {"$set": user_data},    # replace/update fields
                upsert=True             # insert if not exists
            )
        return True

    except Exception as e:
        print(f"❌ Error saving users to MongoDB: {e}")
        return False

def is_supported_email(email):
    """Check if an email domain is supported"""
    try:
        # Validate email format first
        valid, cleaned_email = validate_email_format(email)
        if not valid:
            return False
        
        email = cleaned_email
        domain = email.split('@')[1]
        
        # Check if it's one of the supported services
        if any(email.endswith("@" + service["domain"]) for service in SUPPORTED_SERVICES.values()):
            return True
        
        # Check if it's a registered custom domain
        from models.company import get_company_by_domain
        company = get_company_by_domain(domain)
        return company is not None
        
    except Exception as e:
        print(f"Error checking email support: {e}")
        return False

def register_user(username, email, password):

    print(">>> Defining register_user")

    """Register a new user with comprehensive validation and client secret generation"""
    try:
        # Validate inputs
        valid, clean_username = validate_username(username)
        if not valid:
            return None, clean_username
        
        valid, clean_email = validate_email_format(email)
        if not valid:
            return None, clean_email
        
        valid, clean_password = validate_password(password)
        if not valid:
            return None, clean_password
        
        username = clean_username
        email = clean_email
        password = clean_password
        
        # Check if email is supported
        if not is_supported_email(email):
            return None, "Unsupported email domain"
        
        # Load existing users
        users = load_users()
        
        # Check if user already exists
        if email in users:
            return None, "User already exists"
        
        # Encrypt password
        encryption = Encryption()
        encrypted_password = encryption.encrypt(password)
        
        # Generate user ID
        user_id = generate_user_id(email, password)
        
        # Generate client secret for this user
        client_secret = generate_client_secret(32)
        
        # Encrypt the client secret for storage
        encrypted_client_secret = encryption.encrypt(client_secret)
        
        # Add new user with client secret
        user_doc = {
            "user_id": user_id,
            "username": username,
            "password": encrypted_password,
            "email": email,
            "client_secret": encrypted_client_secret,  
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "login_count": 0
        }
        users_col.insert_one(user_doc)
        
        # Set up user folders
        from utils.file_helpers import setup_user_collections
        try:
            setup_user_collections(email)
        except Exception as e:
            print(f"Warning: Failed to setup user collections: {e}")
            # Don't fail registration if collection setup fails

        # Send welcome email (but not for admin accounts during company creation)
        if not email.startswith('admin@'):
            try:
                from models.company import send_welcome_email
                send_welcome_email(email, username)
            except Exception as e:
                print(f"Warning: Failed to send welcome email: {e}")
                # Don't fail registration if welcome email fails
        
        return {
            "user_id": user_id,
            "username": username,
            "email": email,
            "client_secret": client_secret,  # Return plain client secret for initial setup
            "status": "active",
            "created_at": user_doc["created_at"]
        }, None
        
    except Exception as e:
        print(f"Error registering user: {e}")
        return None, f"Registration failed: {str(e)}"

def authenticate_user(email, password):
    """Authenticate a user with enhanced security and return client secret"""
    try:
        # Validate inputs
        if not email or not password:
            return None, "Email and password are required"
        
        valid, clean_email = validate_email_format(email)
        if not valid:
            return None, "Invalid email format"
        
        email = clean_email
        
        # Check if email is supported
        if not is_supported_email(email):
            return None, "Unsupported email domain"
        
        # Load users
        users = load_users()
        
        # Check if user exists
        if email not in users:
            return None, "User not found"
        
        user_data = users[email]
        
        # Check if user is active
        if user_data.get('status') != 'active':
            return None, "Account is inactive"
        
        # Check password
        try:
            encryption = Encryption()
            encrypted_password = user_data['password']
            decrypted = encryption.decrypt(encrypted_password)
            
            if decrypted == password:
                # Update login stats
                users[email]['last_login'] = datetime.now().isoformat()
                users[email]['login_count'] = user_data.get('login_count', 0) + 1
                save_users(users)
                
                user_id = user_data.get('user_id') or generate_user_id(email, password)
                
                # Decrypt client secret for return
                client_secret = None
                if 'client_secret' in user_data:
                    try:
                        client_secret = encryption.decrypt(user_data['client_secret'])
                    except Exception as e:
                        print(f"Warning: Failed to decrypt client secret for {email}: {e}")
                        # Generate new client secret if decryption fails
                        client_secret = generate_client_secret(32)
                        encrypted_client_secret = encryption.encrypt(client_secret)
                        users[email]['client_secret'] = encrypted_client_secret
                        save_users(users)
                else:
                    # Generate client secret for existing users who don't have one
                    client_secret = generate_client_secret(32)
                    encrypted_client_secret = encryption.encrypt(client_secret)
                    users[email]['client_secret'] = encrypted_client_secret
                    save_users(users)
                
                return {
                    "user_id": user_id,
                    "email": email,
                    "username": user_data['username'],
                    "client_secret": client_secret,  # Include client secret in response
                    "status": user_data.get('status', 'active'),
                    "last_login": users[email]['last_login']
                }, None
            else:
                return None, "Incorrect password"
                
        except Exception as e:
            print(f"Error during password verification: {e}")
            return None, "Authentication failed"
            
    except Exception as e:
        print(f"Error authenticating user: {e}")
        return None, f"Authentication failed: {str(e)}"

def get_client_secret(email):
    """Get client secret for a user"""
    try:
        if not email:
            return None
            
        valid, clean_email = validate_email_format(email)
        if not valid:
            return None
            
        email = clean_email
        users = load_users()
        
        if email not in users:
            return None
            
        user_data = users[email]
        
        if 'client_secret' not in user_data:
            # Generate client secret for users who don't have one
            client_secret = generate_client_secret(32)
            encryption = Encryption()
            encrypted_client_secret = encryption.encrypt(client_secret)
            users[email]['client_secret'] = encrypted_client_secret
            save_users(users)
            return client_secret
        
        # Decrypt existing client secret
        encryption = Encryption()
        try:
            return encryption.decrypt(user_data['client_secret'])
        except Exception as e:
            print(f"Error decrypting client secret for {email}: {e}")
            # Generate new client secret if decryption fails
            client_secret = generate_client_secret(32)
            encrypted_client_secret = encryption.encrypt(client_secret)
            users[email]['client_secret'] = encrypted_client_secret
            save_users(users)
            return client_secret
            
    except Exception as e:
        print(f"Error getting client secret: {e}")
        return None

def update_user_last_login(email):
    """Update user's last login timestamp"""
    try:
        if not email:
            return False
            
        valid, clean_email = validate_email_format(email)
        if not valid:
            return False
            
        email = clean_email
        users = load_users()
        
        if email in users:
            users[email]['last_login'] = datetime.now().isoformat()
            users[email]['login_count'] = users[email].get('login_count', 0) + 1
            return save_users(users)
        
        return False
        
    except Exception as e:
        print(f"Error updating last login: {str(e)}")
        return False

def get_users_by_domain(domain):
    """Get all users for a specific domain"""
    try:
        if not domain or not isinstance(domain, str):
            return []
            
        users = load_users()
        domain_users = []
        
        for user_email, user_data in users.items():
            if user_email.endswith(f'@{domain}'):
                domain_users.append({
                    'user_id': user_data.get('user_id', ''),
                    'username': user_data.get('username'),
                    'email': user_email,
                    'status': user_data.get('status', 'active'),
                    'created_at': user_data.get('created_at'),
                    'last_login': user_data.get('last_login'),
                    'login_count': user_data.get('login_count', 0),
                    'has_client_secret': 'client_secret' in user_data
                })
        
        return domain_users
        
    except Exception as e:
        print(f"Error getting users by domain: {str(e)}")
        return []

def get_user_stats():
    """Get overall user statistics"""
    try:
        users = load_users()
        
        total_users = len(users)
        active_users = len([u for u in users.values() if u.get('status') == 'active'])
        inactive_users = total_users - active_users
        users_with_secrets = len([u for u in users.values() if 'client_secret' in u])
        
        # Calculate users with recent activity (last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_active = 0
        
        for user_data in users.values():
            last_login = user_data.get('last_login')
            if last_login:
                try:
                    login_date = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                    if login_date > thirty_days_ago:
                        recent_active += 1
                except Exception:
                    continue
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': inactive_users,
            'recent_active_users': recent_active,
            'users_with_client_secrets': users_with_secrets
        }
        
    except Exception as e:
        print(f"Error getting user stats: {str(e)}")
        return {
            'total_users': 0, 
            'active_users': 0, 
            'inactive_users': 0, 
            'recent_active_users': 0,
            'users_with_client_secrets': 0
        }

def update_user_status(email, status):
    """Update user status"""
    try:
        if status not in ['active', 'inactive']:
            return False, "Status must be 'active' or 'inactive'"
            
        valid, clean_email = validate_email_format(email)
        if not valid:
            return False, "Invalid email format"
            
        email = clean_email
        users = load_users()
        
        if email not in users:
            return False, "User not found"
        
        users[email]['status'] = status
        users[email]['updated_at'] = datetime.now().isoformat()
        
        if save_users(users):
            return True, None
        else:
            return False, "Failed to save user data"
            
    except Exception as e:
        print(f"Error updating user status: {e}")
        return False, f"Error updating status: {str(e)}"

def get_user_by_email(email):
    """Get user information by email"""
    try:
        if not email:
            return None
            
        valid, clean_email = validate_email_format(email)
        if not valid:
            return None
            
        email = clean_email
        users = load_users()
        
        if email not in users:
            return None
            
        user_data = users[email]
        return {
            'user_id': user_data.get('user_id'),
            'username': user_data.get('username'),
            'email': email,
            'status': user_data.get('status', 'active'),
            'created_at': user_data.get('created_at'),
            'last_login': user_data.get('last_login'),
            'login_count': user_data.get('login_count', 0),
            'updated_at': user_data.get('updated_at'),
            'has_client_secret': 'client_secret' in user_data
        }
        
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None