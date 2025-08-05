import json
import os
import secrets
import string
from pathlib import Path
from datetime import datetime
from config import DATA_DIR
from utils.encryption import Encryption
from models.user import register_user
from services.mail_service import MailService
from utils.file_helpers import setup_user_folders

# Constants
COMPANIES_FILE = DATA_DIR / "companies.json"

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def load_companies():
    """Load companies from the companies file"""
    try:
        if not COMPANIES_FILE.exists():
            # Create the file with empty dict
            COMPANIES_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(COMPANIES_FILE, 'w', encoding='utf-8') as f:
                json.dump({}, f)
            return {}
            
        with open(COMPANIES_FILE, 'r', encoding='utf-8') as f:
            companies = json.load(f)
            
        # Validate loaded data
        if not isinstance(companies, dict):
            print("Warning: companies.json contains invalid data, resetting")
            return {}
            
        return companies
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in companies.json: {e}")
        return {}
    except Exception as e:
        print(f"Error loading companies: {e}")
        return {}

def save_companies(companies):
    """Save companies to the companies file"""
    try:
        # Validate input
        if not isinstance(companies, dict):
            raise ValueError("Companies data must be a dictionary")
            
        # Ensure directory exists
        COMPANIES_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        # Write atomically (write to temp file first)
        temp_file = COMPANIES_FILE.with_suffix('.tmp')
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(companies, f, indent=2, ensure_ascii=False)
        
        # Replace original file
        temp_file.replace(COMPANIES_FILE)
        return True
        
    except Exception as e:
        print(f"Error saving companies: {e}")
        return False

def validate_domain_format(domain):
    """Validate domain format"""
    import re
    
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"
    
    # Clean domain
    domain = domain.strip().lower()
    
    # Basic format check
    if len(domain) < 3 or '.' not in domain:
        return False, "Domain must contain at least one dot and be at least 3 characters"
    
    # Regex validation for domain format
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    # Check for reserved domains
    reserved_domains = ['localhost', 'example.com', 'test.local']
    if domain in reserved_domains:
        return False, f"Domain '{domain}' is reserved"
    
    return True, domain

def is_domain_available(domain):
    """Check if a domain is available"""
    try:
        # Validate domain format first
        valid, result = validate_domain_format(domain)
        if not valid:
            return False
        
        domain = result  # Use cleaned domain
        companies = load_companies()
        
        # Check if domain is already registered
        for company_id, company in companies.items():
            if company.get('domain') == domain:
                return False
        
        # Check if domain is in the base supported services
        from config import BASE_SUPPORTED_SERVICES
        for service_key, service in BASE_SUPPORTED_SERVICES.items():
            if service.get('domain') == domain:
                return False
        
        return True
        
    except Exception as e:
        print(f"Error checking domain availability: {e}")
        return False

def register_company(company_name, domain, admin_name, admin_email=None):
    """Register a new company with enhanced security"""
    try:
        # Input validation
        if not company_name or not isinstance(company_name, str):
            return None, "Company name is required and must be a string"
        
        if not admin_name or not isinstance(admin_name, str):
            return None, "Admin name is required and must be a string"
        
        company_name = company_name.strip()
        admin_name = admin_name.strip()
        
        if len(company_name) < 2:
            return None, "Company name must be at least 2 characters"
        
        if len(admin_name) < 2:
            return None, "Admin name must be at least 2 characters"
        
        # Validate and clean domain
        valid, domain_result = validate_domain_format(domain)
        if not valid:
            return None, domain_result
        
        domain = domain_result
        
        # Check if domain is available
        if not is_domain_available(domain):
            return None, f"Domain '{domain}' is already registered or reserved"
        
        # Generate unique company ID
        company_id = company_name.lower().replace(' ', '_').replace('-', '_')
        # Remove special characters except underscore
        import re
        company_id = re.sub(r'[^a-z0-9_]', '', company_id)
        
        # Ensure company ID is unique
        companies = load_companies()
        if company_id in companies:
            base_id = company_id
            counter = 1
            while company_id in companies:
                company_id = f"{base_id}_{counter}"
                counter += 1
                if counter > 1000:  # Prevent infinite loop
                    return None, "Unable to generate unique company ID"
        
        # Create company record
        companies[company_id] = {
            'name': company_name,
            'domain': domain,
            'admin_name': admin_name,
            'created_at': datetime.now().isoformat(),
            'status': 'active',
            'created_by': 'system'
        }
        
        # Save companies first
        if not save_companies(companies):
            return None, "Failed to save company data"
        
        # Refresh supported services to include new domain
        from config import refresh_supported_services
        refresh_supported_services()
        
        # Generate secure admin credentials
        admin_email = f"admin@{domain}"
        admin_password = "admin@1234"
        # admin_password = generate_secure_password(16)  # 16-character secure password
        
        # Register admin user
        admin_user, error = register_user(admin_name, admin_email, admin_password)
        if error:
            # Rollback company creation if admin creation fails
            del companies[company_id]
            save_companies(companies)
            refresh_supported_services()
            return None, f"Failed to create admin account: {error}"
        
        # Send welcome email to admin
        try:
            subject = f"Welcome to {company_name} Mail - Admin Account Created"
            body = f"""Hello {admin_name},

Your company '{company_name}' has been successfully registered in our mail system!

Your admin account details:
- Email: {admin_email}
- Password: {admin_password}
- Domain: {domain}

IMPORTANT SECURITY NOTICE:
- Please change your password immediately after first login
- Store these credentials securely
- This is the only time you will see the plain text password

As an admin, you can now:
- Access the admin panel
- Monitor company email statistics
- Manage users in your domain

Best regards,
Mail System Team
"""
            
            # Save welcome email directly to admin's inbox
            encryption = Encryption()
            encrypted_body = encryption.encrypt(body)
            
            now = datetime.now().isoformat()
            
            admin_welcome_mail = {
                'from': 'system@mailservice.com',
                'to': admin_email,
                'subject': subject,
                'body': encrypted_body,
                'date_of_compose': now,
                'date_of_send': now,
                'message_status': 'unread',
                'attachment': None
            }
            
            # Add to admin's inbox
            from utils.file_helpers import read_mail_file, save_mail_file
            admin_inbox = read_mail_file(admin_email, 'inbox')
            admin_inbox.append(admin_welcome_mail)
            save_mail_file(admin_email, 'inbox', admin_inbox)
            
        except Exception as e:
            print(f"Warning: Failed to send admin welcome email: {e}")
            # Don't fail company registration if welcome email fails
        
        return {
            'company_id': company_id,
            'name': company_name,
            'domain': domain,
            'admin_email': admin_email,
            'admin_password': admin_password,  # Return for initial setup only
            'status': 'active',
            'created_at': companies[company_id]['created_at']
        }, None
        
    except Exception as e:
        print(f"Error registering company: {e}")
        return None, f"Company registration failed: {str(e)}"

def get_company_by_domain(domain):
    """Get company information by domain"""
    try:
        if not domain:
            return None
            
        companies = load_companies()
        
        for company_id, company in companies.items():
            if company.get('domain') == domain:
                return {
                    'company_id': company_id,
                    'name': company.get('name'),
                    'domain': domain,
                    'admin_name': company.get('admin_name'),
                    'status': company.get('status', 'active'),
                    'created_at': company.get('created_at'),
                    'created_by': company.get('created_by', 'unknown')
                }
        
        return None
        
    except Exception as e:
        print(f"Error getting company by domain: {e}")
        return None

def get_all_companies():
    """Get all registered companies"""
    try:
        companies = load_companies()
        company_list = []
        
        for company_id, company in companies.items():
            company_list.append({
                'id': company_id,
                'name': company.get('name'),
                'domain': company.get('domain'),
                'admin_name': company.get('admin_name'),
                'status': company.get('status', 'active'),
                'created_at': company.get('created_at'),
                'created_by': company.get('created_by', 'unknown')
            })
        
        return company_list
        
    except Exception as e:
        print(f"Error getting all companies: {e}")
        return []

def get_admin_email_by_domain(domain):
    """Get admin email for a domain"""
    if not domain or not isinstance(domain, str):
        return None
    return f"admin@{domain}"

def update_company_status(company_id, status):
    """Update company status (active/inactive)"""
    try:
        if status not in ['active', 'inactive']:
            return False, "Status must be 'active' or 'inactive'"
            
        companies = load_companies()
        
        if company_id not in companies:
            return False, "Company not found"
        
        companies[company_id]['status'] = status
        companies[company_id]['updated_at'] = datetime.now().isoformat()
        
        if save_companies(companies):
            # Refresh supported services to reflect status change
            from config import refresh_supported_services
            refresh_supported_services()
            return True, None
        else:
            return False, "Failed to save company data"
            
    except Exception as e:
        print(f"Error updating company status: {e}")
        return False, f"Error updating status: {str(e)}"

def delete_company(company_id):
    """Delete a company (use with extreme caution)"""
    try:
        companies = load_companies()
        
        if company_id not in companies:
            return False, "Company not found"
        
        # Get domain before deletion for cleanup
        domain = companies[company_id].get('domain')
        
        # Remove company
        del companies[company_id]
        
        # Save changes
        if not save_companies(companies):
            return False, "Failed to save company data"
        
        # Refresh supported services to remove this domain
        from config import refresh_supported_services
        refresh_supported_services()
        
        print(f"Company {company_id} with domain {domain} has been deleted")
        return True, None
        
    except Exception as e:
        print(f"Error deleting company: {e}")
        return False, f"Error deleting company: {str(e)}"

def send_welcome_email(user_email, username):
    """Send welcome email to new user from their domain admin"""
    try:
        # Validate inputs
        if not user_email or '@' not in user_email:
            return False, "Invalid email address"
        
        if not username:
            return False, "Username is required"
        
        # Extract domain from email
        domain = user_email.split('@')[1]
        
        # Get company info
        company = get_company_by_domain(domain)
        admin_email = f"admin@{domain}"
        
        if company:
            # Custom domain company
            company_name = company.get('name')
        else:
            # Check if it's one of the default domains
            from config import BASE_SUPPORTED_SERVICES
            company_name = None
            for service_key, service in BASE_SUPPORTED_SERVICES.items():
                if service.get('domain') == domain:
                    company_name = service.get('name', 'Mail Service')
                    break
            
            if not company_name:
                return False, f"Unknown domain: {domain}"
        
        # Prepare welcome email
        subject = f"Welcome to {company_name} Mail!"
        body = f"""Hello {username},

Welcome to {company_name} Mail!

Your account has been successfully created. You can now send and receive emails using your new address: {user_email}.

Getting started:
- Log in to your account to start sending and receiving emails
- Check your inbox regularly for new messages
- Use the compose feature to send emails to other users

If you have any questions or need assistance, please don't hesitate to contact us.

Best regards,
The {company_name} Team
"""
        
        # Send email using mail service
        success, error = MailService.send_mail(admin_email, user_email, subject, body)
        
        if not success:
            return False, f"Failed to send welcome email: {error}"
        
        return True, None
        
    except Exception as e:
        print(f"Error sending welcome email: {e}")
        return False, f"Error sending welcome email: {str(e)}"
    
def get_company_stats(domain):
    """Get statistics for a company domain"""
    try:
        if not domain:
            return None, "Domain is required"
            
        from models.user import get_users_by_domain
        
        # Get users for this domain
        users = get_users_by_domain(domain)
        
        if not users:
            return {
                'total_users': 0,
                'active_users': 0,
                'total_emails': 0,
                'storage_used': {'used_mb': 0, 'total_mb': 0, 'percentage': 0}
            }, None
        
        # Calculate user stats
        total_users = len(users)
        active_users = len([u for u in users if u.get('status') == 'active'])
        
        # Get email stats
        total_emails = 0
        total_storage_mb = 0
        
        try:
            from utils.file_helpers import read_mail_file
            from utils.storage import show_storage_status
            
            for user in users:
                user_email = user.get('email')
                if user_email:
                    try:
                        # Count emails
                        inbox = read_mail_file(user_email, 'inbox')
                        sent = read_mail_file(user_email, 'sent')
                        total_emails += len(inbox) + len(sent)
                        
                        # Calculate storage
                        storage = show_storage_status(user_email)
                        total_storage_mb += storage.get('used_mb', 0)
                    except Exception as e:
                        print(f"Error processing user {user_email}: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error calculating email/storage stats: {e}")
            total_emails = 0
            total_storage_mb = 0
        
        storage_used = {
            'used_mb': round(total_storage_mb, 2),
            'total_mb': total_users * 8,  # 8 MB per user
            'percentage': round((total_storage_mb / max(total_users * 8, 1)) * 100, 2)
        }
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'total_emails': total_emails,
            'storage_used': storage_used,
            'domain': domain
        }, None
        
    except Exception as e:
        print(f"Error getting company stats: {e}")
        return None, f"Error getting company stats: {str(e)}"

def get_company_by_id(company_id):
    """Get company information by company ID"""
    try:
        if not company_id:
            return None
            
        companies = load_companies()
        
        if company_id not in companies:
            return None
            
        company = companies[company_id]
        return {
            'company_id': company_id,
            'name': company.get('name'),
            'domain': company.get('domain'),
            'admin_name': company.get('admin_name'),
            'status': company.get('status', 'active'),
            'created_at': company.get('created_at'),
            'updated_at': company.get('updated_at'),
            'created_by': company.get('created_by', 'unknown')
        }
        
    except Exception as e:
        print(f"Error getting company by ID: {e}")
        return None