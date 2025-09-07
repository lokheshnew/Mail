import secrets
import string
import re
from datetime import datetime
from pymongo import MongoClient
from utils.encryption import Encryption
from models.user import register_user
from services.mail_service import MailService
from utils.file_helpers import read_mail_collection, save_mail_collection
from config import BASE_SUPPORTED_SERVICES, refresh_supported_services

# MongoDB setup
client = MongoClient("mongodb://localhost:27017")
db = client['mailapp']
companies_collection = db['companies']
users_collection = db['users']

# 1. Generate secure password
def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# 2. Load companies (MongoDB version)
def load_companies():
    try:
        companies = list(companies_collection.find({}, {"_id": 0}))
        return {c['company_id']: c for c in companies}
    except Exception as e:
        print(f"Error loading companies: {e}")
        return {}

# 3. Save companies (MongoDB version)
def save_companies(companies):
    try:
        if not isinstance(companies, dict):
            raise ValueError("Companies data must be a dictionary")
        for company_id, company_data in companies.items():
            companies_collection.update_one(
                {"company_id": company_id},
                {"$set": company_data},
                upsert=True
            )
        return True
    except Exception as e:
        print(f"Error saving companies: {e}")
        return False

# 4. Validate domain format
def validate_domain_format(domain):
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"
    domain = domain.strip().lower()
    if len(domain) < 3 or '.' not in domain:
        return False, "Domain must contain at least one dot and be at least 3 characters"
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    reserved_domains = ['localhost', 'example.com', 'test.local']
    if domain in reserved_domains:
        return False, f"Domain '{domain}' is reserved"
    return True, domain

# 5. Check if domain is available
def is_domain_available(domain):
    valid, result = validate_domain_format(domain)
    if not valid:
        return False
    domain = result
    if companies_collection.find_one({"domain": domain}):
        return False
    for service_key, service in BASE_SUPPORTED_SERVICES.items():
        if service.get('domain') == domain:
            return False
    return True

# 6. Register company
def register_company(company_name, domain, admin_name, admin_email=None):
    try:
        if not company_name or not admin_name:
            return None, "Company and admin name are required"
        company_name = company_name.strip()
        admin_name = admin_name.strip()
        if len(company_name) < 2 or len(admin_name) < 2:
            return None, "Company/Admin name must be at least 2 characters"
        valid, domain_result = validate_domain_format(domain)
        if not valid:
            return None, domain_result
        domain = domain_result
        if not is_domain_available(domain):
            return None, f"Domain '{domain}' is already registered or reserved"

        company_id = re.sub(r'[^a-z0-9_]', '', company_name.lower().replace(' ', '_').replace('-', '_'))
        base_id = company_id
        counter = 1
        while companies_collection.find_one({"company_id": company_id}):
            company_id = f"{base_id}_{counter}"
            counter += 1
            if counter > 1000:
                return None, "Unable to generate unique company ID"

        created_at = datetime.now().isoformat()
        company_doc = {
            "company_id": company_id,
            "name": company_name,
            "domain": domain,
            "admin_name": admin_name,
            "status": "active",
            "created_at": created_at,
            "created_by": "system"
        }
        companies_collection.insert_one(company_doc)
        refresh_supported_services()

        admin_email = f"admin@{domain}"
        admin_password = "admin@1234"

        admin_user, error = register_user(admin_name, admin_email, admin_password)
        if error:
            companies_collection.delete_one({"company_id": company_id})
            refresh_supported_services()
            return None, f"Failed to create admin account: {error}"

        try:
            subject = f"Welcome to {company_name} Mail - Admin Account Created"
            body = f"""Hello {admin_name},

Your company '{company_name}' has been successfully registered!

Admin account:
- Email: {admin_email}
- Password: {admin_password}
- Domain: {domain}

IMPORTANT: Change your password immediately.
"""
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
            admin_inbox = read_mail_collection(admin_email, 'inbox')
            admin_inbox.append(admin_welcome_mail)
            save_mail_collection(admin_email, 'inbox', admin_inbox)
        except Exception as e:
            print(f"Warning: Failed to send admin welcome email: {e}")

        return {
            "company_id": company_id,
            "name": company_name,
            "domain": domain,
            "admin_email": admin_email,
            "admin_password": admin_password,
            "status": "active",
            "created_at": created_at
        }, None
    except Exception as e:
        return None, f"Company registration failed: {str(e)}"

# 7. Get company by domain
def get_company_by_domain(domain):
    if not domain:
        return None
    return companies_collection.find_one({"domain": domain}, {"_id": 0})

# 8. Get all companies
def get_all_companies():
    return list(companies_collection.find({}, {"_id": 0}))

# 9. Get admin email by domain
def get_admin_email_by_domain(domain):
    if not domain or not isinstance(domain, str):
        return None
    return f"admin@{domain}"

# 10. Update company status
def update_company_status(company_id, status):
    if status not in ['active', 'inactive']:
        return False, "Status must be 'active' or 'inactive'"
    result = companies_collection.update_one(
        {"company_id": company_id},
        {"$set": {"status": status, "updated_at": datetime.now().isoformat()}}
    )
    if result.modified_count:
        refresh_supported_services()
        return True, None
    return False, "Company not found or status unchanged"

# 11. Delete company
def delete_company(company_id):
    company = companies_collection.find_one({"company_id": company_id})
    if not company:
        return False, "Company not found"
    companies_collection.delete_one({"company_id": company_id})
    refresh_supported_services()
    print(f"Company {company_id} with domain {company.get('domain')} deleted")
    return True, None

# 12. Send welcome email
def send_welcome_email(user_email, username):
    if not user_email or '@' not in user_email:
        return False, "Invalid email"
    if not username:
        return False, "Username required"
    domain = user_email.split('@')[1]
    company = get_company_by_domain(domain)
    admin_email = f"admin@{domain}"
    company_name = company.get("name") if company else BASE_SUPPORTED_SERVICES.get(domain, {}).get("name", "Mail Service")
    subject = f"Welcome to {company_name} Mail!"
    body = f"Hello {username},\n\nWelcome to {company_name} Mail!"
    success, error = MailService.send_mail(admin_email, user_email, subject, body)
    if not success:
        return False, f"Failed to send welcome email: {error}"
    return True, None

# 13. Get company stats
def get_company_stats(domain):
    if not domain:
        return None, "Domain is required"
    users = list(users_collection.find({"domain": domain}))
    if not users:
        return {'total_users':0,'active_users':0,'total_emails':0,'storage_used':{'used_mb':0,'total_mb':0,'percentage':0}}, None
    total_users = len(users)
    active_users = sum(1 for u in users if u.get('status')=='active')
    total_emails = 0
    total_storage_mb = 0
    for user in users:
        user_email = user.get('email')
        if user_email:
            try:
                inbox = read_mail_collection(user_email,'inbox')
                sent = read_mail_collection(user_email,'sent')
                total_emails += len(inbox)+len(sent)
                # storage = show_storage_status(user_email)
                # total_storage_mb += storage.get('used_mb',0)
            except Exception as e:
                print(f"Error processing user {user_email}: {e}")
    storage_used = {'used_mb': round(total_storage_mb,2),'total_mb': total_users*8,'percentage': round((total_storage_mb/max(total_users*8,1))*100,2)}
    return {'total_users':total_users,'active_users':active_users,'total_emails':total_emails,'storage_used':storage_used,'domain':domain}, None

# 14. Get company by ID
def get_company_by_id(company_id):
    if not company_id:
        return None
    return companies_collection.find_one({"company_id": company_id}, {"_id":0})
