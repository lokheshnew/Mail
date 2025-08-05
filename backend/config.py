import os
import json
from pathlib import Path

# API Key for external service access
API_KEY = '0898c79d9edee1eaf79e1f97718ea84da47472f70884944ba1641b58ed24796c'

# File and directory paths
MAIL_ROOT = 'mail_data'
UPLOAD_FOLDER = os.path.join(MAIL_ROOT, "attachments")
DATA_DIR = Path("mail_users")
USERS_FILE = DATA_DIR / "users.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
KEY_FILE = "secret.key"

# Constants
TRASH_EXPIRY_HOURS = 24
MAX_STORAGE = 8 * 1024 * 1024  # 8 MB

# Email service definitions (base services - never change)
BASE_SUPPORTED_SERVICES = {
    "gmail": {"name": "Gmail", "domain": "gmail.com", "description": "Google Mail Service"},
    "hotmail": {"name": "Hotmail", "domain": "hotmail.com", "description": "Microsoft Hotmail"},
    "outlook": {"name": "Outlook", "domain": "outlook.com", "description": "Microsoft Outlook"},
    "yahoo": {"name": "Yahoo Mail", "domain": "yahoo.com", "description": "Yahoo Mail Service"},
    "custom": {"name": "Custom", "domain": "test.com", "description": "Custom Local Mail"}
}

# Global variable for supported services (includes custom domains)
SUPPORTED_SERVICES = BASE_SUPPORTED_SERVICES.copy()

def load_custom_domains():
    """Load custom domains from companies.json safely"""
    try:
        companies_file = DATA_DIR / "companies.json"
        if not companies_file.exists():
            return {}
            
        with open(companies_file, 'r', encoding='utf-8') as f:
            companies = json.load(f)
            
        custom_domains = {}
        for company_id, company in companies.items():
            domain = company.get('domain')
            company_name = company.get('name')
            
            # Validate required fields
            if not domain or not company_name:
                print(f"Warning: Skipping company {company_id} - missing domain or name")
                continue
            
            # Validate domain format
            if not isinstance(domain, str) or '.' not in domain:
                print(f"Warning: Invalid domain format for company {company_id}: {domain}")
                continue
            
            # Check for duplicate domains
            for existing_service in BASE_SUPPORTED_SERVICES.values():
                if existing_service.get('domain') == domain:
                    print(f"Warning: Domain {domain} conflicts with base service")
                    continue
            
            custom_domains[f"company_{company_id}"] = {
                "name": company_name,
                "domain": domain,
                "description": f"{company_name} Custom Domain",
                "company_id": company_id,
                "status": company.get('status', 'active')
            }
                
        return custom_domains
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in companies.json: {e}")
        return {}
    except FileNotFoundError:
        print("Info: companies.json not found, no custom domains loaded")
        return {}
    except Exception as e:
        print(f"Warning: Could not load custom domains: {e}")
        return {}

def refresh_supported_services():
    """Refresh supported services to include custom domains"""
    global SUPPORTED_SERVICES
    
    try:
        # Start with base services
        updated_services = BASE_SUPPORTED_SERVICES.copy()
        
        # Add custom domains
        custom_domains = load_custom_domains()
        updated_services.update(custom_domains)
        
        # Update global variable atomically
        SUPPORTED_SERVICES = updated_services
        
        print(f"Loaded {len(BASE_SUPPORTED_SERVICES)} base services and {len(custom_domains)} custom domains")
        return SUPPORTED_SERVICES
        
    except Exception as e:
        print(f"Error refreshing supported services: {e}")
        # Keep existing services if refresh fails
        return SUPPORTED_SERVICES

def get_domain_info(domain):
    """Get information about a specific domain"""
    for service_key, service in SUPPORTED_SERVICES.items():
        if service.get('domain') == domain:
            return service
    return None

def is_domain_supported(domain):
    """Check if a domain is supported"""
    return any(service.get('domain') == domain for service in SUPPORTED_SERVICES.values())

def get_all_supported_domains():
    """Get list of all supported domains"""
    return [service.get('domain') for service in SUPPORTED_SERVICES.values() if service.get('domain')]

def validate_config():
    """Validate configuration and return issues"""
    issues = []
    
    # Check API key
    if not API_KEY or len(API_KEY) < 32:
        issues.append("API_KEY is missing or too short")
    
    # Check directories
    required_dirs = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create directory {dir_path}: {e}")
    
    # Check storage limit
    if MAX_STORAGE <= 0:
        issues.append("MAX_STORAGE must be positive")
    
    # Check supported services
    if not SUPPORTED_SERVICES:
        issues.append("No supported services configured")
    
    return issues

# Create necessary directories with error handling
def init_directories():
    """Initialize required directories"""
    directories = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")
            return False
    
    return True

# Initialize configuration
if __name__ != "__main__":  # Only run when imported, not when testing
    init_directories()
    refresh_supported_services()
    
    # Validate configuration
    config_issues = validate_config()
    if config_issues:
        print("Configuration Issues:")
        for issue in config_issues:
            print(f"  - {issue}")
else:
    # For testing
    print("Config module loaded in test mode")