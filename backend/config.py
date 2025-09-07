import os
from pymongo import MongoClient

# MongoDB connection
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "mailapp"
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# API Key for external service access
API_KEY = '0898c79d9edee1eaf79e1f97718ea84da47472f70884944ba1641b58ed24796c'

# File and directory paths
MAIL_ROOT = 'mail_data'
UPLOAD_FOLDER = "uploads"

# Constants
TRASH_EXPIRY_HOURS = 24
MAX_STORAGE = 8 * 1024 * 1024  # 8 MB

# Base email services (never change)
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
    """Load custom domains directly from MongoDB companies collection"""
    custom_domains = {}
    try:
        companies = db.companies.find({}, {"_id": 0, "company_id": 1, "name": 1, "domain": 1, "status": 1})
        for company in companies:
            domain = company.get("domain")
            company_name = company.get("name")
            company_id = company.get("company_id")
            status = company.get("status", "active")

            if not domain or not company_name:
                print(f"Warning: Skipping company {company_id} - missing domain or name")
                continue

            # Skip domains that conflict with base services
            if any(service.get("domain") == domain for service in BASE_SUPPORTED_SERVICES.values()):
                print(f"Warning: Domain {domain} conflicts with base service")
                continue

            custom_domains[f"company_{company_id}"] = {
                "name": company_name,
                "domain": domain,
                "description": f"{company_name} Custom Domain",
                "company_id": company_id,
                "status": status
            }

        return custom_domains

    except Exception as e:
        print(f"Warning: Could not load custom domains from MongoDB: {e}")
        return {}


def refresh_supported_services():
    """Refresh supported services to include custom domains"""
    global SUPPORTED_SERVICES
    try:
        updated_services = BASE_SUPPORTED_SERVICES.copy()
        custom_domains = load_custom_domains()
        updated_services.update(custom_domains)
        SUPPORTED_SERVICES = updated_services
        print(f"Loaded {len(BASE_SUPPORTED_SERVICES)} base services and {len(custom_domains)} custom domains")
        return SUPPORTED_SERVICES
    except Exception as e:
        print(f"Error refreshing supported services: {e}")
        return SUPPORTED_SERVICES


def get_domain_info(domain):
    """Get information about a specific domain"""
    for service in SUPPORTED_SERVICES.values():
        if service.get("domain") == domain:
            return service
    return None


def is_domain_supported(domain):
    """Check if a domain is supported"""
    return any(service.get("domain") == domain for service in SUPPORTED_SERVICES.values())


def get_all_supported_domains():
    """Get list of all supported domains"""
    return [service.get("domain") for service in SUPPORTED_SERVICES.values() if service.get("domain")]


def validate_config():
    """Validate configuration and return issues"""
    issues = []

    if not API_KEY or len(API_KEY) < 32:
        issues.append("API_KEY is missing or too short")

    required_dirs = [MAIL_ROOT, UPLOAD_FOLDER]
    for directory in required_dirs:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create directory {directory}: {e}")

    if MAX_STORAGE <= 0:
        issues.append("MAX_STORAGE must be positive")

    if not SUPPORTED_SERVICES:
        issues.append("No supported services configured")

    return issues


def init_directories():
    """Initialize required directories"""
    directories = [MAIL_ROOT, UPLOAD_FOLDER]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")
            return False
    return True


# Initialize configuration
if __name__ != "__main__":
    init_directories()
    refresh_supported_services()
    issues = validate_config()
    if issues:
        print("Configuration Issues:")
        for issue in issues:
            print(f"  - {issue}")
else:
    print("Config module loaded in MongoDB mode")
