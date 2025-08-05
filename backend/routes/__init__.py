# Import route modules with error handling
try:
    from .auth_routes import auth_bp
except ImportError as e:
    print(f"Warning: Could not import auth_routes: {e}")
    auth_bp = None

try:
    from .mail_routes import mail_bp
except ImportError as e:
    print(f"Warning: Could not import mail_routes: {e}")
    mail_bp = None

try:
    from .file_routes import file_bp
except ImportError as e:
    print(f"Warning: Could not import file_routes: {e}")
    file_bp = None

try:
    from .template_routes import template_bp
except ImportError as e:
    print(f"Warning: Could not import template_routes: {e}")
    template_bp = None

try:
    from .company_routes import company_bp
except ImportError as e:
    print(f"Warning: Could not import company_routes: {e}")
    company_bp = None

try:
    from .service_routes import service_bp
except ImportError as e:
    print(f"Warning: Could not import service_routes: {e}")
    service_bp = None

# Export all blueprints that were successfully imported
__all__ = []
if auth_bp:
    __all__.append('auth_bp')
if mail_bp:
    __all__.append('mail_bp')
if file_bp:
    __all__.append('file_bp')
if template_bp:
    __all__.append('template_bp')
if company_bp:
    __all__.append('company_bp')
if service_bp:
    __all__.append('service_bp')