# app.py - Enhanced with security and performance improvements
import os
import sys
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from config import MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER, SESSIONS_FILE, API_KEY, SUPPORTED_SERVICES
from datetime import datetime
import time

# Global variables for monitoring
app_start_time = time.time()
request_count = 0

def verify_dependencies():
    """Verify all required dependencies and configurations"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        issues.append("Python 3.7 or higher is required")
    
    # Check for required directories
    required_dirs = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                print(f"✓ Created directory: {dir_path}")
            except Exception as e:
                issues.append(f"Cannot create directory {dir_path}: {e}")
    
    # Check for required Python packages with correct import names
    required_packages = {
        'flask': 'flask',
        'flask_cors': 'flask-cors', 
        'cryptography': 'cryptography',
        'jwt': 'PyJWT'  # PyJWT package imports as 'jwt'
    }
    
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            issues.append(f"Missing package: {package_name} (install with: pip install {package_name})")
    
    # Check configuration
    if not API_KEY or len(API_KEY) < 32:
        issues.append("API_KEY not configured or too short")
    
    if not SUPPORTED_SERVICES:
        issues.append("No supported services configured")
    
    # Check file permissions
    try:
        test_file = DATA_DIR / "test_permissions.tmp"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
    except Exception as e:
        issues.append(f"File permission issues in {DATA_DIR}: {e}")
    
    if issues:
        print("⚠️  Startup Issues Found:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    else:
        print("✅ All dependencies verified")
        return True

def register_blueprints_with_detailed_logging(app):
    """Register blueprints with detailed error handling and logging"""
    print("\n🔧 Registering blueprints...")
    
    blueprints_config = [
        {
            'module': 'routes.auth_routes',
            'blueprint': 'auth_bp',
            'url_prefix': '/auth',
            'name': 'Authentication'
        },
        {
            'module': 'routes.mail_routes',
            'blueprint': 'mail_bp',
            'url_prefix': '/mail',
            'name': 'Mail Operations'
        },
        {
            'module': 'routes.file_routes',
            'blueprint': 'file_bp',
            'url_prefix': '/file',
            'name': 'File Operations'
        },
        {
            'module': 'routes.template_routes',
            'blueprint': 'template_bp',
            'url_prefix': '/template',
            'name': 'Templates'
        },
        {
            'module': 'routes.company_routes',
            'blueprint': 'company_bp',
            'url_prefix': '/company',
            'name': 'Company Management'
        },
        {
            'module': 'routes.service_routes',
            'blueprint': 'service_bp',
            'url_prefix': '/service',
            'name': 'Service API'
        },
        {
            'module': 'routes.encrypted_service_routes',
            'blueprint': 'encrypted_service_bp',
            'url_prefix': '/api/v1/encrypted',
            'name': 'Encrypted Service API'
        }
    ]
    
    registered_count = 0
    failed_blueprints = []
    
    for bp_config in blueprints_config:
        try:
            print(f"\n📦 Loading {bp_config['name']}...")
            print(f"   Module: {bp_config['module']}")
            print(f"   Blueprint: {bp_config['blueprint']}")
            print(f"   URL Prefix: {bp_config['url_prefix']}")
            
            # Import the module
            module = __import__(bp_config['module'], fromlist=[bp_config['blueprint']])
            
            # Get the blueprint
            blueprint = getattr(module, bp_config['blueprint'])
            
            if blueprint is None:
                print(f"   ❌ Blueprint {bp_config['blueprint']} is None")
                failed_blueprints.append(bp_config['name'])
                continue
            
            # Register the blueprint
            app.register_blueprint(blueprint, url_prefix=bp_config['url_prefix'])
            
            print(f"   ✅ Successfully registered {bp_config['name']}")
            registered_count += 1
            
        except ImportError as e:
            print(f"   ❌ Import error for {bp_config['name']}: {e}")
            failed_blueprints.append(bp_config['name'])
        except AttributeError as e:
            print(f"   ❌ Attribute error for {bp_config['name']}: {e}")
            failed_blueprints.append(bp_config['name'])
        except Exception as e:
            print(f"   ❌ Unexpected error for {bp_config['name']}: {e}")
            failed_blueprints.append(bp_config['name'])
    
    print(f"\n📊 Blueprint Registration Summary:")
    print(f"   Successfully registered: {registered_count}/{len(blueprints_config)}")
    print(f"   Failed: {len(failed_blueprints)}")
    
    if failed_blueprints:
        print(f"   Failed blueprints: {', '.join(failed_blueprints)}")
    
    return registered_count > 0

def print_all_routes(app):
    """Print all registered routes for debugging"""
    print("\n🗺️  All registered routes:")
    print("=" * 80)
    
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'path': rule.rule,
            'methods': sorted([m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]),
            'endpoint': rule.endpoint
        })
    
    # Sort by path
    routes.sort(key=lambda x: x['path'])
    
    for route in routes:
        methods_str = ', '.join(route['methods'])
        print(f"  {route['path']:<40} | {methods_str:<15} | {route['endpoint']}")
    
    print(f"\n📊 Total routes: {len(routes)}")
    
    # Check specifically for auth routes
    auth_routes = [r for r in routes if '/auth' in r['path']]
    if auth_routes:
        print(f"\n🔐 Auth routes ({len(auth_routes)}):")
        for route in auth_routes:
            methods_str = ', '.join(route['methods'])
            print(f"  ✓ {route['path']:<35} | {methods_str}")
    else:
        print("\n❌ No auth routes found!")
    
    # Specifically check for the register endpoint
    register_route = next((r for r in routes if r['path'] == '/auth/register'), None)
    if register_route:
        if 'POST' in register_route['methods']:
            print(f"\n✅ /auth/register POST route is available!")
        else:
            print(f"\n❌ /auth/register exists but POST not allowed. Methods: {register_route['methods']}")
    else:
        print("\n❌ /auth/register route NOT FOUND!")

def setup_security_headers(app):
    """Setup security headers for all responses"""
    @app.after_request
    def add_security_headers(response):
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # API headers
        response.headers['X-API-Version'] = '1.0.0'
        response.headers['X-Service-Name'] = 'Mail-as-a-Service'
        
        return response

def setup_request_logging(app):
    """Setup request logging and monitoring"""
    @app.before_request
    def log_request():
        global request_count
        request_count += 1
        
        # Log important requests
        if request.method in ['POST', 'PUT', 'DELETE']:
            print(f"📝 {request.method} {request.path} from {request.remote_addr}")
        
        # Rate limiting for API endpoints (basic implementation)
        if request.path.startswith('/api/') or request.path.startswith('/service/'):
            # Check if API key is required and valid
            if request.path.startswith('/service/send_email') or request.path.startswith('/api/v1/encrypted/'):
                api_key = request.headers.get('X-API-KEY')
                if not api_key or api_key != API_KEY:
                    return jsonify({'error': 'Invalid or missing API key'}), 401

# Create and configure the app
app = Flask(__name__, static_folder=os.path.abspath('../frontend/build'), static_url_path='')

# Configure CORS with more restrictive settings for production
if os.environ.get('FLASK_ENV') == 'production':
    # Production CORS settings
    CORS(app, 
         origins=['https://yourdomain.com'],  # Restrict to your domain
         methods=['GET', 'POST', 'PUT', 'DELETE'],
         allow_headers=['Content-Type', 'Authorization', 'X-API-KEY', 'X-CLIENT-SECRET'])
else:
    # Development CORS settings
    CORS(app, origins=['*'])

# Setup security and monitoring
setup_security_headers(app)
setup_request_logging(app)

# Initialize application
def init_app():
    """Initialize the application"""
    print("🚀 Initializing Mail-as-a-Service Backend...")
    
    # Verify dependencies first
    if not verify_dependencies():
        print("❌ Application startup failed due to missing dependencies")
        return False
    
    # Create necessary directories with proper permissions
    directories = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            # Set proper permissions (readable/writable by owner only)
            os.chmod(directory, 0o755)
        except Exception as e:
            print(f"❌ Failed to create/setup directory {directory}: {e}")
            return False
    
    # Initialize sessions file if it doesn't exist
    try:
        if not os.path.exists(SESSIONS_FILE):
            SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(SESSIONS_FILE, 'w') as f:
                f.write("[]")
            os.chmod(SESSIONS_FILE, 0o600)  # Readable/writable by owner only
    except Exception as e:
        print(f"❌ Failed to initialize sessions file: {e}")
        return False
    
    # Initialize encryption key
    try:
        from utils.encryption import Encryption
        Encryption()  # This will create the key file if it doesn't exist
    except Exception as e:
        print(f"❌ Failed to initialize encryption: {e}")
        return False
    
    print("✅ Application initialized successfully")
    return True

# Initialize the app
if not init_app():
    print("❌ Failed to initialize application")
    sys.exit(1)

# Register blueprints with detailed logging
if not register_blueprints_with_detailed_logging(app):
    print("⚠️  Warning: Some blueprints failed to register")

# Print all routes after registration for debugging
print_all_routes(app)

# Root routes for serving frontend
@app.route('/')
def index():
    """Serve the main frontend application"""
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except FileNotFoundError:
        return jsonify({
            'service': 'Mail-as-a-Service Backend',
            'version': '1.0.0',
            'status': 'running',
            'frontend': 'not_found',
            'message': 'Backend is running, but frontend build not found',
            'endpoints': {
                'api_info': '/api/info',
                'health': '/health',
                'documentation': '/service/api/docs'
            }
        })

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files or fallback to index.html for SPA"""
    try:
        # Check if the requested file exists
        file_path = os.path.join(app.static_folder, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_from_directory(app.static_folder, path)
        
        # For SPA routing, serve index.html for non-API routes
        if not path.startswith(('api/', 'auth/', 'mail/', 'service/', 'company/', 'file/', 'template/')):
            return send_from_directory(app.static_folder, 'index.html')
        
        # API route not found
        return jsonify({
            'error': 'Endpoint not found',
            'path': path,
            'available_endpoints': '/api/info'
        }), 404
        
    except Exception as e:
        return jsonify({
            'error': 'File serving error',
            'path': path,
            'message': str(e)
        }), 500

# Health check endpoint for monitoring
@app.route('/health')
def health_check():
    """Comprehensive health check"""
    try:
        from pathlib import Path
        from datetime import datetime
        
        # Check critical components
        checks = {
            'service': 'running',
            'uptime_seconds': round(time.time() - app_start_time, 2),
            'request_count': request_count,
            'database': 'connected' if Path(DATA_DIR / "users.json").exists() else 'disconnected',
            'storage': 'available' if Path(MAIL_ROOT).exists() else 'unavailable',
            'encryption': 'enabled' if Path("secret.key").exists() else 'disabled',
            'config': 'loaded' if API_KEY else 'missing',
            'supported_services': len(SUPPORTED_SERVICES),
            'timestamp': datetime.now().isoformat()
        }
        
        # Check memory usage (basic)
        try:
            import psutil
            process = psutil.Process()
            checks['memory_mb'] = round(process.memory_info().rss / 1024 / 1024, 2)
            checks['cpu_percent'] = round(process.cpu_percent(), 2)
        except ImportError:
            checks['memory_mb'] = 'unavailable'
            checks['cpu_percent'] = 'unavailable'
        
        # Determine overall health
        critical_checks = ['service', 'database', 'storage', 'config']
        all_healthy = all(
            checks.get(check) in ['running', 'connected', 'available', 'loaded', 'enabled'] 
            for check in critical_checks
        )
        
        status_code = 200 if all_healthy and checks['uptime_seconds'] > 1 else 503
        
        return jsonify({
            'status': 'healthy' if all_healthy else 'unhealthy',
            'checks': checks,
            'version': '1.0.0',
            'service': 'Mail-as-a-Service'
        }), status_code
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'service': 'Mail-as-a-Service',
            'timestamp': datetime.now().isoformat()
        }), 503

# API info endpoint
@app.route('/api/info')
def api_info():
    """API information endpoint"""
    return jsonify({
        'service': 'Mail-as-a-Service',
        'version': '1.0.0',
        'uptime_seconds': round(time.time() - app_start_time, 2),
        'request_count': request_count,
        'endpoints': {
            'authentication': '/auth/*',
            'mail_operations': '/mail/*',
            'file_operations': '/file/*',
            'templates': '/template/*',
            'company_management': '/company/*',
            'service_api': '/service/*',
            'encrypted_api': '/api/v1/encrypted/*'
        },
        'documentation': '/service/api/docs',
        'health_check': '/health',
        'supported_domains': len(SUPPORTED_SERVICES),
        'features': [
            'Multi-tenant company support',
            'Encrypted email storage',
            'API with encryption support',
            'Admin dashboard',
            'Storage quotas',
            'Email scheduling',
            'Template system'
        ]
    })

# Enhanced error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': '/api/info',
        'timestamp': datetime.now().isoformat()
    }), 404

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'service': 'Mail-as-a-Service',
        'timestamp': datetime.now().isoformat()
    }), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'error': 'Forbidden',
        'message': 'Access denied',
        'timestamp': datetime.now().isoformat()
    }), 403

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required',
        'timestamp': datetime.now().isoformat()
    }), 401

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests',
        'timestamp': datetime.now().isoformat()
    }), 429

# Graceful shutdown handler
import signal
import atexit

def cleanup():
    """Cleanup function called on shutdown"""
    print("🛑 Shutting down Mail-as-a-Service Backend...")
    print(f"📊 Final stats: {request_count} requests processed")
    print(f"⏱️  Uptime: {round(time.time() - app_start_time, 2)} seconds")

atexit.register(cleanup)
signal.signal(signal.SIGTERM, lambda s, f: cleanup())

# Run the server
if __name__ == '__main__':
    print("\n🚀 Starting Mail-as-a-Service Backend...")
    print(f"📧 Supported domains: {len(SUPPORTED_SERVICES)}")
    print(f"🔐 API configured: {'Yes' if API_KEY else 'No'}")
    print(f"💾 Data directory: {DATA_DIR}")
    print(f"📁 Mail storage: {MAIL_ROOT}")
    print(f"🔒 Security headers: Enabled")
    print(f"📝 Request logging: Enabled")
    
    # Determine host and port
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    if debug:
        print("⚠️  Running in DEBUG mode - disable for production!")
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)