import os
import sys
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from config import MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER, SESSIONS_FILE, API_KEY, SUPPORTED_SERVICES
from datetime import datetime
import time
import signal
import atexit
from utils.json_cache import patch_user_functions
app_start_time = time.time()
request_count = 0

def verify_dependencies():
    issues = []
    
    if sys.version_info < (3, 7):
        issues.append("Python 3.7 or higher is required")
    
    required_dirs = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create directory {dir_path}: {e}")
    
    required_packages = {
        'flask': 'flask',
        'flask_cors': 'flask-cors', 
        'cryptography': 'cryptography',
        'jwt': 'PyJWT'
    }
    
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            issues.append(f"Missing package: {package_name} (install with: pip install {package_name})")
    
    if not API_KEY or len(API_KEY) < 32:
        issues.append("API_KEY not configured or too short")
    
    if not SUPPORTED_SERVICES:
        issues.append("No supported services configured")
    
    try:
        test_file = DATA_DIR / "test_permissions.tmp"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
    except Exception as e:
        issues.append(f"File permission issues in {DATA_DIR}: {e}")
    
    return len(issues) == 0

def register_blueprints_with_detailed_logging(app):
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
        }
        ,
                {
            'module': 'routes.oauth_routes',
            'blueprint': 'oauth_bp',
            'url_prefix': '/oauth',
            'name': 'Oauth'
        }
        ,
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
    
    for bp_config in blueprints_config:
        try:
            module = __import__(bp_config['module'], fromlist=[bp_config['blueprint']])
            blueprint = getattr(module, bp_config['blueprint'])
            
            if blueprint is None:
                continue
            
            app.register_blueprint(blueprint, url_prefix=bp_config['url_prefix'])
            registered_count += 1
            
        except (ImportError, AttributeError, Exception):
            continue
    
    return registered_count > 0

def print_all_routes(app):
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'path': rule.rule,
            'methods': sorted([m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]),
            'endpoint': rule.endpoint
        })
    
    routes.sort(key=lambda x: x['path'])
    return routes

def setup_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-API-Version'] = '1.0.0'
        response.headers['X-Service-Name'] = 'Mail-as-a-Service'
        return response

def setup_request_logging(app):
    @app.before_request
    def log_request():
        global request_count
        request_count += 1
        
        if request.path.startswith('/service/send_email') or request.path.startswith('/api/v1/encrypted/'):
            api_key = request.headers.get('X-API-KEY')
            if not api_key or api_key != API_KEY:
                return jsonify({'error': 'Invalid or missing API key'}), 401

app = Flask(__name__, static_folder=os.path.abspath('../frontend/build'), static_url_path='')

if os.environ.get('FLASK_ENV') == 'production':
    CORS(app, 
         origins=['https://yourdomain.com'],
         methods=['GET', 'POST', 'PUT', 'DELETE'],
         allow_headers=['Content-Type', 'Authorization', 'X-API-KEY', 'X-CLIENT-SECRET'])
else:
    CORS(app, origins=['*'])

setup_security_headers(app)
setup_request_logging(app)

def init_app():
    if not verify_dependencies():
        return False
    
    directories = [MAIL_ROOT, DATA_DIR, UPLOAD_FOLDER]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o755)
        except Exception:
            return False
    
    try:
        if not os.path.exists(SESSIONS_FILE):
            SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(SESSIONS_FILE, 'w') as f:
                f.write("[]")
            os.chmod(SESSIONS_FILE, 0o600)
    except Exception:
        return False
    
    try:
        from utils.encryption import Encryption
        Encryption()
    except Exception:
        return False
    patch_user_functions()
    print("✓ High-performance caching enabled")
    return True

if not init_app():
    sys.exit(1)

if not register_blueprints_with_detailed_logging(app):
    pass

print_all_routes(app)

@app.route('/')
def index():
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
    try:
        file_path = os.path.join(app.static_folder, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_from_directory(app.static_folder, path)
        
        if not path.startswith(('api/', 'auth/', 'mail/', 'service/', 'company/', 'file/', 'template/')):
            return send_from_directory(app.static_folder, 'index.html')
        
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

@app.route('/health')
def health_check():
    try:
        from pathlib import Path
        
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
        
        try:
            import psutil
            process = psutil.Process()
            checks['memory_mb'] = round(process.memory_info().rss / 1024 / 1024, 2)
            checks['cpu_percent'] = round(process.cpu_percent(), 2)
        except ImportError:
            checks['memory_mb'] = 'unavailable'
            checks['cpu_percent'] = 'unavailable'
        
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

@app.route('/api/info')
def api_info():
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

def cleanup():
    pass

atexit.register(cleanup)
signal.signal(signal.SIGTERM, lambda s, f: cleanup())

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.exit(1)