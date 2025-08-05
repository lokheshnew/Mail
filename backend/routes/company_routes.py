from flask import Blueprint, request, jsonify
from models.company import (
    register_company, 
    is_domain_available, 
    get_company_by_domain,
    get_all_companies,
    get_company_stats,
    update_company_status,
    delete_company
)
from models.user import get_users_by_domain
from utils.auth import verify_token, admin_required, is_domain_admin

company_bp = Blueprint('company', __name__)

@company_bp.route('/check_domain', methods=['POST'])
def check_domain_availability():
    """Check if a domain is available for registration"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Clean and validate domain
        domain = domain.strip().lower()
        
        # Basic domain validation
        if '.' not in domain or len(domain.split('.')) < 2:
            return jsonify({'error': 'Invalid domain format'}), 400
        
        # Check for invalid characters
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$', domain):
            return jsonify({'error': 'Invalid domain format'}), 400
        
        available = is_domain_available(domain)
        
        return jsonify({
            'available': available,
            'domain': domain
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error checking domain: {str(e)}'}), 500

@company_bp.route('/register_company', methods=['POST'])
def register_new_company():
    """Register a new company"""
    try:
        data = request.get_json()
        company_name = data.get('company_name', '').strip()
        domain = data.get('domain', '').strip().lower()
        admin_name = data.get('admin_name', '').strip()
        
        # Validation
        if not all([company_name, domain, admin_name]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Additional validation
        if len(company_name) < 2:
            return jsonify({'error': 'Company name must be at least 2 characters'}), 400
        
        if len(admin_name) < 2:
            return jsonify({'error': 'Admin name must be at least 2 characters'}), 400
        
        # Register the company
        company, error = register_company(company_name, domain, admin_name)
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'message': 'Company registered successfully',
            'company': company
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@company_bp.route('/companies', methods=['GET'])
def get_companies():
    """Get all registered companies"""
    try:
        companies = get_all_companies()
        
        return jsonify({
            'companies': companies,
            'count': len(companies)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error fetching companies: {str(e)}'}), 500

@company_bp.route('/companies/<domain>', methods=['GET'])
def get_company_details(domain):
    """Get details for a specific company"""
    try:
        company = get_company_by_domain(domain)
        
        if not company:
            return jsonify({'error': 'Company not found'}), 404
        
        return jsonify({'company': company}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error fetching company: {str(e)}'}), 500

@company_bp.route('/domain_users/<domain>', methods=['GET'])
def get_domain_users(domain):
    """Get all users for a specific domain (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Admin authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Check if user is admin for this domain
        user_email = user_data.get('email')
        if not user_email or not is_domain_admin(user_email, domain):
            return jsonify({'error': 'Access denied. Admin privileges required for this domain.'}), 403
        
        # Get users for this domain
        users = get_users_by_domain(domain)
        
        return jsonify({
            'users': users,
            'domain': domain,
            'count': len(users)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error fetching domain users: {str(e)}'}), 500

@company_bp.route('/domain_stats/<domain>', methods=['GET'])
def get_domain_statistics(domain):
    """Get statistics for a domain (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Admin authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Check if user is admin for this domain
        user_email = user_data.get('email')
        if not user_email or not is_domain_admin(user_email, domain):
            return jsonify({'error': 'Access denied. Admin privileges required for this domain.'}), 403
        
        # Get domain statistics
        stats, error = get_company_stats(domain)
        
        if error:
            return jsonify({'error': error}), 500
        
        return jsonify({
            'stats': stats,
            'domain': domain
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error fetching domain stats: {str(e)}'}), 500
