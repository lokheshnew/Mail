from flask import Blueprint, request, jsonify
from services.template_service import TemplateService
from models.session import get_email_from_token

template_bp = Blueprint('template', __name__)

@template_bp.route('/templates/<email>', methods=['GET'])
def get_templates(email):
    templates, error = TemplateService.get_templates(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"templates": templates})

@template_bp.route('/save_template', methods=['POST'])
def save_template():
    data = request.json
    token = data.get('token')
    email = get_email_from_token(token)
    if not email:
        return jsonify({"error": "Invalid session"}), 401
    
    name = data.get('name')
    subject = data.get('subject')
    body = data.get('body')
    
    success, error = TemplateService.save_template(email, name, subject, body)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Template saved successfully"})