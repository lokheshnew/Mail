import os
from datetime import datetime
from flask import Blueprint, request, jsonify, send_from_directory
from utils.auth import verify_token
from config import UPLOAD_FOLDER
from urllib.parse import quote
import re

file_bp = Blueprint('file', __name__)

def sanitize_email_for_path(email):
    """Make email safe for file paths (replace @ and other unsafe chars)."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', email)

def get_user_from_request():
    """Get user email from JWT token in request headers"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, "Missing or invalid authorization header"
        
        token = auth_header.split(' ')[1]
        user_data = verify_token(token)
        if not user_data:
            return None, "Invalid or expired token"
        
        return user_data.get('email'), None
    except Exception as e:
        return None, f"Token verification failed: {str(e)}"

@file_bp.route('/attachments/<filename>', methods=['GET'])
def get_attachment(filename):
    return send_from_directory(
        UPLOAD_FOLDER, 
        filename, 
        as_attachment=True, 
        download_name=filename.split("_", 1)[1] if "_" in filename else filename
    )

@file_bp.route('/upload', methods=['POST'])
def upload_file():
    try:
        user_email, error = get_user_from_request()
        if error:
            return jsonify({"error": error}), 401
        
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']   # <-- FIX: Get the file object
        
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        safe_email = sanitize_email_for_path(user_email)
        upload_folder = os.path.join(UPLOAD_FOLDER, safe_email)
        os.makedirs(upload_folder, exist_ok=True)

        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        file_url = f"/uploads/{quote(safe_email)}/{filename}"
        return jsonify({"url": file_url})
    except Exception as e:
        return jsonify({"error": f"File upload failed: {str(e)}"}), 500

@file_bp.route('/uploads/<path:email>/<filename>')
def serve_uploaded_file(email, filename):
    try:
        safe_email = sanitize_email_for_path(email)
        upload_folder = os.path.join(UPLOAD_FOLDER, safe_email)
        return send_from_directory(upload_folder, filename)
    except Exception as e:
        return jsonify({"error": "File not found"}), 404
