from flask import Blueprint, request, jsonify
from services.mail_service import MailService
from models.user import load_users
from utils.storage import show_storage_status
from utils.auth import verify_token

mail_bp = Blueprint('mail', __name__)

def get_user_from_request():
    """Get user email from JWT token in request headers"""
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, "Missing or invalid authorization header"
        
        token = auth_header.split(' ')[1]
        
        # Verify JWT token
        user_data = verify_token(token)
        if not user_data:
            return None, "Invalid or expired token"
        
        return user_data.get('email'), None
        
    except Exception as e:
        return None, f"Token verification failed: {str(e)}"

@mail_bp.route('/inbox/<email>', methods=['GET'])
def view_inbox(email):
    # Verify user has access to this email
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    inbox, error = MailService.get_inbox(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"inbox": inbox})

@mail_bp.route('/sent/<email>', methods=['GET'])
def view_sent(email):
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    sent, error = MailService.get_sent(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"sent": sent})

@mail_bp.route('/drafts/<email>', methods=['GET'])
def view_drafts(email):
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    drafts, error = MailService.get_drafts(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"drafts": drafts})

@mail_bp.route('/trash/<email>', methods=['GET'])
def view_trash(email):
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    trash, error = MailService.get_trash(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"trash": trash})

@mail_bp.route('/storage/<email>', methods=['GET'])
def get_storage_info(email):
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    users = load_users()
    if email not in users:
        return jsonify({"error": "User not found"}), 404
    
    try:
        storage_info = show_storage_status(email)
        
        storage_data = {
            "used_mb": storage_info.get("used_mb", 0),
            "total_mb": storage_info.get("total_mb", 8),
            "percentage": storage_info.get("percentage", 0),
            "status": storage_info.get("status", "ok")
        }
        
        return jsonify(storage_data)
    except Exception as e:
        return jsonify({"error": "Failed to get storage info"}), 500

@mail_bp.route('/search', methods=['POST'])
def search_emails():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    query = data.get('query', '')
    folder = data.get('folder', 'inbox')
    
    results, error = MailService.search_emails(user_email, query, folder)
    if error:
        return jsonify({"error": error}), 500
    
    return jsonify({"results": results})

@mail_bp.route('/send', methods=['POST'])
def send_mail():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    recipient = data.get('to')
    subject = data.get('subject')
    body = data.get('body')
    attachment = data.get('attachment')
    
    success, error = MailService.send_mail(user_email, recipient, subject, body, attachment)
    if not success:
        return jsonify({"error": error}), 400
    
    return jsonify({"message": "Email sent successfully"})

@mail_bp.route('/schedule', methods=['POST'])
def schedule_email():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    recipient = data.get('to')
    subject = data.get('subject')
    body = data.get('body')
    scheduled_time = data.get('scheduleTime')
    attachment = data.get('attachment')
    
    if not scheduled_time:
        return jsonify({"error": "Scheduled time is required"}), 400
    
    success, error = MailService.schedule_mail(user_email, recipient, subject, body, scheduled_time, attachment)
    if not success:
        return jsonify({"error": error}), 400
    
    return jsonify({"message": "Email scheduled successfully"})

@mail_bp.route('/scheduled', methods=['GET'])
def fetch_scheduled_emails():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    scheduled, error = MailService.get_scheduled(user_email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"scheduled": scheduled})

@mail_bp.route('/bulk_action', methods=['POST'])
def bulk_action():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    action = data.get('action')
    emails = data.get('emails')
    folder = data.get('folder', 'inbox')
    
    updated_count, error = MailService.bulk_action(user_email, action, emails, folder)
    if error:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": f"Bulk action completed on {updated_count} emails"})

@mail_bp.route('/delete_mail', methods=['POST'])
def delete_mail():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('mail')
    active = data.get('activeTab')
    
    if not target_fields:
        return jsonify({"error": "Missing mail data"}), 400
    
    success, error = MailService.delete_mail(user_email, target_fields, active)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({
        "message_status": "deleted",
        "message": "Deleted successfully"
    }), 200

@mail_bp.route('/mark_read', methods=['POST'])
def mark_read():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('mail')
    active = data.get('activeTab', 'inbox')
    
    success, error = MailService.mark_read(user_email, target_fields, active)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Email marked as read"})

@mail_bp.route('/mark_unread', methods=['POST'])
def mark_unread():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('mail')
    active = data.get('activeTab', 'inbox')
    
    success, error = MailService.mark_unread(user_email, target_fields, active)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Email marked as unread"})

@mail_bp.route('/save_draft', methods=['POST'])
def save_draft():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    recipient = data.get('to', '')
    subject = data.get('subject', '')
    body = data.get('body', '')
    attachment = data.get('attachment')
    
    success, error = MailService.save_draft(user_email, recipient, subject, body, attachment)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Draft saved successfully"})

@mail_bp.route('/delete_draft', methods=['POST'])
def delete_draft():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('draft')
    
    success, error = MailService.permanent_delete(user_email, target_fields, 'drafts')
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Draft deleted successfully"})

@mail_bp.route('/permanent_delete', methods=['POST'])
def permanent_delete():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('mail')
    original_folder = target_fields.get('original_folder', 'inbox')
    
    success, error = MailService.permanent_delete(user_email, target_fields, original_folder)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Email permanently deleted"})

@mail_bp.route('/restore_email', methods=['POST'])
def restore_email():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    data = request.json
    target_fields = data.get('mail')
    original_folder = target_fields.get('original_folder', 'inbox')
    
    success, error = MailService.restore_email(user_email, target_fields, original_folder)
    if not success:
        return jsonify({"error": error}), 500
    
    return jsonify({"message": "Email restored successfully"})

@mail_bp.route('/stats/<email>', methods=['GET'])
def get_email_stats(email):
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    if user_email != email:
        return jsonify({"error": "Access denied"}), 403
    
    stats, error = MailService.get_stats(email)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify(stats)

@mail_bp.route('/recipients', methods=['GET'])
def get_recipients():
    user_email, error = get_user_from_request()
    if error:
        return jsonify({"error": error}), 401
    
    try:
        users = load_users()
        recipient_list = list(users.keys())
        return jsonify({"recipients": recipient_list})
    except Exception as e:
        return jsonify({"error": "Failed to fetch recipients"}), 500