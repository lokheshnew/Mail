from datetime import datetime
from utils.file_helpers import read_mail_file, save_mail_file
from models.user import load_users

class TemplateService:
    @staticmethod
    def get_templates(email):
        """Get a user's templates"""
        users = load_users()
        if email not in users:
            return None, "User not found"
            
        templates = read_mail_file(email, 'templates')
        return templates, None
    
    @staticmethod
    def save_template(email, name, subject, body):
        """Save a template"""
        users = load_users()
        if email not in users:
            return False, "User not found"
        
        template = {
            'name': name,
            'subject': subject,
            'body': body,
            'created_at': datetime.now().isoformat()
        }
        
        templates = read_mail_file(email, 'templates')
        templates.append(template)
        
        if save_mail_file(email, 'templates', templates):
            return True, None
        else:
            return False, "Failed to save template"
    
    @staticmethod
    def delete_template(email, template_name):
        """Delete a template"""
        templates = read_mail_file(email, 'templates')
        
        updated_templates = [t for t in templates if t.get('name') != template_name]
        
        if len(templates) == len(updated_templates):
            return False, "Template not found"
        
        if save_mail_file(email, 'templates', updated_templates):
            return True, None
        else:
            return False, "Failed to delete template"