from datetime import datetime,timedelta
from utils.encryption import Encryption
from utils.file_helpers import read_mail_file, save_mail_file,setup_user_folders
from utils.storage import is_storage_full
from models.user import load_users
import os
import json
from config import TRASH_EXPIRY_HOURS
import base64


class MailService:
    @staticmethod
    def decrypt_emails(emails):
        """Decrypt a list of emails with fallback support"""
        encryption = Encryption()
        decrypted_emails = []
        
        for mail in emails:
            try:
                # Try new AES-GCM format first
                if isinstance(mail.get('body'), dict) and 'ciphertext' in mail.get('body', {}):
                    decrypted_body = encryption.decrypt_aes_gcm(mail['body'])
                else:
                    # Fall back to legacy Fernet encryption
                    decrypted_body = encryption.decrypt(mail['body'])
            except Exception as e:
                print(f"Decryption error for email: {e}")
                decrypted_body = "[Failed to decrypt]"
                
            mail_copy = mail.copy()
            mail_copy['body'] = decrypted_body
            decrypted_emails.append(mail_copy)
            
        return decrypted_emails
    
    @staticmethod
    def get_inbox(email):
        """Get a user's inbox"""
        users = load_users()
        if email not in users:
            return None, "User not found"
            
        inbox = read_mail_file(email, 'inbox')
        return MailService.decrypt_emails(inbox), None
    
    @staticmethod
    def get_sent(email):
        """Get a user's sent folder"""
        users = load_users()
        if email not in users:
            return None, "User not found"
            
        sent = read_mail_file(email, 'sent')
        return MailService.decrypt_emails(sent), None
    
    @staticmethod
    def get_drafts(email):
        """Get a user's drafts folder"""
        users = load_users()
        if email not in users:
            return None, "User not found"
            
        drafts = read_mail_file(email, 'drafts')
        return MailService.decrypt_emails(drafts), None
    
    @staticmethod
    def get_scheduled(email):
        """Get a user's scheduled emails"""
        users = load_users()
        if email not in users:
            return None, "User not found"
            
        scheduled = read_mail_file(email, 'scheduled')
        return MailService.decrypt_emails(scheduled), None
    
    @staticmethod
    def get_trash(email):
        """Get a user's trash folder"""
        users = load_users()
        if email not in users:
            return None, "User not found"
        
        deleted_emails = []
        
        try:
            # Check inbox for deleted emails
            inbox = read_mail_file(email, 'inbox')
            for mail in inbox:
                if mail.get('message_status') == 'deleted':
                    mail_copy = mail.copy()
                    mail_copy['original_folder'] = 'inbox'
                    deleted_emails.append(mail_copy)
            
            # Check sent folder for deleted emails
            sent = read_mail_file(email, 'sent')
            for mail in sent:
                if mail.get('message_status') == 'deleted':
                    mail_copy = mail.copy()
                    mail_copy['original_folder'] = 'sent'
                    deleted_emails.append(mail_copy)
            
            # Check scheduled for deleted emails
            scheduled = read_mail_file(email, 'scheduled')
            for mail in scheduled:
                if mail.get('message_status') == 'deleted':
                    mail_copy = mail.copy()
                    mail_copy['original_folder'] = 'scheduled'
                    deleted_emails.append(mail_copy)
        except Exception as e:
            print(f"Error reading folders for trash: {e}")
            return [], f"Error reading trash: {str(e)}"
        
        return MailService.decrypt_emails(deleted_emails), None
    
    @staticmethod
    def send_mail(sender, recipient, subject, body, attachment=None):
        """Send mail with improved attachment handling for both frontend and API"""
        try:
            # Setup folders for both sender and recipient
            setup_user_folders(sender)
            setup_user_folders(recipient)
            
            # Encrypt body - FIXED: This was missing in the original new version
            encryption = Encryption()
            encrypted_body = encryption.encrypt(body or "")
            
            # Prepare email data
            email_data = {
                "from": sender,
                "to": recipient, 
                "subject": subject,
                "body": encrypted_body,  # Store encrypted body
                "date_of_send": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message_status": "unread",
                "message_id": f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{sender.split('@')[0]}_to_{recipient.split('@')[0]}"
            }
            
            # Handle different attachment formats
            if attachment:
                processed_attachment = MailService._process_attachment(attachment)
                if processed_attachment:
                    email_data["attachment"] = processed_attachment
            
            # Add to sender's sent folder
            sent_emails = read_mail_file(sender, 'sent')
            sent_emails.append(email_data.copy())
            save_mail_file(sender, 'sent', sent_emails)
            
            # Add to recipient's inbox
            inbox_emails = read_mail_file(recipient, 'inbox')
            inbox_emails.append(email_data.copy())
            save_mail_file(recipient, 'inbox', inbox_emails)
            
            return True, None
            
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"
    
    @staticmethod
    def _process_attachment(attachment):
        """Process attachment for different input formats"""
        try:
            if not attachment:
                return None
            
            # Case 1: Base64 object from API (like your Postman request)
            if isinstance(attachment, dict) and 'content' in attachment and 'filename' in attachment:
                return {
                    "filename": attachment['filename'],
                    "content": attachment['content'],  # Already base64 encoded
                    "type": "base64"
                }
            
            # Case 2: File URL/path from frontend upload
            elif isinstance(attachment, str):
                # Check if it's a file path/URL
                if attachment.startswith('/') or 'uploads' in attachment:
                    # Try to read the file and convert to base64
                    file_content = MailService._file_to_base64(attachment)
                    if file_content:
                        # Extract filename from path
                        filename = attachment.split('/')[-1]
                        # Remove timestamp prefix if present (format: YYYYMMDD_HHMMSS_filename)
                        if '_' in filename:
                            parts = filename.split('_')
                            if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                                filename = '_'.join(parts[2:])
                        
                        return {
                            "filename": filename,
                            "content": file_content,
                            "type": "base64",
                            "original_path": attachment  # Keep original path for reference
                        }
                    else:
                        # If file reading fails, store as path reference
                        return {
                            "filename": attachment.split('/')[-1],
                            "path": attachment,
                            "type": "path"
                        }
                else:
                    # Direct base64 string
                    return {
                        "filename": "attachment",
                        "content": attachment,
                        "type": "base64"
                    }
            
            return None
            
        except Exception as e:
            print(f"Error processing attachment: {e}")
            return None
    
    @staticmethod
    def _file_to_base64(file_path):
        """Convert file to base64 string"""
        try:
            # Handle different path formats
            if file_path.startswith('/uploads/'):
                # Remove leading slash and construct full path
                from config import UPLOAD_FOLDER
                actual_path = os.path.join(UPLOAD_FOLDER, file_path[9:])  # Remove '/uploads/'
            elif file_path.startswith('uploads/'):
                from config import UPLOAD_FOLDER
                actual_path = os.path.join(UPLOAD_FOLDER, file_path[8:])  # Remove 'uploads/'
            else:
                actual_path = file_path
            
            # Read file and encode to base64
            if os.path.exists(actual_path):
                with open(actual_path, 'rb') as f:
                    file_content = f.read()
                return base64.b64encode(file_content).decode('utf-8')
            else:
                print(f"File not found: {actual_path}")
                return None
                
        except Exception as e:
            print(f"Error converting file to base64: {e}")
            return None

    
    @staticmethod
    def schedule_mail(sender, recipient, subject, body, scheduled_time, attachment=None):
        """Schedule an email to be sent later"""
        # Input validation
        if not sender or not recipient:
            return False, "Sender and recipient are required"
        
        if not scheduled_time:
            return False, "Scheduled time is required"
        
        users = load_users()
        
        # Check if sender and recipient exist
        if sender not in users or recipient not in users:
            return False, "Sender or recipient not found"
        
        # Check storage limits
        if is_storage_full(sender):
            return False, "Storage limit exceeded"
        
        try:
            # Encrypt body
            encryption = Encryption()
            encrypted_body = encryption.encrypt(body or "")
            
            now = datetime.now().isoformat()
            
            # Create mail object
            mail = {
                'from': sender,
                'to': recipient,
                'subject': subject or "",
                'body': encrypted_body,
                'date_of_compose': now,
                'date_of_send': scheduled_time,
                'message_status': 'scheduled',
                'attachment': attachment
            }
            
            # Add to sender's scheduled folder
            scheduled = read_mail_file(sender, 'scheduled')
            scheduled.append(mail)
            if not save_mail_file(sender, 'scheduled', scheduled):
                return False, "Failed to schedule email"
            
            return True, None
            
        except Exception as e:
            print(f"Error scheduling email: {e}")
            return False, f"Error scheduling email: {str(e)}"
    
    @staticmethod
    def save_draft(sender, recipient, subject, body, attachment=None):
        """Save a draft email"""
        try:
            # Encrypt body
            encryption = Encryption()
            encrypted_body = encryption.encrypt(body or "")
            
            now = datetime.now().isoformat()
            
            # Create draft object
            draft = {
                'from': sender,
                'to': recipient or "",
                'subject': subject or "",
                'body': encrypted_body,
                'date_of_compose': now,
                'message_status': 'draft',
                'attachment': attachment
            }
            
            # Add to drafts folder
            drafts = read_mail_file(sender, 'drafts')
            drafts.append(draft)
            if not save_mail_file(sender, 'drafts', drafts):
                return False, "Failed to save draft"
            
            return True, None
            
        except Exception as e:
            print(f"Error saving draft: {e}")
            return False, f"Error saving draft: {str(e)}"
    
    @staticmethod
    def delete_mail(email, mail_data, folder):
        """Mark an email as deleted"""
        try:
            mails = read_mail_file(email, folder)
            found = False
            
            for mail in mails:
                if (mail.get('from') == mail_data.get('from') and
                    mail.get('to') == mail_data.get('to') and
                    mail.get('subject') == mail_data.get('subject') and
                    mail.get('date_of_send') == mail_data.get('date_of_send')):
                    
                    mail['message_status'] = 'deleted'
                    found = True
                    break
            
            if not found:
                return False, "Mail not found"
            
            if save_mail_file(email, folder, mails):
                return True, None
            else:
                return False, "Failed to save changes"
                
        except Exception as e:
            print(f"Error deleting mail: {e}")
            return False, f"Error deleting mail: {str(e)}"
    
    @staticmethod
    def mark_read(email, mail_data, folder):
        """Mark an email as read"""
        try:
            mails = read_mail_file(email, folder)
            found = False
            
            for mail in mails:
                if (mail.get('from') == mail_data.get('from') and
                    mail.get('to') == mail_data.get('to') and
                    mail.get('subject') == mail_data.get('subject') and
                    mail.get('date_of_send') == mail_data.get('date_of_send')):
                    
                    mail['message_status'] = 'read'
                    found = True
                    break
            
            if not found:
                return False, "Mail not found"
            
            if save_mail_file(email, folder, mails):
                return True, None
            else:
                return False, "Failed to save changes"
                
        except Exception as e:
            print(f"Error marking read: {e}")
            return False, f"Error marking read: {str(e)}"
    
    @staticmethod
    def mark_unread(email, mail_data, folder):
        """Mark an email as unread"""
        try:
            mails = read_mail_file(email, folder)
            found = False
            
            for mail in mails:
                if (mail.get('from') == mail_data.get('from') and
                    mail.get('to') == mail_data.get('to') and
                    mail.get('subject') == mail_data.get('subject') and
                    mail.get('date_of_send') == mail_data.get('date_of_send')):
                    
                    mail['message_status'] = 'unread'
                    found = True
                    break
            
            if not found:
                return False, "Mail not found"
            
            if save_mail_file(email, folder, mails):
                return True, None
            else:
                return False, "Failed to save changes"
                
        except Exception as e:
            print(f"Error marking unread: {e}")
            return False, f"Error marking unread: {str(e)}"
    
    @staticmethod
    def permanent_delete(email, mail_data, original_folder):
        """Permanently delete an email"""
        try:
            mails = read_mail_file(email, original_folder)
            
            updated_mails = [
                mail for mail in mails
                if not (
                    mail.get('from') == mail_data.get('from') and
                    mail.get('to') == mail_data.get('to') and
                    mail.get('subject') == mail_data.get('subject') and
                    mail.get('date_of_send') == mail_data.get('date_of_send')
                )
            ]
            
            if len(mails) == len(updated_mails):
                return False, "Mail not found"
            
            if save_mail_file(email, original_folder, updated_mails):
                return True, None
            else:
                return False, "Failed to save changes"
                
        except Exception as e:
            print(f"Error permanently deleting: {e}")
            return False, f"Error permanently deleting: {str(e)}"
    
    @staticmethod
    def restore_email(email, mail_data, original_folder):
        """Restore a deleted email"""
        try:
            mails = read_mail_file(email, original_folder)
            found = False
            
            for mail in mails:
                if (mail.get('from') == mail_data.get('from') and
                    mail.get('to') == mail_data.get('to') and
                    mail.get('subject') == mail_data.get('subject') and
                    mail.get('date_of_send') == mail_data.get('date_of_send')):
                    
                    mail['message_status'] = 'unread'
                    found = True
                    break
            
            if not found:
                return False, "Mail not found"
            
            if save_mail_file(email, original_folder, mails):
                return True, None
            else:
                return False, "Failed to save changes"
                
        except Exception as e:
            print(f"Error restoring email: {e}")
            return False, f"Error restoring email: {str(e)}"
    
    @staticmethod
    def search_emails(email, query, folder):
        """Search emails in a specific folder"""
        try:
            if not query:
                return [], None
            
            query = query.lower().strip()
            
            if folder == 'trash':
                trash_emails, _ = MailService.get_trash(email)
                if not trash_emails:
                    return [], None
                    
                results = []
                for mail in trash_emails:
                    if (query in mail.get('subject', '').lower() or
                        query in mail.get('from', '').lower() or
                        query in mail.get('body', '').lower()):
                        
                        results.append(mail)
                
                return results, None
            
            mails = read_mail_file(email, folder)
            encryption = Encryption()
            results = []
            
            for mail in mails:
                if mail.get('message_status') == 'deleted':
                    continue
                
                try:
                    decrypted_body = encryption.decrypt(mail['body'])
                except Exception:
                    decrypted_body = ""
                
                if (query in mail.get('subject', '').lower() or
                    query in mail.get('from', '').lower() or
                    query in decrypted_body.lower()):
                    
                    mail_copy = mail.copy()
                    mail_copy['body'] = decrypted_body
                    results.append(mail_copy)
            
            return results, None
            
        except Exception as e:
            print(f"Error searching emails: {e}")
            return [], f"Error searching emails: {str(e)}"
    
    @staticmethod
    def bulk_action(email, action, emails_list, folder):
        """Perform a bulk action on multiple emails"""
        try:
            if not emails_list:
                return 0, "No emails provided"
            
            mails = read_mail_file(email, folder)
            updated_count = 0
            
            for mail in mails:
                for target_email in emails_list:
                    if (mail.get('from') == target_email.get('from') and
                        mail.get('to') == target_email.get('to') and
                        mail.get('subject') == target_email.get('subject') and
                        mail.get('date_of_send') == target_email.get('date_of_send')):
                        
                        if action == 'delete':
                            mail['message_status'] = 'deleted'
                        elif action == 'mark_read':
                            mail['message_status'] = 'read'
                        elif action == 'mark_unread':
                            mail['message_status'] = 'unread'
                        
                        updated_count += 1
                        break
            
            if updated_count > 0:
                if save_mail_file(email, folder, mails):
                    return updated_count, None
                else:
                    return 0, "Failed to save changes"
            
            return 0, "No emails found to update"
            
        except Exception as e:
            print(f"Error in bulk action: {e}")
            return 0, f"Error in bulk action: {str(e)}"
    
    @staticmethod
    def get_stats(email):
        """Get email statistics for a user"""
        try:
            users = load_users()
            if email not in users:
                return None, "User not found"
            
            from utils.storage import show_storage_status
            
            stats = {
                "total_received": 0,
                "total_sent": 0,
                "unread_count": 0,
                "deleted_count": 0,
                "draft_count": 0,
                "storage_used": show_storage_status(email)
            }
            
            # Count inbox emails
            inbox = read_mail_file(email, 'inbox')
            stats["total_received"] = len([m for m in inbox if m.get('message_status') != 'deleted'])
            stats["unread_count"] = len([m for m in inbox if m.get('message_status') == 'unread'])
            stats["deleted_count"] += len([m for m in inbox if m.get('message_status') == 'deleted'])
            
            # Count sent emails
            sent = read_mail_file(email, 'sent')
            stats["total_sent"] = len([m for m in sent if m.get('message_status') != 'deleted'])
            stats["deleted_count"] += len([m for m in sent if m.get('message_status') == 'deleted'])
            
            # Count drafts
            drafts = read_mail_file(email, 'drafts')
            stats["draft_count"] = len(drafts)
            
            return stats, None
            
        except Exception as e:
            print(f"Error getting stats: {e}")
            return None, f"Error getting stats: {str(e)}"