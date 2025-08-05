import os
import json
from config import MAIL_ROOT

def setup_user_folders(email):
    """Create user folders and default JSON files"""
    user_folder = os.path.join(MAIL_ROOT, email)
    folders = ['inbox.json', 'sent.json', 'drafts.json', 'templates.json', 'scheduled.json']
    
    os.makedirs(user_folder, exist_ok=True)
    
    for folder in folders:
        folder_path = os.path.join(user_folder, folder)
        if not os.path.exists(folder_path):
            with open(folder_path, 'w') as f:
                json.dump([], f)

def setup_user_inbox(email):
    """Backward compatibility function"""
    setup_user_folders(email)

def read_mail_file(email, file_type):
    """Read a mail file from the user's folder"""
    file_path = os.path.join(MAIL_ROOT, email, f'{file_type}.json')
    
    if not os.path.exists(file_path):
        return []
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def save_mail_file(email, file_type, data):
    """Save data to a mail file in the user's folder"""
    file_path = os.path.join(MAIL_ROOT, email, f'{file_type}.json')
    
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False