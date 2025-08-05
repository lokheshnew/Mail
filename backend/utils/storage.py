import os
from config import MAIL_ROOT, MAX_STORAGE

def get_folder_size(path):
    """Calculate the total size of a folder in bytes"""
    return sum(os.path.getsize(os.path.join(dp, f))
               for dp, _, files in os.walk(path) for f in files)

def show_storage_status(email):
    """Get the storage status for a user"""
    folder = os.path.join(MAIL_ROOT, email)
    if not os.path.exists(folder):
        return {
            "used_mb": 0,
            "total_mb": MAX_STORAGE / (1024 * 1024),
            "percentage": 0,
            "status": "ok"
        }
    
    used = get_folder_size(folder)
    percent = (used / MAX_STORAGE) * 100
    
    return {
        "used_mb": round(used / (1024 * 1024), 2),
        "total_mb": MAX_STORAGE / (1024 * 1024),
        "percentage": round(percent, 2),
        "status": "full" if percent >= 100 else "warning" if percent >= 90 else "ok"
    }

def is_storage_full(email):
    """Check if a user's storage is full"""
    return show_storage_status(email)['status'] == 'full'