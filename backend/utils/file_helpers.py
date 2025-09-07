from pymongo import MongoClient
from config import MONGO_URI, DB_NAME

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Email collections
EMAIL_COLLECTIONS = ["inbox", "sent", "drafts", "templates", "scheduled"]

def setup_user_collections(email):
    """
    MongoDB doesn't need folders per user.
    This function ensures user exists in the database if needed.
    """
    from models.user import get_user_by_email
    user = get_user_by_email(email)
    if not user:
        raise ValueError(f"User {email} does not exist")
    # No collections creation needed; MongoDB creates collections dynamically
    return True

def setup_user_inbox(email):
    """Backward compatibility function"""
    return setup_user_collections(email)

def read_mail_collection(email, collection_name):
    """Read all emails for a user from a specific MongoDB collection"""
    if collection_name not in EMAIL_COLLECTIONS:
        raise ValueError(f"Invalid collection name: {collection_name}")
    col = db[collection_name]
    try:
        emails = list(col.find({"owner": email}, {"_id": 0}))
        return emails
    except Exception as e:
        print(f"Error reading {collection_name} for {email}: {e}")
        return []

def save_mail_collection(email, collection_name, data):
    """
    Save data to a MongoDB email collection for a user.
    Overwrites all previous emails in that collection for the user.
    """
    if collection_name not in EMAIL_COLLECTIONS:
        raise ValueError(f"Invalid collection name: {collection_name}")
    
    col = db[collection_name]
    try:
        # Remove existing emails for this user in this collection
        col.delete_many({"owner": email})
        if data:
            # Ensure each email has 'owner' field
            for email_doc in data:
                email_doc["owner"] = email
            col.insert_many(data)
        return True
    except Exception as e:
        print(f"Error saving {collection_name} for {email}: {e}")
        return False
