import uuid
from datetime import datetime
from pymongo import MongoClient
from config import MONGO_URI, DB_NAME

# MongoDB client
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
sessions_collection = db["sessions"]


def load_sessions():
    """Load all sessions from MongoDB"""
    try:
        return list(sessions_collection.find({}, {"_id": 0}))
    except Exception as e:
        print(f"❌ Error loading sessions: {e}")
        return []


def save_sessions(sessions):
    """Replace all sessions in MongoDB (rarely needed)"""
    try:
        sessions_collection.delete_many({})
        if sessions:
            sessions_collection.insert_many(sessions)
        return True
    except Exception as e:
        print(f"❌ Error saving sessions: {e}")
        return False


def create_session(email):
    """Create a new session for a user"""
    try:
        token = str(uuid.uuid4())
        sessions_collection.insert_one({
            "email": email,
            "token": token,
            "created_at": datetime.utcnow().isoformat()
        })
        return token
    except Exception as e:
        print(f"❌ Error creating session: {e}")
        return None


def delete_session(token):
    """Delete a session by token"""
    try:
        sessions_collection.delete_one({"token": token})
    except Exception as e:
        print(f"❌ Error deleting session: {e}")


def get_email_from_token(token):
    """Get email from a session token"""
    try:
        session = sessions_collection.find_one({"token": token}, {"_id": 0, "email": 1})
        return session["email"] if session else None
    except Exception as e:
        print(f"❌ Error fetching email from token: {e}")
        return None


def validate_session(token):
    """Validate a session token"""
    email = get_email_from_token(token)
    return email is not None, email
