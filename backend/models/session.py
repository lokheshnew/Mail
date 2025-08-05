import json
import uuid
from config import SESSIONS_FILE

def load_sessions():
    """Load sessions from the sessions file"""
    try:
        if not SESSIONS_FILE.exists():
            with open(SESSIONS_FILE, 'w') as f:
                json.dump([], f)
        with open(SESSIONS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def save_sessions(sessions):
    """Save sessions to the sessions file"""
    try:
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)
        return True
    except Exception:
        return False

def create_session(email):
    """Create a new session for a user"""
    sessions = load_sessions()
    token = str(uuid.uuid4())
    sessions.append({"email": email, "token": token})
    save_sessions(sessions)
    return token

def delete_session(token):
    """Delete a session"""
    sessions = load_sessions()
    sessions = [s for s in sessions if s['token'] != token]
    save_sessions(sessions)

def get_email_from_token(token):
    """Get email from a session token"""
    sessions = load_sessions()
    for session in sessions:
        if session['token'] == token:
            return session['email']
    return None

def validate_session(token):
    """Validate a session token"""
    email = get_email_from_token(token)
    return email is not None, email