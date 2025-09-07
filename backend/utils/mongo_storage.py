from pymongo import MongoClient

# MongoDB client and collections
client = MongoClient("mongodb://localhost:27017")
db = client['mailapp']

users_collection = db['users']
emails_collection = db['emails']

def get_user_storage(email):
    """Calculate total emails and storage used by a single user"""
    if not email:
        return {'total_emails': 0, 'storage_used_mb': 0}

    # Count total emails sent or received
    total_emails = emails_collection.count_documents({
        "$or": [{"from": email}, {"to": email}]
    })

    # Sum storage used
    pipeline = [
        {"$match": {"$or": [{"from": email}, {"to": email}]}},
        {"$group": {"_id": None, "total_size": {"$sum": "$attachment_size_mb"}}}
    ]
    result = list(emails_collection.aggregate(pipeline))
    total_storage_mb = result[0]["total_size"] if result else 0

    return {
        'email': email,
        'total_emails': total_emails,
        'storage_used_mb': round(total_storage_mb, 2)
    }

def get_domain_storage(domain):
    """Calculate total emails and storage used by all users in a domain"""
    if not domain:
        return {
            'total_users': 0,
            'active_users': 0,
            'total_emails': 0,
            'storage_used': {'used_mb': 0, 'total_mb': 0, 'percentage': 0}
        }

    users = list(users_collection.find({"domain": domain}))
    total_users = len(users)
    active_users = sum(1 for u in users if u.get('status') == 'active')

    if total_users == 0:
        return {
            'total_users': 0,
            'active_users': 0,
            'total_emails': 0,
            'storage_used': {'used_mb': 0, 'total_mb': 0, 'percentage': 0}
        }

    user_emails = [u.get('email') for u in users if u.get('email')]

    # Count emails sent/received by these users
    total_emails = emails_collection.count_documents({
        "$or": [{"from": {"$in": user_emails}}, {"to": {"$in": user_emails}}]
    })

    # Calculate total storage
    pipeline = [
        {"$match": {"$or": [{"from": {"$in": user_emails}}, {"to": {"$in": user_emails}}]}},
        {"$group": {"_id": None, "total_size": {"$sum": "$attachment_size_mb"}}}
    ]
    result = list(emails_collection.aggregate(pipeline))
    total_storage_mb = result[0]["total_size"] if result else 0

    # Max storage per user: 8 MB
    storage_used = {
        'used_mb': round(total_storage_mb, 2),
        'total_mb': total_users * 8,
        'percentage': round((total_storage_mb / max(total_users * 8, 1)) * 100, 2)
    }

    return {
        'total_users': total_users,
        'active_users': active_users,
        'total_emails': total_emails,
        'storage_used': storage_used,
        'domain': domain
    }
