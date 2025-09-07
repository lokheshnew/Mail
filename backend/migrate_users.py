import json
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["mailapp"]
users_col = db["users"]

# Load JSON file
with open("users.json", "r") as f:
    data = json.load(f)

# Transform and insert
for email, user_data in data.items():
    users_col.insert_one(user_data)

print("Users migrated successfully!")
