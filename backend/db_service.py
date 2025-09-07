from pymongo import MongoClient

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Create/use database
db = client["mailapp"]

# Define collections
users_col = db["users"]
sessions_col = db["sessions"]
companies_col = db["companies"]
messages_col = db["messages"]
