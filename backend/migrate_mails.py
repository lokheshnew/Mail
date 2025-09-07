import os
import json
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["mailapp"]

base_path = "mail_data"

for user_folder in os.listdir(base_path):
    user_path = os.path.join(base_path, user_folder)

    if os.path.isdir(user_path):
        # Go through drafts.json, inbox.json, etc.
        for file in os.listdir(user_path):
            if file.endswith(".json"):
                collection_name = file.replace(".json", "")  # drafts, inbox, sent, etc.
                file_path = os.path.join(user_path, file)

                with open(file_path, "r") as f:
                    try:
                        mails = json.load(f)
                    except Exception as e:
                        print(f"⚠️ Error reading {file_path}: {e}")
                        mails = []

                if isinstance(mails, list):
                    for mail in mails:
                        # Add owner for easy querying later
                        mail["owner"] = user_folder

                        # Ensure attachment format is consistent
                        if "attachment" in mail and mail["attachment"]:
                            att = mail["attachment"]

                            if isinstance(att, str):
                                mail["attachment"] = {
                                    "filename": "unknown",
                                    "content": att,
                                    "type": "base64"
                                }

                        # Insert into the correct collection
                        db[collection_name].insert_one(mail)

print("✅ Migration completed: All mails moved into their respective collections")
