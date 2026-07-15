import sqlite3
import uuid
import bcrypt
import os

db_path = "data/mirage.db"
os.makedirs("data", exist_ok=True)

conn = sqlite3.connect(db_path)
c = conn.cursor()

uid = str(uuid.uuid4())
pw_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt(12)).decode()

c.execute(
    "INSERT OR REPLACE INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
    (uid, "admin", pw_hash, "admin"),
)

inv = str(uuid.uuid4())[:12]
c.execute(
    "INSERT OR REPLACE INTO invite_codes (code, role, max_uses, used_count) VALUES (?, ?, ?, ?)",
    (inv, "admin", 100, 0),
)

conn.commit()
conn.close()
print(f"ADMIN CREATED: admin / admin123")
print(f"INVITE CODE: {inv}")
