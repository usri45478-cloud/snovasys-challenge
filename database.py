import sqlite3

DB_NAME = "trustvault.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    
    # Documents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        owner TEXT NOT NULL,
        category TEXT DEFAULT 'General',
        created_at TEXT NOT NULL
    )
    """)
    
    # Permissions table (Explicit per-document access grants)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        permission TEXT NOT NULL,
        FOREIGN KEY(doc_id) REFERENCES documents(id)
    )
    """)
    
    # Immutable Audit Trail (Proof of access attempts and results)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_id TEXT,
        status TEXT NOT NULL,
        details TEXT
    )
    """)
    
    # Seed default test users
    seed_users = [
        ("admin", "admin123", "ADMIN"),
        ("alice", "alice123", "USER"),
        ("bob", "bob123", "USER")
    ]
    for u, p, r in seed_users:
        cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", (u, p, r))
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("TrustVault Database Initialized Successfully!")