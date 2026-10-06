import sqlite3

try:
    conn = sqlite3.connect("cybershield.db", timeout=10)
    cur = conn.cursor()
    cur.execute("ALTER TABLE packets ADD COLUMN ttl INTEGER")
    cur.execute("ALTER TABLE packets ADD COLUMN tcp_flags VARCHAR")
    cur.execute("ALTER TABLE packets ADD COLUMN service VARCHAR")
    cur.execute("ALTER TABLE packets ADD COLUMN info VARCHAR")
    cur.execute("ALTER TABLE packets ADD COLUMN dns_info JSON")
    cur.execute("ALTER TABLE packets ADD COLUMN http_info JSON")
    cur.execute("ALTER TABLE packets ADD COLUMN payload_preview JSON")
    cur.execute("ALTER TABLE packets ADD COLUMN layers JSON")
    conn.commit()
    print("Database schema upgraded successfully.")
except Exception as e:
    print("Error:", e)
finally:
    if 'conn' in locals():
        conn.close()
