import sqlite3
conn = sqlite3.connect('cybershield.db')
cur = conn.cursor()
cols = ['dns_info', 'http_info', 'payload_preview', 'layers']
for c in cols:
    try:
        cur.execute(f'ALTER TABLE packets ADD COLUMN {c} JSON')
        print(f'Added {c}')
    except Exception as e:
        print(f"Skipped {c}: {e}")
conn.commit()
conn.close()
