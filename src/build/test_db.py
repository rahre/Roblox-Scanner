import psycopg2

db_url = 'postgresql://gakuran_admin:npg_7mhcJjOT4VWt@ep-spring-glade-a48jdkew.us-east-1.aws.neon.tech/neondb?sslmode=require'
try:
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("INSERT INTO checkers (name, key, role) VALUES ('Rico', 'PENDING', 'checker') ON CONFLICT (name) DO UPDATE SET key = EXCLUDED.key, role = EXCLUDED.role")
    conn.commit()
    print("SUCCESS")
except Exception as e:
    print("ERROR:", e)
