import psycopg2
db_url = 'postgresql://gakuran_admin:npg_7mhcJjOT4VWt@ep-spring-glade-a48jdkew.us-east-1.aws.neon.tech/neondb?sslmode=require'
conn = psycopg2.connect(db_url)
cur = conn.cursor()
cur.execute("SET search_path TO gakuran_admin;")
cur.execute("CREATE TABLE IF NOT EXISTS checkers (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, key TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'checker', created_at TIMESTAMP DEFAULT NOW());")
cur.execute("CREATE TABLE IF NOT EXISTS players (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, added_by TEXT NOT NULL, player_type TEXT NOT NULL DEFAULT 'PC', created_at TIMESTAMP DEFAULT NOW());")
cur.execute("CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, player_name TEXT NOT NULL, report_text TEXT NOT NULL, score INTEGER DEFAULT 0, verdict TEXT DEFAULT 'UNKNOWN', hwid TEXT DEFAULT '', checker_name TEXT NOT NULL DEFAULT 'AK', created_at TIMESTAMP DEFAULT NOW());")
conn.commit()
print("TABLES CREATED")
