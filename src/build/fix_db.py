import psycopg2

db_url = 'postgresql://gakuran_admin:npg_7mhcJjOT4VWt@ep-spring-glade-a48jdkew.us-east-1.aws.neon.tech/neondb?sslmode=require'
try:
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("ALTER TABLE checkers ADD CONSTRAINT checkers_name_unique UNIQUE (name);")
    conn.commit()
    print("SUCCESS")
except Exception as e:
    print("ERROR:", e)
