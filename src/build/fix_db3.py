import psycopg2
db_url = 'postgresql://gakuran_admin:npg_7mhcJjOT4VWt@ep-spring-glade-a48jdkew.us-east-1.aws.neon.tech/neondb?sslmode=require'
conn = psycopg2.connect(db_url)
cur = conn.cursor()
try:
    cur.execute("CREATE SCHEMA IF NOT EXISTS gakuran_admin;")
    conn.commit()
    print("SCHEMA CREATED")
except Exception as e:
    print("SCHEMA ERROR:", e)
