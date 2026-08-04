import psycopg2
db_url = 'postgresql://gakuran_admin:npg_7mhcJjOT4VWt@ep-spring-glade-a48jdkew.us-east-1.aws.neon.tech/neondb?sslmode=require'
conn = psycopg2.connect(db_url)
cur = conn.cursor()
cur.execute("SET search_path TO gakuran_admin;")
cur.execute("DELETE FROM checkers WHERE name IN ('rico2', 'rico3', 'rico4', 'rico5');")
conn.commit()
print("DELETED")
