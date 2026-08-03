import os
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import psycopg2
from datetime import datetime

# Environment Variables
DATABASE_URL = os.environ.get('DATABASE_URL')
MASTER_KEY = os.environ.get('MASTER_KEY', 'natsuxak-master-2024')
PORT = int(os.environ.get('PORT', 10000))

def get_db_connection():
    if not DATABASE_URL:
        print(f"[{datetime.now()}] ERROR: DATABASE_URL not set!")
        return None
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"[{datetime.now()}] ERROR connecting to DB: {e}")
        return None

def init_db():
    conn = get_db_connection()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS checkers (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                key TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'checker',
                created_at TIMESTAMP DEFAULT NOW()
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS players (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                added_by TEXT NOT NULL,
                player_type TEXT NOT NULL DEFAULT 'PC',
                created_at TIMESTAMP DEFAULT NOW()
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                player_name TEXT NOT NULL,
                report_text TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'UNKNOWN',
                hwid TEXT DEFAULT '',
                checker_name TEXT NOT NULL DEFAULT 'AK',
                created_at TIMESTAMP DEFAULT NOW()
            );
            """)
        conn.commit()
        print(f"[{datetime.now()}] Database tables initialized successfully.")
    except Exception as e:
        print(f"[{datetime.now()}] ERROR initializing DB: {e}")
    finally:
        conn.close()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to make custom logging cleaner
        pass
        
    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_text(self, status, text):
        self.send_response(status)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(text.encode('utf-8'))

    def _auth_check(self, name, key):
        if not name or not key:
            return False
        # Master/Owner override
        if name.lower() == 'ak' and key == MASTER_KEY:
            return 'master'
        if name.lower() == 'natsu' and key == MASTER_KEY:
            return 'owner'
        
        conn = get_db_connection()
        if not conn:
            return False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT key, role FROM checkers WHERE LOWER(name) = LOWER(%s)", (name,))
                result = cur.fetchone()
                if result:
                    db_key, role = result
                    if db_key == "" or db_key == "PENDING":
                        # Bind the HWID to this user
                        cur.execute("UPDATE checkers SET key = %s WHERE LOWER(name) = LOWER(%s)", (key, name))
                        conn.commit()
                        return role
                    elif key == db_key:
                        return role
        except Exception as e:
            print(f"[{datetime.now()}] Auth check error: {e}")
        finally:
            conn.close()
        return False

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = dict(urllib.parse.parse_qsl(parsed_path.query))

        print(f"[{datetime.now()}] GET {self.path}")

        if path == '/health':
            self._send_json(200, {"status": "ok"})
            return

        elif path == '/auth':
            name = query.get('name')
            key = query.get('key')
            role = self._auth_check(name, key)
            if role:
                self._send_json(200, {"role": role})
            else:
                self._send_json(403, {"error": "Forbidden"})
            return

        elif path == '/verify':
            name = query.get('name')
            if not name:
                self._send_text(200, "INVALID")
                return
            
            conn = get_db_connection()
            if not conn:
                self._send_text(500, "DB ERROR")
                return
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT player_type, added_by FROM players WHERE LOWER(name) = LOWER(%s)", (name,))
                    result = cur.fetchone()
                    if result:
                        player_type, added_by = result
                        self._send_text(200, f"{player_type}:{added_by}")
                    else:
                        self._send_text(200, "INVALID")
            except Exception as e:
                print(f"[{datetime.now()}] DB error in /verify: {e}")
                self._send_text(500, "DB ERROR")
            finally:
                conn.close()
            return

        elif path == '/reports':
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            role = self._auth_check(auth_name, auth_key)
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return

            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB connection failed"})
                return
            
            try:
                with conn.cursor() as cur:
                    if role in ['master', 'owner']:
                        cur.execute("SELECT player_name FROM reports")
                    else:
                        cur.execute("SELECT player_name FROM reports WHERE LOWER(checker_name) = LOWER(%s)", (auth_name,))
                    
                    reports = [row[0] for row in cur.fetchall()]
                    self._send_json(200, reports)
            except Exception as e:
                print(f"[{datetime.now()}] Error fetching reports: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return

        elif path.startswith('/report/'):
            player_name = urllib.parse.unquote(path.split('/')[-1])
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            role = self._auth_check(auth_name, auth_key)
            
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return

            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
            
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT report_text, checker_name FROM reports WHERE LOWER(player_name) = LOWER(%s)", (player_name,))
                    result = cur.fetchone()
                    if result:
                        report_text, checker_name = result
                        if role in ['master', 'owner'] or auth_name.lower() == checker_name.lower():
                            self._send_text(200, report_text)
                        else:
                            self._send_json(403, {"error": "Forbidden: Not your report"})
                    else:
                        self._send_json(404, {"error": "Report not found"})
            except Exception as e:
                print(f"[{datetime.now()}] Error fetching report: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return
            
        elif path == '/checkers':
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            role = self._auth_check(auth_name, auth_key)
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return

            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
            
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT name FROM checkers")
                    checkers = [row[0] for row in cur.fetchall()]
                    self._send_json(200, checkers)
            except Exception as e:
                print(f"[{datetime.now()}] Error fetching checkers: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            data = {}

        print(f"[{datetime.now()}] POST {self.path}")

        if path == '/player/add':
            auth_name = data.get('auth_name')
            auth_key = data.get('auth_key')
            player_name = data.get('player_name')
            player_type = data.get('player_type', 'PC')
            
            role = self._auth_check(auth_name, auth_key)
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
                
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO players (name, added_by, player_type) VALUES (%s, %s, %s)",
                        (player_name, auth_name, player_type)
                    )
                conn.commit()
                self._send_json(200, {"status": "success"})
            except psycopg2.IntegrityError:
                self._send_json(400, {"error": "Player already exists"})
            except Exception as e:
                print(f"[{datetime.now()}] Error adding player: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return

        elif path == '/report':
            player_name = data.get('name')
            hwid = data.get('hwid', '')
            score = data.get('score', 0)
            verdict = data.get('verdict', 'UNKNOWN')
            report_text = data.get('report', '')
            
            # Print colored alert
            color = '\033[92m' # Green
            if score >= 80:
                color = '\033[91m' # Red
            elif score >= 50:
                color = '\033[93m' # Yellow
            reset = '\033[0m'
            print(f"{color}[{datetime.now()}] REPORT RECEIVED: {player_name} - Score: {score} - Verdict: {verdict}{reset}")
            
            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
                
            try:
                with conn.cursor() as cur:
                    # Find who added the player
                    cur.execute("SELECT added_by FROM players WHERE LOWER(name) = LOWER(%s)", (player_name,))
                    result = cur.fetchone()
                    checker_name = result[0] if result else 'AK'
                    
                    # Insert report
                    cur.execute(
                        "INSERT INTO reports (player_name, report_text, score, verdict, hwid, checker_name) VALUES (%s, %s, %s, %s, %s, %s)",
                        (player_name, report_text, score, verdict, hwid, checker_name)
                    )
                    
                    # Delete player
                    cur.execute("DELETE FROM players WHERE LOWER(name) = LOWER(%s)", (player_name,))
                conn.commit()
                self._send_json(200, {"status": "success"})
            except Exception as e:
                print(f"[{datetime.now()}] Error processing report: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return

        elif path == '/checker/add':
            master_key_body = data.get('master_key')
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            
            is_authorized = False
            if master_key_body == MASTER_KEY:
                is_authorized = True
            elif self.headers.get('X-Master-Key') == MASTER_KEY:
                is_authorized = True
            else:
                role = self._auth_check(auth_name, auth_key)
                if role in ['master', 'owner']:
                    is_authorized = True
                    
            if not is_authorized:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            new_name = data.get('name')
            new_key = data.get('key')
            new_role = data.get('role', 'checker')
            
            if not new_name or not new_key:
                self._send_json(400, {"error": "Missing name or key"})
                return
                
            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
                
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO checkers (name, key, role) 
                        VALUES (%s, %s, %s)
                        ON CONFLICT (name) DO UPDATE 
                        SET key = EXCLUDED.key, role = EXCLUDED.role
                    """, (new_name, new_key, new_role))
                conn.commit()
                self._send_json(200, {"status": "success"})
            except Exception as e:
                print(f"[{datetime.now()}] Error adding checker: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        print(f"[{datetime.now()}] DELETE {self.path}")

        if path.startswith('/checker/'):
            target_name = urllib.parse.unquote(path.split('/')[-1])
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            master_header = self.headers.get('X-Master-Key')
            
            is_authorized = False
            if master_header == MASTER_KEY:
                is_authorized = True
            else:
                role = self._auth_check(auth_name, auth_key)
                if role in ['master', 'owner']:
                    is_authorized = True
                    
            if not is_authorized:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
                
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM checkers WHERE LOWER(name) = LOWER(%s)", (target_name,))
                    if cur.rowcount > 0:
                        self._send_json(200, {"status": "success"})
                    else:
                        self._send_json(404, {"error": "Not Found"})
                conn.commit()
            except Exception as e:
                print(f"[{datetime.now()}] Error deleting checker: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return
            
        elif path.startswith('/player/'):
            target_name = urllib.parse.unquote(path.split('/')[-1])
            auth_name = self.headers.get('X-Name')
            auth_key = self.headers.get('X-Key')
            
            role = self._auth_check(auth_name, auth_key)
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            conn = get_db_connection()
            if not conn:
                self._send_json(500, {"error": "DB error"})
                return
                
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM players WHERE LOWER(name) = LOWER(%s)", (target_name,))
                    if cur.rowcount > 0:
                        self._send_json(200, {"status": "success"})
                    else:
                        self._send_json(404, {"error": "Not Found"})
                conn.commit()
            except Exception as e:
                print(f"[{datetime.now()}] Error deleting player: {e}")
                self._send_json(500, {"error": "Internal error"})
            finally:
                conn.close()
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

def run():
    init_db()
    server_address = ('0.0.0.0', PORT)
    httpd = ThreadedHTTPServer(server_address, RequestHandler)
    
    print("=============================================")
    print(f" NatsuXAK Scanner - Admin Server")
    print(f" Port: {PORT}")
    print(f" Master Key Configured: {'Yes' if MASTER_KEY else 'No'}")
    print("=============================================")
    print(" Endpoints:")
    print("  GET    /health")
    print("  GET    /auth?name=X&key=Y")
    print("  GET    /verify?name=X")
    print("  POST   /player/add")
    print("  POST   /report")
    print("  GET    /reports")
    print("  GET    /report/{player_name}")
    print("  POST   /checker/add")
    print("  GET    /checkers")
    print("  DELETE /checker/{name}")
    print("  DELETE /player/{name}")
    print("=============================================")
    print(f"[{datetime.now()}] Server starting...")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{datetime.now()}] Shutting down server...")
        httpd.server_close()

if __name__ == '__main__':
    run()
