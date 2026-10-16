import os
import json
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from datetime import datetime
from contextlib import contextmanager
import psycopg2
from psycopg2 import pool
import hmac
import hashlib
import secrets
import time as _time

# Environment Variables
DATABASE_URL = os.environ.get('DATABASE_URL')
MASTER_KEY = os.environ.get('MASTER_KEY')
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY environment variable not set! Please set MASTER_KEY before running the server.")

PORT = int(os.environ.get('PORT', 10000))

# ============================================================================
# REPORT AUTHENTICITY
#
# The /report endpoint previously accepted unsigned JSON from anyone. A
# forged "CLEAN" report for any player could be posted with curl and would be
# stored as verified truth, attributed to a checker.
#
# Now: /verify mints a single-use HMAC token bound to {name, hwid, build}.
# /report refuses anything without a valid, unused, correctly-bound token.
# The signing key is derived from MASTER_KEY and never leaves this process.
# ============================================================================
REPORT_TOKEN_TTL = 900          # a token is good for 15 minutes
REPORT_KEY = hmac.new(
    MASTER_KEY.encode('utf-8'),
    b'gakuran-report-token-v1',
    hashlib.sha256
).digest()


def mint_report_token(name, hwid, build):
    """Mint a single-use token bound to this player name, machine, and build."""
    nonce = secrets.token_hex(16)
    expiry = int(_time.time()) + REPORT_TOKEN_TTL
    payload = f"{name}|{hwid}|{build}|{expiry}|{nonce}"
    sig = hmac.new(REPORT_KEY, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{expiry}.{nonce}.{sig}"


def verify_report_token(token, name, hwid, build):
    """
    Returns (ok, reason).
    A token is valid only if its HMAC matches, it has not expired, and the
    name/hwid/build still match the ones it was minted for. Single-use
    enforcement (nonce) happens in the caller against the database.
    """
    if not token or token.count('.') != 2:
        return False, "malformed token"

    parts = token.split('.')
    try:
        expiry = int(parts[0])
    except ValueError:
        return False, "malformed expiry"
    nonce, sig = parts[1], parts[2]

    payload = f"{name}|{hwid}|{build}|{expiry}|{nonce}"
    expected = hmac.new(REPORT_KEY, payload.encode('utf-8'), hashlib.sha256).hexdigest()

    # Constant-time compare — a timing side channel here would let an attacker
    # forge a signature one byte at a time.
    if not hmac.compare_digest(expected, sig):
        return False, "signature mismatch"

    if int(_time.time()) > expiry:
        return False, "token expired"

    return True, nonce

# ============================================================================
# DATABASE CONNECTION POOLING & SEARCH_PATH CONFIGURATION
# ============================================================================
db_pool = None

def init_db_pool():
    global db_pool
    if not DATABASE_URL:
        print(f"[{datetime.now()}] ERROR: DATABASE_URL not set!")
        return
    try:
        # options parameter sets search_path at the protocol level on every session
        db_pool = pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=20,
            dsn=DATABASE_URL,
            options="-c search_path=gakuran_admin,public"
        )
        print(f"[{datetime.now()}] Database connection pool initialized (min=1, max=20).")
    except Exception as e:
        print(f"[{datetime.now()}] ERROR initializing DB connection pool: {e}")

@contextmanager
def get_db():
    """
    Thread-safe context manager to acquire and return pooled database connections.
    Guarantees rollback on exception and always returns the connection to the pool.
    """
    conn = None
    try:
        if db_pool:
            conn = db_pool.getconn()
        elif DATABASE_URL:
            conn = psycopg2.connect(DATABASE_URL, options="-c search_path=gakuran_admin,public")
        yield conn
    except Exception:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    finally:
        if conn:
            if db_pool:
                try:
                    db_pool.putconn(conn)
                except Exception as e:
                    print(f"[{datetime.now()}] Error returning connection to pool: {e}")
            else:
                try:
                    conn.close()
                except Exception:
                    pass

def init_db():
    init_db_pool()
    with get_db() as conn:
        if not conn:
            print(f"[{datetime.now()}] Database unavailable, skipping table setup.")
            return
        try:
            with conn.cursor() as cur:
                cur.execute("CREATE SCHEMA IF NOT EXISTS gakuran_admin;")
                cur.execute("SET search_path TO gakuran_admin,public;")
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
                    build TEXT DEFAULT '',
                    text_crc TEXT DEFAULT '',
                    tampered BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                """)
                # Single-use scan tokens. A nonce recorded here can never be
                # used again, which is what makes a captured report
                # unreplayable.
                cur.execute("""
                CREATE TABLE IF NOT EXISTS used_tokens (
                    nonce TEXT PRIMARY KEY,
                    player_name TEXT,
                    used_at TIMESTAMP DEFAULT NOW()
                );
                """)
                # Build attestation ledger. The first text_crc seen for a build
                # id becomes the reference; any later divergence means that
                # build's binary was patched.
                cur.execute("""
                CREATE TABLE IF NOT EXISTS build_attestation (
                    build TEXT PRIMARY KEY,
                    text_crc TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT NOW()
                );
                """)
            conn.commit()
            print(f"[{datetime.now()}] Database tables initialized successfully.")
        except Exception as e:
            print(f"[{datetime.now()}] ERROR initializing DB: {e}")

# ============================================================================
# RATE LIMITING
# ============================================================================
class AuthRateLimiter:
    """Tracks failed login attempts and locks out IPs after repeated failures."""
    def __init__(self, max_attempts=5, lockout_seconds=300):
        self.lock = threading.Lock()
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.records = {} # ip -> {"failed": int, "locked_until": float}

    def check_lockout(self, ip):
        now = time.time()
        with self.lock:
            record = self.records.get(ip)
            if not record:
                return False, 0
            if record["locked_until"] > now:
                return True, int(record["locked_until"] - now)
            if record["locked_until"] > 0 and record["locked_until"] <= now:
                del self.records[ip]
            return False, 0

    def record_failure(self, ip):
        now = time.time()
        with self.lock:
            record = self.records.setdefault(ip, {"failed": 0, "locked_until": 0})
            record["failed"] += 1
            if record["failed"] >= self.max_attempts:
                record["locked_until"] = now + self.lockout_seconds
                print(f"[{datetime.now()}] WARNING: IP {ip} locked out for {self.lockout_seconds}s after {record['failed']} failed attempts.")
                return True, self.lockout_seconds
            return False, 0

    def record_success(self, ip):
        with self.lock:
            if ip in self.records:
                del self.records[ip]

class SlidingWindowLimiter:
    """Sliding-window rate limiter per IP address to prevent scraping / enumeration."""
    def __init__(self, max_requests=30, window_seconds=60):
        self.lock = threading.Lock()
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history = {} # ip -> list of timestamps

    def is_allowed(self, ip):
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            timestamps = self.history.get(ip, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self.max_requests:
                self.history[ip] = timestamps
                return False
            timestamps.append(now)
            self.history[ip] = timestamps
            return True

auth_limiter = AuthRateLimiter(max_attempts=5, lockout_seconds=300)
verify_limiter = SlidingWindowLimiter(max_requests=30, window_seconds=60)
# Forgery attempts and legitimate scans both hit /report. This keeps an
# attacker from hammering it, and stops one host from flooding the table.
report_limiter = SlidingWindowLimiter(max_requests=12, window_seconds=60)

def get_client_ip(handler):
    forwarded = handler.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return handler.client_address[0]

# ============================================================================
# HTTP SERVER & REQUEST HANDLER
# ============================================================================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep custom output clean
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
        
        with get_db() as conn:
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
        return False

    def _authenticate(self, body_data=None):
        """
        Unified authentication helper checking:
        1. X-Master-Key header
        2. master_key in JSON body
        3. X-Name & X-Key headers
        4. name & key in JSON body
        5. Query parameters (fallback for legacy callers)
        Returns (role, auth_name) or (None, None)
        """
        master_hdr = self.headers.get('X-Master-Key')
        if master_hdr and master_hdr == MASTER_KEY:
            return ('master', 'master')

        if body_data and isinstance(body_data, dict):
            if body_data.get('master_key') == MASTER_KEY:
                return ('master', 'master')

        auth_name = self.headers.get('X-Name')
        auth_key = self.headers.get('X-Key')

        if not auth_name or not auth_key:
            if body_data and isinstance(body_data, dict):
                auth_name = body_data.get('auth_name') or body_data.get('name')
                auth_key = body_data.get('auth_key') or body_data.get('key')

        if not auth_name or not auth_key:
            parsed_path = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(parsed_path.query))
            auth_name = auth_name or query.get('name')
            auth_key = auth_key or query.get('key')

        if auth_name and auth_key:
            role = self._auth_check(auth_name, auth_key)
            if role:
                return (role, auth_name)

        return (None, None)

    # ------------------------------------------------------------------------
    # GET HANDLER
    # ------------------------------------------------------------------------
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = dict(urllib.parse.parse_qsl(parsed_path.query))

        print(f"[{datetime.now()}] GET {path}")

        if path == '/health':
            self._send_json(200, {"status": "ok"})
            return

        elif path == '/auth':
            ip = get_client_ip(self)
            is_locked, remaining = auth_limiter.check_lockout(ip)
            if is_locked:
                print(f"[{datetime.now()}] Auth GET blocked for locked IP: {ip} ({remaining}s left)")
                self._send_json(429, {"error": f"Too many failed attempts. Locked out for {remaining}s."})
                return

            name = self.headers.get('X-Name') or query.get('name')
            key = self.headers.get('X-Key') or query.get('key')
            role = self._auth_check(name, key)
            if role:
                auth_limiter.record_success(ip)
                self._send_json(200, {"role": role})
            else:
                locked, lock_time = auth_limiter.record_failure(ip)
                if locked:
                    self._send_json(429, {"error": f"Too many failed attempts. Locked out for {lock_time}s."})
                else:
                    self._send_json(403, {"error": "Forbidden"})
            return

        elif path == '/verify':
            ip = get_client_ip(self)
            if not verify_limiter.is_allowed(ip):
                print(f"[{datetime.now()}] Rate limit exceeded on /verify from IP: {ip}")
                self._send_text(429, "RATE_LIMITED")
                return

            name = query.get('name')
            if not name:
                self._send_text(200, "INVALID")
                return

            # The scanner sends its HWID and build so the token it receives is
            # bound to this specific player, machine, and scanner version.
            req_hwid = (query.get('hwid') or '')[:128]
            req_build = (query.get('build') or '')[:32]

            with get_db() as conn:
                if not conn:
                    self._send_text(500, "DB ERROR")
                    return
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT player_type, added_by FROM players WHERE LOWER(name) = LOWER(%s)", (name,))
                        result = cur.fetchone()
                        if result:
                            player_type, added_by = result
                            token = mint_report_token(name.lower(), req_hwid, req_build)
                            self._send_text(200, f"{player_type}:{added_by}:{token}")
                        else:
                            self._send_text(200, "INVALID")
                except Exception as e:
                    print(f"[{datetime.now()}] DB error in /verify: {e}")
                    self._send_text(500, "DB ERROR")
            return

        elif path == '/reports':
            role, auth_name = self._authenticate()
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return

            with get_db() as conn:
                if not conn:
                    self._send_json(500, {"error": "DB connection failed"})
                    return
                try:
                    with conn.cursor() as cur:
                        if role in ['master', 'owner']:
                            cur.execute("SELECT player_name FROM reports ORDER BY id DESC")
                        else:
                            cur.execute("SELECT player_name FROM reports WHERE LOWER(checker_name) = LOWER(%s) ORDER BY id DESC", (auth_name,))
                        
                        reports = [row[0] for row in cur.fetchall()]
                        self._send_json(200, reports)
                except Exception as e:
                    print(f"[{datetime.now()}] Error fetching reports: {e}")
                    self._send_json(500, {"error": "Internal error"})
            return

        elif path.startswith('/report/'):
            player_name = urllib.parse.unquote(path.split('/')[-1])
            role, auth_name = self._authenticate()
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return

            with get_db() as conn:
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
            return
            
        elif path == '/checkers':
            role, auth_name = self._authenticate()
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return

            with get_db() as conn:
                if not conn:
                    self._send_json(500, {"error": "DB error"})
                    return
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT name FROM checkers ORDER BY id ASC")
                        checkers = [row[0] for row in cur.fetchall()]
                        self._send_json(200, checkers)
                except Exception as e:
                    print(f"[{datetime.now()}] Error fetching checkers: {e}")
                    self._send_json(500, {"error": "Internal error"})
            return
            
        elif path == '/players':
            role, auth_name = self._authenticate()
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return

            with get_db() as conn:
                if not conn:
                    self._send_json(500, {"error": "DB error"})
                    return
                try:
                    with conn.cursor() as cur:
                        if role in ['master', 'owner']:
                            cur.execute("SELECT name, player_type FROM players ORDER BY id DESC")
                        else:
                            cur.execute("SELECT name, player_type FROM players WHERE LOWER(added_by) = LOWER(%s) ORDER BY id DESC", (auth_name,))
                        
                        players = [{"name": row[0], "type": row[1]} for row in cur.fetchall()]
                        self._send_json(200, players)
                except Exception as e:
                    print(f"[{datetime.now()}] Error fetching players: {e}")
                    self._send_json(500, {"error": "Internal error"})
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

    # ------------------------------------------------------------------------
    # POST HANDLER
    # ------------------------------------------------------------------------
    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        
        try:
            data = json.loads(post_data.decode('utf-8')) if post_data else {}
        except json.JSONDecodeError:
            data = {}

        print(f"[{datetime.now()}] POST {path}")

        # Secure POST /auth (no credentials exposed in query parameters)
        if path == '/auth':
            ip = get_client_ip(self)
            is_locked, remaining = auth_limiter.check_lockout(ip)
            if is_locked:
                print(f"[{datetime.now()}] Auth POST blocked for locked IP: {ip} ({remaining}s left)")
                self._send_json(429, {"error": f"Too many failed attempts. Locked out for {remaining}s."})
                return

            name = data.get('name') or data.get('auth_name') or self.headers.get('X-Name')
            key = data.get('key') or data.get('auth_key') or self.headers.get('X-Key')

            role = self._auth_check(name, key)
            if role:
                auth_limiter.record_success(ip)
                self._send_json(200, {"role": role})
            else:
                locked, lock_time = auth_limiter.record_failure(ip)
                if locked:
                    self._send_json(429, {"error": f"Too many failed attempts. Locked out for {lock_time}s."})
                else:
                    self._send_json(403, {"error": "Forbidden"})
            return

        elif path == '/player/add':
            role, auth_name = self._authenticate(data)
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            player_name = data.get('player_name')
            player_type = data.get('player_type', 'PC')
            if not player_name:
                self._send_json(400, {"error": "Missing player_name"})
                return
                
            with get_db() as conn:
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
            return

        elif path == '/report':
            ip = get_client_ip(self)
            if not report_limiter.is_allowed(ip):
                print(f"[{datetime.now()}] Report rate limit exceeded from IP: {ip}")
                self._send_json(429, {"error": "Rate limited"})
                return

            player_name = data.get('name')
            hwid = data.get('hwid', '')
            score = data.get('score', 0)
            verdict = data.get('verdict', 'UNKNOWN')
            report_text = data.get('report', '')
            build = data.get('build', '')
            text_crc = data.get('text_crc', '')
            token = data.get('token', '')

            if not player_name:
                self._send_json(400, {"error": "Missing player_name"})
                return

            # ------------------------------------------------------------------
            # TOKEN VERIFICATION
            # Without a valid, unused, correctly-bound token this report is a
            # forgery. The old handler stored whatever it was sent.
            # ------------------------------------------------------------------
            ok, reason = verify_report_token(token, player_name.lower(), hwid, build)
            if not ok:
                print(f"[{datetime.now()}] \033[91mREJECTED REPORT for '{player_name}' from {ip}: {reason}\033[0m")
                self._send_json(403, {"error": f"Report rejected: {reason}"})
                return

            nonce = reason  # verify_report_token returns the nonce on success

            # ------------------------------------------------------------------
            # BUILD ATTESTATION
            # The first CRC seen for a build id is the reference. A later
            # divergence means that binary was patched — e.g. a scanner edited
            # to always report CLEAN. Flag it, keep the report, and make the
            # tampering impossible to miss in the admin UI.
            # ------------------------------------------------------------------
            tampered = False
            if text_crc:
                with get_db() as conn:
                    if conn:
                        try:
                            with conn.cursor() as cur:
                                cur.execute("SELECT text_crc FROM build_attestation WHERE build = %s", (build,))
                                ref = cur.fetchone()
                                if ref is None:
                                    cur.execute(
                                        "INSERT INTO build_attestation (build, text_crc) VALUES (%s, %s)",
                                        (build, text_crc)
                                    )
                                    conn.commit()
                                elif ref[0].lower() != text_crc.lower():
                                    tampered = True
                        except Exception as e:
                            print(f"[{datetime.now()}] Attestation error: {e}")

            color = '\033[92m' # Green
            if tampered:
                color = '\033[95m' # Magenta - tampered build
            elif score >= 80:
                color = '\033[91m' # Red
            elif score >= 50:
                color = '\033[93m' # Yellow
            reset = '\033[0m'
            tamper_tag = " \033[95m[TAMPERED BUILD]\033[0m" if tampered else ""
            print(f"{color}[{datetime.now()}] REPORT RECEIVED: {player_name} - Score: {score} - Verdict: {verdict}{tamper_tag}{reset}")

            with get_db() as conn:
                if not conn:
                    self._send_json(500, {"error": "DB error"})
                    return
                try:
                    with conn.cursor() as cur:
                        # Burn the nonce inside the same transaction that stores
                        # the report. INSERT on the primary key is atomic, so a
                        # concurrent replay of the same token loses the race and
                        # gets rejected.
                        try:
                            cur.execute(
                                "INSERT INTO used_tokens (nonce, player_name) VALUES (%s, %s)",
                                (nonce, player_name)
                            )
                        except psycopg2.IntegrityError:
                            print(f"[{datetime.now()}] \033[91mREJECTED REPLAYED token from {ip} for '{player_name}'\033[0m")
                            conn.rollback()
                            self._send_json(403, {"error": "Report rejected: token already used"})
                            return

                        cur.execute("SELECT added_by, player_type FROM players WHERE LOWER(name) = LOWER(%s)", (player_name,))
                        result = cur.fetchone()
                        checker_name = result[0] if result else 'AK'
                        p_type = result[1] if result else 'PC'

                        cur.execute(
                            "INSERT INTO reports (player_name, report_text, score, verdict, hwid, checker_name, build, text_crc, tampered) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (player_name, report_text, score, verdict, hwid, checker_name, build, text_crc, tampered)
                        )
                        
                        if p_type != 'TEST':
                            cur.execute("DELETE FROM players WHERE LOWER(name) = LOWER(%s)", (player_name,))
                    conn.commit()
                    self._send_json(200, {"status": "success"})
                except Exception as e:
                    print(f"[{datetime.now()}] Error processing report: {e}")
                    self._send_json(500, {"error": "Internal error"})
            return

        elif path == '/checker/add':
            role, auth_name = self._authenticate(data)
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            new_name = data.get('name')
            new_key = data.get('key')
            new_role = data.get('role', 'checker')
            
            if not new_name or not new_key:
                self._send_json(400, {"error": "Missing name or key"})
                return
                
            with get_db() as conn:
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
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

    # ------------------------------------------------------------------------
    # DELETE HANDLER
    # ------------------------------------------------------------------------
    def do_DELETE(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        print(f"[{datetime.now()}] DELETE {path}")

        if path.startswith('/checker/'):
            target_name = urllib.parse.unquote(path.split('/')[-1])
            role, auth_name = self._authenticate()
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            with get_db() as conn:
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
            return
            
        elif path.startswith('/player/'):
            target_name = urllib.parse.unquote(path.split('/')[-1])
            role, auth_name = self._authenticate()
            if role not in ['master', 'owner']:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            with get_db() as conn:
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
            return

        elif path.startswith('/report/'):
            target_name = urllib.parse.unquote(path.split('/')[-1])
            role, auth_name = self._authenticate()
            if not role:
                self._send_json(403, {"error": "Forbidden"})
                return
                
            with get_db() as conn:
                if not conn:
                    self._send_json(500, {"error": "DB error"})
                    return
                try:
                    with conn.cursor() as cur:
                        if role in ['master', 'owner']:
                            cur.execute("DELETE FROM reports WHERE LOWER(player_name) = LOWER(%s)", (target_name,))
                        else:
                            cur.execute("DELETE FROM reports WHERE LOWER(player_name) = LOWER(%s) AND LOWER(checker_name) = LOWER(%s)", (target_name, auth_name))
                            
                        if cur.rowcount > 0:
                            self._send_json(200, {"status": "success"})
                        else:
                            self._send_json(404, {"error": "Not Found"})
                    conn.commit()
                except Exception as e:
                    print(f"[{datetime.now()}] Error deleting report: {e}")
                    self._send_json(500, {"error": "Internal error"})
            return
            
        else:
            self._send_json(404, {"error": "Not Found"})

# ============================================================================
# SERVER LIFECYCLE
# ============================================================================
def run():
    init_db()
    server_address = ('0.0.0.0', PORT)
    httpd = ThreadedHTTPServer(server_address, RequestHandler)
    
    print("=============================================")
    print(f" NatsuXAK Scanner - Admin Server")
    print(f" Port: {PORT}")
    print(f" Database Pool: Active (Max 20)")
    print(f" Master Key Configured: {'Yes' if MASTER_KEY else 'No'}")
    print("=============================================")
    print(" Endpoints:")
    print("  GET    /health")
    print("  POST   /auth             (Body: name, key)")
    print("  GET    /auth             (Header or Query fallback)")
    print("  GET    /verify?name=X    (Rate limited)")
    print("  POST   /player/add")
    print("  POST   /report")
    print("  GET    /reports")
    print("  GET    /report/{player_name}")
    print("  POST   /checker/add")
    print("  GET    /checkers")
    print("  DELETE /checker/{name}")
    print("  DELETE /player/{name}")
    print("  DELETE /report/{name}")
    print("=============================================")
    print(f"[{datetime.now()}] Server starting...")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{datetime.now()}] Shutting down server...")
        if db_pool:
            db_pool.closeall()
        httpd.server_close()

if __name__ == '__main__':
    run()
