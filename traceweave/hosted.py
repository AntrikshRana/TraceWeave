"""Bounded online workspace: Supabase Auth, owner-scoped durable snapshots.

The local server remains separate for offline use. No local logs are uploaded
on startup. Saved GPU-trained weights provide dependency-free inference here.
"""
import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .cloud import NoRedirect
from .engine import Engine
from .learning import model_info
from .server import Handler

TABLES = {"events": 5, "contracts": 5, "results": 4, "audit": 4, "operations": 3}
MAX_SNAPSHOT = 8 * 1024 * 1024
COOKIE = "__Host-traceweave"
# Cross-origin cookie attribute: SameSite=None is needed when the front-end
# is served from a different origin (GitHub Pages) than the API (Render).
CROSS_SITE_COOKIE = "; SameSite=None"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class RemoteError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


class Store:
    def __init__(self, url, public_key):
        if not re.fullmatch(r"https://[a-z0-9]{20}\.supabase\.co", url):
            raise ValueError("Set SUPABASE_URL to the dedicated project HTTPS URL")
        if not public_key or not (public_key.startswith("sb_publishable_") or public_key.startswith("eyJ")):
            raise ValueError("Set SUPABASE_PUBLIC_KEY to the publishable/anon key")
        self.url, self.key = url, public_key
        self.cache = OrderedDict()
        self.lock = threading.Lock()

    def request(self, path, token=None, body=None, method=None):
        headers = {"apikey": self.key, "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.url + path, headers=headers,
            data=None if body is None else json.dumps(body).encode(), method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(req, timeout=20) as response:
                raw = response.read(MAX_SNAPSHOT * 2 + 1)
                if len(raw) > MAX_SNAPSHOT * 2:
                    raise RemoteError("Workspace response exceeded its size limit")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RemoteError("Please sign in again to open your workspace.", 401) from None
            if exc.code == 409:
                raise RemoteError("Workspace changed in another tab. Refresh before retrying.", 409) from None
            if path.startswith("/auth/"):
                raise RemoteError("Authentication failed. Confirm your email and check your details, then try again.", 400) from None
            if exc.code == 400:
                raise RemoteError("Storage could not accept this change. Your saved workspace is unchanged; it may have reached its size limit.", 400) from None
            raise RemoteError("Cloud storage is temporarily unavailable. Refresh before retrying an upload.") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RemoteError("Cannot reach cloud storage. Refresh before retrying an upload.") from None

    def load(self, token, owner):
        # RLS scopes both requests using the authenticated user, never a supplied owner ID.
        rows = self.request("/rest/v1/traceweave_workspaces?select=revision&limit=1", token)
        revision = rows[0]["revision"] if rows else 0
        with self.lock:
            cached = self.cache.get(owner)
            if cached and cached[0] == revision:
                self.cache.move_to_end(owner)
                return revision, json.loads(cached[1])
        if not revision:
            return 0, {}
        rows = self.request("/rest/v1/traceweave_workspaces?select=revision,snapshot&limit=1", token)
        if not rows:
            raise RemoteError("Workspace changed. Refresh to continue.", 409)
        row = rows[0]
        self.remember(owner, row["revision"], row["snapshot"])
        return row["revision"], row["snapshot"]

    def remember(self, owner, revision, snapshot):
        encoded = json.dumps(snapshot)
        with self.lock:
            self.cache[owner] = (revision, encoded)
            self.cache.move_to_end(owner)
            while sum(len(value[1]) for value in self.cache.values()) > 16 * 1024 * 1024 or len(self.cache) > 16:
                self.cache.popitem(last=False)

    def save(self, token, owner, revision, snapshot):
        if len(json.dumps(snapshot).encode()) > MAX_SNAPSHOT:
            raise RemoteError("Workspace is full (8 MB including originals and review history). Export your records before adding more.", 413)
        next_revision = self.request("/rest/v1/rpc/traceweave_save", token,
            {"expected_revision": revision, "new_snapshot": snapshot})
        self.remember(owner, next_revision, snapshot)


def restore(snapshot):
    engine = Engine()
    engine.db.execute("CREATE TABLE operations(id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, response TEXT NOT NULL)")
    try:
        with engine.db:
            for table, width in TABLES.items():
                rows = snapshot.get(table, [])
                if not isinstance(rows, list) or len(rows) > 20000:
                    raise ValueError("Invalid workspace rows")
                for stored in rows:
                    if not isinstance(stored, list) or len(stored) != width:
                        raise ValueError("Invalid workspace record")
                    row = list(stored)
                    if table == "events":
                        row[2] = base64.b64decode(row[2], validate=True)
                    engine.db.execute(f"INSERT INTO {table} VALUES({','.join('?' for _ in row)})", row)
        return engine
    except Exception:
        engine.close()
        raise


def snapshot(engine):
    output = {}
    for table in TABLES:
        rows = [list(row) for row in engine.db.execute(f"SELECT * FROM {table}")]
        if table == "events":
            for row in rows:
                row[2] = base64.b64encode(row[2]).decode()
        output[table] = rows
    return output


class HostedHandler(Handler):
    workspace_limit = 1000

    def setup(self):
        self.request.settimeout(30)
        super().setup()

    @property
    def engine(self):
        return self.workspace_engine

    def is_trusted_origin(self, origin):
        if not origin:
            return False
        if origin == self.server.origin:
            return True
        gh = getattr(self.server, "github_pages_origin", None)
        if gh and origin == gh:
            return True
        if re.fullmatch(r"https://[a-zA-Z0-9-]+\.github\.io", origin):
            return True
        return False

    def is_cross_origin(self):
        origin = self.headers.get("Origin")
        if origin and origin != self.server.origin and self.is_trusted_origin(origin):
            return True
        return bool(getattr(self.server, "github_pages_origin", ""))

    def is_trusted_return_url(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return self.is_trusted_origin(origin)

    def local_request(self):
        if self.headers.get("Host") != self.server.public_host:
            return False
        origin = self.headers.get("Origin")
        if self.command == "GET":
            return self.is_trusted_origin(origin) if origin else True
        return self.is_trusted_origin(origin)

    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Referrer-Policy", "no-referrer")
        origin = self.headers.get("Origin")
        if origin and self.is_trusted_origin(origin) and not getattr(self, "_cors_sent", False):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
        for cookie in getattr(self, "cookie_headers", []):
            self.send_header("Set-Cookie", cookie)
        super().end_headers()

    def do_OPTIONS(self):
        self.connection.settimeout(30)
        origin = self.headers.get("Origin")
        if origin and self.is_trusted_origin(origin):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Content-Length", "0")
            self._cors_sent = True
            self.end_headers()
        else:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def set_cookie(self, value):
        self.cookie_headers = getattr(self, "cookie_headers", [])
        self.cookie_headers.append(value)

    def redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def session(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        token = cookie[COOKIE].value if COOKIE in cookie else ""
        if not token or len(token) > 4096 or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
            raise RemoteError("Sign in to open your private workspace.", 401)
        user = self.server.store.request("/auth/v1/user", token)
        if not user.get("id"):
            raise RemoteError("Please sign in again.", 401)
        return token, user

    def read_json(self, limit=3000000):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise RemoteError("JSON required", 415)
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= limit or self.headers.get("Transfer-Encoding"):
            raise ValueError("Request size is invalid")
        body = self.rfile.read(length)
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return body, data

    def send(self, data, status=200, **kwargs):
        if getattr(self, "capture", False):
            self.captured = (data, status, kwargs)
            return
        return super().send(data, status, **kwargs)

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, mutation):
        self.connection.settimeout(30)
        self.workspace_engine = None
        self.capture = False
        path = urlparse(self.path).path
        try:
            # Render probes contain no account information and do not need an origin.
            if path == "/healthz" and not mutation:
                return self.send({"status": "ok"})
            if not self.local_request():
                return self.send({"error": "This request must come from the TraceWeave website."}, 403)
            if not mutation and path in ("/", "/app.js", "/preload.js", "/style.css", "/privacy.html", "/terms.html") and not (path == "/" and parse_qs(urlparse(self.path).query).get("code")):
                return super().do_GET()
            if mutation and path == "/api/auth/logout":
                cross = self.is_cross_origin()
                samesite = CROSS_SITE_COOKIE if cross else "; SameSite=Strict"
                self.set_cookie(f"{COOKIE}=; Path=/; Secure; HttpOnly{samesite}; Max-Age=0")
                return self.send({"ok": True})
            if not mutation and path == "/api/auth/google":
                if not self.server.google_enabled:
                    return self.redirect("/?auth_error=google_unconfigured")
                verifier = b64url(os.urandom(48))
                state = b64url(os.urandom(24))
                challenge = b64url(hashlib.sha256(verifier.encode()).digest())
                self.set_cookie(f"__Host-traceweave-oauth-state={state}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
                self.set_cookie(f"__Host-traceweave-oauth-verifier={verifier}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
                return_to = parse_qs(urlparse(self.path).query).get("return_to", [""])[0]
                if return_to and self.is_trusted_return_url(return_to):
                    self.set_cookie(f"__Host-traceweave-oauth-return={b64url(return_to.encode())}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
                query = urlencode({"provider": "google", "redirect_to": self.server.origin + "/",
                    "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
                return self.redirect(self.server.store.url + "/auth/v1/authorize?" + query)
            if not mutation and path in ("/api/auth/google/callback", "/") and parse_qs(urlparse(self.path).query).get("code"):
                cookies = SimpleCookie(); cookies.load(self.headers.get("Cookie", ""))
                query = parse_qs(urlparse(self.path).query)
                state = cookies.get("__Host-traceweave-oauth-state")
                verifier = cookies.get("__Host-traceweave-oauth-verifier")
                return_cookie = cookies.get("__Host-traceweave-oauth-return")
                return_url = "/"
                if return_cookie:
                    try:
                        target = base64.urlsafe_b64decode(return_cookie.value.encode() + b"==").decode("utf-8")
                        if self.is_trusted_return_url(target):
                            return_url = target
                    except Exception:
                        pass
                if not state or not verifier or (query.get("state") and state.value != query["state"][0]) or not query.get("code"):
                    error_target = "/?auth_error=oauth"
                    if return_url != "/":
                        sep = "&" if "?" in return_url else "?"
                        error_target = f"{return_url}{sep}auth_error=oauth"
                    return self.redirect(error_target)
                result = self.server.store.request("/auth/v1/token?grant_type=pkce", body={
                    "auth_code": query["code"][0], "code_verifier": verifier.value})
                token = result.get("access_token", "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
                    error_target = "/?auth_error=oauth"
                    if return_url != "/":
                        sep = "&" if "?" in return_url else "?"
                        error_target = f"{return_url}{sep}auth_error=oauth"
                    return self.redirect(error_target)
                age = min(int(result.get("expires_in", 3600)), 3600)
                cross = self.is_cross_origin()
                samesite = CROSS_SITE_COOKIE if cross else "; SameSite=Strict"
                self.set_cookie(f"{COOKIE}={token}; Path=/; Secure; HttpOnly{samesite}; Max-Age={age}")
                self.set_cookie("__Host-traceweave-oauth-state=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
                self.set_cookie("__Host-traceweave-oauth-verifier=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
                self.set_cookie("__Host-traceweave-oauth-return=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
                return self.redirect(return_url)
            if mutation and path in ("/api/auth/login", "/api/auth/signup", "/api/auth/recover", "/api/auth/reset"):
                _, data = self.read_json(8192)
                email, password = data.get("email"), data.get("password")
                if path.endswith("recover"):
                    if not isinstance(email, str) or len(email) > 320:
                        raise ValueError("Enter your email address")
                    origin = self.headers.get("Origin")
                    redirect_target = (origin + "/") if origin and self.is_trusted_origin(origin) else (self.server.origin + "/")
                    self.server.store.request("/auth/v1/recover", body={"email": email,
                        "redirect_to": redirect_target})
                    return self.send({"message": "If an account exists for that email, a password reset link is on its way."})
                if path.endswith("reset"):
                    token = data.get("token")
                    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", token) or not isinstance(password, str) or len(password) > 1024:
                        raise ValueError("Enter a valid new password")
                    if len(password) < 8:
                        raise ValueError("Use at least 8 characters for your password")
                    self.server.store.request("/auth/v1/user", token=token, body={"password": password}, method="PUT")
                    cross = self.is_cross_origin()
                    samesite = CROSS_SITE_COOKIE if cross else "; SameSite=Strict"
                    self.set_cookie(f"{COOKIE}={token}; Path=/; Secure; HttpOnly{samesite}; Max-Age=3600")
                    return self.send({"ok": True})
                if not isinstance(email, str) or not isinstance(password, str) or len(email) > 320 or len(password) > 1024:
                    raise ValueError("Enter your email and password")
                if path.endswith("signup"):
                    if len(password) < 8:
                        raise ValueError("Use at least 8 characters for your password")
                    self.server.store.request("/auth/v1/signup", body={"email": email, "password": password})
                    return self.send({"message": "Check your email to confirm your account, then return here to sign in. If no email arrives, contact the workspace owner; Supabase restricts email delivery until an email provider is configured."})
                result = self.server.store.request("/auth/v1/token?grant_type=password", body={"email": email, "password": password})
                token = result.get("access_token", "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
                    raise RemoteError("Could not establish a session.")
                age = min(int(result.get("expires_in", 3600)), 3600)
                cross = self.is_cross_origin()
                samesite = CROSS_SITE_COOKIE if cross else "; SameSite=Strict"
                self.set_cookie(f"{COOKIE}={token}; Path=/; Secure; HttpOnly{samesite}; Max-Age={age}")
                return self.send({"ok": True})
            try:
                token, user = self.session()
            except RemoteError as exc:
                if path == "/api/session" and not mutation and exc.status == 401:
                    return self.send({"hosted": True, "authenticated": False})
                raise
            if path == "/api/session" and not mutation:
                return self.send({"hosted": True, "authenticated": True, "email": user.get("email", ""), "storage": "Supabase"})
            if path == "/api/cloud" and not mutation:
                return self.send({"hosted": True, "configured": True, "connection_verified": True,
                    "mode": "All workspace data is saved automatically to your private Supabase workspace."})
            if path == "/api/model" and not mutation:
                return super().do_GET()
            allowed = {"/api/ingest", "/api/approve", "/api/rollback"} if mutation else {"/api/state", "/api/verify", "/api/export", "/api/history"}
            if path not in allowed:
                return self.send({"error": "Not found"}, 404)
            body = None
            if mutation:
                body, _ = self.read_json()
                operation = self.headers.get("Idempotency-Key", "")
                if not re.fullmatch(r"[a-f0-9-]{36}", operation):
                    raise ValueError("A unique request ID is required")
            revision, saved = self.server.store.load(token, user["id"])
            self.workspace_engine = restore(saved)
            if mutation:
                request_hash = hashlib.sha256(path.encode() + body).hexdigest()
                prior = self.engine.db.execute("SELECT request_hash,response FROM operations WHERE id=?", (operation,)).fetchone()
                if prior:
                    if prior[0] != request_hash:
                        raise RemoteError("Request ID was already used for a different change.", 409)
                    return self.send(json.loads(prior[1]))
                self.rfile = io.BytesIO(body)
                self.capture = True
                super().do_POST()
                self.capture = False
                data, status, kwargs = self.captured
                if status == 200:
                    if len(self.engine.latest()) > 1000:
                        raise RemoteError("Online workspace limit: 1,000 logs. This upload was not saved.", 413)
                    with self.engine.db:
                        self.engine.db.execute("INSERT INTO operations VALUES(?,?,?)", (operation, request_hash, json.dumps(data)))
                        self.engine.db.execute("DELETE FROM operations WHERE rowid NOT IN (SELECT rowid FROM operations ORDER BY rowid DESC LIMIT 256)")
                    self.server.store.save(token, user["id"], revision, snapshot(self.engine))
                return self.send(data, status, **kwargs)
            return super().do_GET()
        except RemoteError as exc:
            self.capture = False
            self.send({"error": str(exc)}, exc.status)
        except (ValueError, TypeError, KeyError, RecursionError, sqlite3.Error):
            self.capture = False
            self.send({"error": "Could not read this request or workspace. No changes were saved."}, 400)
        finally:
            if self.workspace_engine is not None:
                self.workspace_engine.close()


class HostedServer(ThreadingHTTPServer):
    daemon_threads = True
    # Bound simultaneous processing and memory on the free 512 MB instance.
    slots = threading.BoundedSemaphore(4)
    public_host = ""
    origin = ""
    github_pages_origin = ""
    google_enabled = False

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    public_host = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
    if not re.fullmatch(r"[a-z0-9-]+\.onrender\.com", public_host):
        raise SystemExit("RENDER_EXTERNAL_HOSTNAME is required; use traceweave.server for local work")
    store = Store(os.environ.get("SUPABASE_URL", ""), os.environ.get("SUPABASE_PUBLIC_KEY", ""))
    server = HostedServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), HostedHandler)
    server.public_host = public_host
    server.origin = "https://" + public_host
    server.github_pages_origin = os.environ.get("GITHUB_PAGES_ORIGIN", "https://ixotic27.github.io")
    server.store = store
    server.google_enabled = os.environ.get("TRACEWEAVE_GOOGLE_ENABLED") == "1"
    print("TraceWeave online service ready", flush=True)
    info = model_info()
    print(f"Field model: {'loaded' if info['available'] else 'unavailable'}; version={info.get('version', 'none')}; inference=CPU", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
