"""Authentication: one mechanism (the Authorization header), two forms.

Bearer <token>      -> API clients; token scope from GTG_TOKENS ("scope:token,...").
Basic <user:pass>   -> web UI. With GTG_WEBUI_USER set, checks user+pass -> "all" scope.
                       Without it, any username + an API token as password grants that
                       token's scope.

Hashed at-rest storage (recommended — no plaintext secrets in config):
- token entries may be "scope:sha256:<64-hex>" (hash of the token; tokens are
  high-entropy random strings, so an unsalted fast hash is appropriate);
- the web UI password may be stored as GTG_WEBUI_PASS_HASH =
  "pbkdf2_sha256$<iterations>$<salt-hex>$<dk-hex>" (generate with
  `gtg-server hash-password`). Verified credentials are cached in memory (as
  hashes) so per-request Basic auth doesn't re-run the KDF every time.

No cookies, no sessions. CSRF is a non-issue (no ambient credential); mutating
endpoints additionally require Content-Type: application/json (enforced in api.py).
"""
import base64
import hashlib
import hmac
import os
import threading
import time

SCOPES = ("send", "receive", "all")
PBKDF2_ITERATIONS = 210_000


class Principal:
    """A named user or system identity with one credential and one scope."""

    __slots__ = ("name", "scope", "kind", "secret")

    def __init__(self, name, scope, kind, secret):
        self.name = name
        self.scope = scope
        self.kind = kind          # "pbkdf2" | "sha256" | "plain"
        self.secret = secret


def parse_users(pairs):
    """{name: "scope:credential"} -> [Principal].

    Credential forms: 'pbkdf2_sha256$...' (Basic-auth password hash),
    'sha256:<64-hex>' (hashed token), anything else = plaintext token.
    """
    principals = []
    for name, value in sorted(pairs.items()):
        scope, sep, cred = value.strip().partition(":")
        if not sep or scope not in SCOPES or not cred:
            raise ValueError(
                f"invalid GTG_USER_{name} (want scope:credential): {value!r}")
        if cred.startswith("pbkdf2_sha256$"):
            kind = "pbkdf2"
        elif cred.startswith("sha256:"):
            cred = cred[len("sha256:"):].lower()
            if len(cred) != 64 or any(c not in "0123456789abcdef" for c in cred):
                raise ValueError(f"invalid sha256 hash for user {name}")
            kind = "sha256"
        else:
            kind = "plain"
        principals.append(Principal(name, scope, kind, cred))
    return principals


def parse_tokens(spec):
    """'all:tok1,send:sha256:<hex>' -> ({token: scope}, {sha256hex: scope})."""
    plain, hashed = {}, {}
    for entry in [e.strip() for e in spec.split(",") if e.strip()]:
        scope, sep, token = entry.partition(":")
        if not sep or scope not in SCOPES or not token:
            raise ValueError(f"invalid GTG_TOKENS entry (want scope:token): {entry!r}")
        if token.startswith("sha256:"):
            digest = token[len("sha256:"):].lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"invalid sha256 token hash in entry: {entry!r}")
            hashed[digest] = scope
        else:
            plain[token] = scope
    return plain, hashed


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password, iterations=PBKDF2_ITERATIONS, salt=None):
    salt = salt if salt is not None else os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password, encoded):
    try:
        algo, iterations, salt_hex, dk_hex = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


def _eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


class Auth:
    def __init__(self, tokens=None, webui_user="", webui_pass="",
                 webui_pass_hash="", users=None):
        tokens = tokens if tokens is not None else ({}, {})
        if isinstance(tokens, dict):          # backwards-compatible: plain dict
            tokens = (tokens, {})
        self.tokens, self.hashed_tokens = tokens
        self.users = list(users or [])        # [Principal]
        self.webui_user = webui_user
        self.webui_pass = webui_pass
        self.webui_pass_hash = webui_pass_hash
        self._kdf_cache = set()               # sha256 of verified name|pass pairs
        self._kdf_lock = threading.Lock()

    def _check_token(self, token):
        """Bearer-style secret -> (name, scope) or None. Never matches pbkdf2
        credentials (passwords are Basic-only; no username to attribute)."""
        for known, scope in self.tokens.items():
            if _eq(known, token):
                return "token", scope
        digest = hash_token(token)
        for known, scope in self.hashed_tokens.items():
            if _eq(known, digest):
                return "token", scope
        for p in self.users:
            if p.kind == "plain" and _eq(p.secret, token):
                return p.name, p.scope
            if p.kind == "sha256" and _eq(p.secret, digest):
                return p.name, p.scope
        return None

    def _kdf_verify(self, name, password, encoded):
        key = hashlib.sha256(f"{name}\x00{password}".encode()).hexdigest()
        with self._kdf_lock:
            if key in self._kdf_cache:
                return True
        if verify_password(password, encoded):
            with self._kdf_lock:
                self._kdf_cache.add(key)
                if len(self._kdf_cache) > 32:
                    self._kdf_cache.clear()
            return True
        return False

    def _check_basic(self, user, password):
        """-> (name, scope) or None."""
        known_name = False
        for p in self.users:
            if not _eq(p.name, user):
                continue
            known_name = True
            if p.kind == "pbkdf2" and self._kdf_verify(p.name, password, p.secret):
                return p.name, p.scope
            if p.kind == "sha256" and _eq(p.secret, hash_token(password)):
                return p.name, p.scope
            if p.kind == "plain" and _eq(p.secret, password):
                return p.name, p.scope
        if known_name:
            # a known username binds strictly to its own credential — no fallback
            return None
        if self.webui_user and _eq(user, self.webui_user) and \
                self._check_webui_password(password):
            return self.webui_user, "all"
        if not self.webui_user:
            # unknown username + a valid token as the password (browser token login)
            return self._check_token(password)
        return None

    def _check_webui_password(self, password):
        if self.webui_pass_hash:
            return self._kdf_verify(self.webui_user, password, self.webui_pass_hash)
        return bool(self.webui_pass) and _eq(password, self.webui_pass)

    def check(self, header):
        """Authorization header value -> (name, scope), or None if unauthorized."""
        if not header:
            return None
        kind, _, value = header.partition(" ")
        kind, value = kind.strip().lower(), value.strip()
        if kind == "bearer" and value:
            return self._check_token(value)
        if kind == "basic" and value:
            try:
                user, _, password = base64.b64decode(value).decode("utf-8").partition(":")
            except Exception:
                return None
            return self._check_basic(user, password)
        return None

    @staticmethod
    def allows(scope, need):
        return scope == "all" or scope == need


class Backoff:
    """Per-client-IP exponential backoff on auth failures (in-memory)."""

    def __init__(self, base=2.0, cap=300.0):
        self.base = base
        self.cap = cap
        self._lock = threading.Lock()
        self._state = {}              # ip -> (fail_count, blocked_until_monotonic)

    def blocked_for(self, ip):
        """Seconds the ip is still blocked, or 0."""
        with self._lock:
            _, until = self._state.get(ip, (0, 0.0))
            return max(0.0, until - time.monotonic())

    def fail(self, ip):
        with self._lock:
            count, _ = self._state.get(ip, (0, 0.0))
            count += 1
            delay = 0.0 if count < 3 else min(self.base ** (count - 2), self.cap)
            self._state[ip] = (count, time.monotonic() + delay)
            if len(self._state) > 10000:      # bound memory
                self._state.clear()

    def ok(self, ip):
        with self._lock:
            self._state.pop(ip, None)


class RateLimit:
    """Sliding-window rate limit from a 'N/minute|hour|day' spec. '0' disables."""

    PERIODS = {"minute": 60, "hour": 3600, "day": 86400}

    def __init__(self, spec):
        spec = spec.strip()
        if spec in ("", "0", "off"):
            self.n = 0
        else:
            n, _, period = spec.partition("/")
            if period not in self.PERIODS:
                raise ValueError(f"invalid rate spec: {spec!r}")
            self.n = int(n)
            self.window = self.PERIODS[period]
        self._lock = threading.Lock()
        self._events = []             # monotonic timestamps

    def allow(self, count=1):
        if self.n <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            self._events = [t for t in self._events if now - t < self.window]
            if len(self._events) + count > self.n:
                return False
            self._events.extend([now] * count)
            return True
