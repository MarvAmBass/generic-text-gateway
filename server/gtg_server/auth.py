"""Authentication: named principals, one mechanism (the Authorization header).

Every human and every system gets its own identity via GTG_USER_<name> =
"scope:credential" — individually revocable, attributed in logs. Credential kinds:

- pbkdf2_sha256$<iter>$<salt>$<dk>  -> password hash (humans, Basic auth only;
                                       generate with `gtg-server hash-password`)
- sha256:<64-hex>                   -> hashed token (systems, Bearer or Basic)
- anything else                     -> plaintext token (systems, Bearer or Basic)

Bearer <secret> matches token credentials (never password hashes — no username to
attribute). Basic <name>:<secret> matches that principal's own credential only.
Verified passwords are cached in memory (as hashes) so per-request Basic auth
doesn't re-run the KDF.

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
    """{name: "scope:credential"} -> [Principal]."""
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
    def __init__(self, users):
        self.users = list(users)              # [Principal]
        self._kdf_cache = set()               # sha256 of verified name|pass pairs
        self._kdf_lock = threading.Lock()

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

    def _check_token(self, token):
        """Bearer secret -> (name, scope) or None. Never matches pbkdf2."""
        digest = hash_token(token)
        for p in self.users:
            if p.kind == "plain" and _eq(p.secret, token):
                return p.name, p.scope
            if p.kind == "sha256" and _eq(p.secret, digest):
                return p.name, p.scope
        return None

    def _check_basic(self, user, password):
        """Basic name:secret -> (name, scope) or None. Strict name binding."""
        for p in self.users:
            if not _eq(p.name, user):
                continue
            if p.kind == "pbkdf2" and self._kdf_verify(p.name, password, p.secret):
                return p.name, p.scope
            if p.kind == "sha256" and _eq(p.secret, hash_token(password)):
                return p.name, p.scope
            if p.kind == "plain" and _eq(p.secret, password):
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
