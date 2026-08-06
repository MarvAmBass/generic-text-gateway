"""Authentication: one mechanism (the Authorization header), two forms.

Bearer <token>      -> API clients; token scope from GTG_TOKENS ("scope:token,...").
Basic <user:pass>   -> web UI. With GTG_WEBUI_USER set, checks user+pass -> "all" scope.
                       Without it, any username + an API token as password grants that
                       token's scope.

No cookies, no sessions. CSRF is a non-issue (no ambient credential); mutating
endpoints additionally require Content-Type: application/json (enforced in api.py).
"""
import base64
import hmac
import threading
import time

SCOPES = ("send", "receive", "all")


def parse_tokens(spec):
    """'all:tok1,send:tok2' -> {token: scope}. Raises ValueError on bad entries."""
    tokens = {}
    for entry in [e.strip() for e in spec.split(",") if e.strip()]:
        scope, sep, token = entry.partition(":")
        if not sep or scope not in SCOPES or not token:
            raise ValueError(f"invalid GTG_TOKENS entry (want scope:token): {entry!r}")
        tokens[token] = scope
    return tokens


def _eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


class Auth:
    def __init__(self, tokens, webui_user="", webui_pass=""):
        self.tokens = tokens          # {token: scope}
        self.webui_user = webui_user
        self.webui_pass = webui_pass

    def _check_token(self, token):
        for known, scope in self.tokens.items():
            if _eq(known, token):
                return scope
        return None

    def check(self, header):
        """Authorization header value -> scope string, or None if unauthorized."""
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
            if self.webui_user:
                if _eq(user, self.webui_user) and _eq(password, self.webui_pass):
                    return "all"
                return None
            # No web UI credentials configured: accept any user + API token as password.
            return self._check_token(password)
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
