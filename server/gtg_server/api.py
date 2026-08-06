"""HTTPS API + embedded web UI. Stdlib ThreadingHTTPServer, one per bind address.

Auth: Authorization header only — Bearer <token> or Basic <user:pass> (PLAN.md 3.8).
No cookies, no sessions. Mutating endpoints require Content-Type: application/json.
"""
import json
import os
import queue
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .config import is_loopback
from .modem import sms_codec

MAX_BODY = 64 * 1024
MAX_TEXT_LEN = 5000
SSE_HEARTBEAT = 15.0
E164_RE = re.compile(r"\+?[0-9]{3,20}")


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, family, sockaddr, handler, ctx):
        self.address_family = family
        self.tls_ctx = ctx
        super().__init__(sockaddr[:2], handler)

    def get_request(self):
        """Accept, then hand the raw socket to the worker thread.

        The TLS handshake must NOT happen here: wrapping the *listening* socket
        makes accept() perform the handshake in the single serve_forever loop,
        so one client that connects and sends nothing blocks every other request
        indefinitely. Handshaking in the per-connection thread puts it under the
        handler's socket timeout instead.
        """
        sock, addr = self.socket.accept()
        sock.settimeout(Handler.timeout)
        if self.tls_ctx is not None:
            # do_handshake_on_connect=False: the handshake is deferred to the
            # first read, which happens in the per-connection thread under the
            # timeout set above — get_request() itself still runs in the accept
            # loop, so it must not block here.
            sock = self.tls_ctx.wrap_socket(sock, server_side=True,
                                            do_handshake_on_connect=False)
        return sock, addr

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        # Aborted TLS handshakes (e.g. a client refusing our cert pin) and
        # dropped connections are routine — don't spray tracebacks.
        import ssl
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


class ApiState:
    """Shared state handed to every request handler."""

    def __init__(self, cfg, hub, outbox, worker, auth, backoff, rate, store,
                 logger):
        self.cfg = cfg
        self.hub = hub
        self.outbox = outbox
        self.worker = worker
        self.auth = auth
        self.backoff = backoff
        self.rate = rate
        self.store = store
        self.log = logger
        self.subscriber_count = 0
        self.sub_lock = threading.Lock()
        self.webui_html = self._load_webui() if cfg.bool("WEBUI") else None
        self.allowed_recipients = cfg.list("ALLOWED_RECIPIENTS")

    @staticmethod
    def _load_webui():
        path = os.path.join(os.path.dirname(__file__), "webui", "index.html")
        with open(path, encoding="utf-8") as f:
            return f.read().encode("utf-8")

    def recipient_allowed(self, number):
        if not self.allowed_recipients:
            return True
        return any(number.startswith(p) for p in self.allowed_recipients)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30                    # slowloris guard: socket read timeout
    server_version = "generic-text-gateway"
    sys_version = ""

    # `state` is attached via a subclass created in serve()
    state: ApiState = None

    # -- plumbing ------------------------------------------------------------

    def log_message(self, fmt, *args):
        self.state.log.info("%s %s", self.client_address[0], fmt % args)

    def log_error(self, fmt, *args):
        # BaseHTTPRequestHandler's malformed-request errors echo the raw request
        # line/body — which for POST /v1/sim/pin would put the SIM PIN in the
        # log. Log the fact, never the content.
        self.state.log.warning("%s malformed request rejected",
                               self.client_address[0])

    def _client_ip(self):
        return self.client_address[0]

    def _json(self, code, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, err_code, message, extra_headers=None):
        # Don't try to reuse a connection whose request body we may not have
        # drained — it would desync any proxy placed in front of the gateway.
        self.close_connection = True
        self._json(code, {"error": {"code": err_code, "message": message}},
                   extra_headers)

    def _read_json(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._error(415, "unsupported_media_type",
                        "Content-Type must be application/json")
            return None
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._error(400, "bad_request", "missing or oversized body")
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "bad_json", "body is not valid JSON")
            return None
        if not isinstance(data, dict):
            self._error(400, "bad_json", "body must be a JSON object")
            return None
        return data

    def _authorize(self, need):
        """-> (name, scope) or None (response already sent)."""
        ip = self._client_ip()
        blocked = self.state.backoff.blocked_for(ip)
        if blocked > 0:
            self._error(429, "too_many_attempts", "try again later",
                        {"Retry-After": str(int(blocked) + 1)})
            return None
        ident = self.state.auth.check(self.headers.get("Authorization"))
        if ident is None:
            self.state.backoff.fail(ip)
            self._error(401, "unauthorized", "authentication required",
                        {"WWW-Authenticate": 'Basic realm="generic-text-gateway"'})
            return None
        self.state.backoff.ok(ip)
        if not self.state.auth.allows(ident[1], need):
            self._error(403, "forbidden",
                        f"'{ident[0]}' lacks the '{need}' scope")
            return None
        return ident

    # -- routing -------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/healthz":
            return self._json(200, {"status": "ok"})
        if path in ("/", "/ui") and self.state.webui_html is not None:
            return self._serve_webui()
        if path == "/v1/health":
            ident = self._any_scope()
            if ident:
                return self._health(ident)
            return None
        if path == "/v1/modem":
            # IMEI/serial are durable subscriber identifiers — 'all' only.
            if self._authorize("all") is not None:
                return self._json(200, {"modem": self.state.worker.modem_info,
                                        "port": self.state.worker.port_info})
            return None
        if path == "/v1/subscribe":
            if self._authorize("receive") is not None:
                return self._subscribe()
            return None
        if path == "/v1/history":
            if self._authorize("receive") is not None:
                return self._history()
            return None
        if path.startswith("/v1/messages/"):
            ident = self._authorize("send")
            if ident is not None:
                return self._get_message(path, ident)
            return None
        self._error(404, "not_found", "unknown endpoint")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "/v1/messages":
            ident = self._authorize("send")
            if ident is not None:
                return self._send_message(ident)
            return None
        if path == "/v1/sim/pin":
            ident = self._authorize("all")
            if ident is not None:
                return self._sim_pin(ident)
            return None
        self._error(404, "not_found", "unknown endpoint")

    def _any_scope(self):
        """Any valid credential is enough (health/modem/UI).

        The backoff must be consulted BEFORE the credential is evaluated —
        otherwise these routes both skip brute-force throttling and let an
        unauthenticated client burn a PBKDF2 verification per request.
        """
        if self.state.backoff.blocked_for(self._client_ip()) > 0:
            return self._authorize("receive")           # emits 429, no KDF run
        ident = self.state.auth.check(self.headers.get("Authorization"))
        if ident is None:
            return self._authorize("receive")           # emits 401 + backoff
        self.state.backoff.ok(self._client_ip())
        return ident

    # -- endpoints -----------------------------------------------------------

    def _serve_webui(self):
        # The UI itself requires auth so the 401 triggers the browser's
        # native Basic prompt; afterwards fetch/EventSource inherit the creds.
        if self._any_scope() is None:
            return
        body = self.state.webui_html
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; "
                         "style-src 'unsafe-inline'; connect-src 'self'; "
                         "img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _health(self, ident):
        health = self.state.worker.health()
        health["hub"] = self.state.hub.stats()
        health["store_enabled"] = self.state.store is not None
        health["version"] = __version__
        state = health.get("state")
        health["status"] = ("ok" if state == "ready" else
                            "degraded" if state in ("registering", "starting",
                                                    "sim_pin_required") else "down")
        if ident[1] != "all":
            # Low-scope principals get operational state only: no IMEI/serial
            # (durable subscriber identifiers) and no raw error text (host paths).
            for key in ("modem", "port", "last_error"):
                health.pop(key, None)
        self._json(200, health)

    def _get_message(self, path, ident):
        try:
            rec_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return self._error(400, "bad_request", "message id must be an integer")
        rec = self.state.outbox.get(rec_id)
        # Principals only see their own outbound records (404, not 403, so the
        # id space isn't enumerable); 'all' scope sees everything.
        if rec is None or (ident[1] != "all" and rec.get("owner") != ident[0]):
            return self._error(404, "not_found", "no such message")
        self._json(200, self.state.outbox.public(rec))

    def _send_message(self, ident):
        data = self._read_json()
        if data is None:
            return
        to = data.get("to")
        text = data.get("text")
        if isinstance(to, str):
            to = [to]
        if not isinstance(to, list) or not to or \
                not all(isinstance(n, str) and n.strip() for n in to):
            return self._error(400, "bad_request", "'to' must be a non-empty list")
        if not isinstance(text, str) or not text.strip():
            return self._error(400, "bad_request", "'text' must be a non-empty string")
        if len(text) > MAX_TEXT_LEN:
            return self._error(400, "bad_request", f"text longer than {MAX_TEXT_LEN}")
        to = [n.strip() for n in to]
        # Strict E.164-ish validation, mode-independent: the text-mode AT path
        # interpolates the number into a command line, so anything but digits
        # would be AT command injection (CR/LF, quotes, Ctrl-Z).
        if not all(E164_RE.fullmatch(n) for n in to):
            return self._error(400, "bad_request",
                               "recipients must be +?<3-20 digits>")
        for number in to:
            if not self.state.recipient_allowed(number):
                return self._error(403, "recipient_not_allowed",
                                   f"recipient not in allowlist: {number}")
        idem = data.get("idempotency_key") or None
        if idem is not None and not isinstance(idem, str):
            return self._error(400, "bad_request",
                               "idempotency_key must be a string")
        # Charge the rate limit per SMS segment, not per recipient: one 5000-char
        # non-GSM7 message is ~75 billable segments.
        try:
            segments = sum(len(sms_codec.build_submit_pdus(n, text)) for n in to)
        except ValueError:
            return self._error(400, "bad_request", "message cannot be encoded")
        if not self.state.rate.allow(segments):
            return self._error(429, "rate_limited", "send rate limit exceeded",
                               {"Retry-After": "60"})
        health = self.state.worker.health()
        if health["state"] not in ("ready", "registering"):
            return self._error(503, "modem_unavailable",
                               f"modem state: {health['state']}",
                               {"Retry-After": "30"})
        rec, created = self.state.outbox.create(to, text, idem, owner=ident[0])
        if created:
            self.state.log.info("outbound #%s queued by '%s' (%d recipient(s))",
                                rec["id"], ident[0], len(to))
            self.state.worker.submit_send(rec["id"])
        self._json(202 if created else 200, self.state.outbox.public(rec))

    def _sim_pin(self, ident):
        self.state.log.warning("runtime SIM PIN submission by '%s'", ident[0])
        worker = self.state.worker
        cap = self.state.cfg.int("SIM_PIN_MAX_TRIES") + 2
        if self.state.cfg.str("SIM_PIN"):
            return self._error(409, "pin_configured",
                               "GTG_SIM_PIN is configured; runtime entry disabled")
        if worker.pin_submissions >= cap:
            return self._error(423, "pin_locked",
                               "runtime PIN submission cap reached; restart the "
                               "server to try again")
        if worker.health()["sim"] != "pin_required":
            return self._error(409, "pin_not_required",
                               f"SIM state is {worker.health()['sim']}")
        data = self._read_json()
        if data is None:
            return
        pin = data.get("pin", "")
        if not isinstance(pin, str) or not pin.isdigit() or not 4 <= len(pin) <= 8:
            return self._error(400, "bad_pin", "pin must be 4-8 digits")
        reply = worker.submit_pin(pin)
        try:
            result = reply.get(timeout=25)
        except queue.Empty:
            return self._error(504, "pin_timeout", "modem did not answer in time")
        remaining = max(0, cap - worker.pin_submissions)
        self._json(200 if result == "ready" else 422,
                   {"sim": result, "runtime_submissions_left": remaining})

    def _history(self):
        if self.state.store is None:
            return self._error(404, "no_store",
                               "message store is disabled (GTG_STORE_DIR unset)")
        params = _query(self.path)
        box = params.get("box", "inbox")
        if box not in ("inbox", "outbox"):
            return self._error(400, "bad_request", "box must be inbox or outbox")
        try:
            before = int(params["before"]) if "before" in params else None
            limit = int(params.get("limit", 50))
        except ValueError:
            return self._error(400, "bad_request", "before/limit must be integers")
        self._json(200, {"messages": self.state.store.history(box, before, limit)})

    # -- SSE -----------------------------------------------------------------

    def _subscribe(self):
        st = self.state
        with st.sub_lock:
            if st.subscriber_count >= st.cfg.int("MAX_SUBSCRIBERS"):
                return self._error(503, "too_many_subscribers",
                                   "subscriber limit reached", {"Retry-After": "30"})
            st.subscriber_count += 1
        sub = None
        try:
            params = _query(self.path)
            after = None
            raw = self.headers.get("Last-Event-ID") or params.get("after")
            if raw is not None:
                try:
                    after = int(raw)
                except ValueError:
                    after = None
            client_stream = (self.headers.get("X-Stream-Id")
                             or params.get("stream") or None)
            sub = st.hub.subscribe(after=after, stream_id=client_stream)

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            hello = {"stream_id": st.hub.stream_id,
                     "store_enabled": st.store is not None}
            self._sse_write("hello", None, hello)

            while True:
                try:
                    event = sub.queue.get(timeout=SSE_HEARTBEAT)
                except queue.Empty:
                    self.wfile.write(b": hb\n\n")
                    self.wfile.flush()
                    continue
                kind = event["kind"]
                if kind == "message":
                    msg = event["message"]
                    self._sse_write("message", msg["id"], msg)
                    st.hub.confirm_delivered(msg["id"])
                elif kind == "gap":
                    self._sse_write("gap", None, {"reason": "subscriber_too_slow"})
                elif kind == "health":
                    self._sse_write("health", None, event["health"])
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            pass
        finally:
            if sub is not None:
                st.hub.unsubscribe(sub)
            with st.sub_lock:
                st.subscriber_count -= 1

    def _sse_write(self, event, event_id, data):
        chunk = f"event: {event}\n"
        if event_id is not None:
            chunk += f"id: {event_id}\n"
        chunk += f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
        self.wfile.write(chunk.encode("utf-8"))
        self.wfile.flush()


def _query(path):
    params = {}
    if "?" in path:
        for pair in path.split("?", 1)[1].split("&"):
            key, _, value = pair.partition("=")
            if key:
                params[key] = value
    return params


def serve(state, binds, ctx, logger):
    """Start one HTTP server per bind. Returns the server list (already serving)."""
    handler = type("BoundHandler", (Handler,), {"state": state})
    servers = []
    for family, sockaddr in binds:
        try:
            srv = GatewayHTTPServer(family, sockaddr, handler, ctx)
        except OSError as e:
            logger.warning("cannot bind %s: %s", sockaddr, e)
            continue
        loop = threading.Thread(target=srv.serve_forever, daemon=True,
                                name=f"http-{sockaddr[0]}")
        loop.start()
        scheme = "https" if ctx else "http"
        host = f"[{sockaddr[0]}]" if family == socket.AF_INET6 else sockaddr[0]
        logger.info("listening on %s://%s:%s", scheme, host, sockaddr[1])
        servers.append(srv)
    if not servers:
        raise RuntimeError("could not bind any listen address")
    return servers


def check_plaintext_binds(cfg, binds):
    """Refuse plaintext on non-loopback binds unless explicitly allowed."""
    if cfg.str("TLS") != "off" or cfg.bool("TLS_INSECURE_OK"):
        return
    for _, sockaddr in binds:
        if not is_loopback(sockaddr):
            raise RuntimeError(
                f"GTG_TLS=off with non-loopback bind {sockaddr[0]} — set "
                "GTG_TLS_INSECURE_OK=true only if you really mean it")
