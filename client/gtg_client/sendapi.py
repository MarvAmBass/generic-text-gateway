"""Local send API for Home Assistant (and friends).

POST /v1/send   {"to": ["+15551234567"], "text": "..."}          (clean API)
POST /message   {"textMessage": {"text": "..."},                 (compat: the
                 "phoneNumbers": [...]}                           android-sms-gateway
                                                                  shape, Basic auth)
Forwards to the server's POST /v1/messages over the pinned connection with a
client-generated idempotency key; never blind-retries (ambiguous failures are
reported back to the caller as such).
"""
import base64
import hmac
import json
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import normalize_targets

MAX_BODY = 64 * 1024


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, family, sockaddr, handler):
        self.address_family = family
        super().__init__(sockaddr[:2], handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class SendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30
    server_version = "generic-text-client"
    sys_version = ""

    cfg = None
    server_conn = None      # ServerConnection factory
    log = None

    def log_message(self, fmt, *args):
        self.log.info("%s %s", self.client_address[0], fmt % args)

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        self._json(code, {"error": {"message": message}})

    def _check_auth(self):
        user, password = self.cfg.str("BASIC_USER"), self.cfg.str("BASIC_PASS")
        if not user:
            return True                       # auth disabled (warned at startup)
        header = self.headers.get("Authorization", "")
        kind, _, value = header.partition(" ")
        if kind.lower() != "basic":
            return False
        try:
            got_user, _, got_pass = base64.b64decode(value).decode().partition(":")
        except Exception:
            return False
        return (hmac.compare_digest(got_user, user)
                and hmac.compare_digest(got_pass, password))

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._error(400, "missing or oversized body")
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "body is not valid JSON")
            return None

    def do_GET(self):
        if self.path.rstrip("/") == "/health" or self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        self._error(404, "not found")

    def do_POST(self):
        if not self._check_auth():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="generic-text-client"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self.path.rstrip("/")
        data = self._read_json()
        if data is None:
            return
        if path == "/v1/send":
            to = normalize_targets(data.get("to"))
            text = data.get("text")
        elif path == "/message":
            to = normalize_targets(data.get("phoneNumbers"))
            text = (data.get("textMessage") or {}).get("text")
        else:
            return self._error(404, "not found")
        if not to:
            return self._error(400, "no recipients")
        if not isinstance(text, str) or not text.strip():
            return self._error(400, "no text")
        self._forward(to, text)

    def _forward(self, to, text):
        payload = json.dumps({"to": to, "text": text,
                              "idempotency_key": uuid.uuid4().hex}).encode()
        token = (self.cfg.str("SERVER_SEND_TOKEN")
                 or self.cfg.str("SERVER_TOKEN"))
        conn = None
        try:
            conn = self.server_conn.open(timeout=30)
            conn.request("POST", "/v1/messages", body=payload,
                         headers={"Authorization": "Bearer " + token,
                                  "Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = {"raw": body.decode(errors="replace")}
            self._json(resp.status, parsed)
        except ConnectionRefusedError as e:
            self._error(502, f"gateway server unreachable: {e}")
        except Exception as e:
            # Ambiguous — the SMS may or may not have been queued. Never retried
            # here; the idempotency key makes an explicit caller retry safe.
            self.log.error("forward failed (ambiguous): %s", e)
            self._error(502, f"forward failed (state unknown): {e}")
        finally:
            if conn is not None:
                conn.close()


def serve(cfg, server_conn, logger):
    handler = type("BoundSendHandler", (SendHandler,),
                   {"cfg": cfg, "server_conn": server_conn, "log": logger})
    if not cfg.str("BASIC_USER"):
        logger.warning("local send API has NO auth (GTC_BASIC_USER unset) — "
                       "on a host-networking box every container shares loopback!")
    servers = []
    for host, port in cfg.listen_addrs():
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                       flags=socket.AI_PASSIVE)
        except socket.gaierror as e:
            logger.warning("cannot resolve %s:%s: %s", host, port, e)
            continue
        seen = set()
        for family, _, _, _, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6) or \
                    (family, sockaddr) in seen:
                continue
            seen.add((family, sockaddr))
            try:
                srv = LocalHTTPServer(family, sockaddr, handler)
            except OSError as e:
                logger.warning("cannot bind %s: %s", sockaddr, e)
                continue
            threading.Thread(target=srv.serve_forever, daemon=True,
                             name=f"send-api-{sockaddr[0]}").start()
            logger.info("send API listening on http://%s:%s", sockaddr[0], port)
            servers.append(srv)
    if not servers:
        raise RuntimeError("could not bind any send-API address")
    return servers
