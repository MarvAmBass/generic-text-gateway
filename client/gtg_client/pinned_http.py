"""HTTPS with certificate pinning — verify the peer before sending any bytes.

Modes (exactly one): explicit SHA-256 pin, TOFU (trust-on-first-use, persisted),
or classic CA verification via a CA file.
"""
import hashlib
import http.client
import os
import socket
import ssl
import urllib.parse


class PinError(Exception):
    """Peer certificate did not match the pin."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, pin=None, tofu_path=None, cafile=None,
                 timeout=30):
        super().__init__(host, port, timeout=timeout)
        self._pin = (pin or "").lower().replace(":", "")
        self._tofu_path = tofu_path
        self._cafile = cafile

    def connect(self):
        if self._cafile:
            ctx = ssl.create_default_context(cafile=self._cafile)
            self._context = ctx
            return super().connect()

        raw = socket.create_connection((self.host, self.port), self.timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # verified manually below
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        der = self.sock.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest()

        expected = self._pin or self._load_tofu()
        if expected:
            if fp != expected:
                self.close()
                raise PinError(
                    f"server certificate fingerprint mismatch: got {fp}, "
                    f"expected {expected} — refusing to talk")
        elif self._tofu_path:
            self._store_tofu(fp)
        else:
            self.close()
            raise PinError("no pin mode configured (pin, TOFU, or CA required)")

    def _load_tofu(self):
        if not self._tofu_path or not os.path.isfile(self._tofu_path):
            return None
        with open(self._tofu_path) as f:
            return f.read().strip().lower()

    def _store_tofu(self, fp):
        os.makedirs(os.path.dirname(self._tofu_path), exist_ok=True)
        tmp = self._tofu_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(fp + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._tofu_path)


class ServerConnection:
    """Factory for pinned connections to the gateway server."""

    def __init__(self, cfg):
        url = urllib.parse.urlsplit(cfg.str("SERVER_URL"))
        if url.scheme != "https":
            raise ValueError("GTC_SERVER_URL must be https://")
        self.host = url.hostname
        self.port = url.port or 8443
        self.pin = cfg.str("SERVER_PIN_SHA256")
        self.cafile = cfg.str("SERVER_CA") or None
        self.tofu_path = (os.path.join(cfg.str("STATE_DIR"), "tofu.pin")
                          if cfg.bool("SERVER_PIN_TOFU") else None)
        modes = sum(1 for m in (self.pin, self.cafile, self.tofu_path) if m)
        if modes != 1:
            raise ValueError("configure exactly one of GTC_SERVER_PIN_SHA256, "
                             "GTC_SERVER_PIN_TOFU, GTC_SERVER_CA")

    def open(self, timeout=30):
        return PinnedHTTPSConnection(self.host, self.port, pin=self.pin,
                                     tofu_path=self.tofu_path,
                                     cafile=self.cafile, timeout=timeout)
