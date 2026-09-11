"""HTTPS to the gateway server — verify the peer before sending any bytes.

Verification modes (at most one may be configured explicitly):

  system  (default)              OS trust store + hostname verification, i.e. a
                                 Let's Encrypt / corporate-root certificate on
                                 the server just works, no client config.
  ca      GTC_SERVER_CA          a private CA bundle *in addition to* the OS
                                 store, for a root that isn't installed there.
  pin     GTC_SERVER_PIN_SHA256  exact certificate fingerprint — for the
                                 server's self-signed default cert.
  tofu    GTC_SERVER_PIN_TOFU    pin the first fingerprint seen, persisted.

Pinning is opt-in hardening for "I generate my own cert", not a precondition
for using the client: nothing is ever sent over an unverified connection.
"""
import hashlib
import http.client
import os
import socket
import ssl
import urllib.parse

HEX = set("0123456789abcdef")


class PinError(Exception):
    """Peer certificate did not match the pin."""


class TrustError(Exception):
    """Peer certificate did not validate against the configured trust store."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection verified by certificate pin, or by CA chain.

    Pin/TOFU mode compares sha256(DER) by hand right after the handshake and
    before any application bytes (including the auth header) are written; CA
    and system mode use a stdlib default context (chain + hostname checks).
    """

    def __init__(self, host, port, pin=None, tofu_path=None, context=None,
                 timeout=30):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pin = (pin or "").lower().replace(":", "")
        self._tofu_path = tofu_path

    def connect(self):
        if not self._pin and not self._tofu_path:
            try:
                return super().connect()          # CA / system trust store
            except ssl.SSLCertVerificationError as e:
                raise TrustError(
                    f"server certificate for {self.host} did not validate "
                    f"({e.verify_message or e}) — if the server uses its "
                    f"self-signed default certificate, set "
                    f"GTC_SERVER_PIN_SHA256 (from `gtg-server fingerprint`); "
                    f"for a private CA set GTC_SERVER_CA") from e

        raw = socket.create_connection((self.host, self.port), self.timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # verified by pin below
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
        else:
            self._store_tofu(fp)

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
    """Factory for verified connections to the gateway server."""

    def __init__(self, cfg):
        url = urllib.parse.urlsplit(cfg.str("SERVER_URL"))
        if url.scheme != "https":
            raise ValueError("GTC_SERVER_URL must be https://")
        self.host = url.hostname
        self.port = url.port or 8443
        self.pin = cfg.str("SERVER_PIN_SHA256").lower().replace(":", "")
        self.cafile = cfg.str("SERVER_CA") or None
        self.tofu_path = (os.path.join(cfg.str("STATE_DIR"), "tofu.pin")
                          if cfg.bool("SERVER_PIN_TOFU") else None)

        chosen = [name for name, on in (
            ("GTC_SERVER_PIN_SHA256", self.pin),
            ("GTC_SERVER_PIN_TOFU", self.tofu_path),
            ("GTC_SERVER_CA", self.cafile)) if on]
        if len(chosen) > 1:
            raise ValueError("configure at most one of " + ", ".join(chosen) +
                             " — leave all unset to verify against the system "
                             "trust store")
        if self.pin and (len(self.pin) != 64 or not set(self.pin) <= HEX):
            raise ValueError("GTC_SERVER_PIN_SHA256 must be a SHA-256 hex "
                             "digest (64 hex chars) — see `gtg-server "
                             "fingerprint`")
        if self.cafile and not (os.path.isfile(self.cafile) or
                                os.path.isdir(self.cafile)):
            raise ValueError(f"GTC_SERVER_CA: no such file or directory: "
                             f"{self.cafile}")

        self.mode = ("pin" if self.pin else "tofu" if self.tofu_path
                     else "ca" if self.cafile else "system")
        self._ctx = None
        if self.mode in ("ca", "system"):
            # Always the OS trust store (public CAs, company roots installed
            # system-wide); GTC_SERVER_CA adds to it rather than replacing it,
            # so a private CA does not cost you every public one. Hostname
            # verification stays on either way.
            self._ctx = ssl.create_default_context()
            self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if self.cafile:
                where = ("capath" if os.path.isdir(self.cafile) else "cafile")
                try:
                    self._ctx.load_verify_locations(**{where: self.cafile})
                except ssl.SSLError as e:
                    raise ValueError(f"GTC_SERVER_CA: {self.cafile} is not a "
                                     f"readable PEM CA bundle ({e})") from e

    def describe(self):
        """One-line description of how the peer is verified (for logs)."""
        return {
            "pin": f"certificate pin {self.pin[:16]}...",
            "tofu": f"trust-on-first-use pin ({self.tofu_path})",
            "ca": f"system trust store + CA bundle {self.cafile}",
            "system": "system trust store, hostname-verified",
        }[self.mode]

    def open(self, timeout=30):
        return PinnedHTTPSConnection(self.host, self.port, pin=self.pin,
                                     tofu_path=self.tofu_path,
                                     context=self._ctx, timeout=timeout)
