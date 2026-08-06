"""Configuration: environment > INI config file > defaults."""
import configparser
import os
import socket


class Config:
    PREFIX = "GTG_"
    SECTION = "gateway"
    DEFAULTS = {
        "SERIAL_PORT": "auto",
        "BAUD": "115200",
        "SIM_PIN": "",
        "SIM_PIN_MAX_TRIES": "1",
        "LISTEN": "localhost:8443",
        "TLS": "auto",              # auto | provided | off
        "TLS_CERT": "",
        "TLS_KEY": "",
        "TLS_SANS": "",
        "TLS_INSECURE_OK": "false",
        "TOKENS": "",
        "ALLOWED_RECIPIENTS": "",
        "DATA_DIR": "/var/lib/generic-text-gateway",
        "STORE_DIR": "",
        "RING_SIZE": "100",
        "WEBUI": "true",
        "WEBUI_USER": "",
        "WEBUI_PASS": "",
        "WEBUI_PASS_HASH": "",
        "POLL_INTERVAL": "15",
        "RECONCILE_INTERVAL": "300",
        "MAX_SUBSCRIBERS": "20",
        "SEND_RATE": "30/hour",
        "MODESWITCH": "true",
        "LOG_LEVEL": "info",
        "LOG_BODIES": "false",
        "CONFIG": "/etc/generic-text-gateway/gateway.conf",
    }

    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        vals = dict(self.DEFAULTS)
        path = env.get(self.PREFIX + "CONFIG", vals["CONFIG"])
        if path and os.path.isfile(path):
            cp = configparser.ConfigParser()
            cp.read(path)
            if cp.has_section(self.SECTION):
                for key, value in cp.items(self.SECTION):
                    ku = key.upper()
                    if ku in vals:
                        vals[ku] = value
        for key in vals:
            ev = env.get(self.PREFIX + key)
            if ev is not None:
                vals[key] = ev
        self._v = vals

        # Named principals: GTG_USER_<name> env vars / user_<name> INI keys.
        users = {}
        if path and os.path.isfile(path):
            cp = configparser.ConfigParser()
            cp.read(path)
            if cp.has_section(self.SECTION):
                for key, value in cp.items(self.SECTION):
                    if key.lower().startswith("user_"):
                        users[key[len("user_"):].lower()] = value
        user_prefix = self.PREFIX + "USER_"
        for key, value in env.items():
            if key.startswith(user_prefix) and len(key) > len(user_prefix):
                users[key[len(user_prefix):].lower()] = value
        self._users = users

    def users(self):
        """{name: 'scope:credential'} from GTG_USER_* / user_* entries."""
        return dict(self._users)

    def str(self, key):
        return self._v[key].strip()

    def int(self, key):
        return int(self._v[key])

    def bool(self, key):
        return self._v[key].strip().lower() in ("1", "true", "yes", "on")

    def list(self, key):
        raw = self._v[key].strip()
        return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

    def listen_addrs(self, key="LISTEN"):
        """Parse 'host:port,[v6]:port,...' into (host, port) tuples."""
        out = []
        for entry in self.list(key):
            if entry.startswith("["):           # [v6addr]:port
                host, _, port = entry[1:].partition("]")
                port = port.lstrip(":")
            else:
                host, _, port = entry.rpartition(":")
            if not host or not port:
                raise ValueError(f"invalid listen entry: {entry!r}")
            out.append((host, int(port)))
        return out


def resolve_binds(addrs, logger=None):
    """Resolve each (host, port) with getaddrinfo; every returned family gets a bind.

    Returns a list of (family, sockaddr) — deduplicated, order preserved.
    """
    binds, seen = [], set()
    for host, port in addrs:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                       flags=socket.AI_PASSIVE)
        except socket.gaierror as e:
            if logger:
                logger.warning("cannot resolve listen entry %s:%s: %s", host, port, e)
            continue
        for family, _, _, _, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            key = (family, sockaddr)
            if key not in seen:
                seen.add(key)
                binds.append((family, sockaddr))
    return binds


def is_loopback(sockaddr):
    host = sockaddr[0]
    return host in ("127.0.0.1", "::1") or host.startswith("127.")
