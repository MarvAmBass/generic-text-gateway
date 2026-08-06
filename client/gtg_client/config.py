"""Client configuration: environment > INI config file > defaults."""
import configparser
import os


class Config:
    PREFIX = "GTC_"
    SECTION = "client"
    DEFAULTS = {
        "SERVER_URL": "",
        "SERVER_TOKEN": "",
        "SERVER_SEND_TOKEN": "",
        "SERVER_PIN_SHA256": "",
        "SERVER_PIN_TOFU": "false",
        "SERVER_CA": "",
        "HA_URL": "",
        "HA_TOKEN": "",
        "HA_EVENT": "sms_received",
        "HA_SENSOR": "sensor.sms_received",
        "LISTEN": "localhost:8082",
        "BASIC_USER": "",
        "BASIC_PASS": "",
        "STATE_DIR": "/var/lib/generic-text-client",
        "LOG_LEVEL": "info",
        "LOG_BODIES": "false",
        "CONFIG": "/etc/generic-text-client/client.conf",
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

    def str(self, key):
        return self._v[key].strip()

    def bool(self, key):
        return self._v[key].strip().lower() in ("1", "true", "yes", "on")

    def listen_addrs(self):
        out = []
        for entry in [e.strip() for e in self._v["LISTEN"].split(",") if e.strip()]:
            if entry.startswith("["):
                host, _, port = entry[1:].partition("]")
                port = port.lstrip(":")
            else:
                host, _, port = entry.rpartition(":")
            if not host or not port:
                raise ValueError(f"invalid listen entry: {entry!r}")
            out.append((host, int(port)))
        return out


def normalize_targets(target):
    """Absorb the HA template-coercion footgun: str/int/list -> ['+E164', ...]."""
    if target is None:
        return []
    if isinstance(target, (str, int)):
        target = [target]
    out = []
    for t in target:
        if t is None:
            continue
        if isinstance(t, int):
            out.append("+" + str(t))
            continue
        s = str(t).strip().replace(" ", "")
        if not s:
            continue
        if not s.startswith("+") and s.isdigit():
            s = "+" + s
        out.append(s)
    return out
