"""Serial AT port: single-owner command execution + URC routing.

Only the ModemWorker thread may call into an ATPort — one command in flight at a
time, responses matched to the active command, unsolicited lines routed to urc_cb.
"""
import time


class ATError(Exception):
    """Final ERROR / +CMS ERROR / +CME ERROR response."""


class ATTimeout(Exception):
    """No final response within the deadline."""


FINAL_OK = "OK"
FINAL_ERRORS = ("ERROR", "+CMS ERROR:", "+CME ERROR:", "NO CARRIER", "BUSY",
                "NO ANSWER", "COMMAND NOT SUPPORT")


class ATPort:
    def __init__(self, device, baud, urc_cb, logger):
        self.device = device
        self.baud = baud
        self.urc_cb = urc_cb
        self.log = logger
        self.ser = None
        self._buf = b""

    def open(self):
        import serial                                    # lazy: keeps tests dep-free
        self.ser = serial.Serial(self.device, self.baud, timeout=0.3)
        self._buf = b""

    def close(self):
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass
            self.ser = None

    # -- low-level reading ---------------------------------------------------

    def _read_chunk(self):
        data = self.ser.read(4096)
        if data:
            self._buf += data
        return bool(data)

    def _pop_line(self):
        """Return one complete line from the buffer, or None."""
        while True:
            idx = self._buf.find(b"\n")
            if idx < 0:
                return None
            raw, self._buf = self._buf[:idx], self._buf[idx + 1:]
            line = raw.strip(b"\r").decode("utf-8", errors="replace").strip()
            if line:
                return line
            # skip empty lines, keep scanning

    def _readline(self, deadline):
        while True:
            line = self._pop_line()
            if line is not None:
                return line
            if time.monotonic() >= deadline:
                return None
            self._read_chunk()

    # -- public API ----------------------------------------------------------

    def execute(self, cmd, timeout=10.0, payload=None, payload_timeout=40.0,
                collect_extra=None):
        """Send one command, return response lines (finals excluded).

        payload: bytes written after the '>' prompt (AT+CMGS), terminated with Ctrl-Z.
        collect_extra: optional predicate(line) -> True to keep a line even though it
                       looks unsolicited (e.g. '+CMGL:' data lines).
        Raises ATError on error finals, ATTimeout on deadline.
        """
        self.ser.write((cmd + "\r").encode("ascii"))
        self.ser.flush()
        deadline = time.monotonic() + timeout

        if payload is not None:
            # Wait for the '>' prompt (arrives without a newline).
            while b">" not in self._buf:
                if time.monotonic() >= deadline:
                    raise ATTimeout(f"{cmd}: no '>' prompt")
                self._read_chunk()
                # Errors can come instead of the prompt.
                probe = self._buf.decode("utf-8", errors="replace")
                for err in FINAL_ERRORS:
                    if err in probe:
                        self._buf = b""
                        raise ATError(probe.strip())
            self._buf = self._buf[self._buf.find(b">") + 1:]
            self.ser.write(payload + b"\x1a")
            self.ser.flush()
            deadline = time.monotonic() + payload_timeout

        lines = []
        while True:
            line = self._readline(deadline)
            if line is None:
                raise ATTimeout(f"{cmd}: no final response")
            if line == cmd:                              # echo (should be off via ATE0)
                continue
            if line == FINAL_OK:
                return lines
            if any(line.startswith(e) for e in FINAL_ERRORS):
                raise ATError(line)
            if self._is_urc(line) and not (collect_extra and collect_extra(line)):
                self.urc_cb(line)
                continue
            lines.append(line)

    def drain_urcs(self, duration):
        """Read for `duration` seconds, routing every line to urc_cb."""
        deadline = time.monotonic() + duration
        while True:
            line = self._readline(deadline)
            if line is None:
                return
            self.urc_cb(line)

    URC_PREFIXES = ("+CMTI:", "+CMT:", "+CDS:", "+CBM:", "RING", "+CRING",
                    "+CREG:", "+CGREG:", "+CEREG:", "+CUSD:", "NO CARRIER", "^")

    @classmethod
    def _is_urc(cls, line):
        return any(line.startswith(p) for p in cls.URC_PREFIXES)
