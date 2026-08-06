"""Inbound SMS: CMGL/CMGR parsing, multipart reassembly, strategy selection."""
import hashlib
import time

from . import sms_codec


def message_hash(sender, scts, text):
    """Stable identity of an SMS across reads/restarts (sender + SMSC time + body)."""
    h = hashlib.sha256()
    h.update((sender or "").encode())
    h.update(b"|")
    h.update((scts or "").encode())
    h.update(b"|")
    h.update((text or "").encode())
    return h.hexdigest()[:24]


def parse_cmgl_pdu(lines):
    """'+CMGL: idx,stat,...' header + PDU line pairs -> [(index, pdu_hex)]."""
    out, idx = [], None
    for line in lines:
        if line.startswith("+CMGL:"):
            try:
                idx = int(line.split(":", 1)[1].split(",")[0].strip())
            except ValueError:
                idx = None
        elif idx is not None:
            out.append((idx, line.strip()))
            idx = None
    return out


def parse_cmgr_pdu(lines):
    """'+CMGR: stat,...' header + PDU line -> pdu_hex or None."""
    grab = False
    for line in lines:
        if line.startswith("+CMGR:"):
            grab = True
        elif grab:
            return line.strip()
    return None


def parse_cmti(line):
    """'+CMTI: "SM",5' -> (storage, index) or None."""
    if not line.startswith("+CMTI:"):
        return None
    try:
        rest = line.split(":", 1)[1]
        storage = rest.split(",")[0].strip().strip('"')
        index = int(rest.split(",")[1].strip())
        return storage, index
    except (IndexError, ValueError):
        return None


class Assembler:
    """Reassembles concatenated SMS; flushes stale partials after a timeout."""

    def __init__(self, stale_after=300.0):
        self.stale_after = stale_after
        self._parts = {}     # (sender, ref) -> {seq: (decoded, index)}, plus meta

    def add(self, decoded, index):
        """-> (message_dict, [modem_indices]) when complete/single, else None."""
        concat = decoded.get("concat")
        if not concat:
            msg = {"sender": decoded["sender"], "text": decoded["text"],
                   "scts": decoded["scts"], "partial": False}
            return msg, [index] if index is not None else []
        ref, total, seq = concat
        key = (decoded["sender"], ref, total)
        slot = self._parts.setdefault(key, {"t": time.monotonic(), "parts": {}})
        slot["parts"][seq] = (decoded, index)
        if len(slot["parts"]) == total:
            del self._parts[key]
            ordered = [slot["parts"][s] for s in sorted(slot["parts"])]
            text = "".join(d["text"] for d, _ in ordered)
            indices = [i for _, i in ordered if i is not None]
            first = ordered[0][0]
            msg = {"sender": first["sender"], "text": text,
                   "scts": first["scts"], "partial": False}
            return msg, indices
        return None

    def flush_stale(self):
        """-> list of (partial_message, indices) for incomplete sets past timeout."""
        now = time.monotonic()
        out = []
        for key in [k for k, v in self._parts.items() if now - v["t"] > self.stale_after]:
            slot = self._parts.pop(key)
            ordered = [slot["parts"][s] for s in sorted(slot["parts"])]
            text = "".join(d["text"] for d, _ in ordered)
            indices = [i for _, i in ordered if i is not None]
            first = ordered[0][0]
            out.append(({"sender": first["sender"], "text": text,
                         "scts": first["scts"], "partial": True}, indices))
        return out


def select_cnmi(port, logger):
    """Configure the receive strategy. -> 'cmti' | 'cmt' | 'poll'."""
    for setting, strategy in (("2,1,0,0,0", "cmti"), ("1,1,0,0,0", "cmti"),
                              ("2,2,0,0,0", "cmt"), ("1,2,0,0,0", "cmt")):
        try:
            port.execute(f"AT+CNMI={setting}", timeout=5)
            logger.info("receive strategy: %s (AT+CNMI=%s)", strategy, setting)
            return strategy
        except Exception:
            continue
    logger.info("receive strategy: poll (no CNMI mode accepted)")
    return "poll"


def select_storage(port, logger):
    """Prefer SIM storage; fall back to whatever the modem accepts."""
    for storage in ("SM", "ME", "MT"):
        try:
            port.execute(f'AT+CPMS="{storage}","{storage}","{storage}"', timeout=5)
            return storage
        except Exception:
            continue
    logger.warning("could not select message storage; using modem default")
    return None


def storage_usage(port):
    """-> (used, total) of the receive storage, or (None, None)."""
    try:
        lines = port.execute("AT+CPMS?", timeout=5)
    except Exception:
        return None, None
    for line in lines:
        if line.startswith("+CPMS:"):
            parts = line.split(":", 1)[1].split(",")
            try:
                return int(parts[1]), int(parts[2])
            except (IndexError, ValueError):
                return None, None
    return None, None
