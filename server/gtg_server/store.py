"""Optional file store: one JSON file per message, no database.

Enabling GTG_STORE_DIR upgrades delivery semantics (PLAN.md 3.7): the id counter
and stream identity persist in stream.json, so subscriber cursors survive server
restarts and gaps are replayed from the files.
"""
import json
import os
import re
import threading
import uuid

_SAFE = re.compile(r"[^0-9A-Za-z+._-]")


class FileStore:
    def __init__(self, root):
        self.root = root
        self._lock = threading.Lock()
        self.inbox = os.path.join(root, "inbox")
        self.outbox = os.path.join(root, "outbox")
        os.makedirs(self.inbox, exist_ok=True)
        os.makedirs(self.outbox, exist_ok=True)
        self._stream_path = os.path.join(root, "stream.json")
        self._load_stream()
        self._index = self._build_index(self.inbox)      # sorted [(id, path)]
        self._out_index = self._build_index(self.outbox)

    # -- stream identity -----------------------------------------------------

    def _load_stream(self):
        try:
            with open(self._stream_path) as f:
                data = json.load(f)
            self._stream_id = data["stream_id"]
            self._next_id = int(data["next_id"])
        except (OSError, ValueError, KeyError):
            self._stream_id = uuid.uuid4().hex[:12]
            self._next_id = 1
            self._persist_stream(self._next_id)

    def _persist_stream(self, next_id):
        tmp = self._stream_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"stream_id": self._stream_id, "next_id": next_id}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._stream_path)

    def stream(self):
        return self._stream_id, self._next_id

    # -- saving --------------------------------------------------------------

    @staticmethod
    def _build_index(directory):
        index = []
        for name in os.listdir(directory):
            if not name.endswith(".json"):
                continue
            try:
                msg_id = int(name.rsplit("_", 1)[1].split(".")[0])
            except (IndexError, ValueError):
                continue
            index.append((msg_id, os.path.join(directory, name)))
        index.sort()
        return index

    def _filename(self, msg, msg_id, who_key):
        stamp = _SAFE.sub("", (msg.get("received_at") or "").replace(":", ""))
        who = _SAFE.sub("", (msg.get(who_key) or "unknown"))[:24]
        return f"{stamp}_{who}_{msg_id}.json"

    def _write(self, directory, name, payload):
        path = os.path.join(directory, name)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(payload, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return path

    def save_inbound(self, msg, next_id):
        """Persist message + advance the durable id counter. Called under hub lock."""
        with self._lock:
            path = self._write(self.inbox, self._filename(msg, msg["id"], "sender"), msg)
            self._index.append((msg["id"], path))
            self._next_id = next_id
            self._persist_stream(next_id)

    def save_outbound(self, record):
        with self._lock:
            name = self._filename(
                {"received_at": record.get("created_at"),
                 "to": ",".join(record.get("to", []))},
                record["id"], "to")
            path = self._write(self.outbox, name, record)
            self._out_index = [e for e in self._out_index if e[0] != record["id"]]
            self._out_index.append((record["id"], path))
            self._out_index.sort()

    # -- reading -------------------------------------------------------------

    def replay_after(self, after_id, before_id):
        """Inbound messages with after_id < id < before_id, ascending."""
        out = []
        with self._lock:
            entries = [e for e in self._index if after_id < e[0] < before_id]
        for _, path in entries:
            try:
                with open(path) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                continue
        return out

    def history(self, box="inbox", before=None, limit=50):
        """Newest-first page. `before`/`limit` are validated ints — client input
        never reaches the filesystem layer as a path."""
        limit = max(1, min(int(limit), 200))
        with self._lock:
            index = self._index if box == "inbox" else self._out_index
            entries = [e for e in index if before is None or e[0] < before]
            entries = entries[-limit:]
        out = []
        for _, path in reversed(entries):
            try:
                with open(path) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                continue
        return out
