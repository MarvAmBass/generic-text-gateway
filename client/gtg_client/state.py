"""Durable client state: cursor (stream_id + last id) and the processed journal.

The journal stores stable message *hashes* (sender + SMSC timestamp + body, computed
server-side) rather than ids — ids reset when a store-less server restarts, hashes
don't, so replays are caught even across stream resets.

Mark-then-fire: a hash is journaled BEFORE the HA event is posted; a crash between
journal-write and HA-POST drops that one message instead of doubling it.
"""
import json
import os

JOURNAL_KEEP = 500


class State:
    def __init__(self, state_dir):
        self.path = os.path.join(state_dir, "state.json")
        os.makedirs(state_dir, exist_ok=True)
        self.stream_id = None
        self.last_id = None
        self.journal = []               # newest last
        self._journal_set = set()
        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.stream_id = data.get("stream_id")
            self.last_id = data.get("last_id")
            self.journal = list(data.get("journal", []))[-JOURNAL_KEEP:]
            self._journal_set = set(self.journal)
        except (OSError, ValueError):
            pass

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"stream_id": self.stream_id, "last_id": self.last_id,
                       "journal": self.journal[-JOURNAL_KEEP:]}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def on_hello(self, stream_id):
        """New stream id -> invalidate the cursor (tail mode next reconnect)."""
        if stream_id != self.stream_id:
            self.stream_id = stream_id
            self.last_id = None
            self._save()

    def seen(self, msg_hash):
        return msg_hash in self._journal_set

    def mark(self, msg_hash):
        """Journal a hash BEFORE firing HA (mark-then-fire)."""
        if msg_hash in self._journal_set:
            return
        self.journal.append(msg_hash)
        self._journal_set.add(msg_hash)
        if len(self.journal) > JOURNAL_KEEP:
            for old in self.journal[:-JOURNAL_KEEP]:
                self._journal_set.discard(old)
            self.journal = self.journal[-JOURNAL_KEEP:]
        self._save()

    def advance(self, msg_id):
        self.last_id = msg_id
        self._save()
