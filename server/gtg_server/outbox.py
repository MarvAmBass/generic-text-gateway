"""Outbound message records: RAM state machine + idempotency.

queued -> sending -> submitted | failed | submission_unknown
submission_unknown is terminal here and NEVER auto-retried (PLAN.md 3.7).
"""
import collections
import threading
import time
from datetime import datetime, timezone


class Outbox:
    def __init__(self, store=None, keep=500):
        self._lock = threading.Lock()
        self._records = collections.OrderedDict()      # id -> record
        self._idem = {}                                # idempotency_key -> id
        self._next_id = 1
        self.store = store
        self.keep = keep

    def create(self, to, text, idempotency_key=None, owner=None):
        """-> (record, created_bool). Replays return the original record."""
        with self._lock:
            if idempotency_key and idempotency_key in self._idem:
                return dict(self._records[self._idem[idempotency_key]]), False
            rec = {
                "id": self._next_id,
                "to": list(to),
                "text": text,
                "state": "queued",
                "refs": [],                            # +CMGS references
                "error": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "idempotency_key": idempotency_key,
                "owner": owner,                        # principal that queued it
            }
            self._next_id += 1
            self._records[rec["id"]] = rec
            if idempotency_key:
                self._idem[idempotency_key] = rec["id"]
            while len(self._records) > self.keep:
                old_id, old = self._records.popitem(last=False)
                if old.get("idempotency_key"):
                    self._idem.pop(old["idempotency_key"], None)
            return dict(rec), True

    def update(self, rec_id, **fields):
        with self._lock:
            rec = self._records.get(rec_id)
            if rec is None:
                return None
            rec.update(fields)
            rec["updated_at"] = datetime.now(timezone.utc).isoformat()
            snapshot = dict(rec)
        if self.store is not None:
            try:
                self.store.save_outbound(snapshot)
            except OSError:
                pass
        return snapshot

    def get(self, rec_id):
        with self._lock:
            rec = self._records.get(rec_id)
            return dict(rec) if rec else None

    def public(self, rec):
        """Strip internals for API responses."""
        return {k: rec[k] for k in ("id", "to", "state", "refs", "error",
                                    "created_at") if k in rec}
