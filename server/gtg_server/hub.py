"""Broadcast hub: fan-out to every subscriber, RAM replay ring, pending queue.

Semantics (PLAN.md 3.7):
- every inbound message goes to ALL connected subscribers;
- ring replays for reconnects with a valid cursor (Last-Event-ID);
- a message never delivered to anyone stays "pending" and is handed to the next
  subscriber even in tail mode;
- with no file store, deletion-from-SIM happens only after >=1 subscriber actually
  received the message (api.py confirms after the socket write).
"""
import collections
import queue
import threading
import uuid


class Subscriber:
    def __init__(self, maxsize=500):
        self.queue = queue.Queue(maxsize=maxsize)
        self.gapped = False

    def offer(self, event):
        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            if not self.gapped:
                self.gapped = True
                try:                       # drop one queued item to make room
                    self.queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self.queue.put_nowait({"kind": "gap"})
                except queue.Full:
                    pass
            return False


class Hub:
    def __init__(self, ring_size=100, store=None, on_deliverable=None):
        """on_deliverable(modem_indices) is called once a message with no store
        backing has been received by at least one subscriber (SIM delete hook)."""
        self._lock = threading.Lock()
        self.ring = collections.deque(maxlen=ring_size)
        self.subs = set()
        self.store = store
        self.on_deliverable = on_deliverable
        self.pending = {}                    # id -> (message, modem_indices)
        if store is not None:
            self.stream_id, self.next_id = store.stream()
        else:
            self.stream_id, self.next_id = uuid.uuid4().hex[:12], 1

    # -- publishing ----------------------------------------------------------

    def publish(self, msg, modem_indices=None):
        """Assign an id, persist (if store), fan out. Returns the message dict."""
        with self._lock:
            msg = dict(msg)
            msg["id"] = self.next_id
            self.next_id += 1
            if self.store is not None:
                self.store.save_inbound(msg, self.next_id)
            else:
                self.pending[msg["id"]] = (msg, modem_indices or [])
            self.ring.append(msg)
            subs = list(self.subs)
        event = {"kind": "message", "message": msg}
        for sub in subs:
            sub.offer(event)
        return msg

    def confirm_delivered(self, msg_id):
        """Called by the API layer after an SSE socket write succeeded."""
        with self._lock:
            entry = self.pending.pop(msg_id, None)
        if entry and self.on_deliverable:
            _, indices = entry
            self.on_deliverable(indices)

    def broadcast(self, event):
        """Non-message events (health, ...) — best effort, no pending tracking."""
        with self._lock:
            subs = list(self.subs)
        for sub in subs:
            sub.offer(event)

    # -- subscribing ---------------------------------------------------------

    def subscribe(self, after=None, stream_id=None):
        """after: last seen id (Last-Event-ID); stream_id: the stream it belongs to.

        Replay rules:
        - cursor from another stream (or none) -> tail mode: no ring replay;
        - valid cursor -> replay ring/store messages with id > after;
        - pending (never-delivered) messages are ALWAYS enqueued.
        """
        sub = Subscriber()
        with self._lock:
            replay = []
            valid_cursor = (after is not None and stream_id == self.stream_id
                            and 0 <= after < self.next_id)
            if valid_cursor:
                ring_ids = {m["id"] for m in self.ring}
                if self.store is not None:
                    oldest_ring = min(ring_ids) if ring_ids else self.next_id
                    if after < oldest_ring - 1:
                        replay.extend(self.store.replay_after(after, oldest_ring))
                replay.extend(m for m in self.ring if m["id"] > after)
            pending_msgs = [m for m, _ in self.pending.values()]
            replay_ids = {m["id"] for m in replay}
            for msg in sorted(pending_msgs, key=lambda m: m["id"]):
                if msg["id"] not in replay_ids:
                    replay.append(msg)
            replay.sort(key=lambda m: m["id"])
            for msg in replay:
                sub.offer({"kind": "message", "message": msg})
            self.subs.add(sub)
        return sub

    def unsubscribe(self, sub):
        with self._lock:
            self.subs.discard(sub)

    def stats(self):
        with self._lock:
            return {"subscribers": len(self.subs), "pending": len(self.pending),
                    "ring": len(self.ring), "stream_id": self.stream_id,
                    "next_id": self.next_id}
