import queue
import tempfile
import unittest

from gtg_server.hub import Hub
from gtg_server.store import FileStore


def drain(sub):
    out = []
    while True:
        try:
            out.append(sub.queue.get_nowait())
        except queue.Empty:
            return out


class TestHubBroadcast(unittest.TestCase):
    def test_fanout_to_all_subscribers(self):
        hub = Hub(ring_size=10)
        s1 = hub.subscribe()
        s2 = hub.subscribe()
        hub.publish({"sender": "+15551234567", "text": "hi"})
        for sub in (s1, s2):
            events = drain(sub)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["message"]["text"], "hi")

    def test_ring_replay_with_valid_cursor(self):
        hub = Hub(ring_size=10)
        for i in range(3):
            m = hub.publish({"text": f"m{i}"})
            hub.confirm_delivered(m["id"])
        sub = hub.subscribe(after=1, stream_id=hub.stream_id)
        texts = [e["message"]["text"] for e in drain(sub)]
        self.assertEqual(texts, ["m1", "m2"])

    def test_tail_mode_without_cursor_skips_delivered(self):
        hub = Hub(ring_size=10)
        m = hub.publish({"text": "old"})
        hub.confirm_delivered(m["id"])                 # someone received it
        sub = hub.subscribe()                          # no cursor -> tail
        self.assertEqual(drain(sub), [])

    def test_wrong_stream_cursor_is_tail_mode(self):
        hub = Hub(ring_size=10)
        m = hub.publish({"text": "old"})
        hub.confirm_delivered(m["id"])
        sub = hub.subscribe(after=0, stream_id="deadbeef")
        self.assertEqual(drain(sub), [])

    def test_pending_delivered_even_in_tail_mode(self):
        hub = Hub(ring_size=10)
        hub.publish({"text": "unseen"}, modem_indices=[5])   # never confirmed
        sub = hub.subscribe()                                # tail mode
        events = drain(sub)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["message"]["text"], "unseen")

    def test_confirm_triggers_sim_delete(self):
        deleted = []
        hub = Hub(ring_size=10)
        hub.on_deliverable = deleted.append
        m = hub.publish({"text": "x"}, modem_indices=[7, 8])
        hub.confirm_delivered(m["id"])
        self.assertEqual(deleted, [[7, 8]])
        hub.confirm_delivered(m["id"])                 # idempotent
        self.assertEqual(deleted, [[7, 8]])

    def test_gap_marker_on_slow_subscriber(self):
        hub = Hub(ring_size=2000)
        sub = hub.subscribe()
        for i in range(600):                           # queue maxsize is 500
            hub.publish({"text": str(i)})
        events = drain(sub)
        kinds = {e["kind"] for e in events}
        self.assertIn("gap", kinds)
        self.assertLessEqual(len(events), 501)


class TestHubWithStore(unittest.TestCase):
    def test_durable_stream_and_replay_from_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FileStore(tmp)
            hub = Hub(ring_size=2, store=store)
            stream_id = hub.stream_id
            for i in range(5):
                hub.publish({"sender": "+15551234567", "text": f"m{i}",
                             "received_at": "2026-01-01T00:00:00"})
            # New hub, same store: stream survives, cursor stays valid,
            # messages older than the RAM ring come from the files.
            hub2 = Hub(ring_size=2, store=FileStore(tmp))
            self.assertEqual(hub2.stream_id, stream_id)
            self.assertEqual(hub2.next_id, 6)
            sub = hub2.subscribe(after=1, stream_id=stream_id)
            texts = [e["message"]["text"] for e in drain(sub)]
            self.assertEqual(texts, ["m1", "m2", "m3", "m4"])

    def test_history_paging(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FileStore(tmp)
            hub = Hub(ring_size=10, store=store)
            for i in range(10):
                hub.publish({"sender": "+15551234567", "text": f"m{i}",
                             "received_at": "2026-01-01T00:00:00"})
            page1 = store.history("inbox", None, 3)
            self.assertEqual([m["text"] for m in page1], ["m9", "m8", "m7"])
            page2 = store.history("inbox", page1[-1]["id"], 3)
            self.assertEqual([m["text"] for m in page2], ["m6", "m5", "m4"])


if __name__ == "__main__":
    unittest.main()
