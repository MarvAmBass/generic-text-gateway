import io
import tempfile
import unittest

from gtg_client.config import normalize_targets
from gtg_client.relay import SSEReader, message_hash
from gtg_client.state import State


class TestNormalize(unittest.TestCase):
    def test_int_coercion_bug(self):
        # HA's native-type templating turns "+15551234567" into an int.
        self.assertEqual(normalize_targets(15551234567), ["+15551234567"])

    def test_string_and_list(self):
        self.assertEqual(normalize_targets("+15551234567"), ["+15551234567"])
        self.assertEqual(normalize_targets(["15551234567", "+15557654321"]),
                         ["+15551234567", "+15557654321"])

    def test_spaces_and_empty(self):
        self.assertEqual(normalize_targets(["+1 555 123 4567", "", None]),
                         ["+15551234567"])
        self.assertEqual(normalize_targets(None), [])


class TestState(unittest.TestCase):
    def test_cursor_and_journal_survive_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = State(tmp)
            st.on_hello("stream-a")
            st.mark("hash1")
            st.advance(41)
            st2 = State(tmp)
            self.assertEqual(st2.stream_id, "stream-a")
            self.assertEqual(st2.last_id, 41)
            self.assertTrue(st2.seen("hash1"))
            self.assertFalse(st2.seen("hash2"))

    def test_stream_change_resets_cursor_keeps_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = State(tmp)
            st.on_hello("stream-a")
            st.mark("hash1")
            st.advance(41)
            st.on_hello("stream-b")                  # server restarted (no store)
            self.assertIsNone(st.last_id)            # -> tail mode
            self.assertTrue(st.seen("hash1"))        # dedup still works

    def test_journal_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = State(tmp)
            for i in range(600):
                st.mark(f"h{i}")
            self.assertFalse(st.seen("h0"))
            self.assertTrue(st.seen("h599"))


class TestSSEReader(unittest.TestCase):
    def _events(self, raw):
        return list(SSEReader(io.BytesIO(raw)).events())

    def test_parse(self):
        raw = (b"event: hello\ndata: {\"stream_id\": \"abc\"}\n\n"
               b": hb\n\n"
               b"event: message\nid: 7\ndata: {\"text\": \"hi\"}\n\n")
        events = self._events(raw)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "hello")
        self.assertEqual(events[1]["id"], "7")
        self.assertEqual(events[1]["data"], '{"text": "hi"}')

    def test_multiline_data(self):
        events = self._events(b"data: line1\ndata: line2\n\n")
        self.assertEqual(events[0]["data"], "line1\nline2")


class TestMessageHash(unittest.TestCase):
    def test_prefers_server_hash(self):
        self.assertEqual(message_hash({"hash": "srv"}), "srv")

    def test_local_fallback_stable(self):
        m = {"sender": "+15551234567", "scts": "t", "text": "x"}
        self.assertEqual(message_hash(m), message_hash(dict(m)))


if __name__ == "__main__":
    unittest.main()
