import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest

from gtg_client.config import Config, normalize_targets
from gtg_client.relay import SSEReader, message_hash
from gtg_client.pinned_http import ServerConnection
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


@contextlib.contextmanager
def _ca_bundle():
    """A throwaway self-signed PEM, for exercising GTC_SERVER_CA."""
    if not shutil.which("openssl"):
        raise unittest.SkipTest("openssl not available")
    with tempfile.TemporaryDirectory() as tmp:
        cert = os.path.join(tmp, "ca.pem")
        key = os.path.join(tmp, "ca.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "1",
                        "-subj", "/CN=test-ca"], check=True, capture_output=True)
        yield cert


class TestServerConnection(unittest.TestCase):
    PIN = "a" * 64

    def _conn(self, **env):
        env.setdefault("GTC_SERVER_URL", "https://gw.example:8443")
        env.setdefault("GTC_CONFIG", "")          # ignore any host config file
        return ServerConnection(Config(environ=env))

    def test_system_trust_is_the_default(self):
        # A publicly trusted (or company-root) server cert needs no client config.
        conn = self._conn()
        self.assertEqual(conn.mode, "system")
        self.assertTrue(conn.open()._context.check_hostname)

    def test_pin_mode_opt_in(self):
        conn = self._conn(GTC_SERVER_PIN_SHA256=self.PIN)
        self.assertEqual(conn.mode, "pin")

    def test_pin_accepts_colon_form_and_rejects_garbage(self):
        colons = ":".join(self.PIN[i:i + 2] for i in range(0, 64, 2))
        self.assertEqual(self._conn(GTC_SERVER_PIN_SHA256=colons).pin, self.PIN)
        with self.assertRaises(ValueError):
            self._conn(GTC_SERVER_PIN_SHA256="not-a-fingerprint")

    def test_tofu_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._conn(GTC_SERVER_PIN_TOFU="true", GTC_STATE_DIR=tmp)
            self.assertEqual(conn.mode, "tofu")

    def test_ca_mode_adds_to_system_trust(self):
        # A private CA must not cost you the public ones (Let's Encrypt & co).
        def loaded(conn):
            return {(str(c["subject"]), c["serialNumber"])
                    for c in conn._ctx.get_ca_certs()}
        with _ca_bundle() as path:
            conn = self._conn(GTC_SERVER_CA=path)
            self.assertEqual(conn.mode, "ca")
            extra = loaded(conn) - loaded(self._conn())
            self.assertEqual(len(extra), 1)                  # the private CA
            self.assertIn("test-ca", extra.pop()[0])
            self.assertTrue(loaded(self._conn()) <= loaded(conn))

    def test_ca_dir_accepted(self):
        with _ca_bundle() as path:
            self.assertEqual(
                self._conn(GTC_SERVER_CA=os.path.dirname(path)).mode, "ca")

    def test_bad_ca_file_is_a_config_error(self):
        with self.assertRaises(ValueError):
            self._conn(GTC_SERVER_CA="/nonexistent/ca.pem")
        with tempfile.NamedTemporaryFile(suffix=".pem") as empty:
            with self.assertRaises(ValueError):   # not an ssl.SSLError traceback
                self._conn(GTC_SERVER_CA=empty.name)

    def test_modes_are_mutually_exclusive(self):
        with _ca_bundle() as path:
            with self.assertRaises(ValueError):
                self._conn(GTC_SERVER_PIN_SHA256=self.PIN, GTC_SERVER_CA=path)

    def test_https_required(self):
        with self.assertRaises(ValueError):
            self._conn(GTC_SERVER_URL="http://gw.example:8443")


if __name__ == "__main__":
    unittest.main()
