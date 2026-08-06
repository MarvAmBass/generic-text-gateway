"""Regression tests for issues found in the 2026-08-06 security audit."""
import unittest

from gtg_server.api import E164_RE
from gtg_server.auth import Auth, Backoff, hash_password, parse_users
from gtg_server.modem import sms_codec
from gtg_server.outbox import Outbox


class TestRecipientValidation(unittest.TestCase):
    """H1: AT command injection via the 'to' field (text-mode fallback)."""

    INJECTIONS = [
        '+4915100000000"\r\nAT+CUSD=1,"*100#",15\r\nAT+CMGS="+49123',
        "+491511\rAT+CMGD=1,4",
        "+491511\nATD1234;",
        "+49151;AT+CPIN?",
        'AT+CFUN=0',
        '+49151"',
        "+49151\x1aAT",
        "+49 151 000",          # spaces are not valid either
        "",
        "+",
    ]
    # Rejected by API policy only — harmless to the AT layer, just not sane numbers.
    BAD_LENGTH = ["12", "1" * 21]

    def test_injections_rejected(self):
        for payload in self.INJECTIONS + self.BAD_LENGTH:
            self.assertIsNone(E164_RE.fullmatch(payload),
                              f"accepted injection: {payload!r}")

    def test_legitimate_numbers_accepted(self):
        for number in ("+15551234567", "15551234567", "+491234567890",
                       "0555123456"):
            self.assertIsNotNone(E164_RE.fullmatch(number), number)

    def test_pdu_encoder_also_rejects(self):
        """Defense in depth: the PDU path must reject them independently."""
        for payload in self.INJECTIONS:
            with self.assertRaises(ValueError):
                sms_codec.encode_address(payload)


class TestBackoffBeforeCredentialCheck(unittest.TestCase):
    """H2: _any_scope evaluated credentials before consulting the backoff."""

    def test_backoff_blocks_before_kdf(self):
        backoff = Backoff()
        for _ in range(6):
            backoff.fail("10.0.0.9")
        self.assertGreater(backoff.blocked_for("10.0.0.9"), 0)
        self.assertEqual(backoff.blocked_for("10.0.0.10"), 0)   # per-IP

    def test_kdf_cache_does_not_leak_across_users(self):
        users = parse_users({
            "a": "all:" + hash_password("secret-a", iterations=1000),
            "b": "send:" + hash_password("secret-b", iterations=1000),
        })
        auth = Auth(users)
        import base64

        def basic(u, p):
            return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

        self.assertEqual(auth.check(basic("a", "secret-a")), ("a", "all"))
        # b's password must not authenticate as a, even after a is cached
        self.assertIsNone(auth.check(basic("a", "secret-b")))
        self.assertEqual(auth.check(basic("b", "secret-b")), ("b", "send"))


class TestOutboxOwnership(unittest.TestCase):
    """M2: any send token could read every principal's outbound records."""

    def test_owner_recorded(self):
        ob = Outbox()
        rec, created = ob.create(["+15551234567"], "hi", owner="homeassistant")
        self.assertTrue(created)
        self.assertEqual(ob.get(rec["id"])["owner"], "homeassistant")

    def test_public_view_excludes_body_and_owner(self):
        ob = Outbox()
        rec, _ = ob.create(["+15551234567"], "secret body", owner="x")
        public = ob.public(ob.get(rec["id"]))
        self.assertNotIn("text", public)
        self.assertNotIn("owner", public)
        self.assertIn("state", public)


class TestRateLimitBySegments(unittest.TestCase):
    """M6: rate limit charged per recipient, not per billable SMS segment."""

    def test_long_unicode_message_is_many_segments(self):
        # 2500 emoji -> UCS-2 multipart -> dozens of billable segments
        segments = len(sms_codec.build_submit_pdus("+15551234567", "🙂" * 2500))
        self.assertGreater(segments, 50)

    def test_short_message_is_one_segment(self):
        self.assertEqual(
            len(sms_codec.build_submit_pdus("+15551234567", "pong")), 1)


if __name__ == "__main__":
    unittest.main()
