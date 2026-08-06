import base64
import os
import tempfile
import unittest

from gtg_server.auth import (Auth, RateLimit, hash_password, hash_token,
                             parse_tokens, verify_password)
from gtg_server.config import Config


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class TestTokens(unittest.TestCase):
    def test_parse(self):
        plain, hashed = parse_tokens("all:t1, send:t2 ,receive:t3")
        self.assertEqual(plain, {"t1": "all", "t2": "send", "t3": "receive"})
        self.assertEqual(hashed, {})

    def test_parse_hashed(self):
        digest = hash_token("secret-tok")
        plain, hashed = parse_tokens(f"all:t1,send:sha256:{digest}")
        self.assertEqual(plain, {"t1": "all"})
        self.assertEqual(hashed, {digest: "send"})

    def test_parse_rejects_bad_scope(self):
        with self.assertRaises(ValueError):
            parse_tokens("admin:t1")
        with self.assertRaises(ValueError):
            parse_tokens("justatoken")
        with self.assertRaises(ValueError):
            parse_tokens("send:sha256:nothex")


class TestHashedAuth(unittest.TestCase):
    def test_hashed_token_grants_scope(self):
        auth = Auth(parse_tokens("send:sha256:" + hash_token("tok-hashed")))
        self.assertEqual(auth.check("Bearer tok-hashed"), "send")
        self.assertIsNone(auth.check("Bearer wrong"))

    def test_password_hash_roundtrip(self):
        encoded = hash_password("hunter22", iterations=1000)
        self.assertTrue(verify_password("hunter22", encoded))
        self.assertFalse(verify_password("hunter23", encoded))
        self.assertFalse(verify_password("hunter22", "garbage"))

    def test_webui_pass_hash_with_cache(self):
        encoded = hash_password("uipass", iterations=1000)
        auth = Auth(parse_tokens("all:t1"), webui_user="ui",
                    webui_pass_hash=encoded)
        self.assertEqual(auth.check(basic("ui", "uipass")), "all")
        self.assertEqual(auth.check(basic("ui", "uipass")), "all")   # cache hit
        self.assertIsNone(auth.check(basic("ui", "wrong")))
        # hash takes precedence over any plaintext value
        auth2 = Auth(parse_tokens("all:t1"), webui_user="ui",
                     webui_pass="plaintext", webui_pass_hash=encoded)
        self.assertIsNone(auth2.check(basic("ui", "plaintext")))
        self.assertEqual(auth2.check(basic("ui", "uipass")), "all")


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.auth = Auth(parse_tokens("all:sec-all,send:sec-send,receive:sec-recv"),
                         webui_user="marvin-example", webui_pass="hunter22")

    def test_bearer(self):
        self.assertEqual(self.auth.check("Bearer sec-send"), "send")
        self.assertIsNone(self.auth.check("Bearer nope"))
        self.assertIsNone(self.auth.check(None))
        self.assertIsNone(self.auth.check(""))

    def test_basic_webui(self):
        self.assertEqual(self.auth.check(basic("marvin-example", "hunter22")), "all")
        self.assertIsNone(self.auth.check(basic("marvin-example", "wrong")))
        # with a webui user configured, tokens-as-password are NOT accepted
        self.assertIsNone(self.auth.check(basic("x", "sec-all")))

    def test_basic_token_as_password_without_webui_user(self):
        auth = Auth(parse_tokens("receive:sec-recv"))
        self.assertEqual(auth.check(basic("anyone", "sec-recv")), "receive")
        self.assertIsNone(auth.check(basic("anyone", "bad")))

    def test_scopes(self):
        self.assertTrue(Auth.allows("all", "send"))
        self.assertTrue(Auth.allows("send", "send"))
        self.assertFalse(Auth.allows("receive", "send"))


class TestRateLimit(unittest.TestCase):
    def test_limit(self):
        rl = RateLimit("3/hour")
        self.assertTrue(rl.allow(2))
        self.assertTrue(rl.allow(1))
        self.assertFalse(rl.allow(1))

    def test_disabled(self):
        rl = RateLimit("0")
        for _ in range(100):
            self.assertTrue(rl.allow(10))

    def test_bad_spec(self):
        with self.assertRaises(ValueError):
            RateLimit("10/fortnight")


class TestConfig(unittest.TestCase):
    def test_precedence_env_over_file_over_default(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("[gateway]\nbaud = 9600\nring_size = 42\n")
            path = f.name
        try:
            cfg = Config(environ={"GTG_CONFIG": path, "GTG_BAUD": "57600"})
            self.assertEqual(cfg.int("BAUD"), 57600)          # env wins
            self.assertEqual(cfg.int("RING_SIZE"), 42)        # file beats default
            self.assertEqual(cfg.str("LISTEN"), "localhost:8443")  # default
        finally:
            os.unlink(path)

    def test_listen_parsing(self):
        cfg = Config(environ={"GTG_LISTEN": "localhost:8443,[::]:9000,0.0.0.0:8080"})
        self.assertEqual(cfg.listen_addrs(),
                         [("localhost", 8443), ("::", 9000), ("0.0.0.0", 8080)])

    def test_bool(self):
        cfg = Config(environ={"GTG_WEBUI": "false", "GTG_MODESWITCH": "YES"})
        self.assertFalse(cfg.bool("WEBUI"))
        self.assertTrue(cfg.bool("MODESWITCH"))


if __name__ == "__main__":
    unittest.main()
