import base64
import os
import tempfile
import unittest

from gtg_server.auth import (Auth, RateLimit, hash_password, hash_token,
                             parse_users, verify_password)
from gtg_server.config import Config


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def make_users():
    return parse_users({
        "marvin": "all:" + hash_password("geheim", iterations=1000),
        "homeassistant": "send:plain-ha-token",
        "alerting": "receive:sha256:" + hash_token("alert-tok"),
    })


class TestParseUsers(unittest.TestCase):
    def test_kinds(self):
        kinds = {p.name: p.kind for p in make_users()}
        self.assertEqual(kinds, {"marvin": "pbkdf2", "homeassistant": "plain",
                                 "alerting": "sha256"})

    def test_rejects(self):
        with self.assertRaises(ValueError):
            parse_users({"x": "superuser:tok"})
        with self.assertRaises(ValueError):
            parse_users({"x": "noscope"})
        with self.assertRaises(ValueError):
            parse_users({"x": "send:sha256:short"})


class TestPasswordHashing(unittest.TestCase):
    def test_roundtrip(self):
        encoded = hash_password("hunter22", iterations=1000)
        self.assertTrue(verify_password("hunter22", encoded))
        self.assertFalse(verify_password("hunter23", encoded))
        self.assertFalse(verify_password("hunter22", "garbage"))

    def test_salted(self):
        a = hash_password("same-password", iterations=1000)
        b = hash_password("same-password", iterations=1000)
        self.assertNotEqual(a, b)                        # fresh random salt each time
        self.assertTrue(verify_password("same-password", a))
        self.assertTrue(verify_password("same-password", b))


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.auth = Auth(make_users())

    def test_bearer_tokens(self):
        self.assertEqual(self.auth.check("Bearer plain-ha-token"),
                         ("homeassistant", "send"))
        self.assertEqual(self.auth.check("Bearer alert-tok"),
                         ("alerting", "receive"))
        self.assertIsNone(self.auth.check("Bearer nope"))
        self.assertIsNone(self.auth.check(None))
        self.assertIsNone(self.auth.check(""))

    def test_bearer_never_matches_passwords(self):
        self.assertIsNone(self.auth.check("Bearer geheim"))

    def test_basic_per_user(self):
        self.assertEqual(self.auth.check(basic("marvin", "geheim")),
                         ("marvin", "all"))
        self.assertIsNone(self.auth.check(basic("marvin", "wrong")))
        self.assertEqual(self.auth.check(basic("homeassistant", "plain-ha-token")),
                         ("homeassistant", "send"))
        self.assertEqual(self.auth.check(basic("alerting", "alert-tok")),
                         ("alerting", "receive"))

    def test_strict_name_binding(self):
        # right secret + wrong (or unknown) name -> rejected
        self.assertIsNone(self.auth.check(basic("homeassistant", "alert-tok")))
        self.assertIsNone(self.auth.check(basic("stranger", "plain-ha-token")))

    def test_kdf_cache(self):
        self.assertEqual(self.auth.check(basic("marvin", "geheim")),
                         ("marvin", "all"))
        self.assertEqual(self.auth.check(basic("marvin", "geheim")),
                         ("marvin", "all"))              # cache hit
        self.assertIsNone(self.auth.check(basic("marvin", "still-wrong")))

    def test_revocation(self):
        users = [p for p in make_users() if p.name != "homeassistant"]
        auth = Auth(users)
        self.assertIsNone(auth.check("Bearer plain-ha-token"))       # revoked
        self.assertEqual(auth.check("Bearer alert-tok"),
                         ("alerting", "receive"))                     # others live

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
            f.write("[gateway]\nbaud = 9600\nring_size = 42\nuser_filecfg = send:tok\n")
            path = f.name
        try:
            cfg = Config(environ={"GTG_CONFIG": path, "GTG_BAUD": "57600"})
            self.assertEqual(cfg.int("BAUD"), 57600)          # env wins
            self.assertEqual(cfg.int("RING_SIZE"), 42)        # file beats default
            self.assertEqual(cfg.str("LISTEN"), "localhost:8443")  # default
            self.assertEqual(cfg.users(), {"filecfg": "send:tok"})
        finally:
            os.unlink(path)

    def test_env_users(self):
        cfg = Config(environ={
            "GTG_USER_MARVIN": "all:x",
            "GTG_USER_ha_send": "send:y",
            "GTG_CONFIG": "/nonexistent",
        })
        self.assertEqual(cfg.users(), {"marvin": "all:x", "ha_send": "send:y"})

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
