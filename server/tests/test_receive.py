import unittest

from gtg_server.modem import receive


class TestParsers(unittest.TestCase):
    def test_cmti(self):
        self.assertEqual(receive.parse_cmti('+CMTI: "SM",5'), ("SM", 5))
        self.assertEqual(receive.parse_cmti('+CMTI: "ME", 12'), ("ME", 12))
        self.assertIsNone(receive.parse_cmti("+CMT: something"))
        self.assertIsNone(receive.parse_cmti("+CMTI: garbage"))

    def test_cmgl_pdu(self):
        lines = ['+CMGL: 1,1,,25', "07911326040000F0ABCDEF",
                 '+CMGL: 3,0,,30', "0791AA"]
        self.assertEqual(receive.parse_cmgl_pdu(lines),
                         [(1, "07911326040000F0ABCDEF"), (3, "0791AA")])

    def test_cmgr_pdu(self):
        self.assertEqual(receive.parse_cmgr_pdu(['+CMGR: 1,,25', "07AB"]), "07AB")
        self.assertIsNone(receive.parse_cmgr_pdu(["OK-ish noise"]))


class TestAssembler(unittest.TestCase):
    def _decoded(self, text, concat, sender="+15557654321"):
        return {"sender": sender, "text": text, "scts": "2026-01-01T00:00:00+00:00",
                "concat": concat}

    def test_single(self):
        asm = receive.Assembler()
        msg, indices = asm.add(self._decoded("hi", None), 4)
        self.assertEqual(msg["text"], "hi")
        self.assertEqual(indices, [4])

    def test_multipart_out_of_order(self):
        asm = receive.Assembler()
        self.assertIsNone(asm.add(self._decoded("world", (9, 2, 2)), 6))
        msg, indices = asm.add(self._decoded("hello ", (9, 2, 1)), 5)
        self.assertEqual(msg["text"], "hello world")
        self.assertEqual(indices, [5, 6])
        self.assertFalse(msg["partial"])

    def test_stale_flush(self):
        asm = receive.Assembler(stale_after=0.0)
        asm.add(self._decoded("only part ", (7, 3, 1)), 2)
        flushed = asm.flush_stale()
        self.assertEqual(len(flushed), 1)
        msg, indices = flushed[0]
        self.assertTrue(msg["partial"])
        self.assertEqual(indices, [2])

    def test_hash_stability(self):
        h1 = receive.message_hash("+15551234567", "2026-01-01T00:00:00", "text")
        h2 = receive.message_hash("+15551234567", "2026-01-01T00:00:00", "text")
        h3 = receive.message_hash("+15551234567", "2026-01-01T00:00:01", "text")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


if __name__ == "__main__":
    unittest.main()
