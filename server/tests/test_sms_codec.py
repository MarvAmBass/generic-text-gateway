import unittest

from gtg_server.modem import sms_codec as c


class TestGSM7Packing(unittest.TestCase):
    def test_known_vector_hellohello(self):
        # Classic reference vector for LSB-first septet packing.
        septets = c.to_septets("hellohello")
        self.assertEqual(c.pack_septets(septets).hex().upper(),
                         "E8329BFD4697D9EC37")

    def test_unpack_roundtrip(self):
        for text in ("Hello World", "a", "@", "1234567", "x" * 160):
            septets = c.to_septets(text)
            packed = c.pack_septets(septets)
            self.assertEqual(c.from_septets(
                c.unpack_septets(packed, len(septets))), text)

    def test_fill_bits_roundtrip(self):
        septets = c.to_septets("Testing fill bits")
        for fill in range(7):
            packed = c.pack_septets(septets, fill)
            self.assertEqual(
                c.from_septets(c.unpack_septets(packed, len(septets), fill)),
                "Testing fill bits")

    def test_umlauts_are_gsm7(self):
        self.assertTrue(c.is_gsm7("äöüß Grüße àéè ñ"))
        self.assertFalse(c.is_gsm7("emoji 🙂"))

    def test_extension_chars(self):
        text = "brackets [] braces {} euro €"
        septets = c.to_septets(text)
        self.assertEqual(c.from_septets(septets), text)
        # each extension char costs two septets
        self.assertEqual(len(septets), len(text) + 5)


class TestAddress(unittest.TestCase):
    def test_international(self):
        count, toa, bcd = c.encode_address("+15551234567")
        self.assertEqual((count, toa), (11, 0x91))
        self.assertEqual(c.decode_address(count, toa, bcd), "+15551234567")

    def test_even_length(self):
        count, toa, bcd = c.encode_address("+491234567890")
        self.assertEqual(c.decode_address(count, toa, bcd), "+491234567890")

    def test_national(self):
        count, toa, bcd = c.encode_address("0555123456")
        self.assertEqual(toa, 0x81)
        self.assertEqual(c.decode_address(count, toa, bcd), "0555123456")


class TestSubmit(unittest.TestCase):
    def test_single_gsm7(self):
        pdus = c.build_submit_pdus("+15551234567", "Hello World")
        self.assertEqual(len(pdus), 1)
        pdu_hex, cmgs_len = pdus[0]
        self.assertTrue(pdu_hex.startswith("00"))       # no SMSC
        self.assertEqual(len(pdu_hex[2:]) // 2, cmgs_len)
        b = bytes.fromhex(pdu_hex)
        self.assertEqual(b[1] & 0x03, 0x01)             # SMS-SUBMIT
        self.assertEqual(b[1] & 0x40, 0)                # no UDH

    def test_single_ucs2(self):
        pdus = c.build_submit_pdus("+15551234567", "héllo 🙂")
        self.assertEqual(len(pdus), 1)
        b = bytes.fromhex(pdus[0][0])
        # DCS is at offset: smsc(1) fo(1) mr(1) da_len(1) toa(1) bcd(6) pid(1) = 12
        self.assertEqual(b[12], 0x08)

    def test_multipart_gsm7(self):
        text = "A" * 200
        pdus = c.build_submit_pdus("+15551234567", text)
        self.assertEqual(len(pdus), 2)
        for pdu_hex, _ in pdus:
            b = bytes.fromhex(pdu_hex)
            self.assertEqual(b[1] & 0x40, 0x40)         # UDH present

    def test_multipart_no_escape_split(self):
        # 152 chars + '€' (2 septets) forces a split that must not cut the pair.
        text = "x" * 152 + "€" + "y" * 40
        pdus = c.build_submit_pdus("+15551234567", text)
        self.assertEqual(len(pdus), 2)


def _build_deliver(sender, text, concat=None, alphabet="gsm7"):
    """Assemble an SMS-DELIVER PDU from documented fields (test helper)."""
    count, toa, bcd = c.encode_address(sender)
    fo = 0x04 | (0x40 if concat else 0)
    out = bytearray([0x00, fo, count, toa]) + bcd
    out.append(0x00)                                    # PID
    out.append(0x00 if alphabet == "gsm7" else 0x08)    # DCS
    # SCTS 2026-01-02 13:14:15 +01:00 (swapped nibbles; +1h = 4 quarters)
    out += bytes([0x62, 0x10, 0x20, 0x31, 0x41, 0x51, 0x40])
    udh = b""
    if concat:
        ref, total, seq = concat
        udh = bytes([0x05, 0x00, 0x03, ref, total, seq])
    if alphabet == "gsm7":
        septets = c.to_septets(text)
        if udh:
            fill = (7 - len(udh) * 8 % 7) % 7
            udl = (len(udh) * 8 + fill) // 7 + len(septets)
            ud = udh + c.pack_septets(septets, fill)
        else:
            udl = len(septets)
            ud = c.pack_septets(septets)
    else:
        payload = text.encode("utf-16-be")
        ud = udh + payload
        udl = len(ud)
    out.append(udl)
    out += ud
    return out.hex().upper()


class TestDeliver(unittest.TestCase):
    def test_simple(self):
        d = c.decode_deliver(_build_deliver("+15557654321", "Ping pong äöü"))
        self.assertEqual(d["kind"], "deliver")
        self.assertEqual(d["sender"], "+15557654321")
        self.assertEqual(d["text"], "Ping pong äöü")
        self.assertEqual(d["scts"], "2026-01-02T13:14:15+01:00")
        self.assertIsNone(d["concat"])

    def test_ucs2(self):
        d = c.decode_deliver(_build_deliver("+15557654321", "🙂 emoji",
                                            alphabet="ucs2"))
        self.assertEqual(d["text"], "🙂 emoji")

    def test_concat(self):
        d = c.decode_deliver(_build_deliver("+15557654321", "part one ",
                                            concat=(66, 2, 1)))
        self.assertEqual(d["concat"], (66, 2, 1))
        self.assertEqual(d["text"], "part one ")

    def test_submit_deliver_symmetry(self):
        """Encode with build_submit_pdus, decode the UD with the deliver path."""
        text = "Round trip with umlauts äöü and € sign, plus enough text to " \
               "make it interesting for the packer."
        pdus = c.build_submit_pdus("+15551234567", text)
        self.assertEqual(len(pdus), 1)
        b = bytes.fromhex(pdus[0][0])
        udl = b[13]
        payload = b[14:]
        self.assertEqual(c.from_septets(c.unpack_septets(payload, udl)), text)


if __name__ == "__main__":
    unittest.main()
