"""SMS PDU encoding/decoding (3GPP TS 23.040 / GSM 03.38). Pure stdlib.

PDU-first: deterministic handling of umlauts/emoji/multipart on every modem that
supports AT+CMGF=0. Text mode is a worker-level fallback, not handled here.
"""
import os

# GSM 7-bit default alphabet. Index == septet value. 0x1B is the escape marker.
GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæ"
    "ßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXT = {"^": 0x14, "{": 0x28, "}": 0x29, "\\": 0x2F, "[": 0x3C, "~": 0x3D,
            "]": 0x3E, "|": 0x40, "€": 0x65}
GSM7_MAP = {c: i for i, c in enumerate(GSM7_BASIC) if c != "\x1b"}
GSM7_EXT_REV = {v: k for k, v in GSM7_EXT.items()}

SINGLE_GSM7 = 160
MULTI_GSM7 = 153          # 160 - 7 septets for the 6-byte UDH (+1 fill bit)
SINGLE_UCS2 = 140         # bytes
MULTI_UCS2 = 134          # bytes (140 - 6 UDH)


def is_gsm7(text):
    return all(c in GSM7_MAP or c in GSM7_EXT for c in text)


def septet_len(char):
    return 2 if char in GSM7_EXT else 1


def to_septets(text):
    out = []
    for c in text:
        if c in GSM7_MAP:
            out.append(GSM7_MAP[c])
        elif c in GSM7_EXT:
            out.extend((0x1B, GSM7_EXT[c]))
        else:
            raise ValueError(f"not GSM7-encodable: {c!r}")
    return out


def from_septets(septets):
    out, esc = [], False
    for s in septets:
        if esc:
            out.append(GSM7_EXT_REV.get(s, "�"))
            esc = False
        elif s == 0x1B:
            esc = True
        else:
            out.append(GSM7_BASIC[s] if s < 128 else "�")
    return "".join(out)


def pack_septets(septets, fill_bits=0):
    """LSB-first septet packing ('hellohello' -> E8329BFD4697D9EC37)."""
    val, shift, out = 0, fill_bits, bytearray()
    for s in septets:
        val |= (s & 0x7F) << shift
        shift += 7
        while shift >= 8:
            out.append(val & 0xFF)
            val >>= 8
            shift -= 8
    if shift:
        out.append(val & 0xFF)
    return bytes(out)


def unpack_septets(data, count, fill_bits=0):
    val = int.from_bytes(data, "little") >> fill_bits
    return [(val >> (7 * i)) & 0x7F for i in range(count)]


def encode_address(number):
    """-> (digit_count, toa, bcd_bytes). '+...' -> international (0x91)."""
    n = number.strip()
    if n.startswith("+"):
        toa, digits = 0x91, n[1:]
    else:
        toa, digits = 0x81, n
    if not digits.isdigit():
        raise ValueError(f"invalid number: {number!r}")
    padded = digits + ("F" if len(digits) % 2 else "")
    bcd = bytearray()
    for i in range(0, len(padded), 2):
        lo = int(padded[i], 16)
        hi = int(padded[i + 1], 16)
        bcd.append((hi << 4) | lo)
    return len(digits), toa, bytes(bcd)


def decode_address(digit_count, toa, data):
    if (toa & 0x70) == 0x50:                       # alphanumeric sender
        septets = unpack_septets(data, digit_count * 4 // 7)
        return from_septets(septets)
    digits = []
    for b in data:
        digits.append(f"{b & 0x0F:x}")
        digits.append(f"{(b >> 4) & 0x0F:x}")
    s = "".join(digits)[:digit_count].upper().replace("F", "")
    return ("+" + s) if (toa & 0x70) == 0x10 else s


def _split_gsm7(text):
    """Split into chunks of <= MULTI_GSM7 septets without cutting an escape pair."""
    chunks, cur, cur_len = [], [], 0
    for c in text:
        cost = septet_len(c)
        if cur_len + cost > MULTI_GSM7:
            chunks.append("".join(cur))
            cur, cur_len = [], 0
        cur.append(c)
        cur_len += cost
    if cur:
        chunks.append("".join(cur))
    return chunks


def _split_ucs2(text):
    """Split into chunks of <= MULTI_UCS2 UTF-16-BE bytes without cutting surrogates."""
    chunks, cur, cur_len = [], [], 0
    for c in text:
        cost = len(c.encode("utf-16-be"))
        if cur_len + cost > MULTI_UCS2:
            chunks.append("".join(cur))
            cur, cur_len = [], 0
        cur.append(c)
        cur_len += cost
    if cur:
        chunks.append("".join(cur))
    return chunks


def build_submit_pdus(number, text):
    """-> list of (pdu_hex, cmgs_length). Multi-element list = concatenated SMS."""
    gsm7 = is_gsm7(text)
    if gsm7:
        total_sept = sum(septet_len(c) for c in text)
        parts = [text] if total_sept <= SINGLE_GSM7 else _split_gsm7(text)
    else:
        total_bytes = len(text.encode("utf-16-be"))
        parts = [text] if total_bytes <= SINGLE_UCS2 else _split_ucs2(text)

    multi = len(parts) > 1
    ref = os.urandom(1)[0] if multi else 0
    pdus = []
    for seq, part in enumerate(parts, start=1):
        udh = bytes([0x00, 0x03, ref, len(parts), seq]) if multi else b""
        fo = 0x01 | (0x40 if udh else 0)           # SMS-SUBMIT, VPF=00, UDHI if UDH
        digit_count, toa, bcd = encode_address(number)
        tpdu = bytearray([fo, 0x00, digit_count, toa])
        tpdu += bcd
        tpdu.append(0x00)                          # TP-PID
        tpdu.append(0x00 if gsm7 else 0x08)        # TP-DCS
        if gsm7:
            septets = to_septets(part)
            if udh:
                udh_full = bytes([len(udh)]) + udh
                fill = (7 - (len(udh_full) * 8) % 7) % 7
                udl = (len(udh_full) * 8 + fill) // 7 + len(septets)
                ud = udh_full + pack_septets(septets, fill)
            else:
                udl = len(septets)
                ud = pack_septets(septets)
        else:
            payload = part.encode("utf-16-be")
            ud = (bytes([len(udh)]) + udh + payload) if udh else payload
            udl = len(ud)
        tpdu.append(udl)
        tpdu += ud
        pdus.append(("00" + tpdu.hex().upper(), len(tpdu)))
    return pdus


def _decode_scts(data):
    """7 swapped-nibble bytes -> ISO-8601 string with timezone."""
    def sw(b):
        return (b & 0x0F) * 10 + ((b >> 4) & 0x0F)
    yy, mm, dd, hh, mi, ss = (sw(b) for b in data[:6])
    tz_raw = data[6]
    sign = "-" if tz_raw & 0x08 else "+"
    quarters = (tz_raw & 0x07) * 10 + ((tz_raw >> 4) & 0x0F)
    off_h, off_m = divmod(quarters * 15, 60)
    return (f"20{yy:02d}-{mm:02d}-{dd:02d}T{hh:02d}:{mi:02d}:{ss:02d}"
            f"{sign}{off_h:02d}:{off_m:02d}")


def decode_deliver(pdu_hex):
    """Decode an SMS-DELIVER PDU.

    -> {"kind": "deliver", "sender", "text", "scts", "concat": (ref, total, seq)|None}
    or {"kind": "status-report"} / {"kind": "other"} for non-deliver TPDUs.
    """
    b = bytes.fromhex(pdu_hex.strip())
    i = 0
    smsc_len = b[i]
    i += 1 + smsc_len
    fo = b[i]
    i += 1
    mti = fo & 0x03
    if mti == 0x02:
        return {"kind": "status-report"}
    if mti != 0x00:
        return {"kind": "other"}
    udhi = bool(fo & 0x40)
    digit_count = b[i]
    toa = b[i + 1]
    addr_bytes = (digit_count + 1) // 2
    if (toa & 0x70) == 0x50:
        addr_bytes = (digit_count + 1) // 2        # digit_count counts semi-octets here too
    sender = decode_address(digit_count, toa, b[i + 2:i + 2 + addr_bytes])
    i += 2 + addr_bytes
    _pid = b[i]
    dcs = b[i + 1]
    i += 2
    scts = _decode_scts(b[i:i + 7])
    i += 7
    udl = b[i]
    i += 1
    ud = b[i:]

    # DCS -> alphabet: 0 = GSM7, 1 = 8-bit, 2 = UCS-2
    if (dcs & 0xC0) == 0x00:
        alphabet = (dcs >> 2) & 0x03
    elif (dcs & 0xF0) in (0xF0, 0xE0, 0xC0, 0xD0):
        alphabet = (dcs >> 2) & 0x01
    else:
        alphabet = 0

    concat = None
    payload = ud
    udh_full_len = 0
    if udhi and ud:
        udh_len = ud[0]
        udh = ud[1:1 + udh_len]
        udh_full_len = udh_len + 1
        payload = ud[udh_full_len:]
        j = 0
        while j + 2 <= len(udh):
            iei, ie_len = udh[j], udh[j + 1]
            ie = udh[j + 2:j + 2 + ie_len]
            if iei == 0x00 and ie_len == 3:
                concat = (ie[0], ie[1], ie[2])
            elif iei == 0x08 and ie_len == 4:
                concat = ((ie[0] << 8) | ie[1], ie[2], ie[3])
            j += 2 + ie_len

    if alphabet == 0:
        if udh_full_len:
            fill = (7 - (udh_full_len * 8) % 7) % 7
            count = udl - (udh_full_len * 8 + fill) // 7
            text = from_septets(unpack_septets(payload, count, fill))
        else:
            text = from_septets(unpack_septets(payload, udl))
    elif alphabet == 2:
        text = payload.decode("utf-16-be", errors="replace")
    else:
        text = payload.decode("latin-1", errors="replace")

    return {"kind": "deliver", "sender": sender, "text": text, "scts": scts,
            "concat": concat}
