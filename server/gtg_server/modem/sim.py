"""SIM state, PIN entry, network registration, signal — helpers over an ATPort."""
from .at import ATError


def cpin_state(port):
    """-> 'ready' | 'pin_required' | 'puk_required' | 'absent' | 'unknown'."""
    try:
        lines = port.execute("AT+CPIN?", timeout=10)
    except ATError as e:
        msg = str(e).upper()
        if "SIM NOT INSERTED" in msg or "10" in msg:
            return "absent"
        return "unknown"
    for line in lines:
        up = line.upper()
        if "READY" in up:
            return "ready"
        if "SIM PUK" in up:
            return "puk_required"
        if "SIM PIN" in up:
            return "pin_required"
    return "unknown"


def enter_pin(port, pin):
    """Submit the PIN once. Caller checks cpin_state() afterwards."""
    if not pin.isdigit() or not (4 <= len(pin) <= 8):
        raise ValueError("PIN must be 4-8 digits")
    port.execute(f'AT+CPIN="{pin}"', timeout=20)


def registration(port):
    """-> (state_int_or_None, description). Tries CREG, then CEREG/CGREG."""
    descriptions = {0: "not_registered", 1: "home", 2: "searching",
                    3: "denied", 4: "unknown", 5: "roaming"}
    for cmd in ("AT+CREG?", "AT+CEREG?", "AT+CGREG?"):
        try:
            lines = port.execute(cmd, timeout=5)
        except Exception:
            continue
        for line in lines:
            if ":" in line:
                parts = line.split(":", 1)[1].split(",")
                if len(parts) >= 2:
                    try:
                        state = int(parts[1].strip().split()[0])
                        return state, descriptions.get(state, "unknown")
                    except ValueError:
                        continue
    return None, "unknown"


def registered(port):
    state, _ = registration(port)
    return state in (1, 5)


def signal(port):
    """-> (csq_0_31_or_None, dbm_or_None, percent_or_None)."""
    try:
        lines = port.execute("AT+CSQ", timeout=5)
    except Exception:
        return None, None, None
    for line in lines:
        if line.startswith("+CSQ:"):
            try:
                rssi = int(line.split(":")[1].split(",")[0].strip())
            except ValueError:
                return None, None, None
            if rssi == 99:
                return 99, None, None
            return rssi, -113 + 2 * rssi, round(rssi * 100 / 31)
    return None, None, None


def operator(port):
    try:
        lines = port.execute("AT+COPS?", timeout=10)
    except Exception:
        return None
    for line in lines:
        if '"' in line:
            return line.split('"')[1]
    return None
