"""Find the modem's AT port: enumerate candidates, probe with AT, identify."""
import time


def candidates():
    """List candidate serial ports (dicts) — ttyUSB*/ttyACM* first."""
    from serial.tools import list_ports                  # lazy import
    out = []
    for p in list_ports.comports():
        dev = p.device or ""
        if "ttyUSB" in dev or "ttyACM" in dev:
            out.append({
                "device": dev,
                "vid": p.vid, "pid": p.pid,
                "manufacturer": p.manufacturer,
                "product": p.product,
                "serial_number": p.serial_number,
                "location": getattr(p, "location", None),
            })
    out.sort(key=lambda c: c["device"])
    return out


def probe_port(device, baud, logger, attempts=3):
    """True if the port answers AT with OK."""
    import serial
    try:
        with serial.Serial(device, baud, timeout=1.0) as ser:
            for _ in range(attempts):
                ser.reset_input_buffer()
                ser.write(b"AT\r")
                ser.flush()
                time.sleep(0.4)
                resp = ser.read(256).decode("utf-8", errors="replace")
                if "OK" in resp:
                    return True
    except Exception as e:
        logger.debug("probe %s failed: %s", device, e)
    return False


def identify(port):
    """Query modem identity on an open ATPort. Unsupported commands are skipped."""
    info = {}
    for key, cmd in (("ati", "ATI"), ("manufacturer", "AT+CGMI"),
                     ("model", "AT+CGMM"), ("firmware", "AT+CGMR"),
                     ("imei", "AT+CGSN")):
        try:
            lines = port.execute(cmd, timeout=5)
            info[key] = " ".join(lines) if lines else ""
        except Exception:
            info[key] = None
    return info


def find_at_port(cfg_port, baud, logger):
    """-> (device, port_info dict) or (None, None)."""
    if cfg_port and cfg_port != "auto":
        return cfg_port, {"device": cfg_port, "configured": True}
    for cand in candidates():
        logger.info("probing %s (%s %s)", cand["device"],
                    cand.get("manufacturer"), cand.get("product"))
        if probe_port(cand["device"], baud, logger):
            logger.info("AT port found: %s", cand["device"])
            return cand["device"], cand
    return None, None
