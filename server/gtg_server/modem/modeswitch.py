"""ZeroCD mode switching for known USB IDs.

Two methods, tried in order:
1. Built-in (pure stdlib): write the device's known switch message directly via
   usbdevfs — no external dependency (see usbdevfs.py).
2. usb_modeswitch, IF installed: optional fallback; its community database also
   covers quirky variants the built-in table doesn't.

Never sends a guessed switching command to an unknown device — unknown
storage-mode IDs are only reported in health/logs.
"""
import glob
import os
import shutil
import subprocess
import time

from . import usbdevfs

# The standard Huawei ZeroCD switch message: a 31-byte USB mass-storage CBW
# (SCSI START STOP UNIT / eject variant). Field-tested on the E1750.
HUAWEI_ZEROCD_MESSAGE = (
    "55534243123456780000000000000011"
    "062000000100000000000000000000"
)

# (vid, pid) -> switch recipe. Only field-tested devices belong here.
KNOWN_SWITCHES = {
    (0x12D1, 0x1446): {
        "name": "Huawei ZeroCD (E1750 & friends)",
        "message": HUAWEI_ZEROCD_MESSAGE,
        "interface": 0,
        "endpoint": 0x01,
        "helper_args": ["-v", "0x12d1", "-p", "0x1446", "-J"],
        "expected_ids": [(0x12D1, 0x1001), (0x12D1, 0x14AC), (0x12D1, 0x1436)],
    },
}


def usb_ids():
    """Enumerate (vid, pid) via sysfs — Linux only, no deps."""
    ids = set()
    for vendor_file in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        try:
            with open(vendor_file) as f:
                vid = int(f.read().strip(), 16)
            with open(os.path.join(os.path.dirname(vendor_file), "idProduct")) as f:
                pid = int(f.read().strip(), 16)
            ids.add((vid, pid))
        except (OSError, ValueError):
            continue
    return ids


def storage_mode_devices():
    """Known-switchable IDs currently present."""
    present = usb_ids()
    return [i for i in present if i in KNOWN_SWITCHES]


def _switch_builtin(vid_pid, recipe, logger):
    if "message" not in recipe:
        return False
    try:
        return usbdevfs.send_bulk_message(
            vid_pid[0], vid_pid[1], recipe["message"],
            interface=recipe.get("interface", 0),
            endpoint=recipe.get("endpoint", 0x01), logger=logger)
    except (OSError, ValueError) as e:
        logger.warning("built-in modeswitch failed for %04x:%04x: %s",
                       vid_pid[0], vid_pid[1], e)
        return False


def _switch_helper(vid_pid, recipe, logger):
    binary = shutil.which("usb_modeswitch")
    if not binary or "helper_args" not in recipe:
        return False
    logger.info("falling back to usb_modeswitch for %04x:%04x", *vid_pid)
    try:
        subprocess.run([binary] + recipe["helper_args"], check=False, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.TimeoutExpired:
        logger.warning("usb_modeswitch timed out")
        return False


def _wait_switched(recipe, logger, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        present = usb_ids()
        if any(t in present for t in recipe["expected_ids"]):
            # give the kernel a moment to create the tty nodes
            for _ in range(20):
                if glob.glob("/dev/ttyUSB*") or glob.glob("/dev/ttyACM*"):
                    return True
                time.sleep(0.5)
            return True
        time.sleep(1.0)
    logger.warning("device did not reappear with an expected ID after switching")
    return False


def switch(vid_pid, logger, timeout=30.0):
    """Switch one known device: built-in message first, usb_modeswitch fallback."""
    recipe = KNOWN_SWITCHES[vid_pid]
    logger.info("mode-switching %04x:%04x (%s)", vid_pid[0], vid_pid[1],
                recipe["name"])
    sent = _switch_builtin(vid_pid, recipe, logger)
    if not sent:
        sent = _switch_helper(vid_pid, recipe, logger)
    if not sent:
        logger.warning("no working switch method for %04x:%04x (built-in failed, "
                       "usb_modeswitch not installed?)", *vid_pid)
        return False
    return _wait_switched(recipe, logger, timeout)


def maybe_switch(logger):
    """Switch every known storage-mode device present. Returns True if any switched."""
    switched = False
    for vid_pid in storage_mode_devices():
        if switch(vid_pid, logger):
            switched = True
    return switched
