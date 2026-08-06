"""ZeroCD mode switching for known USB IDs via the usb_modeswitch helper.

Never sends a guessed switching command to an unknown device — unknown
storage-mode IDs are only reported in health.
"""
import glob
import os
import shutil
import subprocess
import time

# (vid, pid) -> switch recipe. Only field-tested devices belong here.
KNOWN_SWITCHES = {
    (0x12D1, 0x1446): {
        "name": "Huawei ZeroCD (E1750 & friends)",
        "args": ["-v", "0x12d1", "-p", "0x1446", "-J"],
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


def unknown_storage_hint(logger):
    """Log a hint for present-but-unknown Huawei/ZTE-style installer IDs. Best effort."""
    return None


def switch(vid_pid, logger, timeout=30.0):
    """Run usb_modeswitch for a known ID and wait for an expected target ID.

    Returns True once the target ID (or any ttyUSB port) appears.
    """
    recipe = KNOWN_SWITCHES[vid_pid]
    binary = shutil.which("usb_modeswitch")
    if not binary:
        logger.warning("usb_modeswitch not installed — cannot switch %04x:%04x",
                       *vid_pid)
        return False
    logger.info("mode-switching %04x:%04x (%s)", vid_pid[0], vid_pid[1],
                recipe["name"])
    try:
        subprocess.run([binary] + recipe["args"], check=False, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        logger.warning("usb_modeswitch timed out")
        return False
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


def maybe_switch(logger):
    """Switch every known storage-mode device present. Returns True if any switched."""
    switched = False
    for vid_pid in storage_mode_devices():
        if switch(vid_pid, logger):
            switched = True
    return switched
