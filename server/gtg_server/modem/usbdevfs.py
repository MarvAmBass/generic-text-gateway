"""Pure-stdlib USB mode switching via Linux usbdevfs ioctls.

The classic ZeroCD "switch" is nothing more than a 31-byte USB mass-storage CBW
(bulk message) written to the stick's storage endpoint — which Linux lets us do
directly on /dev/bus/usb/BBB/DDD with three ioctls (detach kernel driver, claim
interface, bulk write). No libusb, no pyusb, no external binary.

Only ever used for USB IDs in the KNOWN_SWITCHES table — never guessed.
"""
import ctypes
import glob
import os


class _BulkTransfer(ctypes.Structure):
    _fields_ = [("ep", ctypes.c_uint), ("len", ctypes.c_uint),
                ("timeout", ctypes.c_uint), ("data", ctypes.c_void_p)]


class _UsbIoctl(ctypes.Structure):
    _fields_ = [("ifno", ctypes.c_int), ("ioctl_code", ctypes.c_int),
                ("data", ctypes.c_void_p)]


def _IOC(direction, type_char, nr, size):
    return (direction << 30) | (size << 16) | (ord(type_char) << 8) | nr


# Sizes differ between 32/64-bit (pointer in the structs) — compute, don't hardcode.
USBDEVFS_CLAIMINTERFACE = _IOC(2, "U", 15, 4)
USBDEVFS_RELEASEINTERFACE = _IOC(2, "U", 16, 4)
USBDEVFS_IOCTL = _IOC(3, "U", 18, ctypes.sizeof(_UsbIoctl))
USBDEVFS_BULK = _IOC(3, "U", 2, ctypes.sizeof(_BulkTransfer))
USBDEVFS_DISCONNECT = _IOC(0, "U", 22, 0)


def find_devnode(vid, pid):
    """(vid, pid) -> '/dev/bus/usb/BBB/DDD' via sysfs, or None."""
    for vendor_file in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        base = os.path.dirname(vendor_file)
        try:
            with open(vendor_file) as f:
                if int(f.read().strip(), 16) != vid:
                    continue
            with open(os.path.join(base, "idProduct")) as f:
                if int(f.read().strip(), 16) != pid:
                    continue
            with open(os.path.join(base, "busnum")) as f:
                bus = int(f.read().strip())
            with open(os.path.join(base, "devnum")) as f:
                dev = int(f.read().strip())
            return f"/dev/bus/usb/{bus:03d}/{dev:03d}"
        except (OSError, ValueError):
            continue
    return None


def send_bulk_message(vid, pid, message_hex, interface=0, endpoint=0x01,
                      timeout_ms=3000, logger=None):
    """Detach the kernel driver, claim the interface, write the switch message.

    Returns True if the message was written. The device disappearing right after
    ("Device is gone") is the expected success signature.
    """
    node = find_devnode(vid, pid)
    if node is None:
        raise FileNotFoundError(f"no devnode for {vid:04x}:{pid:04x}")
    message = bytes.fromhex(message_hex)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(node, os.O_RDWR)
    try:
        # Detach usb-storage from the interface; errors are fine (not bound).
        disconnect = _UsbIoctl(interface, USBDEVFS_DISCONNECT, None)
        libc.ioctl(fd, USBDEVFS_IOCTL, ctypes.byref(disconnect))

        claim = ctypes.c_uint(interface)
        if libc.ioctl(fd, USBDEVFS_CLAIMINTERFACE, ctypes.byref(claim)) != 0:
            raise OSError(ctypes.get_errno(),
                          f"cannot claim interface {interface} on {node}")

        buf = (ctypes.c_char * len(message)).from_buffer_copy(message)
        bulk = _BulkTransfer(endpoint, len(message), timeout_ms,
                             ctypes.cast(buf, ctypes.c_void_p))
        written = libc.ioctl(fd, USBDEVFS_BULK, ctypes.byref(bulk))
        if written != len(message):
            raise OSError(ctypes.get_errno(),
                          f"bulk write returned {written}, expected {len(message)}")
        if logger:
            logger.info("switch message sent to %s (%d bytes)", node, written)

        release = ctypes.c_uint(interface)
        libc.ioctl(fd, USBDEVFS_RELEASEINTERFACE, ctypes.byref(release))
        return True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass                      # device may already be gone — that's success
