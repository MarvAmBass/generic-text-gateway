import ctypes
import unittest

from gtg_server.modem import modeswitch, usbdevfs


class TestSwitchTable(unittest.TestCase):
    def test_huawei_message_is_valid_cbw(self):
        msg = bytes.fromhex(modeswitch.HUAWEI_ZEROCD_MESSAGE)
        self.assertEqual(len(msg), 31)                   # USB mass-storage CBW
        self.assertEqual(msg[:4], b"USBC")               # CBW signature

    def test_recipes_complete(self):
        for vid_pid, recipe in modeswitch.KNOWN_SWITCHES.items():
            self.assertEqual(len(vid_pid), 2)
            self.assertTrue(recipe["expected_ids"], vid_pid)
            # every recipe must have at least one switch method
            self.assertTrue("message" in recipe or "helper_args" in recipe)


class TestUsbdevfsConstants(unittest.TestCase):
    """Guard the ioctl numbers against typos — recompute from the kernel formula."""

    def _ioc(self, direction, nr, size):
        return (direction << 30) | (size << 16) | (0x55 << 8) | nr

    def test_fixed_size_ioctls(self):
        self.assertEqual(usbdevfs.USBDEVFS_CLAIMINTERFACE, self._ioc(2, 15, 4))
        self.assertEqual(usbdevfs.USBDEVFS_RELEASEINTERFACE, self._ioc(2, 16, 4))
        self.assertEqual(usbdevfs.USBDEVFS_DISCONNECT, self._ioc(0, 22, 0))

    def test_struct_size_ioctls_track_pointer_width(self):
        ptr = ctypes.sizeof(ctypes.c_void_p)
        bulk_size = usbdevfs._BulkTransfer.data.offset + ptr
        ioctl_size = usbdevfs._UsbIoctl.data.offset + ptr
        self.assertEqual(usbdevfs.USBDEVFS_BULK, self._ioc(3, 2, bulk_size))
        self.assertEqual(usbdevfs.USBDEVFS_IOCTL, self._ioc(3, 18, ioctl_size))
        # on 64-bit the pointer is 8-aligned -> padding before it
        self.assertEqual(ctypes.sizeof(usbdevfs._BulkTransfer), bulk_size)


if __name__ == "__main__":
    unittest.main()
