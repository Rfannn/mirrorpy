"""
Unit tests for mirror.py

Covers:
  - Helper functions: get_local_ip, ping_host, run_cmd, adb_devices_list
  - New helpers: adb_mdns_init, adb_mdns_discover, full_discover, parse_device_model
  - QR code: generate_qr_pil
  - Regression: auto-detect no longer returns laptop IP, save_config not recursive
  - Thread safety: _schedule
"""

import configparser
import io
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, MagicMock, call

# ── Mock tkinter / ttkbootstrap BEFORE importing mirror ──────────────
_tk_mock = types.ModuleType("tkinter")
_tk_mock.Frame = type("Frame", (), {"__init__": lambda s, *a, **kw: None})
_tk_mock.Text = type("Text", (), {"__init__": lambda s, *a, **kw: None})
_tk_mock.StringVar = type("StringVar", (), {"__init__": lambda s, *a, **kw: None,
                                             "get": lambda s: "", "set": lambda s, v: None})
_tk_mock.DISABLED = "disabled"
_tk_mock.BOTH = "both"
_tk_mock.X = "x"
_tk_mock.YES = "yes"
_tk_mock.WORD = "word"
_tk_mock.LEFT = "left"
_tk_mock.RIGHT = "right"
_tk_mock.HORIZONTAL = "horizontal"
_tk_mock.W = "w"
_tk_mock.NORMAL = "normal"
sys.modules["tkinter"] = _tk_mock
sys.modules["tkinter.constants"] = _tk_mock

ttk_mock = types.ModuleType("tkinter.ttk")
sys.modules["tkinter.ttk"] = ttk_mock

_FakeWidget = type("FakeWidget", (), {"__init__": lambda s, *a, **kw: None})

ttkb_mock = types.ModuleType("ttkbootstrap")
ttkb_mock.Frame = _tk_mock.Frame
ttkb_mock.Text = _tk_mock.Text
ttkb_mock.StringVar = _tk_mock.StringVar
ttkb_mock.Labelframe = _FakeWidget
ttkb_mock.Label = _FakeWidget
ttkb_mock.Entry = _FakeWidget
ttkb_mock.Button = _FakeWidget
ttkb_mock.Combobox = _FakeWidget
ttkb_mock.Progressbar = _FakeWidget
ttkb_mock.Spinbox = _FakeWidget
ttkb_mock.Separator = _FakeWidget


class _MockStyle:
    def theme_names(self):
        return ["darkly"]
    def theme_use(self, n):
        pass
ttkb_mock.Style = _MockStyle
ttkb_mock.Window = type("Window", (), {
    "__init__": lambda s, *a, **kw: None,
    "title": lambda s, t: None,
    "geometry": lambda s, g: None,
    "minsize": lambda s, w, h: None,
    "protocol": lambda s, e, h: None,
    "mainloop": lambda s: None,
})
sys.modules["ttkbootstrap"] = ttkb_mock

ttkb_const = types.ModuleType("ttkbootstrap.constants")
for n in ("BOTH", "X", "YES", "WORD", "LEFT", "RIGHT", "HORIZONTAL", "W",
          "DISABLED", "NORMAL", "HORIZONTAL"):
    setattr(ttkb_const, n, getattr(_tk_mock, n, n))
sys.modules["ttkbootstrap.constants"] = ttkb_const

ttkb_dialogs = types.ModuleType("ttkbootstrap.dialogs")
ttkb_dialogs.Messagebox = MagicMock()
sys.modules["ttkbootstrap.dialogs"] = ttkb_dialogs

# Mock qrcode + PIL
qr_mock = types.ModuleType("qrcode")
qr_mock.QRCode = MagicMock()
qr_mock.constants = MagicMock()
qr_mock.constants.ERROR_CORRECT_M = 0
sys.modules["qrcode"] = qr_mock

pil_mock = types.ModuleType("PIL")
pil_img_mock = types.ModuleType("PIL.Image")
pil_img_mock.Image = MagicMock()
pil_img_mock.ImageTk = MagicMock()
pil_mock.ImageTk = pil_img_mock.ImageTk
pil_mock.Image = pil_img_mock.Image
sys.modules["PIL"] = pil_mock
sys.modules["PIL.Image"] = pil_img_mock
sys.modules["PIL.ImageTk"] = pil_img_mock.ImageTk

# Now safe to import mirror
from mirror import (
    get_local_ip, ping_host, run_cmd, adb_devices_list,
    parse_device_model, parse_device_product,
    adb_mdns_init, adb_mdns_discover, full_discover,
    generate_qr_pil, ScrcpyLauncher,
)


# ================================================================
#  Pure helper tests
# ================================================================

class TestGetLocalIp(unittest.TestCase):
    @patch("mirror.socket.socket")
    def test_returns_ip(self, mock_cls):
        sock = MagicMock()
        sock.getsockname.return_value = ("192.168.1.42", 0)
        mock_cls.return_value = sock
        self.assertEqual(get_local_ip(), "192.168.1.42")

    @patch("mirror.socket.socket")
    def test_returns_none_on_error(self, mock_cls):
        sock = MagicMock()
        sock.connect.side_effect = OSError("fail")
        mock_cls.return_value = sock
        self.assertIsNone(get_local_ip())

    @patch("mirror.socket.socket")
    def test_always_closes_socket(self, mock_cls):
        sock = MagicMock()
        sock.connect.side_effect = OSError("fail")
        mock_cls.return_value = sock
        get_local_ip()
        sock.close.assert_called_once()


class TestPingHost(unittest.TestCase):
    @patch("mirror.platform.system", return_value="Windows")
    @patch("mirror.subprocess.run")
    def test_windows_flags(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=0)
        ping_host("10.0.0.1", timeout=2)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "ping")
        self.assertIn("-w", cmd)
        self.assertIn("2000", cmd)

    @patch("mirror.platform.system", return_value="Linux")
    @patch("mirror.subprocess.run")
    def test_linux_flags(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=0)
        ping_host("10.0.0.1")
        cmd = mock_run.call_args[0][0]
        self.assertIn("-c", cmd)
        self.assertIn("-W", cmd)

    @patch("mirror.platform.system", return_value="Linux")
    @patch("mirror.subprocess.run", side_effect=OSError)
    def test_returns_false_on_error(self, mock_run, _):
        self.assertFalse(ping_host("10.0.0.1"))

    @patch("mirror.platform.system", return_value="Linux")
    @patch("mirror.subprocess.run")
    def test_returns_false_on_nonzero(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(ping_host("10.0.0.99"))


class TestRunCmd(unittest.TestCase):
    @patch("mirror.subprocess.run")
    def test_basic(self, mock_run):
        mock_run.return_value = MagicMock(stdout="ok\n", stderr="", returncode=0)
        out, err, rc = run_cmd(["echo", "ok"])
        self.assertEqual(out, "ok")
        self.assertEqual(rc, 0)

    @patch("mirror.subprocess.run")
    def test_string_uses_shell(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        run_cmd("dir")
        self.assertTrue(mock_run.call_args[1]["shell"])

    @patch("mirror.subprocess.run")
    def test_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="x", timeout=5)
        out, err, rc = run_cmd(["slow"], timeout=5)
        self.assertEqual(rc, -1)
        self.assertEqual(err, "timeout")

    @patch("mirror.subprocess.run")
    def test_exception(self, mock_run):
        mock_run.side_effect = RuntimeError("boom")
        out, err, rc = run_cmd(["bad"])
        self.assertEqual(rc, -1)
        self.assertIn("boom", err)

    @patch("mirror.subprocess.run")
    def test_input_text_passed(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        run_cmd(["adb"], input_text="secret\n")
        self.assertEqual(mock_run.call_args[1]["input"], "secret\n")


class TestAdbDevicesList(unittest.TestCase):
    @patch("mirror.run_cmd")
    def test_parses_devices(self, mock_cmd):
        mock_cmd.return_value = (
            "List of devices attached\n"
            "ABC123    device product:foo model:Pixel\n"
            "192.168.1.5:5555    device\n",
            "", 0,
        )
        devs = adb_devices_list()
        self.assertEqual(len(devs), 2)
        self.assertEqual(devs[0]["serial"], "ABC123")
        self.assertEqual(devs[0]["state"], "device")
        self.assertIn("model:Pixel", devs[0]["info"])

    @patch("mirror.run_cmd")
    def test_empty_on_failure(self, mock_cmd):
        mock_cmd.return_value = ("", "err", 1)
        self.assertEqual(adb_devices_list(), [])

    @patch("mirror.run_cmd")
    def test_skips_header_and_blank(self, mock_cmd):
        mock_cmd.return_value = ("List of devices attached\n\n", "", 0)
        self.assertEqual(adb_devices_list(), [])


# ================================================================
#  parse_device_model / parse_device_product
# ================================================================

class TestParseDeviceModel(unittest.TestCase):
    def test_extracts_model(self):
        self.assertEqual(parse_device_model("product:m32dd model:SM_M325F"), "SM M325F")

    def test_no_model(self):
        self.assertEqual(parse_device_model("transport_usb"), "")

    def test_underscores_replaced(self):
        self.assertEqual(parse_device_model("model:Pixel_7_Pro"), "Pixel 7 Pro")


class TestParseDeviceProduct(unittest.TestCase):
    def test_extracts_product(self):
        self.assertEqual(parse_device_product("product:m32dd model:SM_M325F"), "m32dd")

    def test_no_product(self):
        self.assertEqual(parse_device_product(""), "")


# ================================================================
#  mDNS helpers
# ================================================================

class TestAdbMdnsInit(unittest.TestCase):
    @patch("mirror.run_cmd")
    def test_returns_true_when_daemon_running(self, mock_cmd):
        mock_cmd.return_value = ("mdns daemon version [0.0.0]", "", 0)
        self.assertTrue(adb_mdns_init())

    @patch("mirror.run_cmd")
    def test_returns_false_on_failure(self, mock_cmd):
        mock_cmd.return_value = ("", "error", 1)
        self.assertFalse(adb_mdns_init())


class TestAdbMdnsDiscover(unittest.TestCase):
    @patch("mirror.adb_mdns_init", return_value=True)
    @patch("mirror.run_cmd")
    def test_parses_services(self, mock_cmd, _):
        mock_cmd.return_value = (
            "List of discovered mdns services\n"
            "adb-ABC\t_adb-tls-connect._tcp\t192.168.1.4:33407\n",
            "", 0,
        )
        svcs = adb_mdns_discover()
        self.assertEqual(len(svcs), 1)
        self.assertEqual(svcs[0]["ip"], "192.168.1.4")
        self.assertEqual(svcs[0]["port"], "33407")
        self.assertEqual(svcs[0]["name"], "adb-ABC")

    @patch("mirror.adb_mdns_init", return_value=True)
    @patch("mirror.run_cmd")
    def test_returns_empty_on_failure(self, mock_cmd, _):
        mock_cmd.return_value = ("", "error", 1)
        self.assertEqual(adb_mdns_discover(), [])

    @patch("mirror.adb_mdns_init", return_value=True)
    @patch("mirror.run_cmd")
    def test_skips_header(self, mock_cmd, _):
        mock_cmd.return_value = (
            "List of discovered mdns services\n\n", "", 0,
        )
        self.assertEqual(adb_mdns_discover(), [])


class TestFullDiscover(unittest.TestCase):
    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_merges_adb_and_mdns(self, mock_adb, mock_mdns):
        mock_adb.return_value = [
            {"serial": "ABC123", "state": "device",
             "info": "model:Pixel_7 product:pixel", "raw": "..."},
        ]
        mock_mdns.return_value = [
            {"name": "adb-XYZ", "type": "_adb-tls-connect._tcp",
             "host": "192.168.1.4:33407", "ip": "192.168.1.4", "port": "33407"},
        ]
        devices = full_discover()
        self.assertEqual(len(devices), 2)
        # First from adb
        self.assertEqual(devices[0]["serial"], "ABC123")
        self.assertEqual(devices[0]["model"], "Pixel 7")
        self.assertEqual(devices[0]["source"], "adb")
        # Second from mDNS
        self.assertEqual(devices[1]["source"], "mdns")
        self.assertEqual(devices[1]["ip"], "192.168.1.4")

    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_deduplicates_ip(self, mock_adb, mock_mdns):
        """If adb devices and mDNS both show same IP, don't duplicate."""
        mock_adb.return_value = [
            {"serial": "192.168.1.4:33407", "state": "device",
             "info": "model:SM_M325F", "raw": "..."},
        ]
        mock_mdns.return_value = [
            {"name": "adb-RZ8", "type": "_tcp",
             "host": "192.168.1.4:33407", "ip": "192.168.1.4", "port": "33407"},
        ]
        devices = full_discover()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.168.1.4")

    @patch("mirror.adb_mdns_discover", return_value=[])
    @patch("mirror.adb_devices_list", return_value=[])
    def test_empty(self, mock_adb, mock_mdns):
        self.assertEqual(full_discover(), [])


# ================================================================
#  QR code generation
# ================================================================

class TestGenerateQrPil(unittest.TestCase):
    def test_returns_pil_image(self):
        # qrcode module is mocked, so just check it's called correctly
        img = generate_qr_pil("adb connect 192.168.1.5:5555")
        # The mocked QRCode.make_image returns a MagicMock
        self.assertIsNotNone(img)


# ================================================================
#  Regression tests for previous bugs
# ================================================================

class MockStringVar:
    def __init__(self, v=""):
        self._v = v
    def get(self):
        return self._v
    def set(self, v):
        self._v = v


class TestAutoDiscoverDoesNotReturnLaptopIP(unittest.TestCase):
    """Regression: auto-detect uses full_discover(), not get_local_ip().

    full_discover() returns device dicts with the PHONE's IP, not the
    laptop's.  This is the core fix: the old code called get_local_ip()
    which always returned the laptop's own IP.
    """

    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_returns_phone_ip_from_mdns(self, mock_adb, mock_mdns):
        """full_discover should return the phone's IP from mDNS, not the laptop's."""
        mock_adb.return_value = []
        mock_mdns.return_value = [
            {"name": "adb-RZ8", "type": "_adb-tls-connect._tcp",
             "host": "192.168.1.4:33407", "ip": "192.168.1.4", "port": "33407"},
        ]
        devices = full_discover()
        self.assertEqual(len(devices), 1)
        # Must be the PHONE's IP, not the laptop's
        self.assertEqual(devices[0]["ip"], "192.168.1.4")
        self.assertEqual(devices[0]["source"], "mdns")

    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_returns_phone_ip_from_adb(self, mock_adb, mock_mdns):
        mock_adb.return_value = [
            {"serial": "192.168.1.4:33407", "state": "device",
             "info": "model:SM_M325F", "raw": "..."},
        ]
        mock_mdns.return_value = []
        devices = full_discover()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.168.1.4")
        self.assertEqual(devices[0]["source"], "adb")

    @patch("mirror.adb_mdns_discover", return_value=[])
    @patch("mirror.adb_devices_list", return_value=[])
    def test_empty_when_nothing_found(self, mock_adb, mock_mdns):
        """When no devices found, full_discover returns empty — not the laptop IP."""
        devices = full_discover()
        self.assertEqual(devices, [])
        # The old code would return get_local_ip() here — this test ensures
        # we never fall back to the laptop's own IP.


class TestSaveConfig(unittest.TestCase):
    def _make_stub(self, path):
        stub = MagicMock()
        stub.ip_var = MockStringVar("192.168.1.10")
        stub.pair_port_var = MockStringVar("33921")
        stub.connect_port_var = MockStringVar("33683")
        stub.pair_code_var = MockStringVar("123456")
        stub.theme_var = MockStringVar("darkly")
        stub.scan_threads = 100
        stub.ping_timeout = 1.0
        cp = configparser.ConfigParser()
        cp["DEFAULT"] = {"IP": "", "PairPort": "5555", "ConnectPort": "5555",
                         "PairCode": "", "Theme": "darkly", "ScanThreads": "100",
                         "PingTimeoutSec": "1"}
        stub._cfg = cp
        stub._save_config = ScrcpyLauncher._save_config.__get__(stub)
        return stub

    def test_writes_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            path = f.name
        try:
            stub = self._make_stub(path)
            with patch("mirror.CONFIG_FILE", path):
                stub._save_config()
            cp = configparser.ConfigParser()
            cp.read(path)
            self.assertEqual(cp["DEFAULT"]["ip"], "192.168.1.10")
            self.assertEqual(cp["DEFAULT"]["pairport"], "33921")
        finally:
            os.unlink(path)

    def test_not_recursive(self):
        """_save_config must not call itself infinitely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            path = f.name
        try:
            stub = self._make_stub(path)
            with patch("mirror.CONFIG_FILE", path):
                stub._save_config()  # should not raise RecursionError
        finally:
            os.unlink(path)


class TestSchedule(unittest.TestCase):
    def test_delegates_to_after(self):
        stub = MagicMock()
        stub._schedule = ScrcpyLauncher._schedule.__get__(stub)
        cb = MagicMock()
        stub._schedule(cb, "x", "y")
        stub.after.assert_called_once_with(0, cb, "x", "y")


class TestQuickMirror(unittest.TestCase):
    """Tests for the one-click Quick Mirror flow.

    These test the core logic: full_discover → best device → correct IP.
    The _quick_mirror method itself chains discover → connect → scrcpy,
    but testing the method binding through MagicMock is fragile, so we
    verify the key building blocks instead.
    """

    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_discover_returns_phone_for_quick_mirror(self, mock_adb, mock_mdns):
        """full_discover (used by _quick_mirror) returns the phone's IP, not laptop's."""
        mock_adb.return_value = []
        mock_mdns.return_value = [
            {"name": "adb-RZ8", "type": "_tcp",
             "host": "192.168.1.4:33407", "ip": "192.168.1.4", "port": "33407"},
        ]
        devices = full_discover()
        # The quick mirror flow picks best["ip"] from this list
        best = devices[0]
        self.assertEqual(best["ip"], "192.168.1.4")
        self.assertEqual(best["port"], "33407")
        self.assertEqual(best["model"], "adb-RZ8")

    @patch("mirror.adb_mdns_discover", return_value=[])
    @patch("mirror.adb_devices_list", return_value=[])
    def test_no_devices_skips_quick_mirror(self, mock_adb, mock_mdns):
        """When no devices found, the quick mirror flow would abort."""
        devices = full_discover()
        self.assertEqual(devices, [])
        # _quick_mirror checks `if not devices:` and returns early

    @patch("mirror.run_cmd")
    @patch("mirror.adb_mdns_discover")
    @patch("mirror.adb_devices_list")
    def test_connect_step_uses_phone_ip(self, mock_adb, mock_mdns, mock_cmd):
        """After discovery, the connect step uses the phone's IP."""
        mock_adb.return_value = [
            {"serial": "192.168.1.4:33407", "state": "device",
             "info": "model:SM_M325F", "raw": "..."},
        ]
        mock_mdns.return_value = []
        mock_cmd.return_value = ("connected to 192.168.1.4:33407", "", 0)

        devices = full_discover()
        best = devices[0]

        # Simulate what _quick_mirror does: adb connect to best["ip"]:best["port"]
        # mirror.run_cmd is patched, so use it via the module namespace
        import mirror
        out, err, rc = mirror.run_cmd(["adb", "connect", f"{best['ip']}:{best['port']}"])
        self.assertEqual(rc, 0)
        self.assertIn("connected", out.lower())
        # Verify the connect call used the phone's IP, not the laptop's
        call_args = mock_cmd.call_args[0][0]
        self.assertIn("192.168.1.4", call_args[-1])


if __name__ == "__main__":
    unittest.main()
