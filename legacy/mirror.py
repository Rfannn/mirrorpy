"""
MirrorPy — Wireless scrcpy Launcher
Features: adb mDNS device discovery, QR code pairing, modern ttkbootstrap GUI.
"""

import os
import re
import sys
import socket
import platform
import subprocess
import configparser
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

# UI
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# QR code
import qrcode
from PIL import ImageTk, Image

# ---------- Config & Logging ----------
def app_dir():
    """Directory holding the app's own data files.

    Running from a clone this is the source folder. Under PyInstaller it is the
    folder containing the exe, not the temp extraction dir, so settings survive
    a rebuild.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR = app_dir()
CONFIG_FILE = os.path.join(APP_DIR, "settings.ini")
LOG_FILE = os.path.join(APP_DIR, "scrcpy_launcher.log")


def bundled_tool(name):
    """Return a bundled adb/scrcpy path, or the plain name to resolve via PATH.

    A frozen exe carries its copy in the app folder. Running from a source tree,
    the binaries may sit one level up when this code lives in a subfolder, so
    check the parent too.
    """
    exe = name + (".exe" if os.name == "nt" else "")
    parent = os.path.dirname(APP_DIR)
    for folder in (APP_DIR, parent):
        path = os.path.join(folder, exe)
        if os.path.exists(path):
            return path
    return name


SCREENSHOT_DIR = os.path.join(APP_DIR, "screenshots")

# configparser lowercases option names, so keep every key lowercase.
DEFAULTS = {
    "ip": "",
    "pairport": "5555",
    "connectport": "5555",
    "paircode": "",
    "theme": "dark",
    "scanthreads": "100",
    "pingtimeoutsec": "1",
    "lastdevice": "",
    "quality": "Medium",
    "accent": "pink",
    "autoconnect": "0",
}

logger = logging.getLogger("scrcpy_launcher")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)


# ============================================================
#  Helpers — pure functions, no tkinter dependency
# ============================================================

def get_local_ip():
    """Return this machine's LAN IP via the UDP socket trick."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def ping_host(ip, timeout=1):
    """Ping an IP once; return True if it responds."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


def run_cmd(args, input_text=None, timeout=None):
    """Run a command; return (stdout, stderr, returncode)."""
    try:
        shell = isinstance(args, str)
        proc = subprocess.run(
            args, input=input_text, capture_output=True, text=True,
            shell=shell, timeout=timeout,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def adb_devices_list():
    """Return parsed ``adb devices -l`` output as a list of dicts."""
    out, err, rc = run_cmd([bundled_tool("adb"), "devices", "-l"])
    if rc != 0:
        return []
    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        state = parts[1]
        info = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append({"serial": serial, "state": state, "info": info, "raw": line})
    return devices


def parse_device_model(info_str):
    """Extract model from adb info string like 'product:m32dd model:SM_M325F'."""
    m = re.search(r"model:(\S+)", info_str)
    return m.group(1).replace("_", " ") if m else ""


def parse_device_product(info_str):
    m = re.search(r"product:(\S+)", info_str)
    return m.group(1) if m else ""


# ---------- mDNS helpers ----------

def adb_mdns_init():
    """Start the adb mDNS daemon if it isn't already running. Returns True on success."""
    out, err, rc = run_cmd([bundled_tool("adb"), "mdns", "check"], timeout=5)
    if rc == 0 and "mdns daemon version" in (out + err).lower():
        return True
    # try to start it
    out, err, rc = run_cmd([bundled_tool("adb"), "mdns", "check"], timeout=5)
    return rc == 0


def adb_mdns_discover():
    """
    Discover Android devices via adb mDNS.
    Returns list of dicts: [{ name, type, host, ip, port }, ...]
    """
    # Ensure mDNS daemon is running
    adb_mdns_init()

    out, err, rc = run_cmd([bundled_tool("adb"), "mdns", "services"], timeout=8)
    if rc != 0:
        return []

    services = []
    for line in out.splitlines():
        line = line.strip()
        # skip header and empty lines
        if not line or line.lower().startswith("list of") or line.lower().startswith("error"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        svc_name = parts[0]
        svc_type = parts[1]
        host_port = parts[2]
        # parse ip:port
        if ":" in host_port:
            ip, port = host_port.rsplit(":", 1)
        else:
            ip, port = host_port, ""
        services.append({
            "name": svc_name,
            "type": svc_type,
            "host": host_port,
            "ip": ip,
            "port": port,
        })
    return services


def full_discover():
    """
    Combined discovery: adb devices + mDNS.
    Returns list of device dicts with keys:
      serial, state, model, product, ip, port, source
    """
    results = []
    seen = set()

    # 1) Already-connected devices from adb devices -l
    for dev in adb_devices_list():
        model = parse_device_model(dev["info"])
        product = parse_device_product(dev["info"])
        ip, port = "", ""

        # Try to extract ip:port from serial (e.g. "192.168.1.4:33407")
        if ":" in dev["serial"] and not dev["serial"].startswith("adb-"):
            ip, port = dev["serial"].rsplit(":", 1)

        entry = {
            "serial": dev["serial"],
            "state": dev["state"],
            "model": model or product or dev["serial"],
            "product": product,
            "ip": ip,
            "port": port,
            "info": dev["info"],
            "source": "adb",
        }
        key = dev["serial"]
        if key not in seen:
            results.append(entry)
            seen.add(key)

    # 2) mDNS-discovered devices (wireless debugging)
    for svc in adb_mdns_discover():
        # Check if this IP is already in results
        already = any(r["ip"] == svc["ip"] for r in results)
        if already:
            # Update port if missing
            for r in results:
                if r["ip"] == svc["ip"] and not r["port"]:
                    r["port"] = svc["port"]
            continue

        entry = {
            "serial": f"{svc['ip']}:{svc['port']}",
            "state": "mdns",
            "model": svc["name"],
            "product": "",
            "ip": svc["ip"],
            "port": svc["port"],
            "info": svc["type"],
            "source": "mdns",
        }
        results.append(entry)

    return results


# ============================================================
#  GUI helpers
# ============================================================

def generate_qr_pil(text, box_size=6, border=2):
    """Generate a QR code and return a PIL Image."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(text)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


# ttkbootstrap theme names this interface may use. Listing them keeps the
# check off ttk.Style(), which binds a second root and breaks window creation.
TTK_THEME_NAMES = frozenset([
    "bootstrap-dark", "bootstrap-light", "catppuccin-dark", "catppuccin-light",
    "dracula-dark", "dracula-light", "everforest-dark", "everforest-light",
    "gruvbox-dark", "gruvbox-light", "minty-dark", "minty-light",
    "nord-dark", "nord-light", "one-dark", "one-light",
    "pulse-dark", "pulse-light", "pydata-dark", "pydata-light",
    "sandstone-dark", "sandstone-light", "solarized-dark", "solarized-light",
    "tokyo-night-dark", "tokyo-night-light", "united-dark", "united-light",
    "vapor-dark", "vapor-light",
])


def ttk_theme_name(value):
    """Pick a valid ttkbootstrap theme.

    Both interfaces share one settings file. The glass UI stores "dark" or
    "light" for its own theme, which ttkbootstrap does not know, so map those
    and fall back to a default rather than crashing.
    """
    aliases = {"dark": "bootstrap-dark", "light": "bootstrap-light"}
    name = aliases.get(str(value).strip().lower(), str(value).strip())
    return name if name in TTK_THEME_NAMES else "bootstrap-dark"


def scrcpy_args(preset="Medium", serial=None):
    """Build the scrcpy command line for a quality preset."""
    from ui.theme import QUALITY_PRESETS

    args = [bundled_tool("scrcpy")]
    if serial:
        args += ["-s", serial]
    p = QUALITY_PRESETS.get(preset)
    if not p:
        return args
    if p.get("resolution", "").lower() != "original":
        args += ["--max-size", p["resolution"]]
    if p.get("fps", "").lower() != "original":
        args += ["--max-fps", p["fps"]]
    if p.get("bitrate"):
        args += ["--video-bit-rate", p["bitrate"]]
    return args


# ============================================================
#  GUI Logger widget
# ============================================================

class GuiLogger(ttk.Frame):
    def __init__(self, master, height=10, **kwargs):
        super().__init__(master, **kwargs)
        self.text = ttk.Text(self, height=height, state=DISABLED, wrap=WORD)
        self.text.pack(fill=BOTH, expand=YES)
        self.queue = Queue()
        self._poll()

    def _poll(self):
        try:
            while True:
                msg, tag = self.queue.get_nowait()
                self._append(msg, tag)
        except Empty:
            pass
        self.after(100, self._poll)

    def _append(self, message, tag=None):
        self.text.config(state="normal")
        if tag:
            self.text.insert("end", message + "\n", tag)
            self.text.tag_config(tag, foreground=tag)
        else:
            self.text.insert("end", message + "\n")
        self.text.see("end")
        self.text.config(state="disabled")

    def log(self, message, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.queue.put((f"[{ts}] {message}", self._color(level)))
        log_fn = {"debug": logger.debug, "warning": logger.warning,
                  "error": logger.error}.get(level, logger.info)
        log_fn(message)

    @staticmethod
    def _color(level):
        return {"info": "black", "success": "#2ecc71", "error": "#e74c3c",
                "warning": "#f39c12", "debug": "#95a5a6", "blue": "#3498db"
                }.get(level, "black")


# ============================================================
#  Device Card — compact info panel for the detected device
# ============================================================

class DeviceCard(ttk.Labelframe):
    """Displays the currently detected / connected device."""

    def __init__(self, master, **kwargs):
        super().__init__(master, text="  📱  Device  ", padding=12, **kwargs)

        self._model_var = ttk.StringVar(value="No device detected")
        self._ip_var = ttk.StringVar(value="")
        self._status_var = ttk.StringVar(value="idle")
        self._serial_var = ttk.StringVar(value="")

        # Model / name
        ttk.Label(self, textvariable=self._model_var,
                  font=("Segoe UI", 13, "bold")).pack(anchor=W)
        # IP line
        ttk.Label(self, textvariable=self._ip_var,
                  font=("Consolas", 10)).pack(anchor=W, pady=(2, 0))
        # Status badge
        self._status_label = ttk.Label(self, textvariable=self._status_var,
                                       font=("Segoe UI", 9, "bold"))
        self._status_label.pack(anchor=W, pady=(4, 0))

    def set_device(self, model, ip, port, serial, status="ready"):
        self._model_var.set(model or "Unknown device")
        self._ip_var.set(f"{ip}:{port}" if port else ip)
        self._serial_var.set(serial)
        color = {"ready": "#2ecc71", "connected": "#27ae60",
                 "mirroring": "#e67e22", "idle": "#95a5a6",
                 "error": "#e74c3c"}.get(status, "#95a5a6")
        self._status_label.config(foreground=color)
        self._status_var.set(f"● {status.upper()}")

    def clear(self):
        self._model_var.set("No device detected")
        self._ip_var.set("")
        self._status_var.set("idle")
        self._serial_var.set("")
        self._status_label.config(foreground="#95a5a6")

    @property
    def serial(self):
        return self._serial_var.get()


# ============================================================
#  Main Application
# ============================================================

class ScrcpyLauncher(ttk.Window):
    def __init__(self):
        self._cfg = configparser.ConfigParser()
        self._load_config()
        theme = ttk_theme_name(self._cfg["DEFAULT"].get("theme", "bootstrap-dark"))
        super().__init__(themename=theme)
        self.title("MirrorPy — scrcpy Launcher")
        self.geometry("900x720")
        self.minsize(800, 640)

        # Variables
        self.ip_var = ttk.StringVar(value=self._cfg["DEFAULT"].get("ip", ""))
        self.pair_port_var = ttk.StringVar(value=self._cfg["DEFAULT"].get("pairport", "5555"))
        self.connect_port_var = ttk.StringVar(value=self._cfg["DEFAULT"].get("connectport", "5555"))
        self.pair_code_var = ttk.StringVar(value=self._cfg["DEFAULT"].get("paircode", ""))
        self.theme_var = ttk.StringVar(value=theme)
        self.scan_threads = int(self._cfg["DEFAULT"].get("scanthreads", "100"))
        self.ping_timeout = float(self._cfg["DEFAULT"].get("pingtimeoutsec", "1"))

        self._qr_photo = None  # keep reference to avoid GC

        self._build_ui()
        self._refresh_devices()
        self.logger.log("Ready.  Click **Detect Device** to find your phone.", "info")

    # ---------- Config persistence ----------

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            self._cfg.read(CONFIG_FILE)
        else:
            self._cfg["DEFAULT"] = DEFAULTS.copy()
            with open(CONFIG_FILE, "w") as f:
                self._cfg.write(f)
        for k, v in DEFAULTS.items():
            if k not in self._cfg["DEFAULT"]:
                self._cfg["DEFAULT"][k] = v

    def _save_config(self):
        self._cfg["DEFAULT"]["ip"] = self.ip_var.get().strip()
        self._cfg["DEFAULT"]["pairport"] = self.pair_port_var.get().strip()
        self._cfg["DEFAULT"]["connectport"] = self.connect_port_var.get().strip()
        self._cfg["DEFAULT"]["paircode"] = self.pair_code_var.get().strip()
        self._cfg["DEFAULT"]["theme"] = self.theme_var.get().strip()
        self._cfg["DEFAULT"]["scanthreads"] = str(self.scan_threads)
        self._cfg["DEFAULT"]["pingtimeoutsec"] = str(self.ping_timeout)
        with open(CONFIG_FILE, "w") as f:
            self._cfg.write(f)

    # ---------- Thread-safe scheduling ----------

    def _schedule(self, cb, *a):
        self.after(0, cb, *a)

    # ==========================================================
    #  UI Construction
    # ==========================================================

    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────
        topbar = ttk.Frame(self, padding=(14, 10, 14, 4))
        topbar.pack(fill=X)
        ttk.Label(topbar, text="📱  MirrorPy",
                  font=("Segoe UI", 18, "bold")).pack(side=LEFT)
        ttk.Label(topbar, text="  scrcpy wireless launcher",
                  font=("Segoe UI", 10), foreground="gray").pack(side=LEFT, padx=(0, 20))

        ttk.Label(topbar, text="Theme:").pack(side=RIGHT, padx=(0, 4))
        ttk.Combobox(topbar, values=ttk.Style().theme_names(),
                     textvariable=self.theme_var, width=14,
                     state="readonly").pack(side=RIGHT)
        self.theme_var.trace_add("write", lambda *_: self._on_theme_change())

        # ── Separator ────────────────────────────────────────
        ttk.Separator(self, orient=HORIZONTAL).pack(fill=X, padx=10, pady=4)

        # ── Main content: left (controls) | right (QR + settings)
        body = ttk.Frame(self, padding=10)
        body.pack(fill=BOTH, expand=YES)

        left = ttk.Frame(body)
        left.pack(side=LEFT, fill=BOTH, expand=YES, padx=(0, 10))

        right = ttk.Frame(body, width=280)
        right.pack(side=RIGHT, fill=Y)

        # ── Left side ────────────────────────────────────────

        # Device card
        self.device_card = DeviceCard(left)
        self.device_card.pack(fill=X, pady=(0, 8))

        # Connection section
        conn = ttk.Labelframe(left, text="  🔗  Connection  ", padding=10)
        conn.pack(fill=X, pady=(0, 8))

        # Row 1: IP + Detect button
        r1 = ttk.Frame(conn)
        r1.pack(fill=X, pady=3)
        ttk.Label(r1, text="IP:", width=5).pack(side=LEFT)
        self.ip_entry = ttk.Entry(r1, textvariable=self.ip_var, width=22)
        self.ip_entry.pack(side=LEFT, padx=(0, 6))
        ttk.Label(r1, text="Port:").pack(side=LEFT, padx=(6, 0))
        self.port_entry = ttk.Entry(r1, textvariable=self.connect_port_var, width=8)
        self.port_entry.pack(side=LEFT, padx=(0, 6))

        self.btn_detect = ttk.Button(r1, text="🔍 Detect Device",
                                     bootstyle="info",
                                     command=self._threaded_discover)
        self.btn_detect.pack(side=RIGHT)

        # Row 2: Pair fields
        r2 = ttk.Frame(conn)
        r2.pack(fill=X, pady=3)
        ttk.Label(r2, text="Pair:", width=5).pack(side=LEFT)
        self.pair_port_entry = ttk.Entry(r2, textvariable=self.pair_port_var, width=8)
        self.pair_port_entry.pack(side=LEFT, padx=(0, 6))
        ttk.Label(r2, text="Code:").pack(side=LEFT, padx=(6, 0))
        self.pair_code_entry = ttk.Entry(r2, textvariable=self.pair_code_var,
                                         width=10, show="*")
        self.pair_code_entry.pack(side=LEFT, padx=(0, 6))

        # Row 3: Action buttons (wizard-style)
        btns = ttk.Frame(conn)
        btns.pack(fill=X, pady=(8, 2))

        self.btn_pair = ttk.Button(btns, text="🤝 Pair", bootstyle="warning",
                                   command=self._threaded_pair, width=14)
        self.btn_pair.pack(side=LEFT, padx=(0, 4))

        self.btn_connect = ttk.Button(btns, text="🔌 Connect", bootstyle="primary",
                                      command=self._threaded_connect, width=14)
        self.btn_connect.pack(side=LEFT, padx=(0, 4))

        self.btn_mirror = ttk.Button(btns, text="▶  Mirror", bootstyle="success",
                                     command=self._threaded_start_scrcpy, width=14)
        self.btn_mirror.pack(side=LEFT, padx=(0, 4))

        self.btn_disconnect = ttk.Button(btns, text="⏏  Disconnect",
                                         bootstyle="danger-outline",
                                         command=self._threaded_disconnect, width=14)
        self.btn_disconnect.pack(side=LEFT)

        # One-click Quick Mirror button
        self.btn_quick = ttk.Button(conn, text="⚡  Quick Mirror — Detect, Connect & Mirror",
                                    bootstyle="success-outline",
                                    command=self._threaded_quick_mirror)
        self.btn_quick.pack(fill=X, pady=(8, 2))

        # ADB devices list
        dev_frame = ttk.Labelframe(left, text="  📋  ADB Devices  ", padding=8)
        dev_frame.pack(fill=X, pady=(0, 8))

        dr = ttk.Frame(dev_frame)
        dr.pack(fill=X)
        self.devices_var = ttk.StringVar()
        self.devices_combo = ttk.Combobox(dr, textvariable=self.devices_var,
                                          state="readonly", width=50)
        self.devices_combo.pack(side=LEFT, fill=X, expand=YES, padx=(0, 6))
        ttk.Button(dr, text="↻", bootstyle="outline-info", width=3,
                   command=self._refresh_devices).pack(side=RIGHT)
        ttk.Button(dr, text="Use ▸", bootstyle="outline-success", width=6,
                   command=self._use_selected_device).pack(side=RIGHT, padx=(0, 4))

        # Log
        self.logger = GuiLogger(left, height=14)
        self.logger.pack(fill=BOTH, expand=YES)

        # ── Right side ───────────────────────────────────────

        # QR Code panel
        qr_card = ttk.Labelframe(right, text="  📷  QR Code  ", padding=10)
        qr_card.pack(fill=X, pady=(0, 8))

        self.qr_label = ttk.Label(qr_card, text="Detect a device to\nshow QR code",
                                  justify=CENTER, foreground="gray")
        self.qr_label.pack(fill=BOTH, expand=YES, pady=10)

        ttk.Button(qr_card, text="Copy connect string", bootstyle="outline-secondary",
                   command=self._copy_connect_string).pack(fill=X, pady=(4, 0))

        # Quick scan (ping sweep)
        scan_card = ttk.Labelframe(right, text="  🌐  Network Scan  ", padding=10)
        scan_card.pack(fill=X, pady=(0, 8))

        self.progress = ttk.Progressbar(scan_card, mode="determinate")
        self.progress.pack(fill=X, pady=(0, 4))
        self.progress_label = ttk.Label(scan_card, text="Idle", foreground="gray")
        self.progress_label.pack(anchor=W)
        ttk.Button(scan_card, text="Scan Subnet", bootstyle="secondary-outline",
                   command=self._threaded_scan_network).pack(fill=X, pady=(6, 0))

        # Settings
        sets = ttk.Labelframe(right, text="  ⚙️  Settings  ", padding=10)
        sets.pack(fill=X, pady=(0, 8))

        sr1 = ttk.Frame(sets)
        sr1.pack(fill=X, pady=2)
        ttk.Label(sr1, text="Threads:").pack(side=LEFT)
        self.threads_spin = ttk.Spinbox(sr1, from_=10, to=500, increment=10,
                                        width=6, command=self._update_scan_threads)
        self.threads_spin.set(self.scan_threads)
        self.threads_spin.pack(side=LEFT, padx=(4, 12))
        ttk.Label(sr1, text="Timeout:").pack(side=LEFT)
        self.timeout_spin = ttk.Spinbox(sr1, from_=0.2, to=5.0, increment=0.2,
                                        width=6, command=self._update_ping_timeout)
        self.timeout_spin.set(self.ping_timeout)
        self.timeout_spin.pack(side=LEFT, padx=(4, 0))

        ttk.Button(sets, text="Save Settings", bootstyle="info-outline",
                   command=self._do_save_config).pack(fill=X, pady=(6, 0))

        # Theme chooser
        theme_frame = ttk.Labelframe(right, text="  🎨  Theme  ", padding=10)
        theme_frame.pack(fill=X)
        ttk.Combobox(theme_frame, values=ttk.Style().theme_names(),
                     textvariable=self.theme_var, width=16,
                     state="readonly").pack(fill=X)

        # ── Bottom status bar ────────────────────────────────
        bottom = ttk.Frame(self, padding=(10, 6))
        bottom.pack(fill=X, side=BOTTOM)
        ttk.Separator(bottom, orient=HORIZONTAL).pack(fill=X, pady=(0, 4))
        self.status_label = ttk.Label(bottom, text="● Ready", foreground="gray")
        self.status_label.pack(side=LEFT)

        # IP/port change triggers QR update
        self.ip_var.trace_add("write", lambda *_: self._update_qr())
        self.connect_port_var.trace_add("write", lambda *_: self._update_qr())

    # ==========================================================
    #  QR Code
    # ==========================================================

    def _update_qr(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip:
            return
        connect_str = f"adb connect {ip}:{port}" if port else f"adb connect {ip}"
        try:
            img = generate_qr_pil(connect_str, box_size=5, border=2)
            # resize to fit panel
            img = img.resize((180, 180), Image.LANCZOS)
            self._qr_photo = ImageTk.PhotoImage(img)
            self.qr_label.config(image=self._qr_photo, text="")
        except Exception as e:
            self.logger.log(f"QR generation error: {e}", "warning")

    def _copy_connect_string(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip:
            return
        s = f"adb connect {ip}:{port}" if port else f"adb connect {ip}"
        self.clipboard_clear()
        self.clipboard_append(s)
        self.logger.log(f"Copied: {s}", "info")

    # ==========================================================
    #  Theme
    # ==========================================================

    def _on_theme_change(self):
        theme = ttk_theme_name(self.theme_var.get())
        try:
            self.style.theme_use(theme)
            self._save_config()
        except Exception:
            pass

    # ==========================================================
    #  Settings spinbox callbacks
    # ==========================================================

    def _update_scan_threads(self):
        try:
            self.scan_threads = int(self.threads_spin.get())
        except Exception:
            pass

    def _update_ping_timeout(self):
        try:
            self.ping_timeout = float(self.timeout_spin.get())
        except Exception:
            pass

    def _do_save_config(self):
        self._save_config()
        self.logger.log("Settings saved.", "success")
        self._update_qr()

    # ==========================================================
    #  ADB device management
    # ==========================================================

    def _refresh_devices(self):
        self.logger.log("Refreshing ADB devices...", "info")
        devices = adb_devices_list()
        if not devices:
            self.logger.log("No ADB devices found.", "warning")
            self.devices_combo["values"] = []
            self.devices_var.set("")
            return
        vals = []
        for d in devices:
            model = parse_device_model(d["info"])
            label = f"{d['serial']}  —  {model}  ({d['state']})" if model else \
                    f"{d['serial']}  ({d['state']})"
            vals.append(label)
        self.devices_combo["values"] = vals
        self.devices_var.set(vals[0])
        self.logger.log(f"Found {len(devices)} ADB device(s).", "success")

    def _use_selected_device(self):
        """Fill IP/port from the selected ADB device entry."""
        label = self.devices_var.get()
        if not label:
            return
        serial = label.split("  ")[0].strip()

        # If it's an IP:port serial
        if ":" in serial and not serial.startswith("adb-"):
            ip, port = serial.rsplit(":", 1)
            self.ip_var.set(ip)
            self.connect_port_var.set(port)
            self._update_qr()

        # If it's an adb- mDNS serial, look up from adb devices
        for dev in adb_devices_list():
            if dev["serial"] == serial:
                # Extract IP from info if available
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", dev["serial"])
                if ip_match:
                    self.ip_var.set(ip_match.group(1))
                    self.connect_port_var.set(ip_match.group(2))
                    self._update_qr()
                model = parse_device_model(dev["info"])
                self.device_card.set_device(model or serial, self.ip_var.get(),
                                            self.connect_port_var.get(), serial, "ready")
                break

        self.logger.log(f"Selected device: {serial}", "info")

    # ==========================================================
    #  Device Discovery  (THE FIX: uses adb mdns, not local IP)
    # ==========================================================

    def _threaded_discover(self):
        self.btn_detect.config(state=DISABLED, text="⏳ Detecting…")
        threading.Thread(target=self._discover_device, daemon=True).start()

    def _discover_device(self):
        self.logger.log("Scanning for Android devices via ADB + mDNS…", "info")
        devices = full_discover()

        def _update_ui():
            self.btn_detect.config(state=NORMAL, text="🔍 Detect Device")
            if not devices:
                self.logger.log("No Android devices found.  Make sure USB/Wireless Debugging "
                                "is enabled.", "warning")
                self.device_card.clear()
                return

            # Pick the best device: prefer connected ones, then mDNS
            best = None
            for d in devices:
                if d["state"] == "device":
                    best = d
                    break
            if not best:
                best = devices[0]

            self.ip_var.set(best["ip"])
            if best["port"]:
                self.connect_port_var.set(best["port"])

            self.device_card.set_device(
                model=best["model"],
                ip=best["ip"],
                port=best["port"],
                serial=best["serial"],
                status="ready" if best["state"] == "device" else "detected",
            )

            self.logger.log(
                f"Found: {best['model']}  ({best['ip']}:{best['port']})  "
                f"[{best['source']}]",
                "success",
            )

            # Update ADB devices list
            self._refresh_devices()
            self._update_qr()
            self._save_config()

        self._schedule(_update_ui)

    # ==========================================================
    #  Pair / Connect / Disconnect / Mirror
    # ==========================================================

    def _threaded_pair(self):
        threading.Thread(target=self._pair_device, daemon=True).start()

    def _pair_device(self):
        ip = self.ip_var.get().strip()
        port = self.pair_port_var.get().strip()
        code = self.pair_code_var.get().strip()
        if not ip or not port or not code:
            self.logger.log("Fill IP, pair port, and pairing code first.", "error")
            return
        self.logger.log(f"Pairing to {ip}:{port}…", "info")
        out, err, rc = run_cmd([bundled_tool("adb"), "pair", f"{ip}:{port}"],
                               input_text=code + "\n", timeout=10)
        if rc == 0 and "paired" in out.lower():
            self.logger.log("✓ Paired successfully!", "success")
            self._save_config()
        else:
            # fallback: shell echo
            out2, err2, rc2 = run_cmd(f'echo {code} | adb pair {ip}:{port}')
            if rc2 == 0 and "paired" in (out2.lower() + err2.lower()):
                self.logger.log("✓ Paired successfully!", "success")
                self._save_config()
            else:
                self.logger.log(f"Pair failed.  {out} {err}", "error")

    def _threaded_connect(self):
        threading.Thread(target=self._connect_device, daemon=True).start()

    def _connect_device(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip or not port:
            self.logger.log("Set IP and port first.", "error")
            return
        self.logger.log(f"Connecting to {ip}:{port}…", "info")
        out, err, rc = run_cmd([bundled_tool("adb"), "connect", f"{ip}:{port}"], timeout=8)
        if rc == 0 and ("connected" in out.lower() or "already" in out.lower()):
            self.logger.log("✓ Connected!", "success")
            self._save_config()
            self.after(500, self._refresh_devices)
            self.after(600, lambda: self.device_card.set_device(
                self.device_card._model_var.get(), ip, port,
                self.device_card.serial, "connected"))
        else:
            self.logger.log(f"Connect failed: {out} {err}", "error")

    def _threaded_disconnect(self):
        threading.Thread(target=self._disconnect_device, daemon=True).start()

    def _disconnect_device(self):
        ip = self.ip_var.get().strip()
        if not ip:
            self.logger.log("No IP to disconnect.", "error")
            return
        self.logger.log(f"Disconnecting {ip}…", "info")
        out, err, rc = run_cmd([bundled_tool("adb"), "disconnect", ip], timeout=5)
        if rc == 0:
            self.logger.log("✓ Disconnected.", "success")
            self._schedule(self._refresh_devices)
            self._schedule(lambda: self.device_card.set_device(
                self.device_card._model_var.get(), ip,
                self.connect_port_var.get(), self.device_card.serial, "idle"))
        else:
            self.logger.log(f"Disconnect failed: {err or out}", "error")

    def _threaded_start_scrcpy(self):
        threading.Thread(target=self._start_scrcpy, daemon=True).start()

    def _start_scrcpy(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip or not port:
            self.logger.log("Set IP and port first.", "error")
            return
        self.logger.log(f"Starting scrcpy for {ip}:{port}…", "info")
        try:
            subprocess.Popen([bundled_tool("scrcpy"), "-s", f"{ip}:{port}"])
            self.logger.log("✓ scrcpy launched!", "success")
            self._schedule(lambda: self.device_card.set_device(
                self.device_card._model_var.get(), ip, port,
                self.device_card.serial, "mirroring"))
        except FileNotFoundError:
            self.logger.log("scrcpy not found in PATH.  Make sure scrcpy.exe is "
                            "in this folder or on PATH.", "error")
        except Exception as e:
            self.logger.log(f"Failed to start scrcpy: {e}", "error")

    # ==========================================================
    #  Quick Mirror — one-click detect → connect → mirror
    # ==========================================================

    def _threaded_quick_mirror(self):
        self.btn_quick.config(state=DISABLED, text="⏳ Working…")
        threading.Thread(target=self._quick_mirror, daemon=True).start()

    def _quick_mirror(self):
        """One-click flow: detect device → connect → start scrcpy."""
        def re_enable():
            self.btn_quick.config(state=NORMAL,
                                  text="⚡  Quick Mirror — Detect, Connect & Mirror")

        # Step 1: Discover
        self.logger.log("Quick Mirror: scanning for devices…", "info")
        devices = full_discover()
        if not devices:
            self.logger.log("Quick Mirror: no devices found.  Enable USB/Wireless "
                            "Debugging and try again.", "error")
            self._schedule(re_enable)
            return

        best = None
        for d in devices:
            if d["state"] == "device":
                best = d
                break
        if not best:
            best = devices[0]

        ip = best["ip"]
        port = best["port"]
        model = best["model"]

        # Update UI
        def update_ui():
            self.ip_var.set(ip)
            if port:
                self.connect_port_var.set(port)
            self.device_card.set_device(model, ip, port, best["serial"], "connecting")
            self._update_qr()
        self._schedule(update_ui)

        self.logger.log(f"Quick Mirror: found {model or ip} at {ip}:{port}", "success")

        # Step 2: Connect
        self.logger.log(f"Quick Mirror: connecting to {ip}:{port}…", "info")
        out, err, rc = run_cmd([bundled_tool("adb"), "connect", f"{ip}:{port}"], timeout=8)
        connected = rc == 0 and ("connected" in out.lower() or "already" in out.lower())
        if not connected:
            self.logger.log(f"Quick Mirror: connect failed — {out} {err}", "error")
            self._schedule(re_enable)
            return

        self.logger.log("Quick Mirror: connected!", "success")
        self._schedule(lambda: self.device_card.set_device(
            model, ip, port, best["serial"], "connected"))

        # Step 3: Start scrcpy
        self.logger.log(f"Quick Mirror: launching scrcpy…", "info")
        try:
            subprocess.Popen([bundled_tool("scrcpy"), "-s", f"{ip}:{port}"])
            self.logger.log("Quick Mirror: ✓ scrcpy launched!", "success")
            self._schedule(lambda: self.device_card.set_device(
                model, ip, port, best["serial"], "mirroring"))
        except FileNotFoundError:
            self.logger.log("Quick Mirror: scrcpy.exe not found in PATH.", "error")
        except Exception as e:
            self.logger.log(f"Quick Mirror: failed to start scrcpy — {e}", "error")

        self._schedule(re-enable)
        self._save_config()

    # ==========================================================
    #  Network scan (subnet ping sweep — unchanged logic, improved UI)
    # ==========================================================

    def _threaded_scan_network(self):
        threading.Thread(target=self._scan_network, daemon=True).start()

    def _scan_network(self):
        self._update_scan_threads()
        self._update_ping_timeout()
        local_ip = get_local_ip()
        if not local_ip:
            self.logger.log("Cannot detect local IP.", "error")
            return

        subnet = local_ip.rsplit(".", 1)[0] + "."
        ips = [subnet + str(i) for i in range(1, 255)]
        found = []

        def _init():
            self.progress["maximum"] = len(ips)
            self.progress["value"] = 0
            self.progress_label.config(text="Scanning…")
        self._schedule(_init)

        self.logger.log(f"Scanning {subnet}0/24 ({self.scan_threads} threads)…", "info")
        with ThreadPoolExecutor(max_workers=self.scan_threads) as ex:
            futs = {ex.submit(ping_host, ip, self.ping_timeout): ip for ip in ips}
            done = 0
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok:
                    found.append(ip)
                    self.logger.log(f"Host alive: {ip}", "success")
                done += 1
                self._schedule(self._update_progress, done)

        def _finish():
            self.progress_label.config(text=f"Done — {len(found)} host(s)")
            if found:
                self.ip_var.set(found[0])
                self._update_qr()
                self.logger.log(f"Scan found {len(found)} host(s).  "
                                f"First: {found[0]}", "info")
            else:
                self.logger.log("No hosts found.", "warning")
            self.after(800, lambda: self._update_progress(0))
        self._schedule(_finish)

    def _update_progress(self, value):
        self.progress["value"] = value

    # ==========================================================
    #  Window close
    # ==========================================================

    def on_close(self):
        try:
            self._save_config()
        except Exception:
            pass
        self.destroy()


# ============================================================
#  Entrypoint
# ============================================================

def main():
    app = ScrcpyLauncher()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
