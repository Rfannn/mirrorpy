"""
Wireless scrcpy Launcher (Tkinter + ttkbootstrap)
- No netifaces dependency (uses socket + ping sweep)
- Features: auto detect IP, network scan, adb devices listing,
  Pair / Connect / Disconnect / Start scrcpy, settings saved, logging.
Author: adapted for Rfannn
"""

import os
import sys
import time
import socket
import platform
import subprocess
import configparser
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
import threading

# UI:
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox

# ---------- Config & Logging ----------
CONFIG_FILE = "settings.ini"
LOG_FILE = "scrcpy_launcher.log"
DEFAULTS = {
    "IP": "",
    "PairPort": "5555",
    "ConnectPort": "5555",
    "PairCode": "",
    "Theme": "darkly",
    "ScanThreads": "100",
    "PingTimeoutSec": "1"
}

# Setup file logger
logger = logging.getLogger("scrcpy_launcher")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)


# ---------- Helpers ----------
def get_local_ip():
    """
    Return a sensible local IP address for the default route (e.g. 192.168.x.x)
    Does not require netifaces; uses UDP socket trick.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # IP doesn't have to be reachable; 8.8.8.8 used to determine interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip


def ping_host(ip, timeout=1):
    """
    Ping an IP once; return True if host responds.
    Cross-platform wrapper around ping command.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # -c 1 (count), -W timeout in seconds (Linux). BSD/Mac uses -W in ms? Variation exists.
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


def run_cmd(args, input_text=None, timeout=None):
    """
    Run a command and return (stdout, stderr, returncode).
    Accepts args as list or string. Allows sending input_text to process stdin.
    """
    try:
        if isinstance(args, str):
            shell = True
        else:
            shell = False
        proc = subprocess.run(args, input=input_text, capture_output=True, text=True, shell=shell, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def adb_devices_list():
    """
    Return parsed adb devices list as list of dicts:
    [{ "serial": "...", "state": "...", "info": "..." }, ...]
    """
    out, err, rc = run_cmd(["adb", "devices", "-l"])
    if rc != 0:
        return []
    lines = out.splitlines()
    devices = []
    for line in lines[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else ""
        info = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append({"serial": serial, "state": state, "info": info, "raw": line})
    return devices


# ---------- GUI App ----------
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
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        self.queue.put((formatted, self._level_to_color(level)))
        # also file log
        if level == "debug":
            logger.debug(message)
        elif level == "warning":
            logger.warning(message)
        elif level == "error":
            logger.error(message)
        else:
            logger.info(message)

    @staticmethod
    def _level_to_color(level):
        mapping = {"info": "black", "success": "green", "error": "red", "warning": "orange", "debug": "gray", "blue": "blue"}
        return mapping.get(level, "black")


class ScrcpyLauncher(ttk.Window):
    def __init__(self):
        themename = DEFAULTS.get("Theme", "darkly")
        super().__init__(themename=themename)
        self.title("Wireless scrcpy Launcher — Modern")
        self.geometry("760x560")
        self.minsize(720, 520)

        self.config_parser = configparser.ConfigParser()
        self._load_config()

        # UI variables
        self.ip_var = ttk.StringVar(value=self.config_parser["DEFAULT"].get("IP", ""))
        self.pair_port_var = ttk.StringVar(value=self.config_parser["DEFAULT"].get("PairPort", DEFAULTS["PairPort"]))
        self.connect_port_var = ttk.StringVar(value=self.config_parser["DEFAULT"].get("ConnectPort", DEFAULTS["ConnectPort"]))
        self.pair_code_var = ttk.StringVar(value=self.config_parser["DEFAULT"].get("PairCode", ""))
        self.theme_var = ttk.StringVar(value=self.config_parser["DEFAULT"].get("Theme", DEFAULTS["Theme"]))
        self.scan_threads = int(self.config_parser["DEFAULT"].get("ScanThreads", DEFAULTS["ScanThreads"]))
        self.ping_timeout = float(self.config_parser["DEFAULT"].get("PingTimeoutSec", DEFAULTS["PingTimeoutSec"]))

        self._create_widgets()
        self.logger.log("App ready. Click 'Auto-detect' or 'Scan network' to find your phone.", "info")

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            self.config_parser.read(CONFIG_FILE)
            # ensure defaults exist
            for k, v in DEFAULTS.items():
                if k not in self.config_parser["DEFAULT"]:
                    self.config_parser["DEFAULT"][k] = v
        else:
            self.config_parser["DEFAULT"] = DEFAULTS.copy()
            with open(CONFIG_FILE, "w") as f:
                self.config_parser.write(f)

    def _save_config(self):
        # sync variables into config and save
        self.config_parser["DEFAULT"]["IP"] = self.ip_var.get().strip()
        self.config_parser["DEFAULT"]["PairPort"] = self.pair_port_var.get().strip()
        self.config_parser["DEFAULT"]["ConnectPort"] = self.connect_port_var.get().strip()
        self.config_parser["DEFAULT"]["PairCode"] = self.pair_code_var.get().strip()
        self.config_parser["DEFAULT"]["Theme"] = self.theme_var.get().strip()
        self.config_parser["DEFAULT"]["ScanThreads"] = str(self.scan_threads)
        self.config_parser["DEFAULT"]["PingTimeoutSec"] = str(self.ping_timeout)
        with open(CONFIG_FILE, "w") as f:
            self.config_parser.write(f)

    def _create_widgets(self):
        # Top area: header + small ascii logo
        header = ttk.Frame(self, padding=(12, 12, 12, 6))
        header.pack(fill=X)

        logo_label = ttk.Label(header, text="📱  Wireless scrcpy Launcher", font=("Segoe UI", 16, "bold"))
        logo_label.pack(side=LEFT)

        theme_combo = ttk.Combobox(header, values=ttk.Style().theme_names(), textvariable=self.theme_var, width=16, state="readonly")
        theme_combo.pack(side=RIGHT)
        theme_combo.bind("<<ComboboxSelected>>", self._on_theme_change)

        # Main left and right frames
        main = ttk.Frame(self, padding=10)
        main.pack(fill=BOTH, expand=YES)

        left = ttk.Frame(main)
        left.pack(side=LEFT, fill=BOTH, expand=YES, padx=(0, 8))

        right = ttk.Frame(main, width=260)
        right.pack(side=RIGHT, fill=Y)

        # Left: Controls and log
        controls = ttk.Frame(left)
        controls.pack(fill=X, pady=(0, 8))

        # IP row
        row = ttk.Frame(controls)
        row.pack(fill=X, pady=4)
        ttk.Label(row, text="Phone IP:").pack(side=LEFT)
        self.ip_entry = ttk.Entry(row, textvariable=self.ip_var, width=26)
        self.ip_entry.pack(side=LEFT, padx=(8, 8))

        ttk.Button(row, text="Auto-detect", bootstyle="info-outline", command=self._auto_detect_ip).pack(side=LEFT, padx=6)
        ttk.Button(row, text="Scan network", bootstyle="secondary-outline", command=self._threaded_scan_network).pack(side=LEFT)

        # Ports/pair code
        row2 = ttk.Frame(controls)
        row2.pack(fill=X, pady=4)
        ttk.Label(row2, text="Pair Port:").pack(side=LEFT)
        ttk.Entry(row2, textvariable=self.pair_port_var, width=8).pack(side=LEFT, padx=(8, 12))

        ttk.Label(row2, text="Connect Port:").pack(side=LEFT)
        ttk.Entry(row2, textvariable=self.connect_port_var, width=8).pack(side=LEFT, padx=(8, 12))

        ttk.Label(row2, text="Pair Code:").pack(side=LEFT)
        ttk.Entry(row2, textvariable=self.pair_code_var, width=8, show="*").pack(side=LEFT, padx=(8, 0))

        # Buttons row
        btns = ttk.Frame(controls)
        btns.pack(fill=X, pady=8)
        ttk.Button(btns, text="Pair", bootstyle="warning", command=self._threaded_pair).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Connect", bootstyle="primary", command=self._threaded_connect).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Start Mirroring", bootstyle="success", command=self._threaded_start_scrcpy).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Disconnect", bootstyle="danger", command=self._threaded_disconnect).pack(side=LEFT, padx=6)

        # ADB devices combobox
        devices_frame = ttk.Frame(controls)
        devices_frame.pack(fill=X, pady=6)
        ttk.Label(devices_frame, text="ADB devices:").pack(side=LEFT)
        self.devices_var = ttk.StringVar()
        self.devices_combo = ttk.Combobox(devices_frame, textvariable=self.devices_var, width=48, state="readonly")
        self.devices_combo.pack(side=LEFT, padx=(8, 4))
        ttk.Button(devices_frame, text="Refresh", bootstyle="outline-info", command=self._refresh_devices).pack(side=LEFT)

        # **Create logger before calling _refresh_devices**
        self.logger = GuiLogger(left, height=18)
        self.logger.pack(fill=BOTH, expand=YES)

        # Now safe to refresh devices (logger is ready)
        self._refresh_devices()

        # Right: actions, progress, settings
        card = ttk.Labelframe(right, text="Quick Actions", padding=10)
        card.pack(fill=X, padx=6, pady=6)

        ttk.Button(card, text="Open scrcpy folder", bootstyle="light", command=self._open_folder).pack(fill=X, pady=4)
        ttk.Button(card, text="Show log file", bootstyle="light", command=self._open_logfile).pack(fill=X, pady=4)
        ttk.Button(card, text="Export config", bootstyle="light", command=self._export_config).pack(fill=X, pady=4)

        scan_card = ttk.Labelframe(right, text="Scan & Progress", padding=10)
        scan_card.pack(fill=X, padx=6, pady=6)
        self.progress = ttk.Progressbar(scan_card, orient=HORIZONTAL, length=220, mode="determinate")
        self.progress.pack(fill=X, pady=6)
        self.progress_label = ttk.Label(scan_card, text="Idle")
        self.progress_label.pack()

        settings_card = ttk.Labelframe(right, text="Settings", padding=10)
        settings_card.pack(fill=X, padx=6, pady=6)
        ttk.Label(settings_card, text="Scan threads:").pack(anchor=W)
        self.threads_spin = ttk.Spinbox(settings_card, from_=10, to=500, increment=10, width=8, command=self._update_scan_threads)
        self.threads_spin.set(self.scan_threads)
        self.threads_spin.pack(anchor=W, pady=(2, 8))
        ttk.Label(settings_card, text="Ping timeout (s):").pack(anchor=W)
        self.timeout_spin = ttk.Spinbox(settings_card, from_=0.2, to=5.0, increment=0.2, width=8, command=self._update_ping_timeout)
        self.timeout_spin.set(self.ping_timeout)
        self.timeout_spin.pack(anchor=W, pady=(2, 8))
        ttk.Button(settings_card, text="Save Settings", bootstyle="info", command=self._save_config).pack(fill=X)

        # bottom status bar
        status = ttk.Frame(self, padding=(8, 6))
        status.pack(fill=X)
        self.status_label = ttk.Label(status, text="Ready")
        self.status_label.pack(side=LEFT)

    
    # ---------- UI actions and threaded wrappers ----------
    def _on_theme_change(self, event=None):
        theme = self.theme_var.get()
        try:
            self.style.theme_use(theme)
            self.logger.log(f"Theme changed to {theme}", "blue")
            self._save_config()
        except Exception as e:
            self.logger.log(f"Failed to change theme: {e}", "error")

    def _update_scan_threads(self):
        try:
            self.scan_threads = int(self.threads_spin.get())
            self.logger.log(f"Scan threads set to {self.scan_threads}", "debug")
        except Exception:
            pass

    def _update_ping_timeout(self):
        try:
            self.ping_timeout = float(self.timeout_spin.get())
            self.logger.log(f"Ping timeout set to {self.ping_timeout}s", "debug")
        except Exception:
            pass

    def _open_folder(self):
        folder = os.getcwd()
        self.logger.log(f"Opening folder: {folder}", "info")
        if sys.platform.startswith("win"):
            os.startfile(folder)
        else:
            subprocess.run(["xdg-open", folder])

    def _open_logfile(self):
        self.logger.log(f"Opening log file: {LOG_FILE}", "info")
        if sys.platform.startswith("win"):
            os.startfile(LOG_FILE)
        else:
            subprocess.run(["xdg-open", LOG_FILE])

    def _export_config(self):
        try:
            dst = os.path.join(os.getcwd(), "settings_export.ini")
            with open(dst, "w", encoding="utf-8") as f:
                self.config_parser.write(f)
            self.logger.log(f"Config exported to {dst}", "success")
            Messagebox.ok(message=f"Exported to:\n{dst}", title="Export complete")
        except Exception as e:
            self.logger.log(f"Export failed: {e}", "error")

    # ---------- ADB helpers ----------
    def _refresh_devices(self):
        self.logger.log("Refreshing adb devices...", "info")
        devices = adb_devices_list()
        if not devices:
            self.logger.log("No adb devices found.", "warning")
            self.devices_combo["values"] = []
            self.devices_var.set("")
            return
        vals = [f"{d['serial']} ({d['state']}) {d['info']}" for d in devices]
        self.devices_combo["values"] = vals
        self.devices_var.set(vals[0])
        self.logger.log(f"Found {len(devices)} adb device(s).", "success")

    def _threaded_pair(self):
        threading.Thread(target=self._pair_device, daemon=True).start()

    def _pair_device(self):
        ip = self.ip_var.get().strip()
        port = self.pair_port_var.get().strip()
        code = self.pair_code_var.get().strip()
        if not ip or not port or not code:
            self.logger.log("Please fill IP, pair port and pairing code.", "error")
            return
        self.logger.log(f"Initiating pairing to {ip}:{port} ...", "info")
        # start pairing and send code to stdin
        # Use run_cmd with input to send code
        out, err, rc = run_cmd(["adb", "pair", f"{ip}:{port}"], input_text=code + "\n", timeout=8)
        if rc == 0 and "paired" in out.lower():
            self.logger.log("Pairing successful!", "success")
            self._save_config()
        else:
            # try second approach: run pair, then echo
            out2, err2, rc2 = run_cmd(f'echo {code} | adb pair {ip}:{port}')
            if rc2 == 0 and "paired" in (out2.lower() + err2.lower()):
                self.logger.log("Pairing successful (via echo)!", "success")
                self._save_config()
            else:
                self.logger.log(f"Pair failed. stdout:{out} stderr:{err} stdout2:{out2} stderr2:{err2}", "error")

    def _threaded_connect(self):
        threading.Thread(target=self._connect_device, daemon=True).start()

    def _connect_device(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip or not port:
            self.logger.log("Please set IP and connect port.", "error")
            return
        self.logger.log(f"Connecting to {ip}:{port} ...", "info")
        out, err, rc = run_cmd(["adb", "connect", f"{ip}:{port}"], timeout=6)
        if rc == 0 and ("connected" in out.lower() or "already" in out.lower()):
            self.logger.log("Connected to device.", "success")
            self._save_config()
            # refresh devices list after connect
            time.sleep(0.7)
            self._refresh_devices()
        else:
            self.logger.log(f"Connect failed: {out} {err}", "error")

    def _threaded_disconnect(self):
        threading.Thread(target=self._disconnect_device, daemon=True).start()

    def _disconnect_device(self):
        ip = self.ip_var.get().strip()
        if not ip:
            self.logger.log("Please enter IP to disconnect.", "error")
            return
        self.logger.log(f"Disconnecting {ip} ...", "info")
        out, err, rc = run_cmd(["adb", "disconnect", ip], timeout=4)
        if rc == 0:
            self.logger.log("Disconnected.", "success")
            self._refresh_devices()
        else:
            self.logger.log(f"Disconnect failed: {err or out}", "error")

    def _threaded_start_scrcpy(self):
        threading.Thread(target=self._start_scrcpy, daemon=True).start()

    def _start_scrcpy(self):
        ip = self.ip_var.get().strip()
        port = self.connect_port_var.get().strip()
        if not ip or not port:
            self.logger.log("IP/port missing; cannot start scrcpy.", "error")
            return
        self.logger.log(f"Starting scrcpy for {ip}:{port} ...", "info")
        # Launch scrcpy non-blocking
        try:
            # Use subprocess.Popen so the UI doesn't block
            subprocess.Popen(["scrcpy", "-s", f"{ip}:{port}"])
            self.logger.log("scrcpy started (external window).", "success")
        except Exception as e:
            self.logger.log(f"Failed to start scrcpy: {e}", "error")

    # ---------- Auto-detect & Scan ----------
    def _auto_detect_ip(self):
        self.logger.log("Auto-detecting local IP...", "info")
        ip = get_local_ip()
        self.ip_var.set(detected_ip)
        self.connect_port_var.set(detected_port)

        if ip:
            self.ip_var.set(ip)
            self.logger.log(f"Detected local IP: {ip}", "success")
        else:
            self.logger.log("Could not auto-detect local IP.", "error")

    def _threaded_scan_network(self):
        threading.Thread(target=self._scan_network, daemon=True).start()

    def _scan_network(self):
        self._update_scan_threads()  # sync
        self._update_ping_timeout()
        local_ip = get_local_ip()
        if not local_ip:
            self.logger.log("Cannot detect local IP. Auto-detect failed.", "error")
            return

        subnet = local_ip.rsplit(".", 1)[0] + "."
        ips = [subnet + str(i) for i in range(1, 255)]
        found = []
        self.progress["maximum"] = len(ips)
        self.progress["value"] = 0
        self.progress_label.config(text="Scanning...")

        self.logger.log(f"Scanning subnet {subnet}0/24 using {self.scan_threads} threads...", "info")
        with ThreadPoolExecutor(max_workers=self.scan_threads) as ex:
            futures = {ex.submit(ping_host, ip, self.ping_timeout): ip for ip in ips}
            completed = 0
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok:
                    found.append(ip)
                    self.logger.log(f"Host alive: {ip}", "success")
                completed += 1
                self.progress["value"] = completed
            # finished
        self.progress_label.config(text=f"Scan complete ({len(found)} found)")
        if found:
            # set first found IP as convenience
            self.ip_var.set(found[0])
            self.logger.log(f"Scan found {len(found)} hosts. First set to {found[0]}", "info")
        else:
            self.logger.log("No hosts found on the subnet.", "warning")
        # reset progress after short pause
        time.sleep(0.6)
        self.progress["value"] = 0

    # ---------- Save config shortly -----------
    def _save_config(self):
        self._save_config = self._save_config  # placeholder to avoid linter confusion
        try:
            self._save_config_impl()
            self.logger.log("Settings saved.", "success")
        except Exception as e:
            self.logger.log(f"Failed saving settings: {e}", "error")

    def _save_config_impl(self):
        # commit current values to config file
        self._save_config_impl = getattr(self, "_save_config_impl")
        self.config_parser["DEFAULT"]["IP"] = self.ip_var.get().strip()
        self.config_parser["DEFAULT"]["PairPort"] = self.pair_port_var.get().strip()
        self.config_parser["DEFAULT"]["ConnectPort"] = self.connect_port_var.get().strip()
        self.config_parser["DEFAULT"]["PairCode"] = self.pair_code_var.get().strip()
        self.config_parser["DEFAULT"]["Theme"] = self.theme_var.get().strip()
        self.config_parser["DEFAULT"]["ScanThreads"] = str(self.scan_threads)
        self.config_parser["DEFAULT"]["PingTimeoutSec"] = str(self.ping_timeout)
        with open(CONFIG_FILE, "w") as f:
            self.config_parser.write(f)

    def on_close(self):
        # save config
        try:
            self._save_config_impl()
        except Exception:
            pass
        self.destroy()


# ---------- Entrypoint ----------
def main():
    app = ScrcpyLauncher()
    # attach window close event
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
