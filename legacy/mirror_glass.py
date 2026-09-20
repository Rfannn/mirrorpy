import tkinter as tk
import threading
import os, configparser, subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ui import theme as ui_theme
from ui.theme import Colors, Geo, get_palette
from ui.title_bar import GlassTitleBar
from ui.sidebar import GlassSidebar
from ui.content_area import GlassContentArea
from ui.toast import ToastManager
from ui.dashboard import DashboardPage
from ui.devices import DevicesPage
from ui.quick_actions import QuickActionsPage
from ui.settings_tab import SettingsPage
from ui.logs_tab import LogsPage
from ui.about_tab import AboutPage

from mirror import (
    get_local_ip, ping_host, run_cmd, adb_devices_list,
    full_discover, generate_qr_pil, scrcpy_args, bundled_tool,
    CONFIG_FILE, DEFAULTS, SCREENSHOT_DIR
)

class MirrorPyGlass(tk.Tk):
    def __init__(self):
        super().__init__()
        self._c = Colors()
        self.overrideredirect(True)
        self.geometry(f"{Geo.APP_DEFAULT_WIDTH}x{Geo.APP_DEFAULT_HEIGHT}")
        self.minsize(Geo.APP_MIN_WIDTH, Geo.APP_MIN_HEIGHT)
        self.configure(bg=self._c.BG_DEEP)
        self._cfg = configparser.ConfigParser()
        self._load_config()
        self._qr_photo = None
        self._record_proc = None
        self._rebuilding = False
        self._clear_device = False
        self._quality = self._cfg["DEFAULT"].get("quality", "Medium")
        self._theme = self._cfg["DEFAULT"].get("theme", "dark")
        if self._theme not in ("dark", "light"):
            self._theme = "dark"
        self._accent = self._cfg["DEFAULT"].get("accent", "pink")
        ui_theme.set_theme(self._theme)
        ui_theme.set_accent(self._accent)
        self._c = get_palette()
        self.configure(bg=self._c.BG_DEEP)
        self._build_ui()
        self._prefill_from_config()
        self._toast = ToastManager(self)
        self._bind_keys()
        self.toast("MirrorPy ready", "success")

    def _prefill_from_config(self):
        """Restore the last address so a returning user does not retype it."""
        ip = self._cfg["DEFAULT"].get("ip", "")
        port = self._cfg["DEFAULT"].get("connectport", "")
        if ip: self._dashboard._ip_var.set(ip)
        if port: self._dashboard._port_var.set(port)

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            self._cfg.read(CONFIG_FILE)
        else:
            self._cfg["DEFAULT"] = DEFAULTS.copy()
        for k, v in DEFAULTS.items():
            if k not in self._cfg["DEFAULT"]:
                self._cfg["DEFAULT"][k] = v

    def _save_config(self):
        with open(CONFIG_FILE, "w") as f:
            self._cfg.write(f)

    def _build_ui(self):
        self._titlebar = GlassTitleBar(self, title="MirrorPy",
            on_close=self._on_close, on_minimize=lambda: self.iconify(), on_maximize=self._toggle_max)
        self._titlebar.pack(fill="x")
        self._body = tk.Frame(self, bg=self._c.BG_DEEP)
        self._body.pack(fill="both", expand=True)
        self._sidebar = GlassSidebar(self._body, onNavigate=self._on_navigate,
                                     onToggleTheme=self._toggle_theme)
        self._sidebar.pack(side="left", fill="y")
        self._content = GlassContentArea(self._body)
        self._content.pack(side="left", fill="both", expand=True)
        self._dashboard = DashboardPage(self._content, app=self)
        self._devices = DevicesPage(self._content, app=self)
        self._quick = QuickActionsPage(self._content, app=self)
        self._settings = SettingsPage(self._content, app=self)
        self._logs = LogsPage(self._content)
        self._about = AboutPage(self._content)
        for k, w in [("dashboard",self._dashboard),("devices",self._devices),
                     ("quick_actions",self._quick),("settings",self._settings),
                     ("logs",self._logs),("about",self._about)]:
            self._content.add_page(k, w)
        self._content.show_page("dashboard")
        self._sidebar.navigate_to("dashboard")

    def _on_navigate(self, key): self._content.show_page(key)

    def _snapshot(self):
        """Capture the state worth keeping across a theme rebuild."""
        s = {"ip": "", "port": "", "pair_port": "", "device": None}
        if self._clear_device or not getattr(self, "_dashboard", None):
            return s
        try:
            s["ip"] = self._dashboard._ip_var.get()
            s["port"] = self._dashboard._port_var.get()
            s["pair_port"] = self._dashboard._pair_port.get()
            s["device"] = (self._dashboard._dev_name.cget("text"),
                           self._dashboard._dev_ip.cget("text"))
        except Exception:
            pass
        return s

    def _restore(self, s):
        if not s or self._clear_device:
            return
        for var, key in ((self._dashboard._ip_var, "ip"),
                         (self._dashboard._port_var, "port"),
                         (self._dashboard._pair_port, "pair_port")):
            if s.get(key):
                var.set(s[key])
        if s.get("device"):
            name, addr = s["device"]
            self._dashboard._dev_name.configure(text=name)
            self._dashboard._dev_ip.configure(text=addr)

    def _rebuild_ui(self):
        state = self._snapshot()
        page = self._content._current or "dashboard"
        self._rebuilding = True
        for w in self._body.winfo_children():
            w.destroy()
        self._c = get_palette()
        self._build_ui()
        self._content.show_page(page)
        self._sidebar.navigate_to(page)
        self._restore(state)
        self._rebuilding = False

    def _bind_keys(self):
        """The window is frameless, so the usual OS shortcuts are unavailable."""
        self.bind("<Escape>", lambda e: self._on_close())
        self.bind("<F11>", lambda e: self._toggle_max())
        for i, key in enumerate(["dashboard", "devices", "quick_actions",
                                 "settings", "logs", "about"], start=1):
            self.bind(f"<Control-Key-{i}>", lambda e, k=key: self._on_navigate(k))

    def _persist_ui(self):
        self._cfg["DEFAULT"]["quality"] = self._quality
        self._cfg["DEFAULT"]["accent"] = self._accent
        self._cfg["DEFAULT"]["theme"] = self._theme
        self._save_config()

    def set_quality(self, name):
        self._quality = name
        self._persist_ui()

    def set_accent(self, name):
        self._accent = name
        ui_theme.set_accent(name)
        self._c = get_palette()
        self._persist_ui()
        self._rebuild_ui()
        self.toast("Accent updated", "success")

    def reset_settings(self):
        """Drop saved settings, clear the device card, and rebuild."""
        self._cfg["DEFAULT"] = DEFAULTS.copy()
        self._quality = DEFAULTS["quality"]
        self._theme = "dark"
        self._accent = DEFAULTS["accent"]
        self._clear_device = True
        ui_theme.set_theme(self._theme)
        ui_theme.set_accent(self._accent)
        self._c = get_palette()
        self._save_config()
        self._rebuild_ui()
        self._clear_device = False
        self.toast("Settings reset to defaults", "warning")

    def remember_address(self):
        """Save the current address so the next session prefills it."""
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        if not ip: return
        self._cfg["DEFAULT"]["ip"] = ip
        if port: self._cfg["DEFAULT"]["connectport"] = port
        self._save_config()

    def _toggle_theme(self):
        self._theme = "light" if self._theme == "dark" else "dark"
        ui_theme.set_theme(self._theme)
        self._c = get_palette()
        self._persist_ui()
        self._rebuild_ui()
        self.toast(self._theme.capitalize() + " theme", "info")

    def _toggle_max(self):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        if self.geometry() == f"{sw}x{sh}+0+0":
            w, h = Geo.APP_DEFAULT_WIDTH, Geo.APP_DEFAULT_HEIGHT
            self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        else:
            self.geometry(f"{sw}x{sh}+0+0")

    def toast(self, msg, level="info"):
        self._toast.show(msg, level)
        self._dashboard.log(f"[{level.upper()}] {msg}", level)
        self._logs.log(msg, level)

    def detect_device(self):
        def _do():
            self.toast("Scanning for devices...", "info")
            devices = full_discover()
            if not devices:
                self.toast("No devices found", "warning"); return
            best = next((d for d in devices if d["state"]=="device"), devices[0])
            self.after(0, lambda: self._dashboard._ip_var.set(best["ip"]))
            if best["port"]: self.after(0, lambda: self._dashboard._port_var.set(best["port"]))
            self.after(0, lambda: self._dashboard.set_device(best["model"],best["ip"],best["port"],"ready"))
            self.toast(f"Found: {best['model']} ({best['ip']}:{best['port']})", "success")
            self._update_qr(best["ip"], best["port"])
        threading.Thread(target=_do, daemon=True).start()

    def connect_device(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        if not ip or not port: self.toast("Set IP and port", "error"); return
        def _do():
            self.toast(f"Connecting to {ip}:{port}...", "info")
            out, err, rc = run_cmd([bundled_tool("adb"), "connect", f"{ip}:{port}"], timeout=8)
            if rc==0 and ("connected" in out.lower() or "already" in out.lower()):
                self.toast("Connected!", "success")
                self.after(0, lambda: self._dashboard.set_device("",ip,port,"connected"))
                self.after(0, self.remember_address)
            else: self.toast(f"Failed: {out} {err}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def pair_device(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._pair_port.get().strip()
        code = self._dashboard._pair_code.get().strip()
        if not all([ip,port,code]): self.toast("Fill all fields", "error"); return
        def _do():
            out, err, rc = run_cmd([bundled_tool("adb"), "pair", f"{ip}:{port}"], input_text=code+chr(10), timeout=10)
            if rc==0 and "paired" in out.lower(): self.toast("Paired!", "success")
            else: self.toast(f"Pair failed: {out}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def _serial(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        return f"{ip}:{port}" if port else ip

    def start_mirror(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        if not ip or not port: self.toast("Set IP and port", "error"); return
        def _do():
            try:
                subprocess.Popen(scrcpy_args(self._quality, f"{ip}:{port}"))
                self.toast(f"Mirroring at {self._quality}", "success")
                self.after(0, lambda: self._dashboard.set_device("",ip,port,"mirroring"))
            except FileNotFoundError: self.toast("scrcpy not found", "error")
            except Exception as e: self.toast(f"Failed: {e}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def disconnect_device(self):
        ip = self._dashboard._ip_var.get().strip()
        if not ip: self.toast("No IP", "error"); return
        def _do():
            run_cmd([bundled_tool("adb"), "disconnect", ip], timeout=5)
            self.toast("Disconnected", "success")
            self.after(0, self._dashboard.clear_device)
        threading.Thread(target=_do, daemon=True).start()

    def quick_mirror(self):
        def _do():
            self.toast("Quick Mirror: scanning...", "info")
            devices = full_discover()
            if not devices: self.toast("No devices found", "error"); return
            best = next((d for d in devices if d["state"]=="device"), devices[0])
            ip, port = best["ip"], best["port"]
            self.after(0, lambda: self._dashboard._ip_var.set(ip))
            if port: self.after(0, lambda: self._dashboard._port_var.set(port))
            self.after(0, lambda: self._dashboard.set_device(best["model"],ip,port,"detecting"))
            self._update_qr(ip, port)
            out, err, rc = run_cmd([bundled_tool("adb"), "connect", f"{ip}:{port}"], timeout=8)
            if not (rc==0 and ("connected" in out.lower() or "already" in out.lower())):
                self.toast(f"Connect failed", "error"); return
            self.toast("Connected!", "success")
            self.after(0, lambda: self._dashboard.set_device(best["model"],ip,port,"connected"))
            try:
                subprocess.Popen(scrcpy_args(self._quality, f"{ip}:{port}"))
                self.toast(f"Mirroring at {self._quality}", "success")
                self.after(0, lambda: self._dashboard.set_device(best["model"],ip,port,"mirroring"))
            except Exception as e: self.toast(f"scrcpy failed: {e}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def refresh_devices(self):
        def _do(): devs = adb_devices_list(); self.after(0, lambda: self._devices.update_devices(devs))
        threading.Thread(target=_do, daemon=True).start()

    def scan_network(self):
        self.toast("Scanning subnet...", "info")
        def _do():
            local = get_local_ip()
            if not local: self.toast("Cannot detect IP", "error"); return
            subnet = local.rsplit(".",1)[0] + "."
            found = []
            with ThreadPoolExecutor(max_workers=50) as ex:
                futs = {ex.submit(ping_host,subnet+str(i),1): i for i in range(1,255)}
                for fut in as_completed(futs):
                    try:
                        if fut.result(): found.append(subnet+str(futs[fut]))
                    except: pass
            self.toast(f"Found {len(found)} hosts", "success")
        threading.Thread(target=_do, daemon=True).start()

    def _update_qr(self, ip, port):
        try:
            s = f"adb connect {ip}:{port}" if port else f"adb connect {ip}"
            img = generate_qr_pil(s, box_size=5, border=2).resize((180,180))
            self.after(0, lambda: self._dashboard.update_qr(img))
        except Exception as e: self.toast(f"QR error: {e}", "warning")

    def _on_close(self): self._save_config(); self.destroy()

    # ---------- Quick actions ----------

    def capture_screen(self):
        serial = self._serial()
        if not serial: self.toast("Set IP and port", "error"); return
        def _do():
            os.makedirs(SCREENSHOT_DIR, exist_ok=True)
            name = "shot_%s.png" % datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(SCREENSHOT_DIR, name)
            try:
                with open(path, "wb") as f:
                    proc = subprocess.run([bundled_tool("adb"), "-s", serial, "exec-out", "screencap", "-p"],
                                          stdout=f, stderr=subprocess.PIPE)
                if proc.returncode != 0 or not os.path.getsize(path):
                    if os.path.exists(path): os.remove(path)
                    self.toast("Screenshot failed", "error"); return
                self.toast("Saved " + name, "success")
            except Exception as e:
                self.toast(f"Screenshot failed: {e}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def sync_clipboard(self):
        serial = self._serial()
        if not serial: self.toast("Set IP and port", "error"); return
        def _do():
            out, err, rc = run_cmd([bundled_tool("adb"), "-s", serial, "exec-out", "cmd", "clipboard", "get", "text"], timeout=8)
            if rc != 0:
                self.toast("Clipboard read failed (Android 10+ or app focus needed)", "error"); return
            text = out.strip()
            if not text: self.toast("Device clipboard is empty", "warning"); return
            self.clipboard_clear(); self.clipboard_append(text); self.update()
            self.toast("Copied %d chars from device" % len(text), "success")
        threading.Thread(target=_do, daemon=True).start()

    def push_file(self):
        from tkinter import filedialog
        serial = self._serial()
        if not serial: self.toast("Set IP and port", "error"); return
        path = filedialog.askopenfilename(title="Push file to device")
        if not path: return
        def _do():
            target = "/sdcard/Download/" + os.path.basename(path)
            out, err, rc = run_cmd([bundled_tool("adb"), "-s", serial, "push", path, target], timeout=120)
            if rc == 0: self.toast("Pushed to " + target, "success")
            else: self.toast("Push failed: " + (err or out), "error")
        threading.Thread(target=_do, daemon=True).start()

    def device_info(self):
        serial = self._serial()
        if not serial: self.toast("Set IP and port", "error"); return
        def _do():
            lines = []
            for prop in ("ro.product.model", "ro.build.version.release", "ro.product.manufacturer"):
                out, _, rc = run_cmd([bundled_tool("adb"), "-s", serial, "shell", "getprop", prop], timeout=8)
                if rc == 0 and out.strip(): lines.append(out.strip())
            self.toast(" | ".join(lines) if lines else "No device info", "info" if lines else "error")
        threading.Thread(target=_do, daemon=True).start()

    def restart_adb(self):
        def _do():
            run_cmd([bundled_tool("adb"), "kill-server"])
            run_cmd([bundled_tool("adb"), "start-server"])
            self.toast("ADB restarted", "success")
        threading.Thread(target=_do, daemon=True).start()


def main():
    app = MirrorPyGlass()
    app.protocol("WM_DELETE_WINDOW", app._on_close)
    app.mainloop()

if __name__ == "__main__":
    main()
