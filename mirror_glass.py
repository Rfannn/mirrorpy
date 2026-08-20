import tkinter as tk
import threading
import os, sys, configparser, subprocess, re, socket, platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

from ui.theme import Colors, Fonts, Geo
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
    full_discover, generate_qr_pil, CONFIG_FILE, DEFAULTS, logger
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
        self._build_ui()
        self._toast = ToastManager(self)
        self.toast("MirrorPy ready", "success")

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
        body = tk.Frame(self, bg=self._c.BG_DEEP)
        body.pack(fill="both", expand=True)
        self._sidebar = GlassSidebar(body, onNavigate=self._on_navigate)
        self._sidebar.pack(side="left", fill="y")
        self._content = GlassContentArea(body)
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
            self.toast(f"Found: {best["model"]} ({best["ip"]}:{best["port"]})", "success")
            self._update_qr(best["ip"], best["port"])
        threading.Thread(target=_do, daemon=True).start()

    def connect_device(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        if not ip or not port: self.toast("Set IP and port", "error"); return
        def _do():
            self.toast(f"Connecting to {ip}:{port}...", "info")
            out, err, rc = run_cmd(["adb","connect",f"{ip}:{port}"], timeout=8)
            if rc==0 and ("connected" in out.lower() or "already" in out.lower()):
                self.toast("Connected!", "success")
                self.after(0, lambda: self._dashboard.set_device("",ip,port,"connected"))
            else: self.toast(f"Failed: {out} {err}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def pair_device(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._pair_port.get().strip()
        code = self._dashboard._pair_code.get().strip()
        if not all([ip,port,code]): self.toast("Fill all fields", "error"); return
        def _do():
            out, err, rc = run_cmd(["adb","pair",f"{ip}:{port}"], input_text=code+chr(10), timeout=10)
            if rc==0 and "paired" in out.lower(): self.toast("Paired!", "success")
            else: self.toast(f"Pair failed: {out}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def start_mirror(self):
        ip = self._dashboard._ip_var.get().strip()
        port = self._dashboard._port_var.get().strip()
        if not ip or not port: self.toast("Set IP and port", "error"); return
        def _do():
            try:
                subprocess.Popen(["scrcpy","-s",f"{ip}:{port}"])
                self.toast("scrcpy launched!", "success")
                self.after(0, lambda: self._dashboard.set_device("",ip,port,"mirroring"))
            except FileNotFoundError: self.toast("scrcpy not found", "error")
            except Exception as e: self.toast(f"Failed: {e}", "error")
        threading.Thread(target=_do, daemon=True).start()

    def disconnect_device(self):
        ip = self._dashboard._ip_var.get().strip()
        if not ip: self.toast("No IP", "error"); return
        def _do():
            run_cmd(["adb","disconnect",ip], timeout=5)
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
            out, err, rc = run_cmd(["adb","connect",f"{ip}:{port}"], timeout=8)
            if not (rc==0 and ("connected" in out.lower() or "already" in out.lower())):
                self.toast(f"Connect failed", "error"); return
            self.toast("Connected!", "success")
            self.after(0, lambda: self._dashboard.set_device(best["model"],ip,port,"connected"))
            try:
                subprocess.Popen(["scrcpy","-s",f"{ip}:{port}"])
                self.toast("scrcpy launched!", "success")
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

    # Stubs for quick actions
    def capture_screen(self): self.toast("Screenshot captured", "success")
    def toggle_record(self): self.toast("Recording toggled", "info")
    def push_file(self): self.toast("File push (TODO)", "info")
    def sync_clipboard(self): self.toast("Clipboard sync (TODO)", "info")
    def control_volume(self): self.toast("Volume control (TODO)", "info")
    def restart_adb(self):
        def _do(): run_cmd("adb kill-server"); run_cmd("adb start-server"); self.toast("ADB restarted", "success")
        threading.Thread(target=_do, daemon=True).start()
    def device_info(self): self.toast("Device info (TODO)", "info")
    def clear_cache(self): self.toast("Cache cleared (TODO)", "info")
    def manage_apps(self): self.toast("App manager (TODO)", "info")
    def screen_cast(self): self.toast("Screen cast (TODO)", "info")


def main():
    app = MirrorPyGlass()
    app.protocol("WM_DELETE_WINDOW", app._on_close)
    app.mainloop()

if __name__ == "__main__":
    main()
