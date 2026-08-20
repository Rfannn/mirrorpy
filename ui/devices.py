import tkinter as tk
from ui.theme import Colors, Fonts
from ui.glass_widgets import GlassPanel, GlassButton, GlassEntry, GlassLabel

class DevicesPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = Colors()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._app = app
        self._build()

    def _build(self):
        # Header
        tk.Label(self, text="📱  Device Manager", font=Fonts.HEADING,
                 bg=self._c.BG_DEEP, fg=self._c.TEXT_PRIMARY).pack(anchor="w", padx=12, pady=(12, 6))

        # ADB Devices
        p = GlassPanel(self, title="ADB Devices", icon="📡")
        p.pack(fill="x", padx=12, pady=6)
        self._devices_frame = p.content
        GlassLabel(self._devices_frame, text="Click Refresh to scan for devices", fg=self._c.TEXT_MUTED).pack(padx=8, pady=8)

        btn_bar = tk.Frame(self._devices_frame, bg=self._c.BG_PANEL)
        btn_bar.pack(fill="x", padx=8, pady=(0, 8))
        GlassButton(btn_bar, text="Refresh", icon="↻", style="cyan", width=100, command=self._refresh).pack(side="right")

        # Network Scan
        scan = GlassPanel(self, title="Network Scan", icon="🌐")
        scan.pack(fill="x", padx=12, pady=6)
        sc = scan.content
        self._scan_label = GlassLabel(sc, text="Idle", fg=self._c.TEXT_MUTED)
        self._scan_label.pack(padx=8, pady=4)
        self._progress = tk.Canvas(sc, height=4, bg=self._c.BORDER_SUBTLE, highlightthickness=0)
        self._progress.pack(fill="x", padx=8, pady=(0, 4))
        GlassButton(sc, text="Scan Subnet", style="secondary", width=120, command=self._scan).pack(padx=8, pady=(0, 8))

    def _refresh(self):
        if self._app: self._app.refresh_devices()

    def _scan(self):
        if self._app: self._app.scan_network()

    def update_devices(self, devices):
        for w in self._devices_frame.winfo_children():
            if isinstance(w, GlassPanel): continue
            w.destroy()
        if not devices:
            GlassLabel(self._devices_frame, text="No devices found", fg=self._c.TEXT_MUTED).pack(padx=8, pady=8)
            return
        for d in devices:
            f = tk.Frame(self._devices_frame, bg=self._c.BG_PANEL)
            f.pack(fill="x", padx=8, pady=2)
            GlassLabel(f, text=f"{d.get('model', d.get('serial', '?'))}  ({d.get('ip', '')})").pack(side="left")
            GlassLabel(f, text=d.get('state', ''), fg=self._c.ACCENT_CYAN, font=Fonts.SMALL).pack(side="right")
