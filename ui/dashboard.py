import tkinter as tk
from ui.theme import Colors, Fonts
from ui.glass_widgets import GlassPanel, GlassButton, GlassEntry, GlassLabel, GlassBadge

class DashboardPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = Colors()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._app = app; self._qr_photo = None
        canvas = tk.Canvas(self, bg=self._c.BG_DEEP, highlightthickness=0, bd=0)
        sb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=self._c.BG_DEEP)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("all", width=e.width))
        self._build(inner)

    def _build(self, c):
        dev = GlassPanel(c, title="Device", icon="📱")
        dev.pack(fill="x", padx=12, pady=(12, 6))
        dc = dev.content
        self._dev_name = GlassLabel(dc, text="No device detected", font=Fonts.DEVICE_NAME)
        self._dev_name.pack(anchor="w", padx=8, pady=(4, 2))
        self._dev_ip = GlassLabel(dc, text="", font=Fonts.MONO)
        self._dev_ip.pack(anchor="w", padx=8)
        self._badge = GlassBadge(dc, text="IDLE", color=self._c.STATUS_IDLE)
        self._badge.pack(anchor="w", padx=8, pady=(4, 4))

        GlassButton(c, text="Quick Mirror", icon="⚡", style="primary", width=400, height=48, command=self._on_quick).pack(fill="x", padx=12, pady=6)

        conn = GlassPanel(c, title="Connection", icon="🔗")
        conn.pack(fill="x", padx=12, pady=6)
        cc = conn.content
        r1 = tk.Frame(cc, bg=self._c.BG_PANEL); r1.pack(fill="x", padx=8, pady=4)
        GlassLabel(r1, text="IP:", width=4).pack(side="left")
        self._ip_var = tk.StringVar()
        GlassEntry(r1, textvariable=self._ip_var, placeholder="192.168.1.x", width=18).pack(side="left", padx=(0, 6))
        GlassLabel(r1, text="Port:").pack(side="left", padx=(6, 0))
        self._port_var = tk.StringVar(value="5555")
        GlassEntry(r1, textvariable=self._port_var, width=8).pack(side="left", padx=(0, 6))
        GlassButton(r1, text="Detect", icon="🔍", style="cyan", width=100, command=self._on_detect).pack(side="right")

        r2 = tk.Frame(cc, bg=self._c.BG_PANEL); r2.pack(fill="x", padx=8, pady=4)
        GlassLabel(r2, text="Pair:", width=4).pack(side="left")
        self._pair_port = tk.StringVar(value="5555")
        GlassEntry(r2, textvariable=self._pair_port, width=8).pack(side="left", padx=(0, 6))
        GlassLabel(r2, text="Code:").pack(side="left", padx=(6, 0))
        self._pair_code = tk.StringVar()
        GlassEntry(r2, textvariable=self._pair_code, width=12, show="*").pack(side="left", padx=(0, 6))

        btns = tk.Frame(cc, bg=self._c.BG_PANEL); btns.pack(fill="x", padx=8, pady=(8, 4))
        GlassButton(btns, text="Pair", icon="🤝", style="warning", width=100, command=self._on_pair).pack(side="left", padx=(0, 4))
        GlassButton(btns, text="Connect", icon="🔌", style="success", width=100, command=self._on_connect).pack(side="left", padx=(0, 4))
        GlassButton(btns, text="Mirror", icon="▶", style="cyan", width=100, command=self._on_mirror).pack(side="left", padx=(0, 4))
        GlassButton(btns, text="Disconnect", icon="⏏", style="danger", width=100, command=self._on_disconnect).pack(side="left")

        qr = GlassPanel(c, title="QR Code", icon="📷")
        qr.pack(fill="x", padx=12, pady=6)
        self._qr_label = GlassLabel(qr.content, text="Detect device to show QR", fg=self._c.TEXT_MUTED, justify="center")
        self._qr_label.pack(pady=16)

        lp = GlassPanel(c, title="Log", icon="📋")
        lp.pack(fill="x", padx=12, pady=(6, 12))
        self._log_text = tk.Text(lp.content, height=8, bg=self._c.BG_INPUT, fg=self._c.TEXT_PRIMARY, font=Fonts.MONO_SMALL, relief="flat", bd=0, state="disabled")
        self._log_text.pack(fill="x", padx=8, pady=(0, 8))

    def set_device(self, model, ip, port, status="ready"):
        self._dev_name.configure(text=model or "Unknown")
        self._dev_ip.configure(text=f"{ip}:{port}" if port else ip)
        colors = {"ready": self._c.STATUS_READY, "connected": self._c.ACCENT_CYAN, "mirroring": self._c.ACCENT_RED, "idle": self._c.STATUS_IDLE, "error": self._c.ACCENT_RED}
        self._badge.set_text(status.upper(), colors.get(status, self._c.STATUS_IDLE))

    def clear_device(self):
        self._dev_name.configure(text="No device detected"); self._dev_ip.configure(text="")
        self._badge.set_text("IDLE", self._c.STATUS_IDLE)

    def log(self, msg, level="info"):
        colors = {"info": self._c.TEXT_PRIMARY, "success": self._c.ACCENT_CYAN, "error": self._c.ACCENT_RED, "warning": self._c.ACCENT_AMBER}
        self._log_text.configure(state="normal")
        self._log_text.insert("end", msg + chr(10), level)
        self._log_text.tag_config(level, foreground=colors.get(level, self._c.TEXT_PRIMARY))
        self._log_text.see("end"); self._log_text.configure(state="disabled")

    def _on_quick(self):
        if self._app: self._app.quick_mirror()
    def _on_detect(self):
        if self._app: self._app.detect_device()
    def _on_pair(self):
        if self._app: self._app.pair_device()
    def _on_connect(self):
        if self._app: self._app.connect_device()
    def _on_mirror(self):
        if self._app: self._app.start_mirror()
    def _on_disconnect(self):
        if self._app: self._app.disconnect_device()

    def update_qr(self, image):
        from PIL import ImageTk
        self._qr_photo = ImageTk.PhotoImage(image)
        self._qr_label.configure(image=self._qr_photo, text="")
