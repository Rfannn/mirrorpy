import tkinter as tk
from ui.theme import Colors, Fonts, QUALITY_PRESETS, ACCENT_PRESETS
from ui.glass_widgets import GlassPanel, GlassButton, GlassEntry, GlassToggle, GlassSlider, GlassLabel

class SettingsPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = Colors()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._app = app; self._build()

    def _build(self):
        canvas = tk.Canvas(self, bg=self._c.BG_DEEP, highlightthickness=0, bd=0)
        sb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=self._c.BG_DEEP)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("all", width=e.width))

        tk.Label(inner, text="⚙️  Settings", font=Fonts.HEADING, bg=self._c.BG_DEEP, fg=self._c.TEXT_PRIMARY).pack(anchor="w", padx=12, pady=(12, 6))

        conn = GlassPanel(inner, title="Connection", icon="🔗")
        conn.pack(fill="x", padx=12, pady=6)
        cc = conn.content
        self._auto_connect = tk.BooleanVar()
        r = tk.Frame(cc, bg=self._c.BG_PANEL); r.pack(fill="x", padx=8, pady=4)
        GlassLabel(r, text="Auto-connect on startup").pack(side="left")
        GlassToggle(r, variable=self._auto_connect).pack(side="right")

        qp = GlassPanel(inner, title="Quality Presets", icon="⚡")
        qp.pack(fill="x", padx=12, pady=6)
        qpc = qp.content
        pr = tk.Frame(qpc, bg=self._c.BG_PANEL); pr.pack(fill="x", padx=8, pady=4)
        for name in QUALITY_PRESETS:
            GlassButton(pr, text=name, style="ghost", width=80, command=lambda n=name: self._set_preset(n)).pack(side="left", padx=2)
        self._preset_desc = GlassLabel(qpc, text="High: 1080p 60fps 8M", fg=self._c.TEXT_SECONDARY)
        self._preset_desc.pack(padx=8, pady=(4, 8))

        app_p = GlassPanel(inner, title="Appearance", icon="🎨")
        app_p.pack(fill="x", padx=12, pady=6)
        ac = app_p.content
        r2 = tk.Frame(ac, bg=self._c.BG_PANEL); r2.pack(fill="x", padx=8, pady=4)
        GlassLabel(r2, text="Accent color:").pack(side="left")
        for name, color in ACCENT_PRESETS.items():
            btn = tk.Canvas(r2, width=24, height=24, bg=color, highlightthickness=1, highlightbackground="white", cursor="hand2")
            btn.pack(side="left", padx=4)
            btn.bind("<Button-1>", lambda e, c=color: self._app.toast("Accent: " + c, "info") if self._app else None)

        danger = GlassPanel(inner, title="Danger Zone", icon="⚠️")
        danger.pack(fill="x", padx=12, pady=(6, 12))
        GlassButton(danger.content, text="Reset All Settings", style="danger", width=200, command=self._reset).pack(padx=8, pady=8)

    def _set_preset(self, name):
        p = QUALITY_PRESETS.get(name, {}); self._preset_desc.configure(text=p.get("desc", ""))
        if self._app: self._app.toast("Quality: " + name, "success")

    def _reset(self):
        if self._app: self._app.toast("Settings reset", "warning")
