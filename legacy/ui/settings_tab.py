import tkinter as tk
from ui.theme import get_palette, Fonts, QUALITY_PRESETS, ACCENT_PRESETS
from ui.glass_widgets import GlassPanel, GlassButton, GlassToggle, GlassLabel

class SettingsPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = get_palette()
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
        if self._app:
            self._auto_connect.set(self._app._cfg["DEFAULT"].get("autoconnect", "0") == "1")
        r = tk.Frame(cc, bg=self._c.BG_PANEL); r.pack(fill="x", padx=8, pady=4)
        GlassLabel(r, text="Auto-connect on startup").pack(side="left")
        GlassToggle(r, variable=self._auto_connect, command=self._on_auto_connect).pack(side="right")

        qp = GlassPanel(inner, title="Quality Presets", icon="⚡")
        qp.pack(fill="x", padx=12, pady=6)
        qpc = qp.content
        pr = tk.Frame(qpc, bg=self._c.BG_PANEL); pr.pack(fill="x", padx=8, pady=4)
        self._preset_var = tk.StringVar(value=self._current_preset())
        for name in QUALITY_PRESETS:
            GlassButton(pr, text=name, style="ghost", width=80,
                        command=lambda n=name: self._set_preset(n)).pack(side="left", padx=2)
        self._preset_desc = GlassLabel(qpc, text=self._current_desc(), fg=self._c.TEXT_SECONDARY)
        self._preset_desc.pack(padx=8, pady=(4, 8))

        app_p = GlassPanel(inner, title="Appearance", icon="🎨")
        app_p.pack(fill="x", padx=12, pady=6)
        ac = app_p.content
        r2 = tk.Frame(ac, bg=self._c.BG_PANEL); r2.pack(fill="x", padx=8, pady=4)
        GlassLabel(r2, text="Accent color:").pack(side="left")
        for name, color in ACCENT_PRESETS.items():
            active = self._app and self._app._accent == name
            btn = tk.Canvas(r2, width=24, height=24, bg=color, cursor="hand2",
                            highlightthickness=3 if active else 1,
                            highlightbackground="white" if active else self._c.BG_PANEL)
            btn.pack(side="left", padx=4)
            btn.bind("<Button-1>", lambda e, n=name: self._set_accent(n))
        tk.Label(ac, text="Rebuilds the interface to apply.", font=Fonts.SMALL,
                 bg=self._c.BG_PANEL, fg=self._c.TEXT_MUTED).pack(anchor="w", padx=8, pady=(0, 8))

        danger = GlassPanel(inner, title="Danger Zone", icon="⚠️")
        danger.pack(fill="x", padx=12, pady=(6, 12))
        GlassButton(danger.content, text="Reset All Settings", style="danger", width=200, command=self._reset).pack(padx=8, pady=8)

    def _current_preset(self):
        return self._app._quality if self._app else "Medium"

    def _current_desc(self):
        p = QUALITY_PRESETS.get(self._current_preset(), {})
        return "%s: %s" % (self._current_preset(), p.get("desc", ""))

    def _set_preset(self, name):
        p = QUALITY_PRESETS.get(name, {})
        self._preset_desc.configure(text="%s: %s" % (name, p.get("desc", "")))
        if self._app:
            self._app.set_quality(name)
            self._app.toast("Quality: " + name, "success")

    def _set_accent(self, name):
        if self._app:
            self._app.set_accent(name)

    def _on_auto_connect(self):
        if not self._app: return
        self._app._cfg["DEFAULT"]["autoconnect"] = "1" if self._auto_connect.get() else "0"
        self._app._save_config()

    def _reset(self):
        if not self._app: return
        self._app.reset_settings()
