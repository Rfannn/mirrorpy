import tkinter as tk
from ui.theme import get_palette, Fonts, Geo, NAV_ITEMS

class GlassSidebar(tk.Frame):
    def __init__(self, master, onNavigate=None, onToggleTheme=None, **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_SIDEBAR, width=Geo.SIDEBAR_WIDTH_COLLAPSED, **kw)
        self.pack_propagate(False)
        self._on_nav = onNavigate
        self._on_theme = onToggleTheme
        self._buttons = {}
        self._active = None
        self._expanded = False

        for item in NAV_ITEMS:
            frame = tk.Frame(self, bg=self._c.BG_SIDEBAR, height=44)
            frame.pack(fill="x"); frame.pack_propagate(False)
            lbl = tk.Label(frame, text=item["icon"], font=Fonts.SIDEBAR_ICON,
                           bg=self._c.BG_SIDEBAR, fg=self._c.TEXT_SECONDARY, width=3, cursor="hand2")
            lbl.pack(side="left")
            name = tk.Label(frame, text=item["label"], font=Fonts.BODY,
                           bg=self._c.BG_SIDEBAR, fg=self._c.TEXT_PRIMARY)
            name.pack(side="left", padx=(4,0)); name.pack_forget()
            self._buttons[item["key"]] = {"frame": frame, "icon": lbl, "name": name}
            lbl.bind("<Button-1>", lambda e, k=item["key"]: self._navigate(k))
            name.bind("<Button-1>", lambda e, k=item["key"]: self._navigate(k))
            frame.bind("<Enter>", lambda e, f=frame: f.configure(bg=self._c.BG_PANEL_HOVER))
            frame.bind("<Leave>", lambda e, f=frame, k=item["key"]: f.configure(bg=self._c.ACCENT_PRIMARY if self._active==k else self._c.BG_SIDEBAR))

        tk.Frame(self, bg=self._c.BG_SIDEBAR).pack(fill="both", expand=True)
        self._theme_btn = tk.Label(self, text="🌙" if self._dark() else "☀️", font=Fonts.SIDEBAR_ICON,
                                   bg=self._c.BG_SIDEBAR, fg=self._c.TEXT_SECONDARY, cursor="hand2")
        self._theme_btn.pack(pady=(0,12))
        self._theme_btn.bind("<Button-1>", self._toggle_theme)
        self.bind("<Enter>", self._expand)
        self.bind("<Leave>", self._collapse)

    def _dark(self):
        return self._c.BG_DEEP.lower() < "#808080"

    def _toggle_theme(self, e=None):
        if self._on_theme: self._on_theme()

    def _navigate(self, key):
        if self._active == key: return
        if self._active and self._active in self._buttons:
            b = self._buttons[self._active]
            b["frame"].configure(bg=self._c.BG_SIDEBAR); b["icon"].configure(fg=self._c.TEXT_SECONDARY)
        self._active = key; b = self._buttons[key]
        b["frame"].configure(bg=self._c.ACCENT_PRIMARY); b["icon"].configure(fg="white")
        if self._on_nav: self._on_nav(key)

    def _expand(self, e=None):
        self._expanded = True; self.configure(width=Geo.SIDEBAR_WIDTH_EXPANDED)
        for b in self._buttons.values(): b["name"].pack(side="left", padx=(4,0))

    def _collapse(self, e=None):
        self._expanded = False; self.configure(width=Geo.SIDEBAR_WIDTH_COLLAPSED)
        for b in self._buttons.values(): b["name"].pack_forget()

    def navigate_to(self, key):
        self._navigate(key)
