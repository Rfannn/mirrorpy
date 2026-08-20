import tkinter as tk
from ui.theme import Colors, Fonts, Geo

class GlassTitleBar(tk.Frame):
    def __init__(self, master, title="MirrorPy", on_close=None, on_minimize=None, on_maximize=None, **kw):
        self._c = Colors()
        super().__init__(master, bg=self._c.BG_TITLEBAR, height=Geo.TITLEBAR_HEIGHT, **kw)
        self.pack_propagate(False)
        self._on_close = on_close
        self._on_min = on_minimize
        self._on_max = on_maximize
        self._drag_data = {"x": 0, "y": 0}

        self._title = tk.Label(self, text="  📱  " + title,
                              font=Fonts.TITLEBAR, bg=self._c.BG_TITLEBAR, fg=self._c.TEXT_PRIMARY)
        self._title.pack(side="left", padx=(8,0))

        for text, cmd in [("–", self._minimize), ("□", self._toggle_max), ("✕", self._close)]:
            btn = tk.Label(self, text=text, font=("Segoe UI", 11),
                           bg=self._c.BG_TITLEBAR, fg=self._c.TEXT_SECONDARY, padx=12, pady=2, cursor="hand2")
            btn.pack(side="right")
            btn.bind("<Enter>", lambda e, b=btn: b.configure(fg=self._c.TEXT_PRIMARY))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(fg=self._c.TEXT_SECONDARY))
            if cmd == self._close:
                btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=self._c.ACCENT_RED, fg="white"))
                btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=self._c.BG_TITLEBAR, fg=self._c.TEXT_SECONDARY))
            btn.bind("<Button-1>", lambda e, c=cmd: c())

        self.bind("<Button-1>", self._start_drag)
        self.bind("<B1-Motion>", self._on_drag)
        self._title.bind("<Button-1>", self._start_drag)
        self._title.bind("<B1-Motion>", self._on_drag)

    def _start_drag(self, e):
        self._drag_data["x"] = e.x_root; self._drag_data["y"] = e.y_root

    def _on_drag(self, e):
        dx = e.x_root - self._drag_data["x"]; dy = e.y_root - self._drag_data["y"]
        win = self.winfo_toplevel()
        win.geometry(f"+{win.winfo_x()+dx}+{win.winfo_y()+dy}")
        self._drag_data["x"] = e.x_root; self._drag_data["y"] = e.y_root

    def _close(self):
        if self._on_close: self._on_close()
    def _minimize(self):
        if self._on_min: self._on_min()
    def _toggle_max(self):
        if self._on_max: self._on_max()
