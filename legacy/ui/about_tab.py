import tkinter as tk
from ui.theme import get_palette, Fonts
from ui.glass_widgets import GlassSeparator

class AboutPage(tk.Frame):
    def __init__(self, master, **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._build()

    def _build(self):
        tk.Label(self, text="📱", font=("Segoe UI Emoji", 48), bg=self._c.BG_DEEP).pack(pady=(40, 8))
        tk.Label(self, text="MirrorPy", font=Fonts.HEADING, bg=self._c.BG_DEEP, fg=self._c.TEXT_PRIMARY).pack()
        tk.Label(self, text="v2.0.0", font=Fonts.BODY, bg=self._c.BG_DEEP, fg=self._c.TEXT_SECONDARY).pack()
        tk.Label(self, text="One-click Android screen mirroring", font=Fonts.BODY, bg=self._c.BG_DEEP, fg=self._c.TEXT_SECONDARY).pack(pady=(4, 20))

        GlassSeparator(self).pack(fill="x", padx=40)

        features = [
            ("🔍", "Smart Auto-Detect"), ("⚡", "Quick Mirror"),
            ("📷", "QR Code Pairing"), ("🎨", "Modern UI"),
            ("🔒", "Thread-Safe"), ("💾", "Persistent Config"),
        ]
        grid = tk.Frame(self, bg=self._c.BG_DEEP)
        grid.pack(pady=20)
        for i, (icon, text) in enumerate(features):
            r, col = divmod(i, 2)
            f = tk.Frame(grid, bg=self._c.BG_PANEL, padx=16, pady=12)
            f.grid(row=r, column=col, padx=6, pady=6, sticky="nsew")
            tk.Label(f, text=icon, font=("Segoe UI Emoji", 20), bg=self._c.BG_PANEL).pack()
            tk.Label(f, text=text, font=Fonts.SMALL, bg=self._c.BG_PANEL, fg=self._c.TEXT_PRIMARY).pack()

        GlassSeparator(self).pack(fill="x", padx=40, pady=(20, 0))

        credits = tk.Frame(self, bg=self._c.BG_DEEP)
        credits.pack(pady=20)
        for name, desc in [("scrcpy", "Mirroring engine"), ("ttkbootstrap", "UI themes"), ("qrcode", "QR generation")]:
            tk.Label(credits, text=f"{name} - {desc}", font=Fonts.SMALL, bg=self._c.BG_DEEP, fg=self._c.TEXT_SECONDARY).pack(pady=2)

        tk.Label(self, text="Made with ❤️ by Rfannn", font=Fonts.SMALL, bg=self._c.BG_DEEP, fg=self._c.TEXT_MUTED).pack(pady=(10, 20))
