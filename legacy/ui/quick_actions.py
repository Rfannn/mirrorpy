import tkinter as tk
from ui.theme import get_palette, Fonts
from ui.glass_widgets import GlassButton

class QuickActionsPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._app = app
        self._build()

    def _build(self):
        tk.Label(self, text="⚡  Quick Actions", font=Fonts.HEADING,
                 bg=self._c.BG_DEEP, fg=self._c.TEXT_PRIMARY).pack(anchor="w", padx=12, pady=(12, 6))
        tk.Label(self, text="Actions marked Coming soon are not wired up yet.",
                 font=Fonts.SMALL, bg=self._c.BG_DEEP, fg=self._c.TEXT_MUTED).pack(anchor="w", padx=12)

        grid = tk.Frame(self, bg=self._c.BG_DEEP)
        grid.pack(fill="both", expand=True, padx=12, pady=6)

        actions = [
            ("📸", "Screenshot", "capture_screen", True),
            ("📋", "Get Clipboard", "sync_clipboard", True),
            ("📁", "Push File", "push_file", True),
            ("📊", "Device Info", "device_info", True),
            ("🔄", "Restart ADB", "restart_adb", True),
            ("🎬", "Record", "toggle_record", False),
            ("🔊", "Volume", "control_volume", False),
            ("🔥", "Clear Cache", "clear_cache", False),
            ("📦", "App Manager", "manage_apps", False),
            ("🌐", "Screen Cast", "screen_cast", False),
        ]

        for i, (icon, label, action, available) in enumerate(actions):
            r, col = divmod(i, 3)
            btn = GlassButton(grid, text=label + ("" if available else " (soon)"),
                              icon=icon, style="ghost", width=160, height=80,
                              enabled=available,
                              command=lambda a=action: self._do_action(a))
            btn.grid(row=r, column=col, padx=6, pady=6, sticky="nsew")
            grid.columnconfigure(col, weight=1)

    def _do_action(self, action):
        if self._app and hasattr(self._app, action):
            getattr(self._app, action)()
