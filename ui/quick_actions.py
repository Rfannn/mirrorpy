import tkinter as tk
from ui.theme import Colors, Fonts
from ui.glass_widgets import GlassPanel, GlassButton, GlassLabel

class QuickActionsPage(tk.Frame):
    def __init__(self, master, app=None, **kw):
        self._c = Colors()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._app = app
        self._build()

    def _build(self):
        tk.Label(self, text="⚡  Quick Actions", font=Fonts.HEADING,
                 bg=self._c.BG_DEEP, fg=self._c.TEXT_PRIMARY).pack(anchor="w", padx=12, pady=(12, 6))

        grid = tk.Frame(self, bg=self._c.BG_DEEP)
        grid.pack(fill="both", expand=True, padx=12, pady=6)

        actions = [
            ("📸", "Screenshot", "capture_screen"), ("🎬", "Record", "toggle_record"),
            ("📁", "Push File", "push_file"), ("📋", "Clipboard", "sync_clipboard"),
            ("🔊", "Volume", "control_volume"), ("🔄", "Restart ADB", "restart_adb"),
            ("📊", "Device Info", "device_info"), ("🔥", "Clear Cache", "clear_cache"),
            ("📦", "App Manager", "manage_apps"), ("🌐", "Screen Cast", "screen_cast"),
        ]

        for i, (icon, label, action) in enumerate(actions):
            r, col = divmod(i, 3)
            btn = GlassButton(grid, text=label, icon=icon, style="ghost", width=160, height=80,
                              command=lambda a=action: self._do_action(a))
            btn.grid(row=r, column=col, padx=6, pady=6, sticky="nsew")
            grid.columnconfigure(col, weight=1)

    def _do_action(self, action):
        if self._app and hasattr(self._app, action):
            getattr(self._app, action)()
