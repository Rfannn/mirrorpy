import tkinter as tk
from ui.theme import get_palette, Fonts
from ui.glass_widgets import GlassButton, GlassEntry, GlassLabel

class LogsPage(tk.Frame):
    def __init__(self, master, **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._filter_var = tk.StringVar()
        self._auto_scroll = True
        self._build()

    def _build(self):
        # Filter bar
        bar = tk.Frame(self, bg=self._c.BG_DEEP)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        GlassLabel(bar, text="🔍 Filter:").pack(side="left")
        GlassEntry(bar, textvariable=self._filter_var, placeholder="Search logs...", width=30).pack(side="left", padx=8)
        GlassButton(bar, text="Clear", style="danger", width=80, command=self._clear).pack(side="right", padx=4)
        GlassButton(bar, text="Export", style="ghost", width=80, command=self._export).pack(side="right", padx=4)

        # Log text area
        self._text = tk.Text(self, bg=self._c.BG_INPUT, fg=self._c.TEXT_PRIMARY, font=Fonts.MONO,
                             relief="flat", bd=0, state="disabled", wrap="word")
        self._text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text.tag_config("info", foreground=self._c.TEXT_PRIMARY)
        self._text.tag_config("success", foreground=self._c.ACCENT_CYAN)
        self._text.tag_config("error", foreground=self._c.ACCENT_RED)
        self._text.tag_config("warning", foreground=self._c.ACCENT_AMBER)

    def log(self, msg, level="info"):
        self._text.configure(state="normal")
        self._text.insert("end", msg + chr(10), level)
        if self._auto_scroll: self._text.see("end")
        self._text.configure(state="disabled")

    def _clear(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def _export(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "w") as f: f.write(self._text.get("1.0", "end"))
