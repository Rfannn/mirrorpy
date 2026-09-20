import tkinter as tk
from ui.theme import get_palette, Fonts, Anim

class ToastManager:
    def __init__(self, master):
        self._c = get_palette()
        self._master = master
        self._toasts = []

    def show(self, message, level="info", duration=None):
        duration = duration or Anim.TOAST_DURATION
        colors = {
            "success": self._c.ACCENT_CYAN, "error": self._c.ACCENT_RED,
            "warning": self._c.ACCENT_AMBER, "info": self._c.ACCENT_PRIMARY,
        }
        bg = colors.get(level, self._c.ACCENT_PRIMARY)

        toast = tk.Frame(self._master, bg=bg, padx=12, pady=8)
        lbl = tk.Label(toast, text=message, font=Fonts.BODY, bg=bg, fg="white")
        lbl.pack()
        self._toasts.append(toast)

        y = self._master.winfo_height() - 50 - (len(self._toasts) - 1) * 45
        toast.place(relx=0.5, x=0, y=y, anchor="n")

        self._master.after(duration, lambda: self._dismiss(toast))

    def _dismiss(self, toast):
        if toast in self._toasts:
            self._toasts.remove(toast)
            toast.destroy()
            self._reposition()

    def _reposition(self):
        for i, t in enumerate(self._toasts):
            y = self._master.winfo_height() - 50 - i * 45
            t.place(relx=0.5, x=0, y=y, anchor="n")
