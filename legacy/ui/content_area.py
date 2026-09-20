import tkinter as tk
from ui.theme import get_palette

class GlassContentArea(tk.Frame):
    def __init__(self, master, **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._pages = {}
        self._current = None

    def add_page(self, key, frame):
        self._pages[key] = frame
        frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        frame.lower()

    def show_page(self, key):
        if self._current == key: return
        if self._current and self._current in self._pages:
            self._pages[self._current].lower()
        if key in self._pages:
            self._pages[key].tkraise()
            self._current = key
