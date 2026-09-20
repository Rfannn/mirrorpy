"""
MirrorPy Glass Widgets
"""

import tkinter as tk
from ui.theme import get_palette, Fonts, Geo


def _rounded_rect(canvas, x1, y1, x2, y2, r, **kwargs):
    pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2, x2-r,y2, x1+r,y2, x1,y2, x1,y2-r, x1,y1+r, x1,y1]
    return canvas.create_polygon(pts, smooth=True, **kwargs)

def _color_blend(c1, c2, t):
    r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
    r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
    r=int(r1+(r2-r1)*t); g=int(g1+(g2-g1)*t); b=int(b1+(b2-b1)*t)
    return "#%02x%02x%02x" % (r, g, b)
class GlassPanel(tk.Frame):
    def __init__(self, master, title="", icon="", accent_color=None, collapsible=False, **kw):
        self._c = get_palette()
        self._bg = kw.pop("bg", self._c.BG_PANEL)
        self._bdr = kw.pop("highlightbackground", self._c.BORDER_GLASS)
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._accent = accent_color or self._c.ACCENT_PRIMARY
        self._collapsed = False
        self._header = tk.Frame(self, bg=self._bg, height=32)
        self._header.pack(fill="x", padx=1, pady=(1,0))
        self._header.pack_propagate(False)
        if title:
            txt = "  %s  %s" % (icon, title) if icon else "  %s" % title
            self._tl = tk.Label(self._header, text=txt, font=Fonts.SUBHEADING,
                                bg=self._bg, fg=self._c.TEXT_PRIMARY, anchor="w")
            self._tl.pack(side="left", fill="x", expand=True)
        if collapsible:
            self._ch = tk.Label(self._header, text="▾", font=Fonts.BODY,
                                bg=self._bg, fg=self._c.TEXT_SECONDARY, cursor="hand2")
            self._ch.pack(side="right", padx=(0,8))
            self._ch.bind("<Button-1>", self._toggle)
        self._content = tk.Frame(self, bg=self._bg)
        self._content.pack(fill="both", expand=True, padx=1, pady=(0,1))
        self.bind("<Configure>", self._on_cfg)

    @property
    def content(self):
        return self._content

    def _on_cfg(self, e=None):
        self.configure(highlightbackground=self._bdr, highlightthickness=1, bd=0)

    def _toggle(self, e=None):
        self._collapsed = not self._collapsed
        if self._collapsed:
            self._content.pack_forget()
            self._ch.configure(text="▸")
        else:
            self._content.pack(fill="both", expand=True, padx=1, pady=(0,1))
            self._ch.configure(text="▾")


class GlassButton(tk.Canvas):
    def __init__(self, master, text="", icon="", command=None,
                 style="primary", width=120, height=36, enabled=True, **kw):
        self._c = get_palette()
        self._cmd = command; self._style = style
        self._hovered = False; self._pressed = False
        self._enabled = enabled
        self._text = "%s  %s" % (icon, text) if icon else text
        super().__init__(master, width=width, height=height,
                         bg=self._c.BG_DEEP, highlightthickness=0, bd=0,
                         cursor="hand2" if enabled else "", **kw)
        self._gw = width; self._gh = height; self._draw()
        if enabled:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<ButtonPress-1>", self._on_press)
            self.bind("<ButtonRelease-1>", self._on_release)

    def _sc(self):
        s = {"primary":(self._c.ACCENT_PRIMARY, self._c.TEXT_ON_ACCENT),
             "secondary":(self._c.ACCENT_SECONDARY, self._c.TEXT_ON_ACCENT),
             "cyan":(self._c.ACCENT_CYAN, self._c.BG_DEEP),
             "success":(self._c.ACCENT_GREEN, self._c.BG_DEEP),
             "warning":(self._c.ACCENT_AMBER, self._c.BG_DEEP),
             "danger":(self._c.ACCENT_RED, self._c.TEXT_ON_ACCENT),
             "ghost":(self._c.BG_PANEL, self._c.TEXT_PRIMARY)}
        return s.get(self._style, s["primary"])

    def _draw(self):
        self.delete("all"); bg, fg = self._sc()
        r = Geo.BUTTON_CORNER_RADIUS
        if not self._enabled:
            fill = _color_blend(bg, self._c.BG_DEEP, 0.78)
            bdr = _color_blend(fill, self._c.TEXT_MUTED, 0.25)
            fg = self._c.TEXT_MUTED
        elif self._hovered:
            fill = _color_blend(bg, "#ffffff", 0.15)
            bdr = _color_blend(bg, "#ffffff", 0.3)
        elif self._pressed:
            fill = _color_blend(bg, "#000000", 0.15); bdr = bg
        else:
            fill = bg; bdr = _color_blend(bg, "#ffffff", 0.1)
        _rounded_rect(self, 1, 1, self._gw-1, self._gh-1, r, fill=fill, outline=bdr, width=1)
        self.create_text(self._gw//2, self._gh//2, text=self._text,
                         font=Fonts.BUTTON_BOLD, fill=fg, anchor="center")

    def _on_enter(self, e): self._hovered = True; self._draw()
    def _on_leave(self, e): self._hovered = False; self._pressed = False; self._draw()
    def _on_press(self, e): self._pressed = True; self._draw()
    def _on_release(self, e):
        self._pressed = False; self._draw()
        if self._cmd: self._cmd()

    def set_text(self, text, icon=""):
        self._text = "%s  %s" % (icon, text) if icon else text; self._draw()

    def configure_state(self, state):
        self._enabled = state != "disabled"
        for seq in ("<Enter>", "<Leave>", "<ButtonPress-1>", "<ButtonRelease-1>"):
            self.unbind(seq)
        if self._enabled:
            self.configure(cursor="hand2")
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<ButtonPress-1>", self._on_press)
            self.bind("<ButtonRelease-1>", self._on_release)
        else:
            self._hovered = self._pressed = False
            self.configure(cursor="")
        self._draw()


class GlassEntry(tk.Frame):
    def __init__(self, master, textvariable=None, placeholder="", width=20, show="", **kw):
        self._c = get_palette()
        super().__init__(master, bg=self._c.BG_DEEP, **kw)
        self._ph = placeholder
        self._cv = tk.Canvas(self, height=32, bg=self._c.BG_DEEP, highlightthickness=0, bd=0)
        self._cv.pack(fill="x")
        self._entry = tk.Entry(self, textvariable=textvariable, font=Fonts.BODY,
                               bg=self._c.BG_INPUT, fg=self._c.TEXT_PRIMARY,
                               insertbackground=self._c.TEXT_PRIMARY, relief="flat", bd=0, width=width, show=show)
        if placeholder and not (textvariable and textvariable.get()):
            self._entry.insert(0, placeholder); self._entry.configure(fg=self._c.TEXT_MUTED)
            self._entry.bind("<FocusIn>", self._clr_ph)
            self._entry.bind("<FocusOut>", self._shw_ph)
        self._cv.create_window(6, 1, anchor="nw", window=self._entry)
        self.bind("<Configure>", self._redraw)
        self._entry.bind("<FocusIn>", self._fi)
        self._entry.bind("<FocusOut>", self._fo)

    def _redraw(self, e=None):
        w = self.winfo_width(); self._cv.delete("border")
        self._cv.create_rectangle(0,0,w,32, fill=self._c.BG_INPUT, outline=self._c.BORDER_SUBTLE, width=1, tags="border")
        self._cv.tag_lower("border")

    def _fi(self, e):
        self._cv.delete("glow")
        self._cv.create_rectangle(0,0,self.winfo_width(),32, fill="", outline=self._c.BORDER_FOCUS, width=2, tags="glow")
        self._cv.tag_raise("glow")

    def _fo(self, e): self._cv.delete("glow")

    def _clr_ph(self, e):
        if self._entry.get() == self._ph: self._entry.delete(0,"end"); self._entry.configure(fg=self._c.TEXT_PRIMARY)

    def _shw_ph(self, e):
        if not self._entry.get(): self._entry.insert(0, self._ph); self._entry.configure(fg=self._c.TEXT_MUTED)

    def get(self): v = self._entry.get(); return "" if v == self._ph else v


class GlassToggle(tk.Canvas):
    def __init__(self, master, variable=None, command=None, **kw):
        self._c = get_palette()
        w, h = Geo.TOGGLE_WIDTH, Geo.TOGGLE_HEIGHT
        super().__init__(master, width=w, height=h, bg=self._c.BG_DEEP, highlightthickness=0, bd=0, cursor="hand2", **kw)
        self._var = variable or tk.BooleanVar(value=False)
        self._cmd = command; self._gw = w; self._gh = h
        self.bind("<Button-1>", self._toggle); self._draw()

    @property
    def is_on(self): return self._var.get()

    def _toggle(self, e=None):
        self._var.set(not self._var.get()); self._draw()
        if self._cmd: self._cmd()

    def _draw(self):
        self.delete("all"); on = self._var.get(); r = self._gh // 2
        tc = self._c.ACCENT_CYAN if on else self._c.BORDER_SUBTLE
        pts = [r,0, self._gw-r,0, self._gw,0, self._gw,r, self._gw,self._gh-r, self._gw,self._gh, self._gw-r,self._gh, r,self._gh, 0,self._gh, 0,self._gh-r, 0,r, 0,0]
        self.create_polygon(pts, smooth=True, fill=tc, outline="")
        dr = Geo.TOGGLE_DOT_RADIUS
        cx = (self._gw - 2*dr) if on else dr; cy = self._gh // 2
        self.create_oval(cx-dr, cy-dr, cx+dr, cy+dr, fill=self._c.TEXT_ON_ACCENT, outline="")


class GlassSlider(tk.Canvas):
    def __init__(self, master, from_=0, to=100, variable=None, command=None, width=200, **kw):
        self._c = get_palette(); self._from = from_; self._to = to
        self._var = variable or tk.DoubleVar(value=from_)
        self._cmd = command; self._th = 6; self._tr = 8; self._drag = False
        super().__init__(master, width=width, height=28, bg=self._c.BG_DEEP, highlightthickness=0, bd=0, cursor="hand2", **kw)
        self._gw = width
        self.bind("<Button-1>", self._clk)
        self.bind("<B1-Motion>", self._drg)
        self.bind("<ButtonRelease-1>", self._rel); self._draw()

    def _v2x(self, v):
        f = (v - self._from) / max(self._to - self._from, 1)
        m = self._tr + 2; return m + f * (self._gw - 2*m)

    def _x2v(self, x):
        m = self._tr + 2; f = max(0, min(1, (x - m) / max(self._gw - 2*m, 1)))
        return self._from + f * (self._to - self._from)

    def _draw(self):
        self.delete("all"); v = self._var.get(); cx = self._v2x(v); cy = 14; r = self._tr
        self.create_rectangle(r+2, cy-self._th//2, self._gw-r-2, cy+self._th//2, fill=self._c.BORDER_SUBTLE, outline="")
        self.create_rectangle(r+2, cy-self._th//2, cx, cy+self._th//2, fill=self._c.ACCENT_PRIMARY, outline="")
        self.create_oval(cx-r, cy-r, cx+r, cy+r, fill=self._c.ACCENT_PRIMARY, outline=self._c.TEXT_ON_ACCENT, width=2)

    def _clk(self, e): self._drag=True; self._var.set(self._x2v(e.x)); self._draw()
    def _drg(self, e):
        if self._drag: self._var.set(self._x2v(e.x)); self._draw()
    def _rel(self, e): self._drag = False
    def get(self): return self._var.get()
    def set(self, v): self._var.set(v); self._draw()


class GlassBadge(tk.Canvas):
    def __init__(self, master, text="", color=None, **kw):
        self._c = get_palette(); self._color = color or self._c.ACCENT_CYAN; self._text = text
        super().__init__(master, width=max(len(text)*7+16, 40), height=20,
                         bg=self._c.BG_DEEP, highlightthickness=0, bd=0, **kw)
        self._draw()

    def _draw(self):
        self.delete("all"); w = self.winfo_width() or max(len(self._text)*7+16, 40)
        r = Geo.BADGE_CORNER_RADIUS
        pts = [r,0, w-r,0, w,0, w,r, w,20-r, w,20, w-r,20, r,20, 0,20, 0,20-r, 0,r, 0,0]
        self.create_polygon(pts, smooth=True, fill=self._color, outline="")
        self.create_text(w//2, 10, text=self._text, font=Fonts.BADGE, fill=self._c.TEXT_ON_ACCENT)

    def set_text(self, text, color=None):
        self._text = text
        if color: self._color = color
        self._draw()
    def set_color(self, c): self._color = c; self._draw()


class GlassLabel(tk.Label):
    def __init__(self, master, **kw):
        self._c = get_palette()
        kw.setdefault("bg", self._c.BG_DEEP); kw.setdefault("fg", self._c.TEXT_PRIMARY)
        kw.setdefault("font", Fonts.BODY); kw.setdefault("anchor", "w")
        super().__init__(master, **kw)


class GlassSeparator(tk.Canvas):
    def __init__(self, master, **kw):
        self._c = get_palette()
        super().__init__(master, height=1, bg=self._c.BG_DEEP, highlightthickness=0, bd=0, **kw)
        self.bind("<Configure>", self._draw)
    def _draw(self, e=None):
        self.delete("all")
        self.create_line(0, 0, self.winfo_width(), 0, fill=self._c.BORDER_SUBTLE, width=1)
