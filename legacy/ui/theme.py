"""
MirrorPy Glass Theme — Color palette, fonts, animation constants.
Pure data module with no tkinter imports.
"""

# ============================================================
#  Color Palette
# ============================================================

class Colors:
    """Glass morphism color palette — dark mode (default)."""

    # Backgrounds
    BG_DEEP        = "#0a0a1a"
    BG_SIDEBAR     = "#0f0f23"
    BG_PANEL       = "#16213e"
    BG_PANEL_HOVER = "#1a2744"
    BG_INPUT       = "#0d1b2a"
    BG_TITLEBAR    = "#0c0c1d"

    # Borders
    BORDER_SUBTLE  = "#1e3a5f"
    BORDER_FOCUS   = "#e94560"
    BORDER_GLASS   = "#233554"

    # Accent colors
    ACCENT_PRIMARY = "#e94560"   # Pink-red (CTAs, active)
    ACCENT_SECONDARY = "#533483" # Purple
    ACCENT_CYAN    = "#00d2ff"   # Success / connected
    ACCENT_AMBER   = "#ffc107"   # Warning
    ACCENT_RED     = "#ff4757"   # Error / danger
    ACCENT_GREEN   = "#2ecc71"   # Online
    ACCENT_ORANGE  = "#ff6b35"   # Quick actions

    # Text
    TEXT_PRIMARY   = "#e8e8e8"
    TEXT_SECONDARY = "#8892b0"
    TEXT_MUTED     = "#4a5568"
    TEXT_ON_ACCENT = "#ffffff"

    # Status
    STATUS_IDLE      = "#4a5568"
    STATUS_READY     = "#2ecc71"
    STATUS_CONNECTED = "#00d2ff"
    STATUS_MIRRORING = "#e94560"
    STATUS_ERROR     = "#ff4757"
    STATUS_DETECTING = "#ffc107"


# ============================================================
#  Light Theme Override
# ============================================================

class LightColors(Colors):
    """Light glass morphism palette."""
    BG_DEEP        = "#f0f2f5"
    BG_SIDEBAR     = "#e4e7ec"
    BG_PANEL       = "#ffffff"
    BG_PANEL_HOVER = "#f8f9fa"
    BG_INPUT       = "#f0f2f5"
    BG_TITLEBAR    = "#e8eaf0"
    BORDER_SUBTLE  = "#d1d5db"
    BORDER_GLASS   = "#c9cdd4"
    TEXT_PRIMARY   = "#1a1a2e"
    TEXT_SECONDARY = "#555e6e"
    TEXT_MUTED     = "#9ca3af"


# ============================================================
#  Accent color presets
# ============================================================

ACCENT_PRESETS = {
    "pink":   "#e94560",
    "cyan":   "#00d2ff",
    "purple": "#a855f7",
    "green":  "#2ecc71",
    "orange": "#ff6b35",
}


# ============================================================
#  Active palette
# ============================================================
# Pages read the palette through get_palette() instead of building their own
# Colors() instance, so switching theme or accent recolors the whole app.

_PALETTE = Colors()


def get_palette():
    """Return the palette the UI is currently drawn with."""
    return _PALETTE


def set_theme(name):
    """Switch between 'dark' and 'light'. Returns the new palette."""
    global _PALETTE
    _PALETTE = LightColors() if name == "light" else Colors()
    return _PALETTE


def set_accent(name):
    """Apply an accent preset color to the active palette."""
    color = ACCENT_PRESETS.get(name)
    if color:
        _PALETTE.ACCENT_PRIMARY = color
    return _PALETTE

# ============================================================
#  Fonts
# ============================================================

class Fonts:
    """Font definitions — Segoe UI on Windows, fallback to system default."""
    FAMILY_SANS  = "Segoe UI"
    FAMILY_MONO  = "Consolas"
    FAMILY_EMOJI = "Segoe UI Emoji"

    # Sizes
    TITLEBAR    = (FAMILY_SANS, 13, "bold")
    SIDEBAR_ICON = (FAMILY_EMOJI, 16)
    HEADING     = (FAMILY_SANS, 16, "bold")
    SUBHEADING  = (FAMILY_SANS, 12, "bold")
    BODY        = (FAMILY_SANS, 10)
    BODY_BOLD   = (FAMILY_SANS, 10, "bold")
    SMALL       = (FAMILY_SANS, 9)
    SMALL_BOLD  = (FAMILY_SANS, 9, "bold")
    MONO        = (FAMILY_MONO, 10)
    MONO_SMALL  = (FAMILY_MONO, 9)
    BADGE       = (FAMILY_SANS, 8, "bold")
    BUTTON      = (FAMILY_SANS, 10)
    BUTTON_BOLD = (FAMILY_SANS, 10, "bold")
    HERO        = (FAMILY_SANS, 12, "bold")
    DEVICE_NAME = (FAMILY_SANS, 18, "bold")
    STAT_VALUE  = (FAMILY_SANS, 22, "bold")
    STAT_LABEL  = (FAMILY_SANS, 9)


# ============================================================
#  Animation Constants
# ============================================================

class Anim:
    """Timing and animation constants (all in milliseconds)."""
    PULSE_INTERVAL     = 800    # status dot pulse cycle
    HOVER_GLOW_MS      = 100    # hover transition
    SIDEBAR_EXPAND_MS  = 150    # sidebar accordion expand
    TOAST_DURATION     = 3000   # auto-dismiss toast after 3s
    TOAST_SLIDE_MS     = 200    # toast slide-in animation
    TAB_FADE_MS        = 100    # page transition
    PROGRESS_GLOW_MS   = 50     # progress bar glow tick
    QR_BOUNCE_MS       = 150    # QR code refresh bounce

    # Pulse opacity range (0.0 – 1.0 simulated via color)
    PULSE_DIM   = "#2a2a4a"
    PULSE_BRIGHT = None  # set to accent color at runtime


# ============================================================
#  Geometry Constants
# ============================================================

class Geo:
    """Layout geometry constants."""
    SIDEBAR_WIDTH_COLLAPSED = 56
    SIDEBAR_WIDTH_EXPANDED  = 200
    TITLEBAR_HEIGHT         = 38
    PANEL_CORNER_RADIUS     = 12
    BUTTON_CORNER_RADIUS    = 8
    ENTRY_CORNER_RADIUS     = 6
    TOGGLE_WIDTH            = 44
    TOGGLE_HEIGHT           = 22
    TOGGLE_DOT_RADIUS       = 8
    BADGE_CORNER_RADIUS     = 10
    ICON_SIZE               = 18
    APP_MIN_WIDTH           = 900
    APP_MIN_HEIGHT          = 640
    APP_DEFAULT_WIDTH       = 1080
    APP_DEFAULT_HEIGHT      = 720


# ============================================================
#  Mirror Quality Presets
# ============================================================

QUALITY_PRESETS = {
    "Low": {
        "resolution": "720p",
        "fps": "15",
        "bitrate": "2M",
        "desc": "720p · 15fps · 2 Mbps",
    },
    "Medium": {
        "resolution": "720p",
        "fps": "30",
        "bitrate": "4M",
        "desc": "720p · 30fps · 4 Mbps",
    },
    "High": {
        "resolution": "1080p",
        "fps": "60",
        "bitrate": "8M",
        "desc": "1080p · 60fps · 8 Mbps",
    },
    "Ultra": {
        "resolution": "Original",
        "fps": "Original",
        "bitrate": "50M",
        "desc": "Original · Original · 50 Mbps",
    },
}


# ============================================================
#  Sidebar Navigation Items
# ============================================================

NAV_ITEMS = [
    {"icon": "🏠", "label": "Dashboard",     "key": "dashboard"},
    {"icon": "📱", "label": "Devices",        "key": "devices"},
    {"icon": "⚡", "label": "Quick Actions",  "key": "quick_actions"},
    {"icon": "⚙️", "label": "Settings",       "key": "settings"},
    {"icon": "📋", "label": "Logs",           "key": "logs"},
    {"icon": "ℹ️", "label": "About",          "key": "about"},
]
