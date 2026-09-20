<p align="center">
  <img src="icon.png" width="120" alt="MirrorPy Logo">
</p>

<h1 align="center">📱 MirrorPy</h1>

<p align="center">
  <strong>One-click Android screen mirroring & control — powered by scrcpy</strong>
</p>

<p align="center">
  <a href="https://github.com/Rfannn/mirrorpy/actions"><img src="https://github.com/Rfannn/mirrorpy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Rfannn/mirrorpy/releases"><img src="https://img.shields.io/github/v/release/Rfannn/mirrorpy?include_prereleases" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.9+-yellow" alt="Python">
</p>

---

> **This repo now holds the Python implementation, kept for reference.**
> Development moved to the Rust rewrite at [Rfannn/mirror-rust](https://github.com/Rfannn/mirror-rust),
> which is faster to start, ships a single installer, and no longer needs Python.
> Everything below is the Python version, which still runs.

---

MirrorPy is a desktop GUI for [scrcpy](https://github.com/Genymobile/scrcpy) that mirrors and controls an Android phone from a PC. It finds devices over ADB mDNS, pairs with a QR code or a pairing code, and mirrors in one click. adb and scrcpy ship with the repo, so a clone runs without installing the Android SDK.

## Features

| Feature | Description |
|---------|-------------|
| Smart auto-detect | Finds Android devices through ADB mDNS, no manual IP entry |
| Quick Mirror | One button: detect, connect, mirror |
| QR code | Live QR encoding the `adb connect` string, ready to scan |
| Quality presets | Low, Medium, High and Ultra map to real scrcpy flags |
| Glass UI | Custom Canvas-drawn widgets with a dark and light theme |
| Device card | Phone model, address and connection status at a glance |
| Network scan | Ping sweep across the local subnet |
| USB and Wi-Fi | Works over a USB cable or wireless ADB |
| Quick actions | Screenshot, clipboard, file push, device info, ADB restart |
| Persistent config | Settings save to `settings.ini` next to the app |

## Quick start

### Prerequisites

- Windows 10/11, or Linux (experimental)
- Python 3.9 or newer
- An Android device with Developer Options enabled

adb and scrcpy are bundled in this repo, so there is nothing else to install.

### Install

```bash
git clone https://github.com/Rfannn/mirrorpy.git
cd mirrorpy
pip install -r requirements.txt
```

### Run

Double-click `MirrorPyGlass.exe` if you have it. Otherwise, from a clone:

```bash
python mirror_glass.py     # glass UI (the current interface)
python mirror.py           # classic ttkbootstrap interface
```

On Windows, `mirror_glass.bat` runs the glass UI and `mirror.bat` runs the
classic one. Both fall back to the Python on your PATH.

On Windows you can also double-click `mirror_glass.bat`.

## Usage

### One-click mirror

1. Enable Developer Options on the phone
2. Enable USB debugging or Wireless debugging
3. Click Quick Mirror

MirrorPy discovers the device, connects to it, and starts scrcpy.

### Manual connection

1. Click Detect to find the phone, or type the IP and port
2. Click Connect, then Mirror

### Pairing

Android 11 and newer usually need pairing before the first wireless connection:

1. On the phone, open Settings, Developer Options, Wireless debugging, Pair device
2. Enter the Pair port and Pairing code in MirrorPy
3. Click Pair

### Quality presets

The Settings page picks the streaming profile. Each preset maps to scrcpy flags:

| Preset | Resolution | Frame rate | Bitrate |
|--------|-----------|------------|---------|
| Low | 720 | 15 fps | 2 Mbps |
| Medium | 720 | 30 fps | 4 Mbps |
| High | 1080 | 60 fps | 8 Mbps |
| Ultra | device native | device native | 50 Mbps |

### Keyboard shortcuts

The window is frameless, so it handles these itself:

| Key | Action |
|-----|--------|
| Esc | Close |
| F11 | Toggle fullscreen |
| Ctrl+1 to Ctrl+6 | Jump to a page |

### Files and settings

`settings.ini`, `scrcpy_launcher.log`, and screenshots land next to the application, not in the directory you launched it from. Screenshots go to `screenshots/`.

## Architecture

```
mirrorpy/
├── legacy/                    # The Python implementation
│   ├── mirror_glass.py        # Glass UI entry point
│   ├── mirror.py              # Classic ttkbootstrap UI, plus the shared adb/scrcpy core
│   ├── ui/                    # Glass UI package
│   │   ├── theme.py           # Palette, fonts, geometry, quality presets
│   │   ├── glass_widgets.py   # Canvas-drawn button, toggle, slider, panel, badge
│   │   ├── title_bar.py       # Frameless title bar with drag support
│   │   ├── sidebar.py         # Expand-on-hover navigation
│   │   ├── dashboard.py       # Device card, connection controls, QR, log
│   │   ├── devices.py, quick_actions.py, settings_tab.py,
│   │   │   logs_tab.py, about_tab.py
│   │   └── toast.py, content_area.py
│   ├── test_mirror.py         # Unit tests, 38 cases
│   └── settings.ini           # Written at runtime
├── adb.exe, scrcpy.exe        # Bundled Android tooling, shared by both versions
├── scrcpy-server, *.dll       # scrcpy runtime
└── .github/workflows/         # ci.yml and release.yml
```

The binaries stay at the repository root because the Rust rewrite reuses the
same scrcpy distribution. Both versions resolve them from there.

### Key components

| Component | Purpose |
|-----------|---------|
| `full_discover()` | Combined ADB devices and mDNS discovery |
| `adb_mdns_discover()` | Device discovery through `adb mdns services` |
| `generate_qr_pil()` | QR generation for connection strings |
| `scrcpy_args()` | Quality preset to scrcpy command line |
| `bundled_tool()` | Prefers the bundled adb/scrcpy over PATH |
| `app_dir()` | Resolves where config, logs and binaries live |
| `MirrorPyGlass` | Glass UI application class |
| `get_palette()` / `set_theme()` | Shared palette, used by every page |

## Testing

```bash
python -m unittest test_mirror -v
```

Coverage: helper functions, ADB output parsing, mDNS discovery, QR generation, auto-detect preferring the phone IP over the laptop IP, config load and save, and thread safety.

## CI/CD

### CI

- flake8 linting, including a syntax gate that runs on the whole version matrix
- bandit security scan
- Unit tests on Windows and Linux
- Python 3.9, 3.10, 3.11, 3.12

### Releases

- Triggered by pushing a tag, for example `v2.1.0`
- Builds a Windows `.exe` per interface, with adb, scrcpy and the required DLLs bundled
- Attaches the executables to a GitHub Release

```bash
git tag v2.1.0
git push origin v2.1.0
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named ttkbootstrap` | `pip install -r requirements.txt` |
| `No module named qrcode` | `pip install -r requirements.txt` |
| Device not found | Enable USB or wireless debugging and stay on the same network |
| Auto-detect finds nothing | Run the bundled `adb.exe start-server` once |
| Pairing fails | Reopen the pairing dialog on the phone, the port changes each time |
| Clipboard read fails | Android 10 and newer restrict clipboard reads to the focused app |
| QR code not updating | Re-detect the device to refresh the address |

## License

Apache 2.0. See [LICENSE](LICENSE).

## Acknowledgments

- [scrcpy](https://github.com/Genymobile/scrcpy) by Genymobile
- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) for the classic UI
- [qrcode](https://github.com/lincolnloop/python-qrcode)

---

<p align="center">
  Made by <a href="https://github.com/Rfannn">Rfannn</a>
</p>

