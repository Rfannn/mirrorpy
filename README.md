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
  <img src="https://img.shields.io/badge/python-3.8+-yellow" alt="Python">
</p>

---

MirrorPy is a lightweight desktop GUI for [scrcpy](https://github.com/Genymobile/scrcpy) that makes mirroring your Android phone to your PC effortless. It features **automatic device discovery** via ADB mDNS, **QR code pairing**, and a **one-click Quick Mirror** button — no command line needed.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Smart Auto-Detect** | Discovers Android devices via ADB mDNS — no manual IP entry needed |
| ⚡ **Quick Mirror** | One button: detect → connect → mirror in seconds |
| 📷 **QR Code** | Live QR code encodes `adb connect` string for easy sharing |
| 🎨 **Modern UI** | Clean ttkbootstrap interface with dark/light themes |
| 📱 **Device Card** | Shows phone model, IP, and connection status at a glance |
| 🌐 **Network Scan** | Ping sweep to find devices on your subnet |
| 🔗 **USB & Wi-Fi** | Supports both USB debugging and wireless ADB over Wi-Fi |
| 🛡️ **Thread-Safe** | All background operations are marshalled to the UI thread |
| 📋 **ADB Devices** | Dropdown list with one-click device selection |
| 💾 **Persistent Config** | Settings saved automatically between sessions |

## 🚀 Quick Start

### Prerequisites

- **Windows 10/11** (tested), Linux/macOS (experimental)
- **Python 3.8+** ([download](https://www.python.org/downloads/))
- **Android device** with Developer Options enabled
- **ADB & scrcpy** binaries (included in this repo)

### Install

```bash
git clone https://github.com/Rfannn/mirrorpy.git
cd mirrorpy
pip install -r requirements.txt
```

### Run

```bash
python mirror.py
```

Or double-click `mirror.bat` if using the embedded Python distribution.

## 📖 Usage

### One-Click Mirror (Recommended)

1. Enable **Developer Options** on your Android phone
2. Enable **USB Debugging** or **Wireless Debugging**
3. Click **⚡ Quick Mirror** — that's it!

MirrorPy will automatically:
- Discover your device via ADB mDNS
- Connect to it
- Launch scrcpy for screen mirroring

### Manual Connection

1. Click **🔍 Detect Device** to find your phone
2. Or enter the IP:port manually
3. Click **🔌 Connect**, then **▶ Mirror**

### Pairing (Wireless Debugging)

If your phone requires pairing (Android 11+):
1. Go to **Settings → Developer Options → Wireless Debugging → Pair device**
2. Enter the **Pair Port** and **Pairing Code** in MirrorPy
3. Click **🤝 Pair**

## 🏗️ Architecture

```
mirrorpy/
├── mirror.py              # Main application (GUI + logic)
├── test_mirror.py         # Unit tests (38 tests)
├── requirements.txt       # Python dependencies
├── settings.ini           # User configuration (gitignored)
├── .gitignore
├── adb.exe                # ADB binary (included)
├── scrcpy.exe             # scrcpy binary (included)
├── python/                # Embedded Python (optional)
└── .github/
    └── workflows/
        ├── ci.yml         # CI: lint + test
        └── release.yml    # Release automation
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `full_discover()` | Combined ADB devices + mDNS discovery |
| `adb_mdns_discover()` | Discover devices via `adb mdns services` |
| `generate_qr_pil()` | Generate QR codes for connection strings |
| `ScrcpyLauncher` | Main GUI application class |
| `DeviceCard` | Widget showing detected device info |
| `GuiLogger` | Thread-safe scrolling log widget |

## 🧪 Testing

```bash
# Run all tests
python -m unittest test_mirror -v

# Run specific test class
python -m unittest test_mirror.TestFullDiscover -v
```

Tests cover:
- Helper functions (get_local_ip, ping_host, run_cmd)
- ADB device parsing and mDNS discovery
- QR code generation
- Auto-detect returns phone IP (not laptop IP)
- Config save/load
- Thread safety

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/Rfannn/mirrorpy.git
cd mirrorpy
pip install -r requirements.txt
python -m unittest test_mirror -v
```

### Code Style

- Python 3.8+
- Follow existing conventions
- Add tests for new features
- Keep commits atomic and well-described

## 📋 Changelog

### v2.0.0 (Latest)
- ⚡ **Quick Mirror** — one-click detect → connect → mirror
- 🔍 **Smart Auto-Detect** — uses ADB mDNS to find real Android devices
- 📷 **QR Code** — live QR code for connection strings
- 🎨 **Redesigned UI** — device card, connection wizard, status indicators
- 🛡️ **Thread Safety** — all tkinter updates marshalled to main thread
- 🧪 **38 unit tests** — comprehensive test coverage

### v1.0.0
- Initial release
- Basic scrcpy launcher with USB/Wi-Fi support
- ttkbootstrap GUI
- Network subnet scan

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `Python not found` | Install Python 3.8+ and add to PATH |
| `No module named ttkbootstrap` | Run `pip install ttkbootstrap` |
| `scrcpy not found` | Ensure `scrcpy.exe` is in the project folder or on PATH |
| `ADB device not found` | Enable USB/Wireless Debugging; same Wi-Fi network |
| Auto-detect finds nothing | Check ADB server: run `adb start-server` manually |
| QR code not updating | Re-detect the device to refresh IP/port |

## 📄 License

This project is licensed under the Apache License 2.0 — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [scrcpy](https://github.com/Genymobile/scrcpy) by Genymobile — the mirroring engine
- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) — modern tkinter themes
- [qrcode](https://github.com/lincolnloop/python-qrcode) — QR code generation

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/Rfannn">Rfannn</a>
</p>
