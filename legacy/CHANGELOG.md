# Changelog

All notable changes to MirrorPy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Keyboard shortcuts for the frameless window: Esc closes, F11 toggles fullscreen, Ctrl+1 to Ctrl+6 switch pages
- `scrcpy_args()` builds the scrcpy command line from the selected quality preset
- `bundled_tool()` prefers the adb and scrcpy binaries shipped with the app over PATH
- `app_dir()` resolves config, logs and screenshots next to the application
- `get_palette()`, `set_theme()` and `set_accent()` give the UI one shared palette
- Working quick actions: screenshot, clipboard read, file push, device info
- Disabled state for buttons, used to mark the actions that are not implemented

### Changed
- Settings now apply for real: quality presets reach scrcpy, the accent picker and light/dark toggle recolor and rebuild the interface
- Light theme and accent presets were previously unreachable
- `settings.ini` and `scrcpy_launcher.log` are written next to the app instead of the working directory
- Config keys are lowercase to match how configparser stores them
- The dashboard prefills the last used address, and a successful connect updates it
- README documents the glass UI, its shortcuts, and the preset table

### Fixed
- The glass UI crashed on launch: custom widgets stored their size in `self._w` and `self._h`, which are tkinter's own Canvas attributes
- `mirror_glass.py` used a PEP 701 f-string, so Python 3.9 to 3.11 failed to parse it and CI failed on 8 of 8 test jobs
- Release builds did not bundle adb, scrcpy, or the DLLs scrcpy needs, so the executables could not mirror anything
- The `ui` package was added with a Windows-only path separator in the build
- Neither interface ever read its saved config: every lookup used a capitalised key, and configparser lowercases option names
- The classic interface passed its theme string straight to ttkbootstrap, which rejects the glass UI's `dark` and `light` values

## [2.0.0] - 2024-01-01

### Added
- ⚡ **Quick Mirror** — one-click detect → connect → mirror
- 🔍 **Smart Auto-Detect** — uses ADB mDNS to find real Android devices
- 📷 **QR Code** — live QR code for connection strings
- 🎨 **Redesigned UI** — device card, connection wizard, status indicators
- 🛡️ **Thread Safety** — all tkinter updates marshalled to main thread
- 🧪 **38 unit tests** — comprehensive test coverage

### Fixed
- Auto-detect no longer returns laptop IP instead of phone IP
- Config save no longer causes infinite recursion

## [1.0.0] - 2023-01-01

### Added
- Initial release
- Basic scrcpy launcher with USB/Wi-Fi support
- ttkbootstrap GUI
- Network subnet scan
