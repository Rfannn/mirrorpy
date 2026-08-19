# Changelog

All notable changes to MirrorPy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI/CD pipeline with GitHub Actions
- Automated releases with multi-platform builds (Windows, Linux)
- Security scanning with bandit in CI
- CHANGELOG.md for release documentation

### Changed
- Improved CI with pip caching and multi-platform matrix
- Enhanced release workflow with Linux support

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
