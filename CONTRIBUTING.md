# Contributing to MirrorPy

Thank you for your interest in contributing to MirrorPy! This document provides guidelines and instructions for contributing.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Git
- ADB (Android Debug Bridge)
- An Android device for testing

### Setup

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/mirrorpy.git
cd mirrorpy

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m unittest test_mirror -v
```

## 📝 How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/Rfannn/mirrorpy/issues) first
2. Open a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - OS, Python version, Android version
   - Screenshots if applicable

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and use case
3. Explain why it would benefit users

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your feature/fix:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes** following the code style below
4. **Add tests** for new functionality
5. **Run tests** to ensure nothing is broken:
   ```bash
   python -m unittest test_mirror -v
   ```
6. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add amazing feature"
   ```
7. **Push** to your fork:
   ```bash
   git push origin feature/amazing-feature
   ```
8. **Open a Pull Request**

## 🎯 Code Style

### Python

- Follow PEP 8
- Use type hints where practical
- Keep functions focused and under 50 lines
- Add docstrings for public functions

```python
def discover_devices(timeout: int = 5) -> list[dict]:
    """
    Discover Android devices on the network.
    
    Args:
        timeout: Discovery timeout in seconds
        
    Returns:
        List of device dicts with keys: serial, ip, port, model
    """
    ...
```

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `test:` — Adding tests
- `refactor:` — Code refactoring
- `chore:` — Maintenance

Examples:
```
feat: add QR code generation for pairing
fix: auto-detect returns laptop IP instead of phone
test: add tests for mDNS discovery
docs: update README with installation guide
```

### Pull Requests

- Keep PRs focused on one change
- Reference related issues (e.g., `Fixes #42`)
- Update documentation if needed
- Add tests for new features
- Ensure all tests pass

## 🧪 Testing

### Running Tests

```bash
# All tests
python -m unittest test_mirror -v

# Specific test class
python -m unittest test_mirror.TestFullDiscover -v

# With coverage (install coverage first: pip install coverage)
coverage run -m unittest test_mirror
coverage report
```

### Writing Tests

- Place tests in `test_mirror.py`
- Use `unittest.mock` for external dependencies (ADB, network)
- Test both success and failure cases
- Keep tests fast and isolated

```python
class TestNewFeature(unittest.TestCase):
    @patch("mirror.run_cmd")
    def test_feature_works(self, mock_cmd):
        mock_cmd.return_value = ("success", "", 0)
        result = new_feature()
        self.assertEqual(result, "expected")
```

## 🏗️ Project Structure

```
mirrorpy/
├── mirror.py              # Main application
├── test_mirror.py         # Unit tests
├── requirements.txt       # Dependencies
├── settings.ini           # User config (gitignored)
├── .github/workflows/     # CI/CD
└── README.md              # Documentation
```

## ❓ Questions?

Open an issue with the `question` label or start a [Discussion](https://github.com/Rfannn/mirrorpy/discussions).

## 📜 License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
