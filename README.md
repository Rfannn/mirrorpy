# MirrorPy

**MirrorPy** is a lightweight Android screen mirroring and control tool built on top of [scrcpy](https://github.com/Genymobile/scrcpy), featuring a clean Python GUI powered by [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap).  
It allows you to mirror and control your Android device on Windows via **USB or Wireless Debugging (ADB over Wi-Fi)** — all from a simple launcher.

---

## ✨ Features
- 📱 Real-time Android screen mirroring & control  
- 🌐 Supports both **USB** and **Wireless (ADB over Wi-Fi)** connections  
- 🎨 Modern Python GUI with ttkbootstrap  
- ⚡ Portable: works with **embeddable Python** (no full Python install required)  
- 🖱️ One-click `.bat` launcher for ease of use  

---

## 📦 Requirements
- **Windows** (tested)  
- **scrcpy + ADB binaries** (already included in `mirror/` folder)  
- **Python 3.8+** (standard or [embeddable distribution](https://docs.python.org/3/using/windows.html#embedded-distribution))  

### Python Dependencies
Install required packages with:
```sh
pip install -r requirements.txt
```

Main package:
- `ttkbootstrap`

---

## ⚙️ Setup

1. Clone or download this repository.  
2. On your Android device:  
   - Enable **Developer Options**  
   - Turn on **USB Debugging** (and **Wireless Debugging** if you want Wi-Fi mode)  
3. If using Wi-Fi mode for the first time:  
   - Connect your phone via USB once  
   - Run:  
     ```sh
     adb tcpip 5555
     adb connect <PHONE_IP>:5555
     ```  
   - After that, USB is no longer required.  
4. Launch the app with:  
   ```sh
   launch_mirror.bat
   ```

---

## 🚀 Usage
- Choose **USB** or **Wi-Fi** connection in the launcher  
- Start mirroring instantly with scrcpy  
- Works completely offline (LAN only, no external servers)  

---

## 🛠 Troubleshooting
- **`Python not found`** → Install Python 3.8+ or use embeddable Python in the `mirror/python/` folder.  
- **`No module named ttkbootstrap`** → Install manually:  
  ```sh
  python -m pip install ttkbootstrap
  ```  
- **ADB device not found (Wi-Fi)** → Ensure phone & PC are on the same Wi-Fi network, and Wireless Debugging is enabled.  

---

.
