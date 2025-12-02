# 🛡️ RebelVPN Pro
<a href="https://github.com/Arianlavi/RebelVPN-Pro/releases/download/v1.2.0/V1.2.zip">
  <img src="https://img.shields.io/badge/Download_RebelVPN_Pro-v1.2.0-0099ff?style=for-the-badge&logo=windowsterminal&logoColor=white" alt="Download RebelVPN Pro"/>
</a>

![RebelVPN Pro](screenshot.png)


**Powerful, Modern & Open-Source VPN Client for Windows**  
**کلاینت وی پی ان قدرتمند، مدرن و متن‌ باز برای ویندوز**

Supports **Xray** and **Sing-box** natively • Built for speed and privacy  
پشتیبانی کامل و مستقیم از (Xray و Sing-box)

[![Version](https://img.shields.io/github/v/release/Arianlavi/RebelVPN-Pro?label=Version&color=blue)](https://github.com/Arianlavi/RebelVPN-Pro/releases)
[![Downloads](https://img.shields.io/github/downloads/Arianlavi/RebelVPN-Pro/total?color=success)](https://github.com/Arianlavi/RebelVPN-Pro/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-brightgreen)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/github/license/Arianlavi/RebelVPN-Pro?color=orange)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Arianlavi/RebelVPN-Pro?style=social)](https://github.com/Arianlavi/RebelVPN-Pro/stargazers)

---

## ✨ Features | ویژگی‌ ها

| Feature | توضیحات |
|--------|--------|
| 🔌 **Multiple Protocols** | VLESS • VMess • Trojan • Shadowsocks • SOCKS |
| 🚀 **Sing-box & Xray Native** | Run Sing-box/Xray configs directly without conversion |
| ⚡ **Ultra-Fast Connection** | Automatic lowest-latency server selection |
| 🌐 **System Proxy Integration** | Automatically sets Windows proxy on connect |
| 📊 **Real-time Traffic Monitor** | Live upload/download speed & data usage |
| 🎨 **Modern Dark UI** | Built with CustomTkinter – clean and intuitive |
| 🔍 **Smart Search & Filter** | Quickly find servers by name or tag |
| 📱 **Subscription Support** | Import from URL, Google Drive, or manual config |
| 💾 **Auto-save Everything** | Never lose your configs again |

---

## 📥 Download | دانلود

### Latest Version (Recommended)
[![Download RebelVPN Pro](https://img.shields.io/github/v/release/Arianlavi/RebelVPN-Pro?color=0099ff&label=Download%20Latest&logo=github)](https://github.com/Arianlavi/RebelVPN-Pro/releases/download/v1.2.0/V1.2.zip)

> No installation required • Just download and run  
> بدون نیاز به نصب • فقط دانلود کنید و اجرا کنید

---

## 🚀 Quick Start | راه‌ اندازی سریع

### Method 1: Portable EXE (Recommended)
1. Download from the button above ↑
2. Run `RebelVPN-Pro.exe` (as Administrator recommended)
3. Enjoy!

### Method 2: Run from Source
```bash
git clone https://github.com/Arianlavi/RebelVPN-Pro.git
cd RebelVPN-Pro

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

# Place xray.exe and sing-box.exe in folder
python main.py
```

### Method 3: Build Your Own EXE
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=resources/icon.ico --name "RebelVPN-Pro" main.py
# Then copy xray.exe and sing-box.exe into dist/
```

---

## 🛠️ Requirements | پیش‌ نیازها

- **OS**: Windows 10 / 11 (64-bit)
- **Python**: 3.8+ (only if running from source)
- **Cores** (required):
  - [Xray-core](https://github.com/XTLS/Xray-core/releases)
  - [sing-box](https://github.com/SagerNet/sing-box/releases)

> Just drop `xray.exe` and `sing-box.exe` into the folder

---

## 🤝 Contributing | مشارکت

We welcome contributions! Here's how you can help:

```bash
git clone https://github.com/Arianlavi/RebelVPN-Pro.git
git checkout -b feature/your-amazing-feature
# Make your changes
git commit -m "feat: add amazing feature"
git push origin feature/your-amazing-feature
```

Then open a Pull Request!

### Wanted Features
- [ ] Light/Dark mode toggle
- [ ] System tray icon & minimize to tray
- [ ] Built-in speed test
- [ ] Multiple profiles support
- [ ] Subscription with authentication

---

## ❓ FAQ | سوالات متداول

**Q: Why won't it start?**  
A: Make sure `xray.exe` and `sing-box.exe` are in the folder.

**Q: Connection failed?**  
A: Run as **Administrator** • Check `app.log` • Ensure ports 10808-10809 are free.

**Q: Is it safe?**  
A: **100% Open Source** • No telemetry • No external connections • Auditable code.

---

## 📄 License | مجوز

Released under the **MIT License** — free for personal and commercial use.  
See [LICENSE](LICENSE) for details.

---

## 👨‍💻 Contact | تماس

- GitHub: [@Arianlavi](https://github.com/Arianlavi)
- Telegram: [@Rebeldevx](https://t.me/@rebeldevx)

---

<div align="center">

**Made with ❤️ for free internet — برای اینترنت آزاد**

<br/>

[![Star History](https://api.star-history.com/svg?repos=Arianlavi/RebelVPN-Pro&type=Date)](https://star-history.com/Arianlavi/RebelVPN-Pro)

**اگر این پروژه براتون مفید بود، لطفا یک ستاره ⭐ بزنید!**

<br/>


</div>
