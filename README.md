
### **SPECTRAL CORE**
*Remote-Driven Module Arsenal · Modular · Spectral · Relentless*

[![PyPI](https://img.shields.io/badge/python-%E2%89%A53.8-cyan?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MPL--2.0-purple?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.2.1--GRIMOIRE-pink?style=flat-square)](pyproject.toml)
[![Build](https://img.shields.io/badge/build-spectral%20core-blueviolet?style=flat-square)]()

</div>

---

## 🌌 چیه این؟

**Eidolon** یه فریم‌ورک **ماژولار، ریموت‌محور** برای مدیریت و اجرای ماژول‌های امنیتی/اتوماسیونه.
به جای اینکه ده‌تا اسکریپت پراکنده داشته باشی، همه‌چیز یه جا جمعه:

- 🛰️ **Repositories از راه دور** — ماژول‌ها رو از چند ریموت (با اولویت‌بندی) بکش
- 📦 **نصب خودکار** — tar / tar.zst / git clone
- 🧩 **سیستم ماژول** — هر `.py` که `run(opts)` و `OPTIONS` داشته باشه، ماژوله
- 🎛️ **CLI تعاملی** — با autocomplete، prompt زنده، جدول‌های رنگی، session tracking
- 💾 **Persistence** — globals و sessionها توی SQLite ذخیره می‌شن
- 🎨 **خروجی رنگی** — True-color ANSI، بنر گرادیانتی، کاراکترهای یونیکد

---

## ⚡ نصب

### از منبع (توصیه‌شده)
```bash
git clone https://github.com/null-flame/Eidolon.git
cd Eidolon
pip install .
```

یا

```bash
pip install eidolon-core
