
### **SPECTRAL CORE**
*Remote-Driven Module Arsenal · Modular · Spectral · Relentless*

[![PyPI](https://img.shields.io/badge/python-%E2%89%A53.8-cyan?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MPL--2.0-purple?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.2.1--GRIMOIRE-pink?style=flat-square)](pyproject.toml)
[![Build](https://img.shields.io/badge/build-spectral%20core-blueviolet?style=flat-square)]()

[English](README.md) · **فارسی**

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
```

---

## 👻 Wraith — زیرسیستم C2 داخلی (از 3.2.2)

یک لایه‌ی C2 کامل که به‌شکل یک پکیج مستقل (`wraith/`) داخل همین مخزن زندگی می‌کند و
**موتور اکسپلویت هیچ‌وقت آن را import نمی‌کند**:

- **لیسنر تماماً async** — لوپ asyncio خودش روی ترد خودش، چندکاره‌سازی سشن بدون بلاک
- **پروتکل JSON روی WebSocket** — یک شیء در هر فریم؛ سقف فایل ۱۰ مگابایت در قطعه‌های ۲۵۶ کیلوبایتی
- **بیلدر همان ماژول است، نه کد فریم‌ورک** — فریم‌ورک صفر سورس پی‌لود و صفر کامپایلر دارد؛
  ماژول از نوع `payload` سورس‌های همراه خودش رو دارد و اسکریپتش پی‌لود را با هر زبانی
  (Go، Nim، C، Rust، C#، bash، python، …) می‌سازد، پروفایل لیسنر را امبد می‌کند و توی
  انبار تایپ‌دار ثبتش می‌کند
- **انبار پی‌لود تایپ‌دار** — هر باینیری با type (file-posix / shellcode / cmd / …) و مانیفست SHA-256
- **قرارداد تگ پروتکل** — لیسنر و پی‌لود باید یک تگ گویا مشترک داشته باشند (مثل `ws-json-async`)
  وگرنه با کد 4403 به هم وصل نمی‌شوند؛ پی‌لودی که تحت گویای دیگری ثبت شده باشد، هرگز یک فیلد فیلتر‌شده ماژول‌ها را پیدا نمی‌کند

```bash
eidolon ❯ c2 serve                    # لیسنر بالا می‌آید — token و endpoint تصادفی خودکار
eidolon ❯ use ghost-implant            # ماژول بیلدر پی‌لود — هر زبانی
eidolon ❯ run                          # پی‌لود ساخته و تایپ‌دار ثبت می‌شود
eidolon ❯ c2 payloads                 # انبار: name · type · protocol · backend · sha256
eidolon ❯ c2 sessions                 # جدول زنده‌ی سشن‌ها
eidolon ❯ c2 stop                     # خاموشی — موقع exit هم خودکار
```

هر پی‌لودی که وصل شود همان لحظه در کنسول گزارش می‌شود:

```
  ⬢ payload connected  5f8e12c2 · alice@corp-ws · go/linux-amd64 · 10.4.2.9:51515
```

ماژول‌های اکسپلویت دست آزاد کامل دارند (فایل خام، شل‌کد، دستور، هر ایده)، ولی
اگر از انبار پی‌لود بگیرند، فیلد اختصاصی کار را یک‌جا می‌کند: اعلان یک اپشن با
`"kind": "payload"` و تیپ‌های مجاز (`"types": (…)`) — فریم‌ورک موقع `set payload ghost-go`
ممیز می‌کند و تایپ ناهماهنگ جلوی روز درمی‌شود؛ موقع run هم به جای رشته، یک manifest dict با
`path` / `type` / `protocol` / `sha256` دریافت می‌کند. مسیر فایل خام هم همیشه مجاز است
(با تایپ `external`).

وابستگی جدید: `websockets>=11` (TLS اختیاری با `cryptography`).
