# SecureAI 3.0

منصة أمن سيبراني مبنية على **FastAPI + SQLite + JWT + PWA** مع أدوات اختبار أخلاقي وتنبيهات مجانية.

## الميزات المضافة

1. 🌍 دعم متعدد اللغات: العربية + الإنجليزية + الفرنسية
2. 📧 إرسال التقارير عبر Email باستخدام `smtplib`
3. 🤖 Telegram Bot للتنبيهات
4. 🔗 Discord/Slack Webhooks مجانية
5. 🗄️ قاعدة بيانات SQLite لحفظ السجلات والتنبيهات والمراقبة
6. 🔐 نظام مصادقة JWT بحسابات مستخدمين
7. 📱 PWA Mobile App قابل للتثبيت على الهاتف
8. 🌐 Subdomain Enumeration
9. 🐛 OWASP Top 10 Scanner
10. 📊 تصدير CSV/JSON للتقارير

## هيكل المشروع

```text
SecureAI/
├── backend/
│   ├── main.py
│   ├── auth.py
│   ├── db.py
│   ├── notifications.py
│   ├── scanner.py
│   ├── threats.py
│   ├── tools.py
│   ├── alerts.py
│   └── requirements.txt
└── frontend/
    ├── index.html
    ├── manifest.json
    ├── service-worker.js
    └── secureai-icon.svg
```

## التشغيل الآن

### 1) تثبيت المتطلبات
```bash
cd backend
pip install -r requirements.txt
```

### 2) تشغيل الخادم
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3) فتح الواجهة
افتح:

```text
http://localhost:8000/app/
```

> لا تفتح `index.html` مباشرة من الملفات إذا أردت الـPWA أو الـService Worker. افتحه من خلال الخادم.

## حسابات المستخدمين

- أنشئ حساباً من الواجهة
- سيتم حفظ الحسابات في SQLite داخل `backend/secureai.db`
- جميع عمليات الفحص والـmonitoring ستكون مرتبطة بالمستخدم الحالي

## إعداد الإشعارات

من تبويب **الإشعارات** داخل الواجهة يمكنك إعداد:

- Telegram Bot Token + Chat ID
- Discord Webhook URL
- Slack Webhook URL
- SMTP Host/Port/User/Password/Sender

## تحويله لتطبيق على الهاتف

### Android
1. افتح `http://YOUR-IP:8000/app/` من Chrome على الهاتف
2. اختر **Add to Home Screen** أو **Install App**

### iPhone
1. افتح الرابط من Safari
2. اضغط **Share**
3. اختر **Add to Home Screen**

> إذا كنت تشغل المشروع محلياً على الكمبيوتر، استخدم عنوان الشبكة المحلية مثل `http://192.168.1.10:8000/app/` بدل `localhost` عند الفتح من الهاتف.

## أهم نقاط النهاية

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `GET /stats`
- `POST /scan`
- `POST /scan/full`
- `POST /tools/subdomains`
- `POST /tools/owasp`
- `POST /reports/email`
- `GET /reports/export?format=json`
- `GET /reports/export?format=csv`
- `POST /settings/notifications`

## تنبيه قانوني

هذه الأدوات للاختبار الأخلاقي المصرح به فقط. لا تستخدمها على أي هدف بدون تصريح صريح.
