# SecureAI 3.0 Enhanced 🛡️

منصة أمن سيبراني احترافية | FastAPI + SQLite + JWT + PWA

## الميزات

- ✅ فحص أمان المواقع (Headers, Threats, AI Report)
- ✅ فحص 60+ منفذ مع Banner Grabbing وتلميحات الثغرات
- ✅ OWASP Top 10 Scanner
- ✅ كشف التسريبات (API Keys, JWT, AWS)
- ✅ تحليل DNS + فحص SSL
- ✅ Subdomain Enumeration
- ✅ Username Lookup عبر 18 منصة
- ✅ مراقبة مستمرة + تنبيهات
- ✅ لوحة Admin كاملة
- ✅ PWA - تثبيت كتطبيق على الهاتف
- ✅ دعم عربي / إنجليزي / فرنسي

## التشغيل المحلي

استخدام Python 3.11+:

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

افتح: http://localhost:8000/app/

## متغيرات البيئة

انسخ ملف `.env.example` إلى `.env`:

| المتغير | الوصف |
|---|---|
| SECUREAI_JWT_SECRET | مفتاح JWT (مطلوب - غيّره!) |
| SECUREAI_ADMIN_KEY | مفتاح لوحة Admin |
| SECUREAI_DB_PATH | مسار قاعدة البيانات |

## النشر على الإنترنت

### Railway (مجاني)
1. ارفع على GitHub
2. اربط بـ Railway
3. Start Command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`

### Heroku ($5/شهر)
```bash
heroku create my-secureai
heroku config:set SECUREAI_JWT_SECRET=my-secret
git push heroku main
```

### Docker
```bash
docker build -t secureai .
docker run -p 8000:8000 -e SECUREAI_JWT_SECRET=secret secureai
```

## لوحة Admin

```
Header: x-admin-key: مفتاحك

/admin/stats   - إحصائيات النظام
/admin/users   - قائمة المستخدمين
/admin/scans   - جميع الفحوصات
/admin/alerts  - جميع التنبيهات
```

## تحذير قانوني
هذه الأدوات للاختبار الأخلاقي المصرح به فقط.
