# 🪖 מערכת ניהול ציוד — Equipment Management System

מערכת ווב לניהול קבלת/השבת ציוד צבאי: נשק, אמצעי ראיית לילה, ציוד קשר ועוד.
מבוססת על **Google Apps Script** כ-Backend ו-**Google Sheets** כבסיס נתונים.

---

## ✨ יכולות המערכת

| מודול | תיאור |
|-------|--------|
| 🔫 **קבלת נשק** | טופס קבלת נשק + ציוד נלווה עם חתימה דיגיטלית |
| 📻 **קבלת קשר** | טופס קבלת ציוד קשר עם חתימה דיגיטלית |
| 🔄 **העברה/זיכוי** | זיכוי ציוד — מלא או חלקי — עם PDF מצורף למייל |
| 👤 **ניהול משתמשים** | הוספה/עריכה/מחיקה של משתמשים ותפקידים |
| 📊 **דוחות** | צפייה בכל הרשומות, סינון וייצוא |
| 📋 **יומן ביקורת** | תיעוד כל הפעולות במערכת עם timestamps |

---

## 🏗️ ארכיטקטורה

```
┌─────────────────────────────────────────────────────┐
│                   Frontend (HTML)                   │
│  index.html  │  weapons  │  radio  │  management   │
│              └──────────────────────────────────────│
│                    auth-client.js                   │
│              JWT Authentication + API calls         │
└────────────────────────┬────────────────────────────┘
                         │ HTTPS
                         ▼
┌─────────────────────────────────────────────────────┐
│            Google Apps Script (Backend)             │
│   Auth.js │ Weapons.js │ Radio.js │ Main.js        │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              Google Sheets (Database)               │
│  משתמשים │ יומן ביקורת │ נשקים │ קשר              │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 התקנה מהירה

### דרישות מוקדמות

| כלי | גרסה מינימלית | הורדה |
|-----|--------------|-------|
| Git | כלשהי | [git-scm.com](https://git-scm.com) |
| Node.js | 16+ | [nodejs.org](https://nodejs.org) |
| Python | 3.x | [python.org](https://python.org) |

> **Windows?** התקן [Git for Windows](https://git-scm.com/download/win), לחץ ימני על התיקייה ← **"Git Bash Here"**

### הוראות

```bash
# 1. הורד את הפרויקט
git clone https://github.com/TalInbar87/gadhan.git
cd gadhan

# 2. הרץ את אשף ההתקנה
bash init.sh
```

האשף ינחה אותך שלב אחר שלב בכל ההגדרות. ⏱️ כ-10-15 דקות.

---

## 📋 מה האשף עושה

```
שלב 1 — כניסה לחשבון Google (clasp login)
שלב 2 — יצירת / חיבור פרויקט Google Apps Script
שלב 3 — הגדרת 4 גיליונות Google Sheets
שלב 4 — יצירת מפתח אבטחה JWT
שלב 5 — העלאת הקוד ל-Google (clasp push + deploy)
שלב 6 — יצירת .env ו-config.js
שלב 7 — הגדרת Hosting (Netlify / Vercel / סטטי)
```

---

## 🔐 אבטחה

- **JWT Authentication** — כל בקשה מאומתת עם טוקן חתום
- **תפקידים והרשאות** — Admin / Operator / Viewer / User
- **אין סודות בקוד** — כל הערכים הרגישים ב-`.env` (gitignored)
- **HTTPS בלבד** — כל התקשורת מוצפנת

### תפקידים

| תפקיד | הרשאות |
|--------|--------|
| `admin` | הכל — כולל ניהול משתמשים ודוחות |
| `operator` | קריאה, כתיבה, צפייה בדוחות |
| `viewer` | קריאה + צפייה בדוחות בלבד |
| `user` | כתיבה בלבד (הגשת טפסים) |

---

## 🗂️ מבנה הפרויקט

```
gadhan/
├── 📄 index.html                  # דף כניסה
├── 📄 index-secure.html           # דשבורד ראשי
├── 📄 weapons-checkout-secure.html # קבלת נשק
├── 📄 radio-checkout-secure.html  # קבלת קשר
├── 📄 weapons-transfer.html       # העברה / זיכוי
├── 📄 user-management.html        # ניהול משתמשים
├── 📄 audit-log.html              # יומן ביקורת
├── 📄 auth-client.js              # ספריית אימות
│
├── 🔧 init.sh                     # אשף התקנה ראשוני
├── 🔧 deploy.sh                   # פריסה מקומית
├── 🔧 build.sh                    # יצירת config.js
│
├── 📁 appScripts/unified/
│   ├── Auth.js                    # אימות והרשאות
│   ├── Main.js                    # ניתוב בקשות
│   ├── Weapons.js                 # מודול נשק
│   ├── Radio.js                   # מודול קשר
│   ├── Config.js                  # קונפיגורציה (gitignored)
│   └── Utils.js                   # פונקציות עזר
│
├── 📄 .env                        # סודות (gitignored)
├── 📄 config.js                   # URL (gitignored, נוצר אוטומטית)
├── 📄 netlify.toml                # הגדרות Netlify
└── 📄 vercel.json                 # הגדרות Vercel
```

---

## 🔄 תהליך עבודה יומיומי

לאחר ההתקנה הראשונית, לכל שינוי עתידי:

```bash
# ערוך קבצים...
# ואז:
./deploy.sh
```

הסקריפט יבצע אוטומטית:
- ✅ הזרקת ערכי `.env` ל-`Config.js`
- ✅ `clasp push` אם היו שינויים ב-GAS
- ✅ עדכון deployment אם ה-URL השתנה
- ✅ `git commit + push`

---

## ☁️ Hosting

המערכת תומכת בשלוש אפשרויות:

| אפשרות | הגדרה |
|--------|-------|
| **Netlify** | חבר GitHub repo ← הוסף `GAS_URL` ב-Environment Variables |
| **Vercel** | חבר GitHub repo ← הוסף `GAS_URL` ב-Environment Variables |
| **סטטי** | העלה את כל קבצי ה-HTML + `config.js` לשרת |

---

## 📝 רישיון

פרויקט זה מיועד לשימוש פנים-ארגוני. ניתן לשכפל ולהתאים לצרכים שלך.
