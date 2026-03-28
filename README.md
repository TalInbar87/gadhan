# 🪖 מערכת ניהול ציוד — Equipment Management System

מערכת ווב לניהול קבלת/השבת ציוד צבאי: נשק, אמצעי ראיית לילה, ציוד קשר ועוד.
מבוססת על **Google Apps Script** כ-Backend ו-**Google Sheets** כבסיס נתונים.

---

## ✨ יכולות המערכת

| מודול | תיאור |
|-------|--------|
| 🔫 **קבלת נשק** | טופס קבלת נשק + 58 פריטי ציוד נלווה עם חתימה דיגיטלית |
| 📻 **קבלת קשר** | טופס קבלת ציוד קשר עם חתימה דיגיטלית |
| 🔄 **העברה / זיכוי / ראש-בראש / איפסון** | העברת ציוד בין חיילים, זיכוי מלא/חלקי, השוואה, ואיפסון לגיליון נפרד |
| 📦 **סיכום מלאי נשקים** | טבלה חיה: כל 58 פריטים × כל מסגרת + חיפוש לפי מספר מוצר |
| 📋 **ספירת מלאי נשקייה** | GUI לספירת מלאי פיזי עם היסטוריה (מנהל בלבד) |
| 👤 **ניהול משתמשים** | הוספה/עריכה/מחיקה של משתמשים ותפקידים |
| 📊 **דוחות** | צפייה בכל הרשומות, סינון וייצוא |
| 📋 **יומן ביקורת** | תיעוד כל הפעולות במערכת עם timestamps |
| 💾 **גיבוי אוטומטי** | גיבוי יומי (08:00 + 21:00) לכל ה-Sheets כ-Excel ב-Google Drive |

---

## 🏗️ ארכיטקטורה

```
┌──────────────────────────────────────────────────────────────┐
│                        Frontend (HTML)                       │
│  index-secure    │  weapons-checkout  │  radio-checkout      │
│  weapons-transfer│  weapons-inventory │  armory-count        │
│  user-management │  audit-log                                │
│─────────────────────────────────────────────────────────────│
│                      auth-client.js                          │
│              SecureAuthClient + AuthGuard (JWT)              │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS — URLSearchParams POST
                            ▼
┌──────────────────────────────────────────────────────────────┐
│               Google Apps Script (Backend)                   │
│  Main.js  │  Auth.js  │  Weapons.js  │  Radio.js            │
│  Armory.js│  Backup.js│  Utils.js    │  Config.js           │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                  Google Sheets (Database)                    │
│  משתמשים │ יומן ביקורת │ נשקים │ קשר │ נשקייה              │
└──────────────────────────────────────────────────────────────┘
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
שלב 3 — הגדרת 5 גיליונות Google Sheets (כולל נשקייה)
שלב 4 — יצירת מפתח אבטחה JWT
שלב 5 — העלאת הקוד ל-Google (clasp push + deploy)
שלב 6 — יצירת .env ו-config.js
שלב 7 — הגדרת Hosting (Netlify / Vercel / סטטי)
שלב 8 — הפעלת גיבוי אוטומטי (backup_setupTriggers)
```

---

## ⚙️ הגדרת גיבוי אוטומטי (פעם אחת)

לאחר הפריסה הראשונית, יש להפעיל את הטריגרים ב-GAS Editor **פעם אחת**:

1. פתח [GAS Editor](https://script.google.com) ← בחר את הפרויקט
2. ב-Triggers (⏰) ← Add Trigger:
   - Function: `backup_morning` | Time-driven | Every day | Hour 8
3. Add Trigger נוסף:
   - Function: `backup_evening` | Time-driven | Every day | Hour 21

גיבויים נשמרים ב-Drive תחת: `גיבוי / DD.MM.YYYY / גיבוי בוקר|ערב - [שם גיליון].xlsx`

---

## 🔐 אבטחה

- **JWT Authentication** — כל בקשה מאומתת עם טוקן חתום (תוקף: שעה)
- **תפקידים והרשאות** — admin / sergeant
- **אין סודות בקוד** — כל הערכים הרגישים ב-`.env` (gitignored)
- **HTTPS בלבד** — כל התקשורת מוצפנת

### תפקידים

| תפקיד | הרשאות |
|--------|--------|
| `admin` | הכל — כולל ניהול משתמשים, דוחות, ספירת מלאי נשקייה |
| `sergeant` | קריאה, כתיבה, דוחות, העברות — ללא ניהול משתמשים / נשקייה |

---

## 🗂️ מבנה הפרויקט

```
gadhan/
├── 📄 index.html                      # דף כניסה
├── 📄 index-secure.html               # דשבורד ראשי (לפי תפקיד)
├── 📄 weapons-checkout-secure.html    # קבלת נשק + ציוד נלווה
├── 📄 radio-checkout-secure.html      # קבלת ציוד קשר
├── 📄 weapons-transfer.html           # העברה / זיכוי / ראש-בראש / איפסון
├── 📄 weapons-inventory.html          # סיכום מלאי נשקים + חיפוש מוצר
├── 📄 armory-count.html               # ספירת מלאי נשקייה (מנהל בלבד)
├── 📄 user-management.html            # ניהול משתמשים
├── 📄 audit-log.html                  # יומן ביקורת
├── 📄 auth-client.js                  # ספריית אימות (SecureAuthClient + AuthGuard)
│
├── 🔧 init.sh                         # אשף התקנה ראשוני
├── 🔧 deploy.sh                       # פריסה + commit + push
├── 🔧 build.sh                        # יצירת config.js
│
├── 📁 appScripts/unified/
│   ├── Main.js                        # ניתוב כל הבקשות (doPost / doGet)
│   ├── Auth.js                        # אימות JWT + ניהול משתמשים
│   ├── Weapons.js                     # מודול נשק (58 פריטים)
│   ├── Radio.js                       # מודול קשר
│   ├── Armory.js                      # מודול ספירת מלאי נשקייה
│   ├── Backup.js                      # גיבוי אוטומטי ל-Drive
│   ├── Config.js                      # קונפיגורציה (gitignored)
│   ├── Utils.js                       # פונקציות עזר משותפות
│   └── appsscript.json               # הגדרות GAS (scopes, timezone)
│
├── 📄 .env                            # סודות (gitignored)
├── 📄 config.js                       # URL ציבורי (gitignored, נוצר אוטומטית)
├── 📄 LEARNING.md                     # מסמך ידע — כל הפונקציות והמבנים
├── 📄 netlify.toml                    # הגדרות Netlify
└── 📄 vercel.json                     # הגדרות Vercel
```

---

## 🔄 תהליך עבודה יומיומי

```bash
# ערוך קבצים...
# ואז:
bash deploy.sh
```

הסקריפט יבצע אוטומטית:
- ✅ הזרקת ערכי `.env` ל-`Config.js`
- ✅ `clasp push` אם היו שינויים ב-GAS
- ✅ עדכון deployment חדש
- ✅ `git commit + push`

---

## ☁️ Hosting

| אפשרות | הגדרה |
|--------|-------|
| **Netlify** | חבר GitHub repo ← הוסף `GAS_URL` ב-Environment Variables |
| **Vercel** | חבר GitHub repo ← הוסף `GAS_URL` ב-Environment Variables |
| **סטטי** | העלה את כל קבצי ה-HTML + `config.js` לשרת |

---

## 📚 תיעוד מפורט

ראה [`LEARNING.md`](./LEARNING.md) — מסמך ידע מלא לכל מפתח/תהליך חדש.

---

## 📝 רישיון

פרויקט זה מיועד לשימוש פנים-ארגוני. ניתן לשכפל ולהתאים לצרכים שלך.
