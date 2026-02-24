# 🎖️ גדחה"ו קומנדו 8219 - מערכת ניהול ציוד

מערכת מקוונת לניהול חתימה על נשקים וציוד קשר עם אבטחה מלאה.

## 📁 מבנה הפרויקט

```
gadhan/
├── index.html                          # דף התחברות
├── index-secure.html                   # דף הבית (אחרי התחברות)
├── weapons-checkout-secure.html        # מערכת חתימה על נשקים
├── radio-checkout-secure.html          # מערכת חתימה על קשר
├── user-management.html                # ניהול משתמשים
├── audit-log.html                      # יומן ביקורת
├── auth-client.js                      # ספריית Authentication
│
├── appScripts/                         # Google Apps Scripts
│   ├── permissionsAppScript-clean.js   # מערכת אבטחה והרשאות
│   ├── weaponAppScript-clean.js        # סקריפט נשקים
│   └── radioAppScript-clean.js         # סקריפט קשר
│
├── .github/workflows/
│   └── deploy.yml                      # GitHub Actions - Deploy אוטומטי
│
├── deploy.sh                           # Deploy ידני
└── GITHUB_ACTIONS_SETUP.md            # הוראות הגדרה
```

## 🚀 Deployment

### אפשרות 1: GitHub Actions (אוטומטי) ⭐ מומלץ

כל push לענף `main` אוטומטית מעלה את הקוד ל-Google Apps Script.

**הגדרה:** ראה [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md)

### אפשרות 2: Deploy ידני

```bash
# התקנת clasp (פעם אחת)
npm install -g @google/clasp
clasp login

# יצירת קבצי .clasp
echo '{"scriptId":"YOUR_PERMISSIONS_SCRIPT_ID"}' > appScripts/.clasp-permissions.json
echo '{"scriptId":"YOUR_WEAPONS_SCRIPT_ID"}' > appScripts/.clasp-weapons.json
echo '{"scriptId":"YOUR_RADIO_SCRIPT_ID"}' > appScripts/.clasp-radio.json

# Deploy
./deploy.sh all              # כל הסקריפטים
./deploy.sh permissions      # רק permissions
./deploy.sh weapons          # רק weapons
./deploy.sh radio            # רק radio
```

## 🔐 מערכת האבטחה

### Flow:
```
Frontend (HTML)
    ↓
permissionsAppScript (Authentication/Authorization)
    ↓
weaponAppScript / radioAppScript (Data Processing)
    ↓
Google Sheets (Storage)
```

### תפקידים והרשאות:

| תפקיד | הרשאות |
|-------|---------|
| **Admin** | כל ההרשאות (ניהול משתמשים, דוחות, כתיבה, מחיקה) |
| **Operator** | כתיבה, קריאה, צפייה בדוחות |
| **Viewer** | קריאה וצפייה בדוחות בלבד |
| **User** | כתיבה של הנתונים שלו בלבד |

## 📊 Google Sheets

| Sheet | ID | תיאור |
|-------|-----|-------|
| **Users** | `1x3QU2...` | משתמשים והרשאות |
| **Audit Log** | `16dqe...` | יומן כל הפעולות |
| **Weapons** | `1kPB-...` | דוח צלם (נשקים) |
| **Radio** | `1jUDD...` | דוח קשר |

## 🛠️ עדכון URLs אחרי Deploy

### עדכון אוטומטי (מומלץ) ⚡

```bash
# עדכן את כל ה-URLs בבת אחת
npm run update-urls -- \
  --permissions="https://script.google.com/macros/s/YOUR_NEW_ID/exec" \
  --weapons="https://script.google.com/macros/s/YOUR_NEW_ID/exec" \
  --radio="https://script.google.com/macros/s/YOUR_NEW_ID/exec"

# או עם Node ישירות
node update-urls.js --permissions=<URL> --weapons=<URL> --radio=<URL>
```

### קבצים שמתעדכנים אוטומטית:
- ✅ index.html
- ✅ index-secure.html
- ✅ weapons-checkout-secure.html
- ✅ radio-checkout-secure.html
- ✅ user-management.html
- ✅ audit-log.html

**📚 למדריך מפורט ראה:** [URL_UPDATE_GUIDE.md](URL_UPDATE_GUIDE.md)

## 📝 משתמש ברירת מחדל

אחרי הרצת `initializeSystem()` בpermissionsAppScript:

```
Username: admin
Password: admin123
```

**חשוב:** שנה את הסיסמה מיד!

## 🔧 הגדרת Scripts

### permissionsAppScript
1. צור Standalone Script ב-Google Apps Script
2. הדבק את `permissionsAppScript-clean.js`
3. ערוך את `CONFIG.SHEETS` עם ה-Sheet IDs שלך
4. ערוך את `CONFIG.ORIGINAL_SCRIPTS` עם URLs של weapons ו-radio
5. הרץ `initializeSystem()`
6. Deploy → Web App → Execute as: Me, Access: Anyone

### weaponAppScript / radioAppScript
1. פתח את Google Sheet של הנשקים/קשר
2. Extensions → Apps Script
3. הדבק את הקוד המתאים
4. הרץ `forcePermissions()`
5. Deploy → Web App → Execute as: Me, Access: Anyone

## 🧪 בדיקה

```bash
# בדיקת Permissions Script
# הרץ בApps Script Editor:
testConnection()

# בדיקת Email ב-Weapons/Radio
testSendEmail()
```

## 📚 תיעוד נוסף

- [הגדרת GitHub Actions](GITHUB_ACTIONS_SETUP.md)
- [clasp Documentation](https://github.com/google/clasp)

## 🆘 תמיכה

בעיות? פתח Issue ב-GitHub או צור קשר עם מנהל המערכת.

---

**© 2026 גדחה"ו קומנדו 8219 | כל הזכויות שמורות**
