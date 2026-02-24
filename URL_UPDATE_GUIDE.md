# 🔄 מדריך עדכון URLs אחרי Deploy

## 📋 סקירה כללית

אחרי שאתה עושה Deploy חדש של Google Apps Scripts, אתה צריך לעדכן את ה-URLs בכל קבצי ה-HTML.

הפרויקט כולל **3 סקריפטים**:
1. **permissionsAppScript** - מערכת אבטחה והרשאות
2. **weaponAppScript** - מערכת נשקים
3. **radioAppScript** - מערכת קשר

---

## 🎯 אפשרות 1: עדכון אוטומטי (מומלץ)

### שלב 1: הכן את ה-URLs החדשים

אחרי Deploy, תקבל 3 URLs חדשים:

```
PERMISSIONS_URL="https://script.google.com/macros/s/AKfyc.../exec"
WEAPONS_URL="https://script.google.com/macros/s/AKfyc.../exec"
RADIO_URL="https://script.google.com/macros/s/AKfyc.../exec"
```

### שלב 2: הרץ את הסקריפט

```bash
node update-urls.js \
  --permissions="PERMISSIONS_URL" \
  --weapons="WEAPONS_URL" \
  --radio="RADIO_URL"
```

**דוגמה מלאה:**
```bash
node update-urls.js \
  --permissions="https://script.google.com/macros/s/AKfycbxYOUR_NEW_ID_HERE/exec" \
  --weapons="https://script.google.com/macros/s/AKfycbyYOUR_NEW_ID_HERE/exec" \
  --radio="https://script.google.com/macros/s/AKfycbzYOUR_NEW_ID_HERE/exec"
```

### שלב 3: בדוק ו-Commit

```bash
# בדוק מה השתנה
git diff

# Commit השינויים
git add .
git commit -m "Updated Google Apps Script URLs after deployment"
git push
```

---

## 🔧 אפשרות 2: עדכון ידני

### קבצים לעדכון:

#### 1. **index.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
```

#### 2. **index-secure.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
```

#### 3. **weapons-checkout-secure.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
const GOOGLE_SCRIPT_URL = 'NEW_PERMISSIONS_URL'; // שים לב: לא WEAPONS_URL!
```
**⚠️ שים לב:** `GOOGLE_SCRIPT_URL` ב-weapons-checkout-secure.html גם הוא צריך להיות ה-permissions URL (לא weapons URL), כי זה עובר דרך middleware האבטחה.

#### 4. **radio-checkout-secure.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
const GOOGLE_SCRIPT_URL = 'NEW_PERMISSIONS_URL'; // שים לב: לא RADIO_URL!
```

#### 5. **user-management.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
```

#### 6. **audit-log.html**
```javascript
const API_URL = 'NEW_PERMISSIONS_URL';
```

---

## 📝 רשימת URLs הנוכחיים (למקרה שצריך לזהות אותם)

### Permissions Script (Standalone)
```
https://script.google.com/macros/s/AKfycbwsFyStcK6uhjqwhENW15dCzg1L4CpsDnJ8QQ4nBm7ZZTre0k53BPrmx7AE8F2Cs_CGIQ/exec
```

### Weapons Script (Embedded in Sheet)
```
https://script.google.com/macros/s/AKfycby_vOgDCI8ZHR3sH42fMkXpDuCljYrpgZ3SO7YgnC97Yg0Rsm3y0P_uj0VNpnYo12Xg/exec
```

### Radio Script (Embedded in Sheet)
```
https://script.google.com/macros/s/AKfycbxG1ymau8BHFFzIyqPqqe-jSIEZgc00SHoV4LMANhQbBRDm45U0RK1Ajh6m0Xcn099X/exec
```

---

## 🔍 איך לקבל את ה-URL החדש?

### ב-Google Apps Script Editor:

1. לחץ **Deploy** → **Manage deployments**
2. בחר את ה-deployment האחרון
3. העתק את ה-**Web app URL**
4. ה-URL צריך להיות בפורמט:
   ```
   https://script.google.com/macros/s/AKfyc.../exec
   ```

---

## ⚙️ עדכון נוסף: permissionsAppScript CONFIG

אם שינית את ה-weapons או radio scripts, תזכור לעדכן גם את `permissionsAppScript.js`:

```javascript
const CONFIG = {
    // ...
    ORIGINAL_SCRIPTS: {
      WEAPONS: 'NEW_WEAPONS_URL',  // ← עדכן כאן
      RADIO: 'NEW_RADIO_URL'       // ← עדכן כאן
    },
    // ...
};
```

אחר כך תעשה Deploy מחדש של permissionsAppScript.

---

## ✅ Checklist

- [ ] קיבלתי 3 URLs חדשים מ-Google Apps Script
- [ ] הרצתי `node update-urls.js` עם ה-URLs החדשים
- [ ] בדקתי ש-`git diff` מראה את השינויים הנכונים
- [ ] Commit ו-Push ל-GitHub
- [ ] אם שיניתי weapons/radio URLs, עדכנתי גם את permissionsAppScript CONFIG
- [ ] בדקתי שהמערכת עובדת (התחברות + שליחת טופס)

---

## 🆘 בעיות נפוצות

### הסקריפט לא מוצא קבצים
```bash
# ודא שאתה בתיקיית הפרויקט הראשית
cd /path/to/gadhan
node update-urls.js ...
```

### URL לא תקין
ודא שה-URL:
- מתחיל ב-`https://script.google.com/macros/s/`
- מסתיים ב-`/exec`
- אין רווחים או תווים מיוחדים

### עדכנתי אבל עדיין לא עובד
1. נקה cache של הדפדפן (Ctrl+Shift+Del)
2. בדוק שה-deployment ב-Google Apps Script הוא "Anyone" ולא "Me"
3. ודא שהגרסה ב-Vercel עודכנה (עשה deploy מחדש אם צריך)

---

**זהו! אחרי העדכון, כל ה-HTML files יצביעו ל-Scripts החדשים שלך.** 🎉
