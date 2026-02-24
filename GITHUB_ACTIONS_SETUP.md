# 🚀 הגדרת GitHub Actions ל-Google Apps Script

## מה זה עושה?
כל פעם שאתה עושה `push` לענף `main`, GitHub Actions אוטומטית:
1. ✅ מעלה את הקוד ל-Google Apps Script
2. ✅ עושה Deploy חדש
3. ✅ מעדכן את כל 3 הסקריפטים (Permissions, Weapons, Radio)

---

## 📋 שלבי ההתקנה

### שלב 1: התקנת clasp במחשב שלך

```bash
# התקן clasp
npm install -g @google/clasp

# התחבר ל-Google
clasp login
```

זה יפתח דפדפן - אשר את ההרשאות.

---

### שלב 2: קבלת CLASPRC_JSON

אחרי ההתחברות, הקובץ `~/.clasprc.json` נוצר. תעתיק את התוכן שלו:

```bash
# הצג את התוכן
cat ~/.clasprc.json
```

תקבל משהו כזה:
```json
{
  "token": {
    "access_token": "ya29.a0...",
    "refresh_token": "1//0g...",
    "scope": "...",
    "token_type": "Bearer",
    "expiry_date": 1234567890
  },
  "oauth2ClientSettings": {
    "clientId": "...",
    "clientSecret": "...",
    "redirectUri": "..."
  },
  "isLocalCreds": false
}
```

**העתק את כל התוכן הזה!** תצטרך אותו בשלב הבא.

---

### שלב 3: קבלת Script IDs

כל Apps Script צריך את ה-Script ID שלו.

#### איך לקבל Script ID?

1. פתח את ה-Apps Script ב-Google
2. לחץ על ⚙️ **Project Settings**
3. תחת **IDs**, העתק את **Script ID**

תעשה את זה עבור 3 הסקריפטים:
- ✅ **Permissions Script ID**
- ✅ **Weapons Script ID**
- ✅ **Radio Script ID**

כל אחד צריך ליצור קובץ `.clasp.json` בפורמט הזה:

```json
{"scriptId":"<SCRIPT_ID_כאן>"}
```

---

### שלב 4: הוספת Secrets ל-GitHub

עכשיו תכניס את כל הנתונים האלה ל-GitHub Secrets:

1. לך ל-GitHub repository שלך
2. לחץ על **Settings** (למעלה)
3. בצד שמאל: **Secrets and variables** → **Actions**
4. לחץ **New repository secret**

הוסף 4 Secrets:

#### Secret #1: `CLASPRC_JSON`
- **Name:** `CLASPRC_JSON`
- **Value:** הדבק את כל תוכן הקובץ `~/.clasprc.json` (מ-שלב 2)

#### Secret #2: `SCRIPT_ID_PERMISSIONS`
```json
{"scriptId":"YOUR_PERMISSIONS_SCRIPT_ID_HERE"}
```

#### Secret #3: `SCRIPT_ID_WEAPONS`
```json
{"scriptId":"YOUR_WEAPONS_SCRIPT_ID_HERE"}
```

#### Secret #4: `SCRIPT_ID_RADIO`
```json
{"scriptId":"YOUR_RADIO_SCRIPT_ID_HERE"}
```

---

### שלב 5: בדיקה

עכשיו תעשה push לפרויקט:

```bash
git add .
git commit -m "Added GitHub Actions"
git push origin main
```

לך ל-GitHub → **Actions** ותראה את ה-workflow רץ!

---

## 🎯 איך להשתמש מעכשיו?

### לעדכן את הסקריפטים:

1. ערוך את הקוד ב-`appScripts/`
2. Commit ו-Push:
   ```bash
   git add appScripts/
   git commit -m "Updated weapons script"
   git push
   ```
3. GitHub Actions אוטומטית יעשה Deploy!

### להריץ ידנית:

1. לך ל-GitHub → **Actions**
2. בחר **Deploy to Google Apps Script**
3. לחץ **Run workflow**

---

## ⚠️ טיפים חשובים

1. **אל תשתף את ה-Secrets!** הם פרטיים ונשארים ב-GitHub בלבד
2. **Token פג תוקף?** תריץ `clasp login` שוב ותעדכן את `CLASPRC_JSON`
3. **שגיאות?** בדוק ב-GitHub Actions → Logs

---

## 🆘 בעיות נפוצות

### בעיה: "Error: Could not read API credentials"
**פתרון:** ודא ש-`CLASPRC_JSON` מועתק נכון (כולל כל ה-JSON)

### בעיה: "Script ID not found"
**פתרון:** ודא שה-Script IDs נכונים (בדוק ב-Project Settings)

### בעיה: "Insufficient permissions"
**פתרון:** תריץ `clasp login` שוב ותאשר את כל ההרשאות

---

## 📚 משאבים נוספים

- [clasp Documentation](https://github.com/google/clasp)
- [GitHub Actions Docs](https://docs.github.com/en/actions)

---

**זהו! מעכשיו כל עדכון קוד יעלה אוטומטית ל-Google Apps Script! 🎉**
