# CLAUDE.md — הנחיות לכל תהליך/מפתח

## חובה לפני כל שינוי בקוד

**קרא את `LEARNING.md`** — מסמך הידע המלא של הפרויקט.
הוא מכסה את כל הפונקציות, מבני הנתונים, API routes, ודפוסי עבודה.

```
/Users/talinbar/Desktop/gadhan/LEARNING.md
```

---

## Required Skills

לפני עבודה על פיצ'רים חדשים, טען:
- `LEARNING.md` — ארכיטקטורה + כל הפונקציות הקיימות
- בדוק code reuse לפני כתיבת קוד חדש

---

## כללי עבודה

### שליחת בקשה ל-GAS
```javascript
// תמיד URLSearchParams — לא JSON body
const p = new URLSearchParams();
p.append('data', JSON.stringify({ action: '...', token: authClient.token }));
fetch(API_URL, { method: 'POST', body: p });
```

### בדיקת תשובה
```javascript
if (json.statusCode === 200) { ... }  // לא json.ok / json.success
```

### פריסה
```bash
bash deploy.sh  # תמיד — לא clasp push ישיר
```

---

## מבנה הפרויקט

```
Frontend:  *.html + auth-client.js
Backend:   appScripts/unified/*.js (GAS)
Database:  5 Google Sheets (ראה LEARNING.md)
Deploy:    deploy.sh → clasp push + git commit + push
```

---

## לפני הוספת action חדש

1. בדוק ב-`LEARNING.md` שהפונקציה לא קיימת כבר
2. כתוב לוגיקה במודול הרלוונטי (Weapons/Radio/Armory/וכו')
3. הוסף handler ב-`Main.js`
4. הוסף `case` ב-switch ב-`doPost`
5. בדוק הרשאה נדרשת
6. `bash deploy.sh`
