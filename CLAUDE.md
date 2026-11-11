# CLAUDE.md — gadhan (מערכת ניהול ציוד וחתימות)

> **פרויקט פרטי** (GitHub `TalInbar87/gadhan`). הקובץ הגלובלי `~/.claude/CLAUDE.md` חל כאן; חוקי tai / המחלקה לא חלים.
> הקובץ הזה מכיל רק מה שייחודי ל-gadhan, כולל החריגות מהכללים הגלובליים.

## ⚠️ חריגות מברירות המחדל הגלובליות

| נושא | ברירת מחדל גלובלית | בפרויקט הזה |
|---|---|---|
| Stack | Supabase + Vercel | **Google Apps Script** (backend) + **Google Sheets** (DB) + HTML סטטי |
| קבצי ידע | `learning.md` + `memory.md` | **`LEARNING.md`** (אותיות גדולות). אין עדיין `memory.md` |
| Git flow | branch → PR → merge | `deploy.sh` עושה commit + `push origin main` ישירות (ראה פריסה) |
| טסטים | Vitest, חובה | **אין עדיין test runner.** לפני פיצ'ר חדש — להציע הקמה, לא לדלג בשקט |

## חובה לפני כל שינוי בקוד
קרא את `LEARNING.md` — מסמך הידע המלא: כל הפונקציות, מבני הנתונים, API actions ודפוסי עבודה.
לפני כתיבת קוד חדש — בדוק שם שהפונקציה לא קיימת כבר (code reuse).

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

## מבנה הפרויקט
```
Frontend:  *.html + auth-client.js
Backend:   appScripts/unified/*.js (GAS)
Database:  Google Sheets (ראה LEARNING.md §2)
Deploy:    deploy.sh → clasp push + deploy → git add -A + commit + push origin main
```

## פריסה
```bash
bash deploy.sh  # תמיד — לא clasp push ישיר
```
- זו פריסה לפרודקשן **וגם** commit של **כל** תיקיית העבודה (`git add -A`) ו-push ישיר ל-`main`.
- להריץ רק כשטל מבקש פריסה. לפני הרצה — `git status` ולוודא שאין קבצים לא קשורים שייכנסו ל-commit.

## לפני הוספת action חדש
1. בדוק ב-`LEARNING.md` שהפונקציה לא קיימת כבר
2. כתוב לוגיקה במודול הרלוונטי (Weapons/Radio/Armory/וכו')
3. הוסף handler ב-`Main.js`
4. הוסף `case` ב-switch ב-`doPost`
5. בדוק הרשאה נדרשת (בצד השרת, בתחילת ה-handler)
6. `bash deploy.sh` — רק באישור
