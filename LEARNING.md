# 📚 LEARNING.md — מסמך ידע מלא

> **מטרה:** כל תהליך / מפתח חדש חייב לקרוא מסמך זה לפני שנוגע בקוד.
> הוא מכסה את כל הפונקציות, מבני הנתונים, דפוסי העבודה והמלכודות הנפוצות.

---

## תוכן עניינים

1. [ארכיטקטורה כללית](#1-ארכיטקטורה-כללית)
2. [Google Sheets — מבנה הגיליונות](#2-google-sheets--מבנה-הגיליונות)
3. [GAS Modules — כל הפונקציות](#3-gas-modules--כל-הפונקציות)
4. [API Routes — כל הactions](#4-api-routes--כל-הactions)
5. [Frontend — דפים ותפקידיהם](#5-frontend--דפים-ותפקידיהם)
6. [Authentication Flow](#6-authentication-flow)
7. [דפוסי עבודה נכונים](#7-דפוסי-עבודה-נכונים)
8. [Config — מפתחות חשובים](#8-config--מפתחות-חשובים)
9. [מלכודות נפוצות](#9-מלכודות-נפוצות)
10. [פריסה ותחזוקה](#10-פריסה-ותחזוקה)

---

## 1. ארכיטקטורה כללית

```
Frontend (HTML + Vanilla JS)
    ↓ URLSearchParams POST (לא JSON body — חשוב!)
Google Apps Script Web App (/exec)
    ↓ doPost → Main.js → handler לפי action
Google Sheets (5 spreadsheets נפרדים)
```

**נקודות קריטיות:**
- כל בקשה נשלחת כ-`POST` עם `URLSearchParams` — **לא** `Content-Type: application/json`
- ה-body: `data={"action":"...","token":"...","...":...}` (JSON מוצמד כ-string בשדה `data`)
- תשובת GAS תמיד: `{ statusCode, message, data, timestamp }`
- בדיקת הצלחה: `json.statusCode === 200` (**לא** `json.success` ו-**לא** `json.ok`)

---

## 2. Google Sheets — מבנה הגיליונות

### 2.1 גיליון נשקים (`CONFIG.SHEETS.WEAPONS`)

**טאב "כל הרשומות"** — רשומת נשק לכל חייל:

| עמודה | Index | תוכן |
|-------|-------|------|
| A | 0 | תאריך ושעה |
| B | 1 | שם מלא |
| C | 2 | מספר אישי |
| D | 3 | טלפון |
| E | 4 | מייל |
| F | 5 | מסגרת |
| G | 6 | צוות |
| H–BM | 7–64 | 58 פריטי ציוד (ראה `WEAPONS_ITEM_LIST`) |

**טאבים נוספים בגיליון נשקים:**
- `זיכויים` — ארכיון זיכויים (כל הרשומות + BN=פריטים שזוכו + BO=תאריך + BP=ע"י)
- `העברות` — היסטוריית העברות בין חיילים
- `ziuvud_<שם>` — גיליון זיווד לכל יחידה
- `ziuvud_כל הרשומות` — גיליון זיווד ראשי
- `איפסון` — פריטים שאופסנו (נוצר אוטומטית)

### 2.2 גיליון קשר (`CONFIG.SHEETS.RADIO`)

**טאב "כל הרשומות":**

| עמודה | Index | תוכן |
|-------|-------|------|
| A | 0 | מספר אישי |
| B | 1 | תאריך |
| C | 2 | שם מלא |
| D | 3 | טלפון |
| E | 4 | מייל |
| F | 5 | מסגרת |
| G–T | 6–19 | פריטי קשר (624, 91, עמוד, מגבר, וכו') |

### 2.3 גיליון משתמשים (`CONFIG.SHEETS.USERS`)

עמודות: `username | password_hash | role | fullName | personalNumber | phone | email | unit | team | active`

### 2.4 גיליון יומן ביקורת (`CONFIG.SHEETS.AUDIT_LOG`)

עמודות: `timestamp | action | performedBy | details | ip`

### 2.5 גיליון נשקייה (`CONFIG.SHEETS.ARMORY`)

**טאב "ספירות מלאי"** — ספירה היסטורית:

| עמודה | Index | תוכן |
|-------|-------|------|
| A | 0 | timestamp |
| B | 1 | performer (שם המבצע) |
| C–BN | 2–65 | 58 פריטים (כמות מספרית לכל פריט) |

---

## 3. GAS Modules — כל הפונקציות

### 3.1 Main.js — ניתוב בקשות

| פונקציה | תיאור |
|---------|-------|
| `doGet(e)` | GET requests — בדיקת חיבור, fallback |
| `doPost(e)` | כל POST requests — parse → route → handler |
| `handleLogin(data, e)` | התחברות, מחזיר JWT token |
| `handleVerifyToken(data, e)` | וידוא תקינות token |
| `handleSubmitData(data, e)` | שמירת טופס (נשק / קשר) |
| `handleGetExisting(data, e)` | שליפת נתוני חייל קיים |
| `handleCreateUser(data, e)` | יצירת משתמש חדש |
| `handleCreditData(data, e)` | זיכוי מלא |
| `handlePartialCredit(data, e)` | זיכוי חלקי |
| `handleTransferItems(data, e)` | העברת פריטים בין חיילים |
| `handleSwapItems(data, e)` | ראש-בראש (החלפה) |
| `handleGetAuditLog(data, e)` | שליפת יומן ביקורת |
| `handleGetWeaponsInventory(data, e)` | סיכום מלאי + שמות לפי מסגרת |
| `handleGetArmoryCount(data, e)` | ספירת מלאי נשקייה אחרונה |
| `handleSaveArmoryCount(data, e)` | שמירת ספירת מלאי נשקייה |
| `handleApsonGet(data, e)` | שליפת פריטים באיפסון לחייל |
| `handleApsonAdd(data, e)` | הוספת פריטים לאיפסון |
| `handleApsonRemove(data, e)` | הסרת פריטים מאיפסון |
| `initializeSystem()` | אתחול ראשוני של המערכת |
| `testConnection()` | בדיקת חיבור לכל הגיליונות |

---

### 3.2 Weapons.js — מודול נשק

#### שמירה וקריאה
| פונקציה | תיאור |
|---------|-------|
| `weapons_checkPersonalNumber(pn, callback)` | בדיקה אם חייל קיים, קריאת callback עם הנתונים |
| `weapons_saveToSheet(data)` | שמירה לכל הגיליונות הרלוונטיים |
| `weapons_saveToMainSheet(ss, data, ts)` | שמירה לטאב "כל הרשומות" |
| `weapons_saveToUnitSheet(ss, data, ts)` | שמירה לטאב יחידה |
| `weapons_saveToZivudSheet(ss, data, ts)` | שמירה לגיליון זיווד |
| `weapons_saveToMainZivudSheet(ss, data, ts)` | שמירה לגיליון זיווד ראשי |
| `weapons_createZivudSheet(ss, name)` | יצירת גיליון זיווד חדש |
| `weapons_createUnitSheet(ss, name)` | יצירת טאב יחידה חדש |
| `weapons_prepareRowData(data, ts)` | הכנת שורת נתונים לשמירה |
| `weapons_prepareZivudRowData(data, ts)` | הכנת שורת זיווד |

#### זיכוי
| פונקציה | תיאור |
|---------|-------|
| `weapons_handleCredit(data)` | זיכוי מלא — ארכיב + מחיקה |
| `weapons_handlePartialCredit(data)` | זיכוי חלקי — רק פריטים נבחרים |
| `weapons_findCreditRow(sheet, pn)` | מציאת שורת חייל בגיליון זיכויים |
| `weapons_getOrCreateCreditSheet(ss)` | קבלת/יצירת גיליון זיכויים |
| `weapons_getOrCreateCreditZivudSheet(ss)` | קבלת/יצירת גיליון זיכויי זיווד |
| `weapons_archiveZivudToCredit(ss, pn, ...)` | ארכיב זיווד לגיליון זיכויים |

#### העברה וראש-בראש
| פונקציה | תיאור |
|---------|-------|
| `weapons_handleTransferItems(data)` | העברת פריטים ממקור ליעד |
| `weapons_handleSwap(data)` | ראש-בראש — החלפת פריט בין חיילים |
| `weapons_transferNoteItems(ss, srcPN, tgtPN, keys)` | העברת פריטי הערות |
| `weapons_clearNoteItems(ss, pn, keys)` | מחיקת פריטי הערות |
| `weapons_readNotesMap(ss, pn)` | קריאת מפת הערות לחייל |

#### PDF ומייל
| פונקציה | תיאור |
|---------|-------|
| `weapons_sendEmailFast(data)` | שליחת מייל מהיר |
| `weapons_generateAndSendPDF(data)` | יצירת PDF ושליחה |
| `weapons_createPdfHtml(data, ts)` | HTML לPDF קבלת נשק |
| `weapons_createCreditPdfHtml(...)` | HTML לPDF זיכוי מלא |
| `weapons_createPartialCreditPdfHtml(...)` | HTML לPDF זיכוי חלקי |
| `weapons_createTransferPdfHtml(...)` | HTML לPDF העברה |
| `weapons_createSwapPdfHtml(...)` | HTML לPDF ראש-בראש |
| `weapons_sendEmail(data, pdf, ts)` | שליחת מייל עם PDF |
| `weapons_sendEmailWithRotation(options)` | שליחת מייל עם rotation בין חשבונות |
| `weapons_savePdfToDrive(pdf, unit, team, type)` | שמירת PDF ב-Drive |
| `weapons_saveCurrentPdf(blob, pn, unit, team)` | שמירת PDF נוכחי של חייל |
| `weapons_updateCurrentPdf(pn)` | עדכון PDF נוכחי לאחר שינוי |

#### מלאי ואיפסון
| פונקציה | תיאור |
|---------|-------|
| `weapons_getInventorySummary()` | סיכום מלאי: counts + names(+value+pn+inApson) לפי מסגרת |
| `weapons_apson_ensureSheet()` | יצירת טאב "איפסון" אם לא קיים |
| `weapons_apson_get(pn)` | שליפת פריטי איפסון לחייל לפי מספר אישי |
| `weapons_apson_add(data)` | הוספת פריטים לגיליון האיפסון |
| `weapons_apson_remove(pn, itemKeys)` | הסרת פריטים ספציפיים מהאיפסון |

#### עזר
| פונקציה | תיאור |
|---------|-------|
| `weapons_driveTimestamp()` | timestamp בפורמט תיקייה |
| `weapons_addMatolHeaderToExistingSheets()` | עדכון headers בגיליונות קיימים |
| `weapons_queueEmail(data)` | תור מייל (לשליחה מאוחרת) |
| `weapons_sendQueuedEmails()` | שליחת מיילים מהתור |

---

### 3.3 Radio.js — מודול קשר

| פונקציה | תיאור |
|---------|-------|
| `radio_checkPersonalNumber(pn, callback)` | בדיקת חייל קיים בגיליון קשר |
| `radio_saveToSheet(data)` | שמירה לגיליון קשר |
| `radio_saveToMainSheet(ss, data, ts)` | שמירה לטאב ראשי |
| `radio_saveToUnitSheet(ss, data, ts)` | שמירה לטאב יחידה |
| `radio_createUnitSheet(ss, name)` | יצירת טאב יחידה |
| `radio_prepareRowData(data, ts)` | הכנת שורת נתונים |
| `radio_handleCredit(data)` | זיכוי מלא קשר |
| `radio_handlePartialCredit(data)` | זיכוי חלקי קשר |
| `radio_generateAndSendPDF(data)` | יצירת PDF ושליחה |
| `radio_createPdfHtml(data, ts)` | HTML לPDF קבלת קשר |
| `radio_createCreditPdfHtml(...)` | HTML לPDF זיכוי קשר |
| `radio_createPartialCreditPdfHtml(...)` | HTML לPDF זיכוי חלקי קשר |
| `radio_sendEmail(data, pdf, ts)` | שליחת מייל קשר |

---

### 3.4 Auth.js — אימות

| פונקציה | תיאור |
|---------|-------|
| `auth_login(username, password)` | כניסה, מחזיר JWT |
| `auth_verifyToken(token)` | אימות token, מחזיר payload |
| `auth_hasPermission(token, permission)` | בדיקת הרשאה ספציפית |
| `auth_createUser(data)` | יצירת משתמש חדש |
| `auth_getUsers()` | רשימת כל המשתמשים |
| `auth_updateUser(data)` | עדכון משתמש |
| `auth_deleteUser(username)` | מחיקת משתמש |
| `bulkImportUsers()` | ייבוא מרובה של משתמשים (ידני) |

**הרשאות לפי תפקיד:**
- `admin`: read, write, delete, view_reports, manage_users, credit, audit_log, transfer
- `sergeant`: read, write, delete, view_reports, transfer

---

### 3.5 Armory.js — נשקייה

| פונקציה | תיאור |
|---------|-------|
| `armory_ensureSheet()` | יצירת טאב "ספירות מלאי" אם לא קיים |
| `armory_getLatestCount()` | שליפת ספירת המלאי האחרונה (שורה אחרונה) |
| `armory_saveCount(data)` | שמירת ספירה חדשה (append שורה) |

---

### 3.6 Backup.js — גיבוי

| פונקציה | תיאור |
|---------|-------|
| `backup_morning()` | מפעיל `backup_run('בוקר')` — trigger ב-08:00 |
| `backup_evening()` | מפעיל `backup_run('ערב')` — trigger ב-21:00 |
| `backup_run(timeLabel)` | גיבוי כל הגיליונות כ-Excel לתיקיית Drive |
| `backup_setupTriggers()` | הגדרת triggers אוטומטיים (מריצים פעם אחת!) |
| `backup_getOrCreateFolder(parent, name)` | מציאת/יצירת תיקייה ב-Drive |

**נתיב גיבוי:** `Drive/גיבוי/DD.MM.YYYY/גיבוי בוקר|ערב - [שם].xlsx`

---

### 3.7 Utils.js — עזר

| פונקציה | תיאור |
|---------|-------|
| `createResponse(statusCode, message, data)` | יצירת אובייקט תשובה סטנדרטי |
| `createJsonpResponse(data, callback)` | תשובת JSONP (GET requests) |
| `formatTimestamp()` | timestamp בפורמט DD/MM/YYYY HH:MM:SS |
| `findExistingRow(sheet, value, column)` | מציאת שורה לפי ערך בעמודה |
| `parsePostData(e)` | parse של POST body מ-URLSearchParams |

---

## 4. API Routes — כל ה-actions

כל הבקשות: `POST` לכתובת `API_URL` (מוגדר ב-`config.js`)

**מבנה הבקשה:**
```javascript
const p = new URLSearchParams();
p.append('data', JSON.stringify({
    action: 'ACTION_NAME',
    token: authClient.token,
    // ...שאר הנתונים
}));
fetch(API_URL, { method: 'POST', body: p });
```

**מבנה התשובה:**
```javascript
{ statusCode: 200, message: "...", data: {...}, timestamp: "..." }
```

| action | הרשאה נדרשת | תיאור |
|--------|------------|-------|
| `login` | ללא | התחברות — username + password |
| `verify_token` | ללא | וידוא token קיים |
| `submit_data` | `write` | שמירת טופס חדש |
| `get_existing` | `read` | שליפת נתוני חייל קיים |
| `create_user` | `manage_users` | יצירת משתמש |
| `credit_data` | `credit` | זיכוי מלא |
| `partial_credit` | `credit` | זיכוי חלקי |
| `transfer_items` | `transfer` | העברת פריטים |
| `swap_items` | `transfer` | ראש-בראש |
| `get_audit_log` | `audit_log` | יומן ביקורת |
| `get_weapons_inventory` | `view_reports` | סיכום מלאי נשקים |
| `get_armory_count` | `view_reports` | ספירת מלאי נשקייה |
| `save_armory_count` | `view_reports` | שמירת ספירת נשקייה |
| `apson_get` | `write` | פריטי איפסון לחייל |
| `apson_add` | `write` | הוספה לאיפסון |
| `apson_remove` | `write` | הסרה מאיפסון |

---

## 5. Frontend — דפים ותפקידיהם

| קובץ | תפקיד | גישה |
|------|--------|------|
| `index.html` | דף כניסה (login) | ציבורי |
| `index-secure.html` | דשבורד — ניווט לפי תפקיד | מאומת |
| `weapons-checkout-secure.html` | קבלת נשק + 58 פריטים + חתימה | מאומת |
| `radio-checkout-secure.html` | קבלת ציוד קשר + חתימה | מאומת |
| `weapons-transfer.html` | העברה / זיכוי / ראש-בראש / איפסון | `write` |
| `weapons-inventory.html` | מלאי: טבלה 58×מסגרות + חיפוש מוצר | מאומת |
| `armory-count.html` | ספירת מלאי פיזי נשקייה | `manage_users` (מנהל בלבד) |
| `user-management.html` | CRUD משתמשים | `manage_users` |
| `audit-log.html` | צפייה ביומן פעולות | `audit_log` |

### auth-client.js — ספריית אימות

**`SecureAuthClient`:**
- `authClient.token` — ה-JWT הנוכחי (property, לא function!)
- `authClient.user` — אובייקט המשתמש המחובר (`username`, `role`, `fullName`, וכו')
- `authClient.login(username, password)` — התחברות
- `authClient.verify()` — בדיקת תוקף token

**`AuthGuard`:**
```javascript
// כל מאומת:
const guard = new AuthGuard(authClient);

// עם הרשאה ספציפית:
const guard = new AuthGuard(authClient, 'manage_users');

// שימוש:
await guard.checkAuth(); // מחזיר true/false, מנתב ל-login אם נדרש
```

---

## 6. Authentication Flow

```
1. משתמש מזין username + password
2. Frontend → POST action:'login' → GAS
3. GAS: Auth.js בודק credentials בגיליון משתמשים
4. GAS מחזיר JWT signed עם JWT_SECRET (תוקף 1 שעה)
5. Frontend שומר token ב-localStorage
6. כל בקשה עתידית שולחת token בגוף ה-JSON
7. GAS מאמת token בכל בקשה לפני ביצוע
```

---

## 7. דפוסי עבודה נכונים

### שליחת בקשה ל-GAS (חובה!)
```javascript
// ✅ נכון — URLSearchParams
const p = new URLSearchParams();
p.append('data', JSON.stringify({ action: 'my_action', token: authClient.token }));
const res = await fetch(API_URL, { method: 'POST', body: p });
const json = await res.json();
if (json.statusCode === 200) { /* הצלחה */ }

// ❌ שגוי — JSON body גורם לשגיאת CORS preflight
fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({...})
});
```

### בדיקת תשובה מ-GAS
```javascript
// ✅ נכון
if (json.statusCode === 200) { ... }

// ❌ שגוי
if (json.ok) { ... }
if (json.success) { ... }
```

### גישה ל-token
```javascript
// ✅ נכון
authClient.token

// ❌ שגוי
authClient.getToken()
```

### יצירת handler ב-Main.js
```javascript
// 1. הוסף case ב-switch:
case 'my_action': return handleMyAction(data, e);

// 2. צור handler — דפוס חובה:
function handleMyAction(data, request) {
  // ── אימות token ──
  var payload = JWTUtil.verify(data.token, CONFIG.JWT_SECRET);
  if (!payload) return createResponse(401, 'Invalid or expired token', null);

  // ── בדיקת הרשאה (בחר לפי הצורך) ──
  // אפשרויות: 'write' | 'view_reports' | 'manage_users'
  if (!Authorization.canAccessResource(payload, null, 'write')) {
    return createResponse(403, 'Insufficient permissions', null);
  }

  // ── לוגיקה ──
  try {
    var result = my_module_function(data);
    return result.success
      ? createResponse(200, 'ok', result.data)
      : createResponse(500, result.error, null);
  } catch (e) {
    return createResponse(500, 'Server error: ' + e.toString(), null);
  }
}
```

> ⚠️ **אין `AuthMiddleware` במערכת** — אל תשתמש בו. תמיד `JWTUtil.verify` + `Authorization.canAccessResource`.

> ❌ **שגיאה נפוצה**: `CONFIG.AUTH.JWT_SECRET` — **לא קיים**. הנתיב הנכון הוא תמיד `CONFIG.JWT_SECRET`.
> בכל handler חדש שנכתב עם `CONFIG.AUTH.JWT_SECRET` יתקבל: `TypeError: Cannot read properties of undefined (reading 'JWT_SECRET')`.

---

## 8. Config — מפתחות חשובים

קובץ `Config.js` (gitignored) נוצר אוטומטית מ-`.env` ע"י `deploy.sh`.

```javascript
CONFIG.JWT_SECRET              // מפתח חתימת JWT
CONFIG.TOKEN_EXPIRATION        // תוקף token בשניות (3600)
CONFIG.TIMEZONE                // 'Asia/Jerusalem'

CONFIG.SHEETS.USERS            // Sheet ID — משתמשים
CONFIG.SHEETS.AUDIT_LOG        // Sheet ID — יומן ביקורת
CONFIG.SHEETS.WEAPONS          // Sheet ID — נשקים
CONFIG.SHEETS.RADIO            // Sheet ID — קשר
CONFIG.SHEETS.ARMORY           // Sheet ID — נשקייה

CONFIG.WEAPONS.MAIN_SHEET_NAME // 'כל הרשומות'
CONFIG.WEAPONS.PN_COLUMN       // 3 (עמודה C, 1-indexed)

CONFIG.ARMORY.SHEET_NAME       // 'ספירות מלאי'

CONFIG.RADIO.MAIN_SHEET_NAME   // 'כל הרשומות'
CONFIG.RADIO.PN_COLUMN         // 1 (עמודה A, 1-indexed)

CONFIG.EMAIL.GADHAN            // כתובת CC קבועה
CONFIG.EMAIL.RELAY_URL_2..5    // כתובות relay לrotation מיילים

CONFIG.DRIVE.ROOT_FOLDER_ID    // ID תיקיית שורש ב-Drive
CONFIG.DRIVE.PDF_WEAPONS       // ID תיקיית PDF נשקים
CONFIG.DRIVE.PDF_RADIO         // ID תיקיית PDF קשר
```

**.env variables נדרשים:**
```
GAS_DEPLOYMENT_ID=...
GAS_URL=https://script.google.com/macros/s/.../exec
JWT_SECRET=...
SHEET_USERS=...
SHEET_AUDIT_LOG=...
SHEET_WEAPONS=...
SHEET_RADIO=...
SHEET_ARMORY=...
ROOT_FOLDER_ID=...
PDF_WEAPONS_FOLDER=...
PDF_RADIO_FOLDER=...
```

---

## 9. מלכודות נפוצות

### CORS
**בעיה:** `Access to fetch ... blocked by CORS policy`
**סיבה:** שימוש ב-`Content-Type: application/json` מפעיל preflight שGAS לא מטפל בו
**פתרון:** תמיד `URLSearchParams` ללא header מיוחד

### Token כ-method
**בעיה:** `authClient.getToken is not a function`
**פתרון:** `authClient.token` (property, לא method)

### בדיקת הצלחה
**בעיה:** קוד נכשל בשקט כי בודק `json.ok` או `json.success`
**פתרון:** בדוק תמיד `json.statusCode === 200`

### מספרים עם 0 בהתחלה ב-Sheets
**בעיה:** ערך `"0523456"` מוזן כמספר ← Sheets שומר `523456`
**פתרון:** פרמט עמודה כ-`Plain Text` לפני הזנה
**לשים לב:** `getValues()` מחזיר מספר גם בתאים מפורמטים כטקסט אם הערך הבסיסי הוא מספר

### ביצוע GAS עם Webhook
**בעיה:** GAS מחזיר `302 redirect` לשירותים חיצוניים (כמו Telegram)
**סיבה:** URL `/exec` מבצע redirect פנימי ב-Google
**פתרון:** Long polling במקום webhook, או proxy שעוקב אחרי redirect

### גיליון לא קיים
**בעיה:** `sheet.getDataRange()` זורק שגיאה אם גיליון לא קיים
**פתרון:** תמיד לבדוק `if (!sheet) return { success: false, error: '...' };`

### טריגרים ב-GAS
**חשוב:** `backup_setupTriggers()` יש להריץ **פעם אחת** ב-GAS Editor.
אחרי `clasp push` הטריגרים נשמרים — לא צריך להריץ שוב.

---

## 10. פריסה ותחזוקה

### פריסה רגילה
```bash
bash deploy.sh
```
מבצע: inject .env → clasp push (אם יש שינויים ב-GAS) → deploy חדש → git commit + push

### בדיקת מצב
```javascript
// ב-GAS Editor:
testConnection()  // בודק חיבור לכל 5 הגיליונות
```

### גיבוי ידני מיידי
```javascript
// ב-GAS Editor:
backup_run('בוקר')  // או backup_run('ערב')
```

### הוספת action חדש — checklist
1. [ ] כתוב פונקציית לוגיקה במודול הרלוונטי (`Weapons.js` / `Radio.js` / וכו')
2. [ ] הוסף handler ב-`Main.js`
3. [ ] הוסף `case` ב-switch ב-`doPost`
4. [ ] הוסף הרשאה נדרשת בתחילת ה-handler
5. [ ] הוסף קריאה מ-frontend עם `URLSearchParams`
6. [ ] בדוק `json.statusCode === 200` בתשובה
7. [ ] הרץ `bash deploy.sh`

### הוספת פריט ציוד חדש — checklist
1. [ ] הוסף ל-`WEAPONS_ITEM_LIST` ב-`Weapons.js` עם `key`, `label`, `col` חדשים
2. [ ] עדכן headers בגיליון ה-Sheets
3. [ ] עדכן `weapons_createUnitSheet` ו-`weapons_createZivudSheet` אם יש
4. [ ] בדוק שה-col index מתאים לעמודה בגיליון

---

## 11. המלצות Refactoring עתידיות

> ⚠️ **לא לבצע ללא סביבת בדיקות** — שינויים אלה משפיעים על לוגיקת הליב הפנימית.
> לכל שלב יש לבדוק ידנית: קבלת נשק, זיכוי, העברה — ב-staging לפני פרוס לייב.

---

### שלב א' — הושלם ✅
**מחיקת קוד מת** (בוצע 2026-03-28):
- `weapons_queueEmail` — נמחק
- `weapons_sendQueuedEmails` — נמחק
- `weapons_sendEmailFast` — נמחק
- `weapons_addMatolHeaderToExistingSheets` — נמחק

---

### שלב ב' — ממתין 🔲
**איחוד Sheet Operations ל-`Utils.js`**

**הבעיה:** 4 פונקציות מוגדרות פעמיים — פעם ב-`Weapons.js` ופעם ב-`Radio.js`:

| כפילות | הבדל בפועל |
|--------|------------|
| `weapons_saveToMainSheet` ↔ `radio_saveToMainSheet` | רק שם הגיליון |
| `weapons_saveToUnitSheet` ↔ `radio_saveToUnitSheet` | רק שם הגיליון |
| `weapons_createUnitSheet` ↔ `radio_createUnitSheet` | רק headers וצבע |
| `weapons_prepareRowData` ↔ `radio_prepareRowData` | רק סדר העמודות |

**הפתרון:**
```javascript
// Utils.js — פונקציה אחת כללית
function saveToMainSheet(ss, data, timestamp, config, prepareFn) { ... }

// Weapons.js — wrapper קצר
function weapons_saveToMainSheet(ss, data, ts) {
  return saveToMainSheet(ss, data, ts, CONFIG.WEAPONS, weapons_prepareRowData);
}

// Radio.js — wrapper קצר
function radio_saveToMainSheet(ss, data, ts) {
  return saveToMainSheet(ss, data, ts, CONFIG.RADIO, radio_prepareRowData);
}
```

**תוצאה משוערת:** ~200 שורות פחות, תיקון באג אחד מתקן גם נשקים וגם קשר.

**לפני ביצוע — לבדוק:**
- [ ] קבלת נשק מחייל חדש (שמירה לכל הגיליונות)
- [ ] קבלת ציוד קשר מחייל חדש
- [ ] עדכון רשומה קיימת (שניהם)

---

### שלב ג' — ממתין 🔲
**איחוד PDF Generation + Credit Operations**

**הבעיה:** 8 פונקציות PDF עם מבנה HTML זהה, ו-2 פונקציות credit (weapons/radio) עם 70%+ לוגיקה משותפת.

**פונקציות PDF לאיחוד:**
- `weapons_createPdfHtml` ↔ `radio_createPdfHtml`
- `weapons_createCreditPdfHtml` ↔ `radio_createCreditPdfHtml`
- `weapons_createPartialCreditPdfHtml` ↔ `radio_createPartialCreditPdfHtml`

**פונקציות Credit לאיחוד:**
- `weapons_handleCredit` ↔ `radio_handleCredit`
- `weapons_handlePartialCredit` ↔ `radio_handlePartialCredit`

**הפתרון המוצע:**
```javascript
// Utils.js
function createPdfHtml(type, data, timestamp, schema) {
  // type: 'checkout' | 'credit' | 'partial_credit' | 'transfer' | 'swap'
  // schema: { title, fields, color, itemList }
}
```

**תוצאה משוערת:** ~550 שורות פחות (~9% מהקוד הכולל).

**לפני ביצוע — לבדוק:**
- [ ] זיכוי מלא נשק + PDF שנשלח במייל
- [ ] זיכוי חלקי נשק + קשר
- [ ] העברה + ראש-בראש

---

*מסמך זה עודכן לאחרונה: 2026-03-28*
*גרסת מערכת: deployment @106+*
