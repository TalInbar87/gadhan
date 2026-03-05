/**
 * ================================================================
 * Utility Functions - פונקציות עזר משותפות
 * ================================================================
 * createResponse | createJsonpResponse | formatTimestamp
 * findExistingRow | parsePostData
 * ================================================================
 */

/**
 * יצירת תשובה סטנדרטית (JSON עם statusCode)
 */
function createResponse(statusCode, message, data) {
  return ContentService
    .createTextOutput(JSON.stringify({
      statusCode,
      message,
      data,
      timestamp: new Date().toISOString()
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * יצירת תשובת JSONP (לבקשות GET)
 */
function createJsonpResponse(data, callback) {
  return ContentService
    .createTextOutput(callback + '(' + JSON.stringify(data) + ')')
    .setMimeType(ContentService.MimeType.JAVASCRIPT);
}

/**
 * עיצוב תאריך ושעה בזמן מקומי
 */
function formatTimestamp() {
  return Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'yyyy-MM-dd HH:mm:ss');
}

/**
 * מחפש שורה קיימת לפי ערך בעמודה
 * @param {GoogleAppsScript.Spreadsheet.Sheet} sheet
 * @param {string|number} value  - הערך לחיפוש
 * @param {number}        column - עמודה (1-indexed)
 * @returns {number|null}        - שורה (1-indexed) או null
 */
function findExistingRow(sheet, value, column) {
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return null;
  const values = sheet.getRange(2, column, lastRow - 1, 1).getValues();
  for (let i = 0; i < values.length; i++) {
    if (values[i][0].toString() === value.toString()) return i + 2;
  }
  return null;
}

/**
 * שליחת מייל — Brevo API אם BREVO_API_KEY מוגדר ב-Script Properties,
 * אחרת fallback ל-MailApp.
 *
 * @param {Object}  opts
 * @param {string}  opts.to       - כתובת נמען
 * @param {string}  opts.subject  - נושא
 * @param {string}  opts.body     - גוף המייל (טקסט)
 * @param {Blob}   [opts.pdfBlob] - PDF מצורף (אופציונלי)
 */
function sendEmail(opts) {
  const to      = opts.to;
  const subject = opts.subject;
  const body    = opts.body;
  const pdfBlob = opts.pdfBlob || null;

  const apiKey = PropertiesService.getScriptProperties().getProperty('BREVO_API_KEY');

  if (apiKey) {
    // ─── Brevo API ──────────────────────────────────────────────
    const senderEmail = Session.getActiveUser().getEmail();
    const payload = {
      sender:      { name: 'מערכת ניהול ציוד', email: senderEmail },
      to:          [{ email: to }],
      subject:     subject,
      textContent: body
    };
    if (pdfBlob) {
      payload.attachment = [{
        content: Utilities.base64Encode(pdfBlob.getBytes()),
        name:    pdfBlob.getName()
      }];
    }
    const response = UrlFetchApp.fetch('https://api.brevo.com/v3/smtp/email', {
      method:             'post',
      headers:            { 'api-key': apiKey, 'Content-Type': 'application/json' },
      payload:            JSON.stringify(payload),
      muteHttpExceptions: true
    });
    const code = response.getResponseCode();
    if (code !== 201) {
      Logger.log('⚠️ Brevo error ' + code + ': ' + response.getContentText());
      throw new Error('Brevo send failed: HTTP ' + code);
    }
    Logger.log('✅ Email sent via Brevo to: ' + to);
  } else {
    // ─── MailApp fallback ────────────────────────────────────────
    const mailOpts = { to: to, subject: subject, body: body };
    if (pdfBlob) mailOpts.attachments = [pdfBlob];
    MailApp.sendEmail(mailOpts);
    Logger.log('✅ Email sent via MailApp to: ' + to);
  }
}

/**
 * פענוח נתוני POST - מנסה מספר שיטות לפי סוג ה-Content-Type
 * מחזיר אובייקט JS מפוענח, או null אם כל הניסיונות כשלו
 */
function parsePostData(e) {
  // Method 1a: JSON direct
  if (e.postData && e.postData.contents) {
    try {
      const d = JSON.parse(e.postData.contents);
      Logger.log('📦 Parsed: JSON direct');
      return d;
    } catch (_) {}

    // Method 1b: URL-encoded (data=%7B%22action%22...)
    // Note: URLSearchParams encodes spaces as '+', decodeURIComponent alone doesn't handle that
    try {
      const raw = e.postData.contents;
      const val = raw.startsWith('data=') ? raw.slice(5) : raw;
      const d = JSON.parse(decodeURIComponent(val.replace(/\+/g, ' ')));
      Logger.log('📦 Parsed: URL-encoded body');
      return d;
    } catch (_) {}
  }

  // Method 2: e.parameter.data
  if (e.parameter && e.parameter.data) {
    try {
      const d = JSON.parse(decodeURIComponent(e.parameter.data.replace(/\+/g, ' ')));
      Logger.log('📦 Parsed: parameter.data');
      return d;
    } catch (_) {}
  }

  // Method 3: e.parameters.data[0]
  if (e.parameters && e.parameters.data && e.parameters.data[0]) {
    try {
      const d = JSON.parse(decodeURIComponent(e.parameters.data[0].replace(/\+/g, ' ')));
      Logger.log('📦 Parsed: parameters.data[0]');
      return d;
    } catch (_) {}
  }

  return null;
}
