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
    try {
      const raw = e.postData.contents;
      const val = raw.startsWith('data=') ? raw.slice(5) : raw;
      const d = JSON.parse(decodeURIComponent(val));
      Logger.log('📦 Parsed: URL-encoded body');
      return d;
    } catch (_) {}
  }

  // Method 2: e.parameter.data
  if (e.parameter && e.parameter.data) {
    try {
      const d = JSON.parse(decodeURIComponent(e.parameter.data));
      Logger.log('📦 Parsed: parameter.data');
      return d;
    } catch (_) {}
  }

  // Method 3: e.parameters.data[0]
  if (e.parameters && e.parameters.data && e.parameters.data[0]) {
    try {
      const d = JSON.parse(decodeURIComponent(e.parameters.data[0]));
      Logger.log('📦 Parsed: parameters.data[0]');
      return d;
    } catch (_) {}
  }

  return null;
}
