/**
 * ================================================================
 * Google Apps Script - מערכת ניהול קשר (מכשירי קשר)
 * ================================================================
 * 
 * תיאור: סקריפט לניהול חתימה על ציוד קשר ותקשורת
 * Sheet: Radio (ID: 1jUDDvC2PPYOcEWHgb2fc5Jds_K_YYhjveHYIgAurEBc)
 * 
 * הוראות התקנה:
 * 1. פתח את Google Sheet של הקשר
 * 2. לחץ על Extensions > Apps Script
 * 3. הדבק את הקוד הזה
 * 4. הרץ את הפונקציה forcePermissions() כדי לאשר הרשאות
 * 5. Deploy > New deployment > Web app
 * 6. Execute as: Me | Who has access: Anyone
 * 7. העתק את ה-URL והדבק ב-HTML
 * 
 * מבנה Sheet:
 * - כל הרשומות: גיליון ראשי עם כל הנתונים
 * - גיליונים נפרדים לפי מסגרת: פלוגה א׳, פלוגה ב׳, פלוגה ג׳, פלס״מ, וכו׳
 * 
 * @OnlyCurrentDoc
 * ================================================================
 */

// ================================================================
// הרשאות נדרשות
// ================================================================

var SCOPES = [
  'https://www.googleapis.com/auth/spreadsheets',  // גישה לשיטס
  'https://www.googleapis.com/auth/script.send_mail'  // שליחת מיילים
];

// ================================================================
// קונפיגורציה
// ================================================================

const CONFIG = {
  TIMEZONE: "Asia/Jerusalem",
  MAIN_SHEET_NAME: "כל הרשומות",
  HEADER_COLOR: "#1e40af",  // כחול
  DEFAULT_UNIT: "ללא מסגרת"
};

// ================================================================
// טיפול בבקשות GET - בדיקת קיום מספר אישי
// ================================================================

/**
 * מטפל בבקשות GET מהמערכת
 * משמש לבדיקה האם מספר אישי כבר קיים במערכת
 */
function doGet(e) {
  try {
    // בדיקה שיש פרמטרים
    if (!e || !e.parameter) {
      Logger.log('❌ No parameters received in doGet');
      return createJsonpResponse({ error: 'No parameters received' }, 'callback');
    }
    
    const action = e.parameter.action;
    const callback = e.parameter.callback || 'callback';
    
    if (action === 'checkPersonalNumber') {
      return handleCheckPersonalNumber(e.parameter.personalNumber, callback);
    }
    
    // פעולה לא מוכרת
    return createJsonpResponse({ error: 'Unknown action' }, callback);
    
  } catch (error) {
    Logger.log('❌ Error in doGet: ' + error.toString());
    // בדיקה בטוחה של callback
    const callback = (e && e.parameter && e.parameter.callback) || 'callback';
    return createJsonpResponse({ error: error.toString() }, callback);
  }
}

/**
 * בודק אם מספר אישי קיים במערכת ומחזיר את הנתונים
 */
function handleCheckPersonalNumber(personalNumber, callback) {
  Logger.log('🔍 Checking personal number: ' + personalNumber);
  
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const allRecordsSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);
  
  // אם אין גיליון "כל הרשומות"
  if (!allRecordsSheet) {
    return createJsonpResponse({ exists: false }, callback);
  }
  
  // חיפוש מספר אישי בעמודה A (אינדקס 0)
  const data = allRecordsSheet.getDataRange().getValues();
  
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] == personalNumber) {
      Logger.log('✓ Found existing record at row ' + (i + 1));
      
      // החזרת הנתונים הקיימים
      const existingData = {
        exists: true,
        data: {
          personalNumber: data[i][0],
          fullName: data[i][2],
          phone: "0" + data[i][3],
          email: data[i][4],
          unit: data[i][5],
          radio624: data[i][6],
          radio91: data[i][7],
          hasColumn: data[i][8] == "1" ? true : false,
          columnNumber: data[i][9],
          amplifier: data[i][10],
          rigidAdapter: data[i][11],
          longAntenna: data[i][12],
          mad: data[i][13],
          flexibleAdapter: data[i][14],
          shortAntenna: data[i][15],
          speaker: data[i][16],
          madona: data[i][17],
          apple: data[i][18],
          pear: data[i][19]
        }
      };
      
      return createJsonpResponse(existingData, callback);
    }
  }
  
  // מספר אישי לא נמצא
  Logger.log('✗ Personal number not found');
  return createJsonpResponse({ exists: false }, callback);
}

// ================================================================
// טיפול בבקשות POST - שמירת נתונים
// ================================================================

/**
 * מטפל בבקשות POST מהמערכת
 * שומר את נתוני החתימה ושולח PDF במייל
 */
function doPost(e) {
  try {
    Logger.log('🎯 doPost called!');

    // בדיקה שיש נתונים
    if (!e.postData) {
      Logger.log('❌ No postData found!');
      return createJsonResponse({
        success: false,
        error: 'No postData found'
      });
    }

    // פענוח הנתונים
    const data = JSON.parse(e.postData.contents);
    Logger.log('✅ Data parsed successfully');

    // בדיקה אם זו בקשת זיכוי
    if (data.action === 'credit') {
      return handleCredit(data);
    }

    Logger.log('📥 Personal Number: ' + data.personalNumber);
    Logger.log('🏢 Unit: ' + data.unit);

    // שמירת הנתונים
    saveToSheet(data);

    // יצירת PDF ושליחת מייל
    generateAndSendPDF(data);

    // החזרת תשובת הצלחה
    return createJsonResponse({
      success: true,
      message: 'Data saved and email sent successfully'
    });

  } catch (error) {
    Logger.log('❌ Error in doPost: ' + error.toString());
    return createJsonResponse({
      success: false,
      error: error.toString()
    });
  }
}

/**
 * טיפול בזיכוי - העברת רשומה לגיליון זיכויים ומחיקה מהגיליונות
 */
function handleCredit(data) {
  const personalNumber = data.personalNumber;
  Logger.log('💳 Credit request for: ' + personalNumber);

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const mainSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);

  if (!mainSheet) {
    return createJsonResponse({ success: false, error: 'Main sheet not found' });
  }

  // חיפוש הרשומה בגיליון הראשי - עמודה A = מספר אישי
  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1;
  let rowData = null;

  for (let i = 1; i < allData.length; i++) {
    if (allData[i][0] == personalNumber) { // עמודה A = מספר אישי
      foundRow = i + 1;
      rowData = allData[i];
      break;
    }
  }

  if (foundRow === -1) {
    return createJsonResponse({ success: false, error: 'Record not found' });
  }

  // יצירת/קבלת גיליון זיכויים
  let creditSheet = ss.getSheetByName('זיכויים');
  if (!creditSheet) {
    creditSheet = ss.insertSheet('זיכויים');
    const headers = [
      "מספר אישי", "תאריך ושעה", "שם מלא", "טלפון", "מייל", "מסגרת",
      "624", "91", "עמוד", "מספר עמוד", "מגבר", "מתאם קשיח", "אנטנה לונג",
      "מעד", "מתאם גמיש", "אנטנה שורט", "רמק", "מדונה", "תפוח", "אגס",
      "תאריך זיכוי", "זוכה על ידי"
    ];
    creditSheet.appendRow(headers);
    const headerRange = creditSheet.getRange(1, 1, 1, headers.length);
    headerRange.setBackground("#8B0000");
    headerRange.setFontColor("#FFFFFF");
    headerRange.setFontWeight("bold");
    headerRange.setHorizontalAlignment("right");
  }

  // הוספת השורה לזיכויים עם metadata
  const creditRow = [...rowData, data.creditAt || new Date().toISOString(), data.creditBy || 'unknown'];
  creditSheet.appendRow(creditRow);
  Logger.log('✓ Record added to credits sheet');

  // מחיקה מהגיליון הראשי
  mainSheet.deleteRow(foundRow);
  Logger.log('✓ Record deleted from main sheet');

  // מחיקה מגיליון המסגרת (אם קיים)
  const unit = rowData[5]; // עמודה F = מסגרת
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const unitData = unitSheet.getDataRange().getValues();
      for (let i = 1; i < unitData.length; i++) {
        if (unitData[i][0] == personalNumber) { // עמודה A = מספר אישי
          unitSheet.deleteRow(i + 1);
          Logger.log('✓ Record deleted from unit sheet: ' + unit);
          break;
        }
      }
    }
  }

  return createJsonResponse({
    success: true,
    message: 'Credit completed - record moved to credits sheet'
  });
}

// ================================================================
// פונקציות שמירה
// ================================================================

/**
 * שומר את הנתונים ב-Google Sheet
 */
function saveToSheet(data) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const timestamp = Utilities.formatDate(new Date(), CONFIG.TIMEZONE, "yyyy-MM-dd HH:mm:ss");
  
  // שמירה בגיליון לפי מסגרת
  saveToUnitSheet(ss, data, timestamp);
  
  // שמירה בגיליון "כל הרשומות"
  saveToMainSheet(ss, data, timestamp);
}

/**
 * שומר בגיליון לפי מסגרת (יחידה)
 */
function saveToUnitSheet(ss, data, timestamp) {
  const sheetName = data.unit || CONFIG.DEFAULT_UNIT;
  let sheet = ss.getSheetByName(sheetName);
  
  // אם הגיליון לא קיים, צור אותו
  if (!sheet) {
    sheet = createUnitSheet(ss, sheetName);
  }
  
  // בדיקה אם מספר אישי כבר קיים
  const existingRow = findExistingRow(sheet, data.personalNumber, 1); // עמודה A
  
  // הכנת השורה
  const rowData = prepareRowData(data, timestamp);
  
  if (existingRow) {
    // עדכון שורה קיימת
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ Updated existing row ' + existingRow + ' in sheet: ' + sheetName);
  } else {
    // הוספת שורה חדשה
    sheet.appendRow(rowData);
    Logger.log('✓ Added new row to sheet: ' + sheetName);
  }
}

/**
 * שומר בגיליון הראשי "כל הרשומות"
 */
function saveToMainSheet(ss, data, timestamp) {
  let mainSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);
  
  // אם הגיליון הראשי לא קיים, צור אותו
  if (!mainSheet) {
    mainSheet = createUnitSheet(ss, CONFIG.MAIN_SHEET_NAME);
  }
  
  // בדיקה אם מספר אישי כבר קיים
  const existingRow = findExistingRow(mainSheet, data.personalNumber, 1);
  
  // הכנת השורה
  const rowData = prepareRowData(data, timestamp);
  
  if (existingRow) {
    // עדכון שורה קיימת
    mainSheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ Updated existing row ' + existingRow + ' in main sheet');
  } else {
    // הוספת שורה חדשה
    mainSheet.appendRow(rowData);
    Logger.log('✓ Added new row to main sheet');
  }
}

/**
 * יוצר גיליון חדש עם כותרות
 */
function createUnitSheet(ss, sheetName) {
  const sheet = ss.insertSheet(sheetName);
  
  // כותרות
  const headers = [
    "מספר אישי", "תאריך ושעה", "שם מלא", "טלפון", "מייל", "מסגרת",
    "624", "91", "עמוד", "מספר עמוד", "מגבר", "מתאם קשיח", "אנטנה לונג",
    "מעד", "מתאם גמיש", "אנטנה שורט", "רמק", "מדונה", "תפוח", "אגס"
  ];
  
  sheet.appendRow(headers);
  
  // עיצוב כותרות
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground(CONFIG.HEADER_COLOR);
  headerRange.setFontColor("#FFFFFF");
  headerRange.setFontWeight("bold");
  headerRange.setHorizontalAlignment("right");
  
  Logger.log('✓ Created new sheet: ' + sheetName);
  return sheet;
}

/**
 * מחפש שורה קיימת לפי מספר אישי
 */
function findExistingRow(sheet, personalNumber, column) {
  const lastRow = sheet.getLastRow();
  
  if (lastRow <= 1) return null; // אין רשומות מעבר לכותרת
  
  const values = sheet.getRange(2, column, lastRow - 1, 1).getValues();
  
  for (let i = 0; i < values.length; i++) {
    if (values[i][0].toString() === personalNumber.toString()) {
      return i + 2; // +2 כי המערך מתחיל מ-0 והשורות מתחילות מ-2
    }
  }
  
  return null;
}

/**
 * מכין את נתוני השורה לשמירה
 */
function prepareRowData(data, timestamp) {
  return [
    data.personalNumber,
    timestamp,
    data.fullName,
    data.phone,
    data.email,
    data.unit || "",
    data.radio624 || "",
    data.radio91 || "",
    data.hasColumn ? "1" : "",
    data.columnNumber || "",
    data.amplifier || "",
    data.rigidAdapter || "",
    data.longAntenna || "",
    data.mad || "",
    data.flexibleAdapter || "",
    data.shortAntenna || "",
    data.speaker || "",
    data.madona || "",
    data.apple || "",
    data.pear || ""
  ];
}

// ================================================================
// פונקציות PDF ומייל
// ================================================================

/**
 * יוצר PDF ושולח במייל
 */
function generateAndSendPDF(data) {
  try {
    Logger.log('📄 Generating PDF...');
    
    const timestamp = Utilities.formatDate(new Date(), CONFIG.TIMEZONE, "yyyy-MM-dd HH:mm:ss");
    const htmlContent = createPdfHtml(data, timestamp);
    
    // יצירת PDF
    const blob = Utilities.newBlob(htmlContent, 'text/html', 'checkout.html');
    const pdf = blob.getAs('application/pdf');
    pdf.setName(`אישור_קבלת_ציוד_${data.personalNumber}_${new Date().getTime()}.pdf`);
    
    Logger.log('✅ PDF created successfully');
    
    // שליחת מייל
    sendEmail(data, pdf, timestamp);
    
  } catch (error) {
    Logger.log('❌ Error in generateAndSendPDF: ' + error.toString());
    throw error;
  }
}

/**
 * יוצר את תוכן ה-HTML ל-PDF
 */
function createPdfHtml(data, timestamp) {
  return `
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <style>
        * { font-family: 'Arial', sans-serif; margin: 0; padding: 0; }
        body { padding: 20px; background: #f5f5f5; }
        .header { background: #1e40af; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header p { font-size: 14px; opacity: 0.9; }
        .content { background: white; padding: 20px; border-radius: 8px; }
        .field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }
        .field-label { font-weight: bold; min-width: 150px; color: #1e40af; }
        .field-value { flex: 1; }
        .disclaimer { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .signature-section { margin-top: 20px; text-align: center; }
        .signature-section img { max-width: 250px; border: 1px solid #ccc; padding: 3px; background: white; }
        .footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>✓ אישור קבלת ציוד קשר</h1>
        <p>מערכת ניהול מכשירי קשר - גדחה"ו קומנדו 8219</p>
      </div>
      
      <div class="content">
        <div class="field">
          <div class="field-label">תאריך ושעה:</div>
          <div class="field-value">${timestamp}</div>
        </div>
        <div class="field">
          <div class="field-label">שם מלא:</div>
          <div class="field-value">${data.fullName}</div>
        </div>
        <div class="field">
          <div class="field-label">מספר אישי:</div>
          <div class="field-value">${data.personalNumber}</div>
        </div>
        <div class="field">
          <div class="field-label">טלפון:</div>
          <div class="field-value">${data.phone}</div>
        </div>
        ${data.unit ? `<div class="field"><div class="field-label">מסגרת:</div><div class="field-value">${data.unit}</div></div>` : ''}
        ${data.radio624 ? `<div class="field"><div class="field-label">מ.ק 624:</div><div class="field-value">${data.radio624}</div></div>` : ''}
        ${data.radio91 ? `<div class="field"><div class="field-label">מ.ק 91:</div><div class="field-value">${data.radio91}</div></div>` : ''}
        ${data.hasColumn ? `<div class="field"><div class="field-label">עמוד:</div><div class="field-value">כן${data.columnNumber ? ' - מספר: ' + data.columnNumber : ''}</div></div>` : ''}
        ${data.amplifier ? `<div class="field"><div class="field-label">מגבר:</div><div class="field-value">${data.amplifier}</div></div>` : ''}
        ${data.rigidAdapter ? `<div class="field"><div class="field-label">מתאם קשיח:</div><div class="field-value">${data.rigidAdapter}</div></div>` : ''}
        ${data.longAntenna ? `<div class="field"><div class="field-label">אנטנה לונג:</div><div class="field-value">${data.longAntenna}</div></div>` : ''}
        ${data.mad ? `<div class="field"><div class="field-label">מעד:</div><div class="field-value">${data.mad}</div></div>` : ''}
        ${data.flexibleAdapter ? `<div class="field"><div class="field-label">מתאם גמיש:</div><div class="field-value">${data.flexibleAdapter}</div></div>` : ''}
        ${data.shortAntenna ? `<div class="field"><div class="field-label">אנטנה שורט:</div><div class="field-value">${data.shortAntenna}</div></div>` : ''}
        ${data.speaker ? `<div class="field"><div class="field-label">רמק:</div><div class="field-value">${data.speaker}</div></div>` : ''}
        ${data.madona ? `<div class="field"><div class="field-label">מדונה:</div><div class="field-value">${data.madona}</div></div>` : ''}
        ${data.apple ? `<div class="field"><div class="field-label">תפוח:</div><div class="field-value">${data.apple}</div></div>` : ''}
        ${data.pear ? `<div class="field"><div class="field-label">אגס:</div><div class="field-value">${data.pear}</div></div>` : ''}
      </div>
      
      <div class="disclaimer">
        <strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את ציוד הקשר המפורט במסמך זה, 
        וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.
      </div>
      
      ${data.signature ? `
      <div class="signature-section">
        <div class="field-label" style="display: block; margin-bottom: 5px;">חתימת החייל:</div>
        <img src="${data.signature}" alt="חתימה"/>
      </div>` : ''}
      
      <div class="footer">
        <p>מסמך זה נוצר אוטומטית על ידי מערכת ניהול מכשירי קשר | © 2026 כל הזכויות שמורות</p>
      </div>
    </body>
    </html>
  `;
}

/**
 * שולח מייל עם קובץ PDF
 */
function sendEmail(data, pdf, timestamp) {
  const subject = `אישור קבלת ציוד קשר - ${data.fullName}`;
  const body = `
שלום ${data.fullName},

אישור קבלת ציוד הקשר נקלט במערכת בהצלחה.

פרטי האישור:
━━━━━━━━━━━━━━━━━━━━━━
תאריך ושעה: ${timestamp}
מספר אישי: ${data.personalNumber}
${data.unit ? `מסגרת: ${data.unit}` : ''}

מצורף אישור PDF מפורט.

בברכה,
מערכת ניהול מכשירי קשר
גדחה"ו קומנדו 8219
  `;
  
  Logger.log('📨 Sending email to: ' + data.email);
  
  MailApp.sendEmail({
    to: data.email,
    subject: subject,
    body: body,
    attachments: [pdf]
  });
  
  Logger.log('✅ Email sent successfully');
}

// ================================================================
// פונקציות עזר
// ================================================================

/**
 * יוצר תשובת JSONP (לבקשות GET)
 */
function createJsonpResponse(data, callback) {
  const result = JSON.stringify(data);
  return ContentService
    .createTextOutput(callback + '(' + result + ')')
    .setMimeType(ContentService.MimeType.JAVASCRIPT);
}

/**
 * יוצר תשובת JSON (לבקשות POST)
 */
function createJsonResponse(data) {
  return ContentService
    .createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

// ================================================================
// פונקציות הרשאות ובדיקה
// ================================================================

/**
 * פונקציה לאישור הרשאות - הרץ אותה ראשונה!
 * זה יבקש הרשאות ל-Spreadsheets ו-Mail
 */
function forcePermissions() {
  // בקש הרשאה לשליחת מיילים
  MailApp.getRemainingDailyQuota();
  
  // בקש הרשאה ל-Spreadsheet
  SpreadsheetApp.getActiveSpreadsheet();
  
  Logger.log('✅ Permissions requested. Please authorize in the popup.');
}

/**
 * פונקציה לבדיקת שליחת מייל
 */
function testSendEmail() {
  Logger.log('🧪 Testing email functionality...');
  
  const testData = {
    personalNumber: "1234567",
    fullName: "בדיקה טסט",
    email: "test@example.com",
    phone: "0501234567",
    unit: "פלוגה א׳",
    radio624: "12345",
    radio91: "67890"
  };
  
  try {
    generateAndSendPDF(testData);
    Logger.log('✅ Test email sent successfully!');
  } catch (error) {
    Logger.log('❌ Test failed: ' + error.toString());
  }
}
