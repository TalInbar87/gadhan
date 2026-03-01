/**
 * ================================================================
 * Google Apps Script - מערכת ניהול נשקים (דוח צלם)
 * ================================================================
 * 
 * תיאור: סקריפט לניהול חתימה על נשקים ואמצעי לחימה
 * Sheet: Weapons/Tzalem (ID: 1kPB-CL0dY7J-J_-KmOYvLUNc9Zw4vJhDYij_SOwRJN0)
 * 
 * הוראות התקנה:
 * 1. פתח את Google Sheet של הנשקים
 * 2. לחץ על Extensions > Apps Script
 * 3. הדבק את הקוד הזה
 * 4. הרץ את הפונקציה forcePermissions() כדי לאשר הרשאות
 * 5. Deploy > New deployment > Web app
 * 6. Execute as: Me | Who has access: Anyone
 * 7. העתק את ה-URL והדבק ב-HTML
 * 
 * מבנה Sheet:
 * - כל הרשומות: גיליון ראשי עם כל הנתונים
 * - גיליונים נפרדים לפי מסגרת: פלוגה א׳, פלוגה ב׳, פלוגה ג׳, מפקדה, וכו׳
 * 
 * @OnlyCurrentDoc
 * ================================================================
 */
//With testttttt@2222
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
  HEADER_COLOR: "#2F5233",  // ירוק צבאי
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
  
  // חיפוש מספר אישי בעמודה C (אינדקס 2)
  const data = allRecordsSheet.getDataRange().getValues();
  
  for (let i = 1; i < data.length; i++) {
    if (data[i][2] == personalNumber) {
      Logger.log('✓ Found existing record at row ' + (i + 1));
      
      // החזרת הנתונים הקיימים
      const existingData = {
        exists: true,
        data: {
          personalNumber: data[i][2],
          fullName: data[i][1],
          phone: "0" + data[i][3],
          email: data[i][4],
          unit: data[i][5],
          weaponType: data[i][6],
          weaponNumber: data[i][7],
          trig: data[i][8],
          lior: data[i][9],
          pagion: data[i][10],
          zavon: data[i][11],
          m5: data[i][12],
          shacha: data[i][13],
          achbar: data[i][14],
          adi: data[i][15],
          ido: data[i][16],
          kiro: data[i][17],
          binoculars: data[i][18] == 1 ? true : false,
          compass: data[i][19] == 1 ? true : false,
          zayin: data[i][20],
          pak: data[i][21]
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

    // ניתוב לפי פעולה
    if (data.action === 'credit') {
      return handleCredit(data);
    }
    if (data.action === 'partial_credit') {
      return handlePartialCredit(data);
    }
    if (data.action === 'transfer_items') {
      return handleTransferItems(data);
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
 * מחזיר את מספר השורה (1-indexed) של מספר אישי בגיליון זיכויים, או -1 אם לא קיים
 */
function findCreditRow(creditSheet, personalNumber) {
  if (creditSheet.getLastRow() < 2) return -1;
  const data = creditSheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][2] == personalNumber) return i + 1;
  }
  return -1;
}

/**
 * מחזיר/יוצר גיליון זיכויים עם כותרות אחידות
 * עמודות: A-V (נתוני חייל) + W (פריטים שזוכו) + X (תאריך זיכוי) + Y (זוכה על ידי)
 */
function getOrCreateCreditSheet(ss) {
  let creditSheet = ss.getSheetByName('זיכויים');
  if (!creditSheet) {
    creditSheet = ss.insertSheet('זיכויים');
    const headers = [
      "תאריך ושעה", "שם מלא", "מספר אישי", "טלפון", "מייל", "מסגרת",
      "סוג נשק", "מספר נשק", "טריג׳", "ליאור", "פגיון", "זאבון", "m5",
      'שח"ע', "עכבר", "עדי", "עידו", "קירו", "משקפה", "מצפן", "ציין", "פק",
      "פריטים שזוכו", "תאריך זיכוי", "זוכה על ידי"
    ];
    creditSheet.appendRow(headers);
    const hr = creditSheet.getRange(1, 1, 1, headers.length);
    hr.setBackground("#8B0000");
    hr.setFontColor("#FFFFFF");
    hr.setFontWeight("bold");
    hr.setHorizontalAlignment("right");
  }
  return creditSheet;
}

/**
 * טיפול בזיכוי - העברת רשומה לגיליון זיכויים ומחיקה מהגיליונות
 * אם מספר אישי כבר קיים בגיליון זיכויים - לא מוסיף שורה חדשה
 */
function handleCredit(data) {
  const personalNumber = data.personalNumber;
  Logger.log('💳 Credit request for: ' + personalNumber);

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const mainSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);

  if (!mainSheet) {
    return createJsonResponse({ success: false, error: 'Main sheet not found' });
  }

  // חיפוש הרשומה בגיליון הראשי
  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1;
  let rowData = null;

  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == personalNumber) {
      foundRow = i + 1;
      rowData = allData[i];
      break;
    }
  }

  if (foundRow === -1) {
    return createJsonResponse({ success: false, error: 'Record not found' });
  }

  const creditSheet = getOrCreateCreditSheet(ss);

  // הוסף לגיליון זיכויים רק אם מספר אישי לא קיים שם עדיין
  const existingCreditRow = findCreditRow(creditSheet, personalNumber);
  if (existingCreditRow === -1) {
    const creditRow = [...rowData, 'הכל', data.creditAt || new Date().toISOString(), data.creditBy || 'unknown'];
    creditSheet.appendRow(creditRow);
    Logger.log('✓ Record added to credits sheet');
  } else {
    Logger.log('⚠️ Personal number already exists in credits sheet - skipping duplicate');
  }

  // מחיקה מהגיליון הראשי
  mainSheet.deleteRow(foundRow);
  Logger.log('✓ Record deleted from main sheet');

  // מחיקה מגיליון המסגרת (אם קיים)
  const unit = rowData[5];
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const unitData = unitSheet.getDataRange().getValues();
      for (let i = 1; i < unitData.length; i++) {
        if (unitData[i][2] == personalNumber) {
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
// מיפוי מפתחות פריטים לעמודות בגיליון
// ================================================================

const ITEM_COLUMN_MAP = {
  weapon:     [6, 7],   // G, H - סוג נשק + מספר נשק
  trig:       [8],      // I  - טריג׳
  lior:       [9],      // J  - ליאור
  pagion:     [10],     // K  - פגיון
  zavon:      [11],     // L  - זאבון
  m5:         [12],     // M  - m5
  shacha:     [13],     // N  - שח"ע
  achbar:     [14],     // O  - עכבר
  adi:        [15],     // P  - עדי
  ido:        [16],     // Q  - עידו
  kiro:       [17],     // R  - קירו
  binoculars: [18],     // S  - משקפה
  compass:    [19],     // T  - מצפן
  zayin:      [20],     // U  - ציין
  pak:        [21]      // V  - פק
};

/**
 * זיכוי חלקי - זיכוי פריטים נבחרים בלבד
 * אם כל הפריטים נבחרו - מבצע זיכוי מלא (מוחק שורה)
 * אחרת - מנקה את העמודות שנבחרו ומוסיף ערך לגיליון זיכויים
 */
function handlePartialCredit(data) {
  const { personalNumber, selectedItems, creditBy, creditAt, creditSignature } = data;
  Logger.log('💳 Partial credit for: ' + personalNumber + ', items: ' + JSON.stringify(selectedItems));

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const mainSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);
  if (!mainSheet) {
    return createJsonResponse({ success: false, error: 'Main sheet not found' });
  }

  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1, rowData = null;
  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == personalNumber) {
      foundRow = i + 1;
      rowData = allData[i];
      break;
    }
  }
  if (foundRow === -1) {
    return createJsonResponse({ success: false, error: 'Record not found' });
  }

  const creditSheet = getOrCreateCreditSheet(ss);
  const existingCreditRow = findCreditRow(creditSheet, personalNumber);

  if (existingCreditRow === -1) {
    // שורה חדשה: העתק נתונים בסיסיים, נקה פריטים שלא נבחרו
    const creditRowData = [...rowData];
    Object.keys(ITEM_COLUMN_MAP).forEach(key => {
      if (!selectedItems.includes(key)) {
        ITEM_COLUMN_MAP[key].forEach(col => { creditRowData[col] = ''; });
      }
    });
    creditSheet.appendRow([
      ...creditRowData,
      selectedItems.join(', '),
      creditAt || new Date().toISOString(),
      creditBy || 'unknown'
    ]);
    Logger.log('✓ New credit row added for ' + personalNumber);
  } else {
    // שורה קיימת: עדכן ערכי פריטים שנבחרו + מיזוג עמודת "פריטים שזוכו"
    selectedItems.forEach(key => {
      if (ITEM_COLUMN_MAP[key]) {
        ITEM_COLUMN_MAP[key].forEach(colIdx => {
          creditSheet.getRange(existingCreditRow, colIdx + 1).setValue(rowData[colIdx]);
        });
      }
    });
    // עמודה W (23) = פריטים שזוכו — מיזוג עם קיים
    const existingItems = creditSheet.getRange(existingCreditRow, 23).getValue() || '';
    const mergedItems = existingItems
      ? existingItems + ', ' + selectedItems.join(', ')
      : selectedItems.join(', ');
    creditSheet.getRange(existingCreditRow, 23).setValue(mergedItems);
    // עמודות X, Y — עדכן תאריך ומבצע
    creditSheet.getRange(existingCreditRow, 24).setValue(creditAt || new Date().toISOString());
    creditSheet.getRange(existingCreditRow, 25).setValue(creditBy || 'unknown');
    Logger.log('✓ Existing credit row updated for ' + personalNumber);
  }

  // נקה את הפריטים שנבחרו מהשורה המקורית
  selectedItems.forEach(key => {
    if (ITEM_COLUMN_MAP[key]) {
      ITEM_COLUMN_MAP[key].forEach(colIdx => {
        mainSheet.getRange(foundRow, colIdx + 1).setValue('');
      });
    }
  });

  // עדכן גם בגיליון המסגרת אם קיים
  const unit = rowData[5];
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const unitData = unitSheet.getDataRange().getValues();
      for (let i = 1; i < unitData.length; i++) {
        if (unitData[i][2] == personalNumber) {
          selectedItems.forEach(key => {
            if (ITEM_COLUMN_MAP[key]) {
              ITEM_COLUMN_MAP[key].forEach(colIdx => {
                unitSheet.getRange(i + 1, colIdx + 1).setValue('');
              });
            }
          });
          break;
        }
      }
    }
  }

  Logger.log('✓ Partial credit completed for ' + personalNumber + ', items: ' + selectedItems.join(', '));
  return createJsonResponse({
    success: true,
    message: 'Partial credit completed'
  });
}

/**
 * העברת פריטים - מנקה פריטים נבחרים מחייל המקור ומוסיף לחייל היעד
 */
function handleTransferItems(data) {
  const { sourcePersonalNumber, targetPersonalNumber, selectedItems, transferBy, transferAt } = data;
  Logger.log('🔄 Transfer from ' + sourcePersonalNumber + ' to ' + targetPersonalNumber + ', items: ' + JSON.stringify(selectedItems));

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const mainSheet = ss.getSheetByName(CONFIG.MAIN_SHEET_NAME);
  if (!mainSheet) {
    return createJsonResponse({ success: false, error: 'Main sheet not found' });
  }

  const allData = mainSheet.getDataRange().getValues();

  // מצא שורת מקור
  let sourceRow = -1, sourceData = null;
  // מצא שורת יעד
  let targetRow = -1, targetData = null;

  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == sourcePersonalNumber) { sourceRow = i + 1; sourceData = allData[i]; }
    if (allData[i][2] == targetPersonalNumber) { targetRow = i + 1; targetData = allData[i]; }
  }

  if (sourceRow === -1) {
    return createJsonResponse({ success: false, error: 'חייל המקור לא נמצא במערכת' });
  }
  if (targetRow === -1) {
    return createJsonResponse({ success: false, error: 'חייל היעד לא נמצא במערכת — יש להוסיפו תחילה דרך טופס הנשק' });
  }

  // העבר כל פריט שנבחר: נקה מהמקור, הגדר ביעד
  selectedItems.forEach(key => {
    const cols = ITEM_COLUMN_MAP[key];
    if (!cols) return;

    cols.forEach(colIdx => {
      const val = sourceData[colIdx];
      // הגדר ביעד
      mainSheet.getRange(targetRow, colIdx + 1).setValue(val);
      // נקה מהמקור
      mainSheet.getRange(sourceRow, colIdx + 1).setValue('');
    });
  });

  // עדכן גיליון מסגרת המקור אם קיים
  const sourceUnit = sourceData[5];
  if (sourceUnit) {
    const srcUnitSheet = ss.getSheetByName(sourceUnit);
    if (srcUnitSheet) {
      const srcUnitData = srcUnitSheet.getDataRange().getValues();
      for (let i = 1; i < srcUnitData.length; i++) {
        if (srcUnitData[i][2] == sourcePersonalNumber) {
          selectedItems.forEach(key => {
            if (ITEM_COLUMN_MAP[key]) {
              ITEM_COLUMN_MAP[key].forEach(colIdx => {
                srcUnitSheet.getRange(i + 1, colIdx + 1).setValue('');
              });
            }
          });
          break;
        }
      }
    }
  }

  // עדכן גיליון מסגרת היעד אם קיים
  const targetUnit = targetData[5];
  if (targetUnit) {
    const tgtUnitSheet = ss.getSheetByName(targetUnit);
    if (tgtUnitSheet) {
      const tgtUnitData = tgtUnitSheet.getDataRange().getValues();
      for (let i = 1; i < tgtUnitData.length; i++) {
        if (tgtUnitData[i][2] == targetPersonalNumber) {
          selectedItems.forEach(key => {
            const cols = ITEM_COLUMN_MAP[key];
            if (!cols) return;
            cols.forEach(colIdx => {
              tgtUnitSheet.getRange(i + 1, colIdx + 1).setValue(sourceData[colIdx]);
            });
          });
          break;
        }
      }
    }
  }

  // רשום בגיליון העברות (צור אם לא קיים)
  let transferSheet = ss.getSheetByName('העברות');
  if (!transferSheet) {
    transferSheet = ss.insertSheet('העברות');
    const headers = [
      "תאריך העברה", "מספר אישי מקור", "שם מקור", "מספר אישי יעד", "שם יעד",
      "פריטים שהועברו", "בוצע על ידי"
    ];
    transferSheet.appendRow(headers);
    const hr = transferSheet.getRange(1, 1, 1, headers.length);
    hr.setBackground("#1e3a5f");
    hr.setFontColor("#FFFFFF");
    hr.setFontWeight("bold");
    hr.setHorizontalAlignment("right");
  }

  transferSheet.appendRow([
    transferAt || new Date().toISOString(),
    sourcePersonalNumber,
    sourceData[1],       // שם מלא מקור
    targetPersonalNumber,
    targetData[1],       // שם מלא יעד
    selectedItems.join(', '),
    transferBy || 'unknown'
  ]);

  Logger.log('✓ Transfer completed: ' + selectedItems.join(', ') + ' from ' + sourcePersonalNumber + ' to ' + targetPersonalNumber);
  return createJsonResponse({
    success: true,
    message: 'Transfer completed'
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
  const existingRow = findExistingRow(sheet, data.personalNumber, 3); // עמודה C
  
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
  const existingRow = findExistingRow(mainSheet, data.personalNumber, 3);
  
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
    "תאריך ושעה", "שם מלא", "מספר אישי", "טלפון", "מייל", "מסגרת",
    "סוג נשק", "מספר נשק", "טריג׳", "ליאור", "פגיון", "זאבון", "m5",
    'שח"ע', "עכבר", "עדי", "עידו", "קירו", "משקפה", "מצפן", "ציין", "פק"
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
    timestamp,
    data.fullName,
    data.personalNumber,
    data.phone,
    data.email,
    data.unit || "",
    data.weaponType || "",
    data.weaponNumber || "",
    // כוונות - בדוק גם כוונת רגילה וגם כוונת נוספת
    (data.sightType === "טריג׳" ? data.sightNumber : "") || 
      (data.additionalSightType === "טריג׳" ? data.additionalSightNumber : "") || "",
    (data.sightType === "ליאור" ? data.sightNumber : "") || 
      (data.additionalSightType === "ליאור" ? data.additionalSightNumber : "") || "",
    (data.sightType === "פגיון" ? data.sightNumber : "") || 
      (data.additionalSightType === "פגיון" ? data.additionalSightNumber : "") || "",
    (data.sightType === "זאבון" ? data.sightNumber : "") || 
      (data.additionalSightType === "זאבון" ? data.additionalSightNumber : "") || "",
    (data.sightType === "m5" ? data.sightNumber : "") || 
      (data.additionalSightType === "m5" ? data.additionalSightNumber : "") || "",
    // אמרל"ים - שים מספר בעמודה המתאימה
    data.nvdType === 'שח"ע' ? (data.nvdNumber || "") : "",
    data.nvdType === "עכבר" ? (data.nvdNumber || "") : "",
    data.nvdType === "עדי" ? (data.nvdNumber || "") : "",
    data.nvdType === "עידו" ? (data.nvdNumber || "") : "",
    data.nvdType === "קירו" ? (data.nvdNumber || "") : "",
    // משקפה ומצפן - 1 או ריק
    data.hasBinoculars ? "1" : "",
    data.hasCompass ? "1" : "",
    // ציין ופק - מספר או ריק
    data.hasZayin ? (data.zayinNumber || "") : "",
    data.hasPak ? (data.pakNumber || "") : ""
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
    pdf.setName(`אישור_חתימה_${data.personalNumber}_${new Date().getTime()}.pdf`);
    
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
        .header { background: #2F5233; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header p { font-size: 14px; opacity: 0.9; }
        .content { background: white; padding: 20px; border-radius: 8px; }
        .field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }
        .field-label { font-weight: bold; min-width: 150px; color: #2F5233; }
        .field-value { flex: 1; }
        .disclaimer { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .signature-section { margin-top: 20px; text-align: center; }
        .signature-section img { max-width: 250px; border: 1px solid #ccc; padding: 3px; background: white; }
        .footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>✓ אישור חתימה על נשק</h1>
        <p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p>
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
        ${data.weaponType ? `<div class="field"><div class="field-label">סוג נשק:</div><div class="field-value">${data.weaponType}</div></div>` : ''}
        ${data.weaponNumber ? `<div class="field"><div class="field-label">מספר נשק:</div><div class="field-value">${data.weaponNumber}</div></div>` : ''}
        ${data.sightType ? `<div class="field"><div class="field-label">סוג כוונת:</div><div class="field-value">${data.sightType}</div></div>` : ''}
        ${data.sightNumber ? `<div class="field"><div class="field-label">מספר כוונת:</div><div class="field-value">${data.sightNumber}</div></div>` : ''}
        ${data.additionalSightType ? `<div class="field"><div class="field-label">סוג כוונת נוסף:</div><div class="field-value">${data.additionalSightType}</div></div>` : ''}
        ${data.additionalSightNumber ? `<div class="field"><div class="field-label">מספר כוונת נוסף:</div><div class="field-value">${data.additionalSightNumber}</div></div>` : ''}
        ${data.nvdType ? `<div class="field"><div class="field-label">סוג אמרל:</div><div class="field-value">${data.nvdType}</div></div>` : ''}
        ${data.nvdNumber ? `<div class="field"><div class="field-label">מספר אמרל:</div><div class="field-value">${data.nvdNumber}</div></div>` : ''}
        ${data.hasBinoculars ? `<div class="field"><div class="field-label">משקפה:</div><div class="field-value">כן</div></div>` : ''}
        ${data.hasCompass ? `<div class="field"><div class="field-label">מצפן:</div><div class="field-value">כן</div></div>` : ''}
        ${data.hasZayin ? `<div class="field"><div class="field-label">ציין:</div><div class="field-value">כן${data.zayinNumber ? ' - מספר: ' + data.zayinNumber : ''}</div></div>` : ''}
        ${data.hasPak ? `<div class="field"><div class="field-label">פק:</div><div class="field-value">כן${data.pakNumber ? ' - מספר: ' + data.pakNumber : ''}</div></div>` : ''}
      </div>
      
      <div class="disclaimer">
        <strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את אמצעי הלחימה והציוד המפורטים במסמך זה, 
        וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.
      </div>
      
      ${data.signature ? `
      <div class="signature-section">
        <div class="field-label" style="display: block; margin-bottom: 5px;">חתימת החייל:</div>
        <img src="${data.signature}" alt="חתימה"/>
      </div>` : ''}
      
      <div class="footer">
        <p>מסמך זה נוצר אוטומטית על ידי מערכת דוח צלם מקוון | © 2026 כל הזכויות שמורות</p>
      </div>
    </body>
    </html>
  `;
}

/**
 * שולח מייל עם קובץ PDF
 */
function sendEmail(data, pdf, timestamp) {
  const subject = `אישור חתימה על נשק - ${data.fullName}`;
  const body = `
שלום ${data.fullName},

אישור חתימתך על נשק ואמצעי לחימה נקלט במערכת בהצלחה.

פרטי החתימה:
━━━━━━━━━━━━━━━━━━━━━━
תאריך ושעה: ${timestamp}
מספר אישי: ${data.personalNumber}
${data.unit ? `מסגרת: ${data.unit}` : ''}
${data.weaponType ? `סוג נשק: ${data.weaponType}` : ''}
${data.weaponNumber ? `מספר נשק: ${data.weaponNumber}` : ''}

מצורף אישור PDF מפורט.

בברכה,
מערכת דוח צלם מקוון
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
    unit: "מפקדה",
    weaponType: "M4",
    weaponNumber: "123456"
  };
  
  try {
    generateAndSendPDF(testData);
    Logger.log('✅ Test email sent successfully!');
  } catch (error) {
    Logger.log('❌ Test failed: ' + error.toString());
  }
}
