/**
 * ================================================================
 * Weapons Module - מודול נשקים
 * ================================================================
 * מבנה גיליון נשקים (כל הרשומות):
 * A(0)=תאריך ושעה | B(1)=שם מלא | C(2)=מספר אישי
 * D(3)=טלפון | E(4)=מייל | F(5)=מסגרת
 * G(6)=סוג נשק | H(7)=מספר נשק
 * I(8)=טריג׳ | J(9)=ליאור | K(10)=פגיון | L(11)=זאבון | M(12)=m5
 * N(13)=שח"ע | O(14)=עכבר | P(15)=עדי | Q(16)=עידו | R(17)=קירו
 * S(18)=משקפה | T(19)=מצפן | U(20)=ציין | V(21)=פק
 *
 * גיליון זיכויים: אותן עמודות A-V + W=פריטים שזוכו + X=תאריך זיכוי + Y=זוכה על ידי
 * גיליון העברות: תאריך | מקור PN | שם מקור | יעד PN | שם יעד | פריטים | בוצע ע"י
 *
 * כל הפונקציות מחזירות plain object { success, message?, error? }
 * (הניתוב ל-HTTP response נעשה ב-Main.js)
 * ================================================================
 */

// מיפוי מפתחות פריטים לשמות עבריים (לשימוש במיילים)
const WEAPONS_ITEM_NAMES_HE = {
  weapon:     'נשק',
  trig:       "טריג'",
  lior:       'ליאור',
  pagion:     'פגיון',
  zavon:      'זאבון',
  m5:         'm5',
  shacha:     'שח"ע',
  achbar:     'עכבר',
  adi:        'עדי',
  ido:        'עידו',
  kiro:       'קירו',
  binoculars: 'משקפה',
  compass:    'מצפן',
  zayin:      'ציין',
  pak:        'פק',
  matol:      'מטול'
};

// מיפוי מפתחות פריטים לעמודות (0-indexed) בגיליון הנשקים
const WEAPONS_ITEM_COLUMN_MAP = {
  weapon:     [6, 7],  // G, H - סוג נשק + מספר נשק
  trig:       [8],     // I  - טריג׳
  lior:       [9],     // J  - ליאור
  pagion:     [10],    // K  - פגיון
  zavon:      [11],    // L  - זאבון
  m5:         [12],    // M  - m5
  shacha:     [13],    // N  - שח"ע
  achbar:     [14],    // O  - עכבר
  adi:        [15],    // P  - עדי
  ido:        [16],    // Q  - עידו
  kiro:       [17],    // R  - קירו
  binoculars: [18],    // S  - משקפה
  compass:    [19],    // T  - מצפן
  zayin:      [20],    // U  - ציין
  pak:        [21],    // V  - פק
  matol:      [22]     // W  - מטול
};

// ================================================================
// Check Personal Number
// ================================================================

/**
 * בדיקת קיום מספר אישי בגיליון נשקים
 * מחזיר JSONP response ישירות (נקרא מ-doGet)
 */
function weapons_checkPersonalNumber(personalNumber, callback) {
  Logger.log('🔍 [Weapons] Checking PN: ' + personalNumber);
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) return createJsonpResponse({ exists: false }, callback);

  const rows = mainSheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i][2] == personalNumber) { // עמודה C = מספר אישי
      return createJsonpResponse({
        exists: true,
        data: {
          personalNumber: rows[i][2],
          fullName:       rows[i][1],
          phone:          '0' + rows[i][3],
          email:          rows[i][4],
          unit:           rows[i][5],
          weaponType:     rows[i][6],
          weaponNumber:   rows[i][7],
          trig:           rows[i][8],
          lior:           rows[i][9],
          pagion:         rows[i][10],
          zavon:          rows[i][11],
          m5:             rows[i][12],
          shacha:         rows[i][13],
          achbar:         rows[i][14],
          adi:            rows[i][15],
          ido:            rows[i][16],
          kiro:           rows[i][17],
          binoculars:     rows[i][18] == 1,
          compass:        rows[i][19] == 1,
          zayin:          rows[i][20],
          pak:            rows[i][21],
          matol:          rows[i][22] || ''
        }
      }, callback);
    }
  }
  return createJsonpResponse({ exists: false }, callback);
}

// ================================================================
// Save to Sheet
// ================================================================

/**
 * שמירת נתוני חתימה בגיליון הנשקים (גיליון מסגרת + גיליון ראשי)
 */
function weapons_saveToSheet(data) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const ts = formatTimestamp();
  weapons_saveToUnitSheet(ss, data, ts);
  weapons_saveToMainSheet(ss, data, ts);
}

function weapons_saveToUnitSheet(ss, data, timestamp) {
  const sheetName = data.unit || CONFIG.WEAPONS.DEFAULT_UNIT;
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) sheet = weapons_createUnitSheet(ss, sheetName);

  const existingRow = findExistingRow(sheet, data.personalNumber, CONFIG.WEAPONS.PN_COLUMN);
  const rowData = weapons_prepareRowData(data, timestamp);

  if (existingRow) {
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ [Weapons] Updated unit sheet: ' + sheetName);
  } else {
    sheet.appendRow(rowData);
    Logger.log('✓ [Weapons] Added to unit sheet: ' + sheetName);
  }
}

function weapons_saveToMainSheet(ss, data, timestamp) {
  let mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) mainSheet = weapons_createUnitSheet(ss, CONFIG.WEAPONS.MAIN_SHEET_NAME);

  const existingRow = findExistingRow(mainSheet, data.personalNumber, CONFIG.WEAPONS.PN_COLUMN);
  const rowData = weapons_prepareRowData(data, timestamp);

  if (existingRow) {
    mainSheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ [Weapons] Updated main sheet');
  } else {
    mainSheet.appendRow(rowData);
    Logger.log('✓ [Weapons] Added to main sheet');
  }
}

function weapons_createUnitSheet(ss, sheetName) {
  const sheet = ss.insertSheet(sheetName);
  const headers = [
    'תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת',
    'סוג נשק', 'מספר נשק', "טריג׳", 'ליאור', 'פגיון', 'זאבון', 'm5',
    'שח"ע', 'עכבר', 'עדי', 'עידו', 'קירו', 'משקפה', 'מצפן', 'ציין', 'פק', 'מטול'
  ];
  sheet.appendRow(headers);
  const hr = sheet.getRange(1, 1, 1, headers.length);
  hr.setBackground(CONFIG.WEAPONS.HEADER_COLOR);
  hr.setFontColor('#FFFFFF');
  hr.setFontWeight('bold');
  hr.setHorizontalAlignment('right');
  Logger.log('✓ [Weapons] Created sheet: ' + sheetName);
  return sheet;
}

/**
 * פונקציית מיגרציה חד-פעמית: מוסיפה כותרת 'מטול' בעמודה W (23) לכל גיליונות הנשקים הקיימים
 * יש להריץ פעם אחת מה-GAS editor
 */
function weapons_addMatolHeaderToExistingSheets() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const sheets = ss.getSheets();
  const MATOL_COL = 23; // עמודה W, 1-indexed

  sheets.forEach(function(sheet) {
    const name = sheet.getName();
    // דלג על גיליון זיכויים
    if (name === CONFIG.WEAPONS.CREDIT_SHEET_NAME) return;

    const lastCol = sheet.getLastColumn();
    const firstRow = sheet.getRange(1, 1, 1, Math.max(lastCol, MATOL_COL)).getValues()[0];

    // בדוק אם כבר קיים 'מטול' בעמודה W
    if (firstRow[MATOL_COL - 1] === 'מטול') {
      Logger.log('✓ [Migration] Sheet "' + name + '" already has מטול header');
      return;
    }

    // הוסף כותרת מטול בעמודה W
    sheet.getRange(1, MATOL_COL).setValue('מטול');
    // עצב את הכותרת החדשה כמו שאר הכותרות
    const cell = sheet.getRange(1, MATOL_COL);
    cell.setBackground(CONFIG.WEAPONS.HEADER_COLOR);
    cell.setFontColor('#FFFFFF');
    cell.setFontWeight('bold');
    cell.setHorizontalAlignment('right');
    Logger.log('✓ [Migration] Added מטול header to sheet "' + name + '"');
  });

  Logger.log('✅ [Migration] weapons_addMatolHeaderToExistingSheets complete');
}

function weapons_prepareRowData(data, timestamp) {
  return [
    timestamp,
    data.fullName,
    data.personalNumber,
    data.phone,
    data.email,
    data.unit || '',
    data.weaponType   || '',
    data.weaponNumber || '',
    // כוונות - כוונה ראשית ו/או נוספת
    (data.sightType === "טריג׳" ? data.sightNumber : '') || (data.additionalSightType === "טריג׳" ? data.additionalSightNumber : '') || '',
    (data.sightType === 'ליאור'  ? data.sightNumber : '') || (data.additionalSightType === 'ליאור'  ? data.additionalSightNumber : '') || '',
    (data.sightType === 'פגיון'  ? data.sightNumber : '') || (data.additionalSightType === 'פגיון'  ? data.additionalSightNumber : '') || '',
    (data.sightType === 'זאבון'  ? data.sightNumber : '') || (data.additionalSightType === 'זאבון'  ? data.additionalSightNumber : '') || '',
    (data.sightType === 'm5'     ? data.sightNumber : '') || (data.additionalSightType === 'm5'     ? data.additionalSightNumber : '') || '',
    // אמרל"ים
    data.nvdType === 'שח"ע' ? (data.nvdNumber || '') : '',
    data.nvdType === 'עכבר'  ? (data.nvdNumber || '') : '',
    data.nvdType === 'עדי'   ? (data.nvdNumber || '') : '',
    data.nvdType === 'עידו'  ? (data.nvdNumber || '') : '',
    data.nvdType === 'קירו'  ? (data.nvdNumber || '') : '',
    // ציוד נוסף
    data.hasBinoculars ? '1' : '',
    data.hasCompass    ? '1' : '',
    data.hasZayin ? (data.zayinNumber || '') : '',
    data.hasPak   ? (data.pakNumber   || '') : '',
    data.weaponType === 'מטול' ? (data.matolNumber || '') : ''
  ];
}

// ================================================================
// Credit Sheet Helpers
// ================================================================

/**
 * מחזיר שורה (1-indexed) של מספר אישי בגיליון זיכויים, או -1
 * מספר אישי נמצא בעמודה C (index 2) בגיליון זיכויים של נשקים
 */
function weapons_findCreditRow(creditSheet, personalNumber) {
  if (creditSheet.getLastRow() < 2) return -1;
  const rows = creditSheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i][2] == personalNumber) return i + 1; // column C
  }
  return -1;
}

/**
 * מחזיר/יוצר גיליון זיכויים עם כותרות אחידות
 * עמודות: A-V (נתוני חייל) + W (פריטים שזוכו) + X (תאריך זיכוי) + Y (זוכה על ידי)
 */
function weapons_getOrCreateCreditSheet(ss) {
  let sheet = ss.getSheetByName('זיכויים');
  if (!sheet) {
    sheet = ss.insertSheet('זיכויים');
    const headers = [
      'תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת',
      'סוג נשק', 'מספר נשק', "טריג׳", 'ליאור', 'פגיון', 'זאבון', 'm5',
      'שח"ע', 'עכבר', 'עדי', 'עידו', 'קירו', 'משקפה', 'מצפן', 'ציין', 'פק', 'מטול',
      'פריטים שזוכו', 'תאריך זיכוי', 'זוכה על ידי'
    ];
    sheet.appendRow(headers);
    const hr = sheet.getRange(1, 1, 1, headers.length);
    hr.setBackground('#8B0000');
    hr.setFontColor('#FFFFFF');
    hr.setFontWeight('bold');
    hr.setHorizontalAlignment('right');
  }
  return sheet;
}

// ================================================================
// Full Credit
// ================================================================

/**
 * זיכוי מלא - העברת רשומה לגיליון זיכויים + מחיקה מגיליונות
 * @returns {{ success: boolean, message?: string, error?: string }}
 */
function weapons_handleCredit(data) {
  const { personalNumber, creditAt, creditBy } = data;
  Logger.log('💳 [Weapons] Full credit: ' + personalNumber);

  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) return { success: false, error: 'Main sheet not found' };

  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1, rowData = null;
  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == personalNumber) { foundRow = i + 1; rowData = allData[i]; break; }
  }
  if (foundRow === -1) return { success: false, error: 'Record not found' };

  const creditSheet = weapons_getOrCreateCreditSheet(ss);

  // הוסף לזיכויים רק אם לא קיים
  if (weapons_findCreditRow(creditSheet, personalNumber) === -1) {
    creditSheet.appendRow([...rowData, 'הכל', creditAt || new Date().toISOString(), creditBy || 'unknown']);
    Logger.log('✓ Added to credit sheet');
  } else {
    Logger.log('⚠️ Already in credit sheet - skipping duplicate');
  }

  // מחק מהגיליון הראשי
  mainSheet.deleteRow(foundRow);
  Logger.log('✓ Deleted from main sheet');

  // מחק מגיליון המסגרת
  const unit = rowData[5];
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const ud = unitSheet.getDataRange().getValues();
      for (let i = 1; i < ud.length; i++) {
        if (ud[i][2] == personalNumber) { unitSheet.deleteRow(i + 1); break; }
      }
    }
  }

  // שלח מייל אישור זיכוי לחייל עם PDF מצורף
  try {
    const email    = rowData[4];
    const fullName = rowData[1];
    if (email) {
      const ts  = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
      const html = weapons_createCreditPdfHtml(rowData, creditBy, data.creditSignature, ts);
      const blob = Utilities.newBlob(html, 'text/html', 'credit.html');
      const pdf  = blob.getAs('application/pdf');
      pdf.setName('אישור_זיכוי_' + personalNumber + '_' + Date.now() + '.pdf');
      MailApp.sendEmail({
        to:          email,
        subject:     'אישור זיכוי ציוד - ' + fullName,
        body:        'שלום ' + fullName + ',\n\n' +
                     'כל הציוד שלך הוחזר ורשומך זוכתה במערכת.\n\n' +
                     'מספר אישי: ' + personalNumber + '\n' +
                     (unit ? 'מסגרת: ' + unit + '\n' : '') +
                     'בוצע על ידי: ' + (creditBy || 'לא ידוע') + '\n' +
                     'תאריך: ' + ts + '\n\n' +
                     'מצורף אישור PDF מפורט.\n\n' +
                     'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
        attachments: [pdf]
      });
      Logger.log('✅ [Weapons] Credit email with PDF sent to: ' + email);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Credit email failed: ' + emailErr);
  }

  return { success: true, message: 'Credit completed' };
}

// ================================================================
// Partial Credit
// ================================================================

/**
 * זיכוי חלקי - זיכוי פריטים נבחרים בלבד
 * @returns {{ success: boolean, message?: string, error?: string }}
 */
function weapons_handlePartialCredit(data) {
  const { personalNumber, selectedItems, creditBy, creditAt } = data;
  Logger.log('💳 [Weapons] Partial credit: ' + personalNumber + ', items: ' + JSON.stringify(selectedItems));

  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) return { success: false, error: 'Main sheet not found' };

  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1, rowData = null;
  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == personalNumber) { foundRow = i + 1; rowData = allData[i]; break; }
  }
  if (foundRow === -1) return { success: false, error: 'Record not found' };

  const creditSheet = weapons_getOrCreateCreditSheet(ss);
  const existingCreditRow = weapons_findCreditRow(creditSheet, personalNumber);

  if (existingCreditRow === -1) {
    // שורה חדשה: העתק נתוני חייל, נקה פריטים שלא נבחרו
    const cr = [...rowData];
    Object.keys(WEAPONS_ITEM_COLUMN_MAP).forEach(key => {
      if (!selectedItems.includes(key)) {
        WEAPONS_ITEM_COLUMN_MAP[key].forEach(ci => { cr[ci] = ''; });
      }
    });
    creditSheet.appendRow([
      ...cr,
      selectedItems.join(', '),
      creditAt || new Date().toISOString(),
      creditBy || 'unknown'
    ]);
    Logger.log('✓ New credit row added for ' + personalNumber);
  } else {
    // שורה קיימת: עדכן ערכי פריטים נבחרים + מיזוג עמודת "פריטים שזוכו"
    selectedItems.forEach(key => {
      if (WEAPONS_ITEM_COLUMN_MAP[key]) {
        WEAPONS_ITEM_COLUMN_MAP[key].forEach(ci => {
          creditSheet.getRange(existingCreditRow, ci + 1).setValue(rowData[ci]);
        });
      }
    });
    // עמודה X (24): מיזוג רשימת פריטים (W=מטול הוסר, X=פריטים שזוכו)
    const prev = creditSheet.getRange(existingCreditRow, 24).getValue() || '';
    creditSheet.getRange(existingCreditRow, 24).setValue(
      prev ? prev + ', ' + selectedItems.join(', ') : selectedItems.join(', ')
    );
    // עמודות Y (25), Z (26): עדכון תאריך ומבצע
    creditSheet.getRange(existingCreditRow, 25).setValue(creditAt || new Date().toISOString());
    creditSheet.getRange(existingCreditRow, 26).setValue(creditBy || 'unknown');
    Logger.log('✓ Existing credit row updated for ' + personalNumber);
  }

  // נקה פריטים שנבחרו מהגיליון הראשי
  selectedItems.forEach(key => {
    if (WEAPONS_ITEM_COLUMN_MAP[key]) {
      WEAPONS_ITEM_COLUMN_MAP[key].forEach(ci => {
        mainSheet.getRange(foundRow, ci + 1).setValue('');
      });
    }
  });

  // נקה גם מגיליון המסגרת
  const unit = rowData[5];
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const ud = unitSheet.getDataRange().getValues();
      for (let i = 1; i < ud.length; i++) {
        if (ud[i][2] == personalNumber) {
          selectedItems.forEach(key => {
            if (WEAPONS_ITEM_COLUMN_MAP[key]) {
              WEAPONS_ITEM_COLUMN_MAP[key].forEach(ci => {
                unitSheet.getRange(i + 1, ci + 1).setValue('');
              });
            }
          });
          break;
        }
      }
    }
  }

  // שלח מייל אישור זיכוי חלקי לחייל עם PDF מצורף
  try {
    const email    = rowData[4];
    const fullName = rowData[1];
    if (email) {
      const ts      = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
      const itemsHe = selectedItems.map(k => WEAPONS_ITEM_NAMES_HE[k] || k).join(', ');
      const html    = weapons_createPartialCreditPdfHtml(rowData, selectedItems, creditBy, data.creditSignature, ts);
      const blob    = Utilities.newBlob(html, 'text/html', 'partial_credit.html');
      const pdf     = blob.getAs('application/pdf');
      pdf.setName('אישור_זיכוי_חלקי_' + personalNumber + '_' + Date.now() + '.pdf');
      MailApp.sendEmail({
        to:          email,
        subject:     'אישור זיכוי חלקי - ' + fullName,
        body:        'שלום ' + fullName + ',\n\n' +
                     'הציוד הבא זוכה ממשקך:\n' + itemsHe + '\n\n' +
                     'מספר אישי: ' + personalNumber + '\n' +
                     (unit ? 'מסגרת: ' + unit + '\n' : '') +
                     'בוצע על ידי: ' + (creditBy || 'לא ידוע') + '\n' +
                     'תאריך: ' + ts + '\n\n' +
                     'מצורף אישור PDF מפורט.\n\n' +
                     'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
        attachments: [pdf]
      });
      Logger.log('✅ [Weapons] Partial credit email with PDF sent to: ' + email);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Partial credit email failed: ' + emailErr);
  }

  return { success: true, message: 'Partial credit completed' };
}

// ================================================================
// Transfer Items
// ================================================================

/**
 * העברת פריטים - מנקה מחייל מקור ומוסיף לחייל יעד
 * @returns {{ success: boolean, message?: string, error?: string }}
 */
function weapons_handleTransferItems(data) {
  const { sourcePersonalNumber, targetPersonalNumber, selectedItems, transferBy, transferAt } = data;
  Logger.log('🔄 [Weapons] Transfer ' + sourcePersonalNumber + ' → ' + targetPersonalNumber);

  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) return { success: false, error: 'Main sheet not found' };

  const allData = mainSheet.getDataRange().getValues();
  let sourceRow = -1, sourceData = null;
  let targetRow = -1, targetData = null;

  for (let i = 1; i < allData.length; i++) {
    if (allData[i][2] == sourcePersonalNumber) { sourceRow = i + 1; sourceData = allData[i]; }
    if (allData[i][2] == targetPersonalNumber) { targetRow = i + 1; targetData = allData[i]; }
  }

  if (sourceRow === -1) return { success: false, error: 'חייל המקור לא נמצא במערכת' };
  if (targetRow === -1) return { success: false, error: 'חייל היעד לא נמצא במערכת — יש להוסיפו תחילה דרך טופס הנשק' };

  // בדוק שלחייל היעד אין כבר ציוד מהסוגים המועברים
  const conflictingItems = selectedItems.filter(key => {
    const cols = WEAPONS_ITEM_COLUMN_MAP[key];
    if (!cols) return false;
    return cols.some(ci => {
      const val = targetData[ci];
      return val !== '' && val !== null && val !== undefined && val != 0 && val !== false;
    });
  });

  if (conflictingItems.length > 0) {
    const names = conflictingItems.map(k => WEAPONS_ITEM_NAMES_HE[k] || k).join(', ');
    Logger.log('⛔ Transfer blocked — target already has: ' + names);
    return {
      success: false,
      error:   'ההעברה לא בוצעה — לחייל היעד (' + targetData[1] + ') כבר קיים: ' + names
    };
  }

  // העבר ערכים: הגדר ביעד, נקה ממקור
  selectedItems.forEach(key => {
    const cols = WEAPONS_ITEM_COLUMN_MAP[key];
    if (!cols) return;
    cols.forEach(ci => {
      mainSheet.getRange(targetRow, ci + 1).setValue(sourceData[ci]);
      mainSheet.getRange(sourceRow, ci + 1).setValue('');
    });
  });

  // עדכן גיליון מסגרת מקור
  const srcUnit = sourceData[5];
  if (srcUnit) {
    const srcSheet = ss.getSheetByName(srcUnit);
    if (srcSheet) {
      const sd = srcSheet.getDataRange().getValues();
      for (let i = 1; i < sd.length; i++) {
        if (sd[i][2] == sourcePersonalNumber) {
          selectedItems.forEach(key => {
            if (WEAPONS_ITEM_COLUMN_MAP[key]) {
              WEAPONS_ITEM_COLUMN_MAP[key].forEach(ci => {
                srcSheet.getRange(i + 1, ci + 1).setValue('');
              });
            }
          });
          break;
        }
      }
    }
  }

  // עדכן גיליון מסגרת יעד
  const tgtUnit = targetData[5];
  if (tgtUnit) {
    const tgtSheet = ss.getSheetByName(tgtUnit);
    if (tgtSheet) {
      const td = tgtSheet.getDataRange().getValues();
      for (let i = 1; i < td.length; i++) {
        if (td[i][2] == targetPersonalNumber) {
          selectedItems.forEach(key => {
            const cols = WEAPONS_ITEM_COLUMN_MAP[key];
            if (!cols) return;
            cols.forEach(ci => {
              tgtSheet.getRange(i + 1, ci + 1).setValue(sourceData[ci]);
            });
          });
          break;
        }
      }
    }
  }

  // רשום בגיליון העברות
  let transferSheet = ss.getSheetByName('העברות');
  if (!transferSheet) {
    transferSheet = ss.insertSheet('העברות');
    const headers = [
      'תאריך העברה', 'מספר אישי מקור', 'שם מקור',
      'מספר אישי יעד', 'שם יעד', 'פריטים שהועברו', 'בוצע על ידי'
    ];
    transferSheet.appendRow(headers);
    const hr = transferSheet.getRange(1, 1, 1, headers.length);
    hr.setBackground('#1e3a5f');
    hr.setFontColor('#FFFFFF');
    hr.setFontWeight('bold');
    hr.setHorizontalAlignment('right');
  }
  transferSheet.appendRow([
    transferAt || new Date().toISOString(),
    sourcePersonalNumber, sourceData[1],  // שם מקור
    targetPersonalNumber, targetData[1],  // שם יעד
    selectedItems.join(', '),
    transferBy || 'unknown'
  ]);

  // שלח מיילים למקור וליעד
  try {
    const ts      = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    const itemsHe = selectedItems.map(k => WEAPONS_ITEM_NAMES_HE[k] || k).join(', ');

    if (sourceData[4]) {
      MailApp.sendEmail({
        to:      sourceData[4],
        subject: 'אישור העברת ציוד - ' + sourceData[1],
        body:    'שלום ' + sourceData[1] + ',\n\n' +
                 'הציוד הבא הועבר ממשקך לחייל ' + targetData[1] +
                 ' (מ"א ' + targetPersonalNumber + '):\n' + itemsHe + '\n\n' +
                 'בוצע על ידי: ' + (transferBy || 'לא ידוע') + '\n' +
                 'תאריך: ' + ts + '\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219'
      });
      Logger.log('✅ [Weapons] Transfer email sent to source: ' + sourceData[4]);
    }

    if (targetData[4]) {
      MailApp.sendEmail({
        to:      targetData[4],
        subject: 'קבלת ציוד מועבר - ' + targetData[1],
        body:    'שלום ' + targetData[1] + ',\n\n' +
                 'הציוד הבא הועבר אליך מחייל ' + sourceData[1] +
                 ' (מ"א ' + sourcePersonalNumber + '):\n' + itemsHe + '\n\n' +
                 'בוצע על ידי: ' + (transferBy || 'לא ידוע') + '\n' +
                 'תאריך: ' + ts + '\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219'
      });
      Logger.log('✅ [Weapons] Transfer email sent to target: ' + targetData[4]);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Transfer email failed: ' + emailErr);
  }

  Logger.log('✓ Transfer completed');
  return { success: true, message: 'Transfer completed' };
}

// ================================================================
// PDF & Email
// ================================================================

// ────────────────────────────────────────────────────────────────
// Credit PDF helpers (full + partial)
// ────────────────────────────────────────────────────────────────

/**
 * מייצר HTML לPDF זיכוי מלא — בנוי מנתוני rowData של הגיליון
 */
function weapons_createCreditPdfHtml(rowData, creditBy, creditSignature, ts) {
  const sightDefs = [
    { label: "טריג׳", col: 8  }, { label: 'ליאור', col: 9  },
    { label: 'פגיון',  col: 10 }, { label: 'זאבון', col: 11 }, { label: 'm5', col: 12 }
  ];
  const nvdDefs = [
    { label: 'שח"ע', col: 13 }, { label: 'עכבר', col: 14 },
    { label: 'עדי',   col: 15 }, { label: 'עידו', col: 16 }, { label: 'קירו', col: 17 }
  ];
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var sightRows = sightDefs.filter(function(s) { return rowData[s.col]; })
    .map(function(s) { return f('כוונת', s.label + ' — ' + rowData[s.col]); }).join('');
  var nvdRows = nvdDefs.filter(function(n) { return rowData[n.col]; })
    .map(function(n) { return f('אמרל', n.label + ' — ' + rowData[n.col]); }).join('');

  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #8B0000; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.header p { font-size: 14px; opacity: 0.9; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #8B0000; }' +
    '.field-value { flex: 1; }' +
    '.sig { margin-top: 20px; text-align: center; }' +
    '.sig img { max-width: 250px; border: 1px solid #ccc; padding: 3px; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>✓ אישור זיכוי ציוד - נשקים</h1>' +
    '<p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    f('תאריך זיכוי', ts) +
    f('שם מלא',      rowData[1]) +
    f('מספר אישי',   String(rowData[2])) +
    f('מסגרת',       rowData[5]) +
    f('סוג נשק',     rowData[6]) +
    f('מספר נשק',    rowData[7]) +
    sightRows + nvdRows +
    (rowData[18] ? f('משקפה', 'כן') : '') +
    (rowData[19] ? f('מצפן',  'כן') : '') +
    (rowData[20] ? f('ציין',  rowData[20]) : '') +
    (rowData[21] ? f('פק',    rowData[21]) : '') +
    (rowData[22] ? f('מטול',  rowData[22]) : '') +
    f('זוכה על ידי', creditBy || '') +
    '</div>' +
    (creditSignature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת המאשר:</div><img src="' + creditSignature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

/**
 * מייצר HTML לPDF זיכוי חלקי — מציג רק את הפריטים שנבחרו
 */
function weapons_createPartialCreditPdfHtml(rowData, selectedItems, creditBy, creditSignature, ts) {
  var ITEM_DEFS = {
    weapon:     { label: 'נשק',         cols: [6, 7]  },
    trig:       { label: "טריג׳ כוונת", cols: [8]     },
    lior:       { label: 'ליאור כוונת', cols: [9]     },
    pagion:     { label: 'פגיון כוונת', cols: [10]    },
    zavon:      { label: 'זאבון כוונת', cols: [11]    },
    m5:         { label: 'm5 כוונת',    cols: [12]    },
    shacha:     { label: 'שח"ע אמרל',   cols: [13]    },
    achbar:     { label: 'עכבר אמרל',   cols: [14]    },
    adi:        { label: 'עדי אמרל',    cols: [15]    },
    ido:        { label: 'עידו אמרל',   cols: [16]    },
    kiro:       { label: 'קירו אמרל',   cols: [17]    },
    binoculars: { label: 'משקפה',       cols: [18]    },
    compass:    { label: 'מצפן',        cols: [19]    },
    zayin:      { label: 'ציין',        cols: [20]    },
    pak:        { label: 'פק',          cols: [21]    },
    matol:      { label: 'מטול',        cols: [22]    }
  };
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var itemRows = selectedItems.map(function(key) {
    var def = ITEM_DEFS[key];
    if (!def) return '';
    var vals = def.cols.map(function(c) { return rowData[c]; }).filter(function(v) { return v && v !== '' && v != 0; });
    return f(def.label, vals.length > 0 ? vals.join(' — ') : 'כן');
  }).join('');

  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #7B3F00; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.header p { font-size: 14px; opacity: 0.9; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #7B3F00; }' +
    '.field-value { flex: 1; }' +
    '.sig { margin-top: 20px; text-align: center; }' +
    '.sig img { max-width: 250px; border: 1px solid #ccc; padding: 3px; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>✓ אישור זיכוי חלקי - נשקים</h1>' +
    '<p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    f('תאריך זיכוי', ts) +
    f('שם מלא',      rowData[1]) +
    f('מספר אישי',   String(rowData[2])) +
    f('מסגרת',       rowData[5]) +
    itemRows +
    f('זוכה על ידי', creditBy || '') +
    '</div>' +
    (creditSignature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת המאשר:</div><img src="' + creditSignature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

function weapons_generateAndSendPDF(data) {
  const ts = formatTimestamp();
  const blob = Utilities.newBlob(weapons_createPdfHtml(data, ts), 'text/html', 'checkout.html');
  const pdf  = blob.getAs('application/pdf');
  pdf.setName('אישור_חתימה_' + data.personalNumber + '_' + Date.now() + '.pdf');
  weapons_sendEmail(data, pdf, ts);
}

function weapons_createPdfHtml(data, timestamp) {
  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #2F5233; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.header p { font-size: 14px; opacity: 0.9; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #2F5233; }' +
    '.field-value { flex: 1; }' +
    '.disclaimer { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }' +
    '.sig { margin-top: 20px; text-align: center; }' +
    '.sig img { max-width: 250px; border: 1px solid #ccc; padding: 3px; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>✓ אישור חתימה על נשק</h1>' +
    '<p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    '<div class="field"><div class="field-label">תאריך ושעה:</div><div class="field-value">' + timestamp + '</div></div>' +
    '<div class="field"><div class="field-label">שם מלא:</div><div class="field-value">' + data.fullName + '</div></div>' +
    '<div class="field"><div class="field-label">מספר אישי:</div><div class="field-value">' + data.personalNumber + '</div></div>' +
    '<div class="field"><div class="field-label">טלפון:</div><div class="field-value">' + data.phone + '</div></div>' +
    (data.unit         ? '<div class="field"><div class="field-label">מסגרת:</div><div class="field-value">'         + data.unit         + '</div></div>' : '') +
    (data.weaponType   ? '<div class="field"><div class="field-label">סוג נשק:</div><div class="field-value">'       + data.weaponType   + '</div></div>' : '') +
    (data.weaponNumber ? '<div class="field"><div class="field-label">מספר נשק:</div><div class="field-value">'      + data.weaponNumber + '</div></div>' : '') +
    (data.sightType    ? '<div class="field"><div class="field-label">סוג כוונת:</div><div class="field-value">'     + data.sightType    + '</div></div>' : '') +
    (data.sightNumber  ? '<div class="field"><div class="field-label">מספר כוונת:</div><div class="field-value">'    + data.sightNumber  + '</div></div>' : '') +
    (data.additionalSightType   ? '<div class="field"><div class="field-label">כוונת נוספת:</div><div class="field-value">'       + data.additionalSightType   + '</div></div>' : '') +
    (data.additionalSightNumber ? '<div class="field"><div class="field-label">מספר כוונת נוסף:</div><div class="field-value">'   + data.additionalSightNumber + '</div></div>' : '') +
    (data.nvdType      ? '<div class="field"><div class="field-label">סוג אמרל:</div><div class="field-value">'      + data.nvdType      + '</div></div>' : '') +
    (data.nvdNumber    ? '<div class="field"><div class="field-label">מספר אמרל:</div><div class="field-value">'     + data.nvdNumber    + '</div></div>' : '') +
    (data.hasBinoculars ? '<div class="field"><div class="field-label">משקפה:</div><div class="field-value">כן</div></div>' : '') +
    (data.hasCompass    ? '<div class="field"><div class="field-label">מצפן:</div><div class="field-value">כן</div></div>'   : '') +
    (data.hasZayin ? '<div class="field"><div class="field-label">ציין:</div><div class="field-value">כן' + (data.zayinNumber ? ' - ' + data.zayinNumber : '') + '</div></div>' : '') +
    (data.hasPak   ? '<div class="field"><div class="field-label">פק:</div><div class="field-value">כן'   + (data.pakNumber   ? ' - ' + data.pakNumber   : '') + '</div></div>' : '') +
    '</div>' +
    '<div class="disclaimer"><strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את אמצעי הלחימה והציוד המפורטים במסמך זה, וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.</div>' +
    (data.signature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת החייל:</div><img src="' + data.signature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

function weapons_sendEmail(data, pdf, timestamp) {
  MailApp.sendEmail({
    to:          data.email,
    subject:     'אישור חתימה על נשק - ' + data.fullName,
    body:        'שלום ' + data.fullName + ',\n\n' +
                 'אישור חתימתך על נשק ואמצעי לחימה נקלט במערכת בהצלחה.\n\n' +
                 'תאריך: ' + timestamp + '\n' +
                 'מספר אישי: ' + data.personalNumber + '\n' +
                 (data.unit       ? 'מסגרת: ' + data.unit       + '\n' : '') +
                 (data.weaponType ? 'סוג נשק: ' + data.weaponType + '\n' : '') +
                 '\nמצורף אישור PDF מפורט.\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
    attachments: [pdf]
  });
  Logger.log('✅ [Weapons] Email sent to: ' + data.email);
}
