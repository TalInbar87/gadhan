/**
 * ================================================================
 * Weapons Module - מודול נשקים
 * ================================================================
 * מבנה גיליון נשקים (כל הרשומות):
 * A(0)=תאריך ושעה | B(1)=שם מלא | C(2)=מספר אישי | D(3)=טלפון | E(4)=מייל
 * F(5)=מסגרת | G(6)=צוות
 * H(7)=נגב | I(8)=M16 | J(9)=M4 | K(10)=מטול
 * L(11)=טריג׳ | M(12)=ליאור | N(13)=פגיון | O(14)=זאבון | P(15)=m5
 * Q(16)=שח"ע | R(17)=עכבר | S(18)=עדי | T(19)=עידו | U(20)=קירו
 * V(21)=משקפה | W(22)=מצפן | X(23)=ציין | Y(24)=פק
 *
 * גיליון זיכויים: אותן עמודות A-Y + Z=פריטים שזוכו + AA=תאריך זיכוי + AB=זוכה על ידי
 * גיליון העברות: תאריך | מקור PN | שם מקור | יעד PN | שם יעד | פריטים | בוצע ע"י
 *
 * כל הפונקציות מחזירות plain object { success, message?, error? }
 * (הניתוב ל-HTTP response נעשה ב-Main.js)
 * ================================================================
 */

// מיפוי מפתחות פריטים לשמות עבריים (לשימוש במיילים)
const WEAPONS_ITEM_NAMES_HE = {
  negev:      'נגב',
  m16:        'M16',
  m4:         'M4',
  matol:      'מטול',
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
  pak:        'פק'
};

// מיפוי מפתחות פריטים לעמודות (0-indexed) בגיליון הנשקים
// A(0)=תאריך | B(1)=שם | C(2)=מ"א | D(3)=טל | E(4)=מייל | F(5)=מסגרת | G(6)=צוות
// H(7)=נגב | I(8)=M16 | J(9)=M4 | K(10)=מטול
// L(11)=טריג׳ | M(12)=ליאור | N(13)=פגיון | O(14)=זאבון | P(15)=m5
// Q(16)=שח"ע | R(17)=עכבר | S(18)=עדי | T(19)=עידו | U(20)=קירו
// V(21)=משקפה | W(22)=מצפן | X(23)=ציין | Y(24)=פק
const WEAPONS_ITEM_COLUMN_MAP = {
  negev:      [7],     // H  - נגב
  m16:        [8],     // I  - M16
  m4:         [9],     // J  - M4
  matol:      [10],    // K  - מטול
  trig:       [11],    // L  - טריג׳
  lior:       [12],    // M  - ליאור
  pagion:     [13],    // N  - פגיון
  zavon:      [14],    // O  - זאבון
  m5:         [15],    // P  - m5
  shacha:     [16],    // Q  - שח"ע
  achbar:     [17],    // R  - עכבר
  adi:        [18],    // S  - עדי
  ido:        [19],    // T  - עידו
  kiro:       [20],    // U  - קירו
  binoculars: [21],    // V  - משקפה
  compass:    [22],    // W  - מצפן
  zayin:      [23],    // X  - ציין
  pak:        [24]     // Y  - פק
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
          team:           rows[i][6]  || '',
          negev:          rows[i][7]  || '',
          m16:            rows[i][8]  || '',
          m4:             rows[i][9]  || '',
          matol:          rows[i][10] || '',
          trig:           rows[i][11] || '',
          lior:           rows[i][12] || '',
          pagion:         rows[i][13] || '',
          zavon:          rows[i][14] || '',
          m5:             rows[i][15] || '',
          shacha:         rows[i][16] || '',
          achbar:         rows[i][17] || '',
          adi:            rows[i][18] || '',
          ido:            rows[i][19] || '',
          kiro:           rows[i][20] || '',
          binoculars:     rows[i][21] == 1,
          compass:        rows[i][22] == 1,
          zayin:          rows[i][23] || '',
          pak:            rows[i][24] || ''
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
    'תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות',
    'נגב', 'M16', 'M4', 'מטול',
    "טריג׳", 'ליאור', 'פגיון', 'זאבון', 'm5',
    'שח"ע', 'עכבר', 'עדי', 'עידו', 'קירו',
    'משקפה', 'מצפן', 'ציין', 'פק'
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
    data.unit  || '',
    data.team  || '',
    // נשקים
    data.negev || '',
    data.m16   || '',
    data.m4    || '',
    data.matol || '',
    // כוונות
    data.trig   || '',
    data.lior   || '',
    data.pagion || '',
    data.zavon  || '',
    data.m5     || '',
    // אמרל"ים
    data.shacha || '',
    data.achbar || '',
    data.adi    || '',
    data.ido    || '',
    data.kiro   || '',
    // ציוד נוסף
    data.hasBinoculars ? '1' : '',
    data.hasCompass    ? '1' : '',
    data.hasZayin ? (data.zayinNumber || '') : '',
    data.hasPak   ? (data.pakNumber   || '') : ''
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
      'תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות',
      'נגב', 'M16', 'M4', 'מטול',
      "טריג׳", 'ליאור', 'פגיון', 'זאבון', 'm5',
      'שח"ע', 'עכבר', 'עדי', 'עידו', 'קירו',
      'משקפה', 'מצפן', 'ציין', 'פק',
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
        subject:     'אישור זיכוי נשק - ' + fullName,
        body:        'שלום ' + fullName + ',\n' +
                     'הציוד זוכה במערכת\n' +
                     'ע"י: ' + (creditBy || 'לא ידוע') + '\n\n' +
                     'מצ"ב קובץ אישור חתום',
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
    // עמודה Z (26): מיזוג רשימת פריטים שזוכו
    const prev = creditSheet.getRange(existingCreditRow, 26).getValue() || '';
    creditSheet.getRange(existingCreditRow, 26).setValue(
      prev ? prev + ', ' + selectedItems.join(', ') : selectedItems.join(', ')
    );
    // עמודות AA (27), AB (28): עדכון תאריך ומבצע
    creditSheet.getRange(existingCreditRow, 27).setValue(creditAt || new Date().toISOString());
    creditSheet.getRange(existingCreditRow, 28).setValue(creditBy || 'unknown');
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
        subject:     'אישור זיכוי נשק - ' + fullName,
        body:        'שלום ' + fullName + ',\n' +
                     'הציוד זוכה במערכת\n' +
                     'ע"י: ' + (creditBy || 'לא ידוע') + '\n\n' +
                     'מצ"ב קובץ אישור חתום',
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
  const weaponDefs = [
    { label: 'נגב',  col: 7  }, { label: 'M16',  col: 8  },
    { label: 'M4',   col: 9  }, { label: 'מטול', col: 10 }
  ];
  const sightDefs = [
    { label: "טריג׳", col: 11 }, { label: 'ליאור', col: 12 },
    { label: 'פגיון',  col: 13 }, { label: 'זאבון', col: 14 }, { label: 'm5', col: 15 }
  ];
  const nvdDefs = [
    { label: 'שח"ע', col: 16 }, { label: 'עכבר', col: 17 },
    { label: 'עדי',   col: 18 }, { label: 'עידו', col: 19 }, { label: 'קירו', col: 20 }
  ];
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var weaponRows = weaponDefs.filter(function(w) { return rowData[w.col]; })
    .map(function(w) { return f('נשק', w.label + ' — ' + rowData[w.col]); }).join('');
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
    weaponRows + sightRows + nvdRows +
    (rowData[21] ? f('משקפה', 'כן') : '') +
    (rowData[22] ? f('מצפן',  'כן') : '') +
    (rowData[23] ? f('ציין',  rowData[23]) : '') +
    (rowData[24] ? f('פק',    rowData[24]) : '') +
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
    negev:      { label: 'נגב',         cols: [7]     },
    m16:        { label: 'M16',         cols: [8]     },
    m4:         { label: 'M4',          cols: [9]     },
    matol:      { label: 'מטול',        cols: [10]    },
    trig:       { label: "טריג׳ כוונת", cols: [11]    },
    lior:       { label: 'ליאור כוונת', cols: [12]    },
    pagion:     { label: 'פגיון כוונת', cols: [13]    },
    zavon:      { label: 'זאבון כוונת', cols: [14]    },
    m5:         { label: 'm5 כוונת',    cols: [15]    },
    shacha:     { label: 'שח"ע אמרל',   cols: [16]    },
    achbar:     { label: 'עכבר אמרל',   cols: [17]    },
    adi:        { label: 'עדי אמרל',    cols: [18]    },
    ido:        { label: 'עידו אמרל',   cols: [19]    },
    kiro:       { label: 'קירו אמרל',   cols: [20]    },
    binoculars: { label: 'משקפה',       cols: [21]    },
    compass:    { label: 'מצפן',        cols: [22]    },
    zayin:      { label: 'ציין',        cols: [23]    },
    pak:        { label: 'פק',          cols: [24]    }
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
    (data.unit   ? '<div class="field"><div class="field-label">מסגרת:</div><div class="field-value">' + data.unit  + '</div></div>' : '') +
    (data.team   ? '<div class="field"><div class="field-label">צוות:</div><div class="field-value">'   + data.team  + '</div></div>' : '') +
    (data.negev  ? '<div class="field"><div class="field-label">נגב:</div><div class="field-value">'    + data.negev + '</div></div>' : '') +
    (data.m16    ? '<div class="field"><div class="field-label">M16:</div><div class="field-value">'    + data.m16   + '</div></div>' : '') +
    (data.m4     ? '<div class="field"><div class="field-label">M4:</div><div class="field-value">'     + data.m4    + '</div></div>' : '') +
    (data.matol  ? '<div class="field"><div class="field-label">מטול:</div><div class="field-value">'   + data.matol + '</div></div>' : '') +
    (data.trig   ? '<div class="field"><div class="field-label">כוונת טריג׳:</div><div class="field-value">'  + data.trig   + '</div></div>' : '') +
    (data.lior   ? '<div class="field"><div class="field-label">כוונת ליאור:</div><div class="field-value">'  + data.lior   + '</div></div>' : '') +
    (data.pagion ? '<div class="field"><div class="field-label">כוונת פגיון:</div><div class="field-value">'  + data.pagion + '</div></div>' : '') +
    (data.zavon  ? '<div class="field"><div class="field-label">כוונת זאבון:</div><div class="field-value">'  + data.zavon  + '</div></div>' : '') +
    (data.m5     ? '<div class="field"><div class="field-label">כוונת m5:</div><div class="field-value">'     + data.m5     + '</div></div>' : '') +
    (data.shacha ? '<div class="field"><div class="field-label">אמרל שח"ע:</div><div class="field-value">'    + data.shacha + '</div></div>' : '') +
    (data.achbar ? '<div class="field"><div class="field-label">אמרל עכבר:</div><div class="field-value">'    + data.achbar + '</div></div>' : '') +
    (data.adi    ? '<div class="field"><div class="field-label">אמרל עדי:</div><div class="field-value">'     + data.adi    + '</div></div>' : '') +
    (data.ido    ? '<div class="field"><div class="field-label">אמרל עידו:</div><div class="field-value">'    + data.ido    + '</div></div>' : '') +
    (data.kiro   ? '<div class="field"><div class="field-label">אמרל קירו:</div><div class="field-value">'    + data.kiro   + '</div></div>' : '') +
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
                 (data.unit  ? 'מסגרת: ' + data.unit + '\n' : '') +
                 (data.negev ? 'נגב: '  + data.negev + '\n' : '') +
                 (data.m16   ? 'M16: '  + data.m16   + '\n' : '') +
                 (data.m4    ? 'M4: '   + data.m4    + '\n' : '') +
                 (data.matol ? 'מטול: ' + data.matol + '\n' : '') +
                 '\nמצורף אישור PDF מפורט.\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
    attachments: [pdf]
  });
  Logger.log('✅ [Weapons] Email sent to: ' + data.email);
}
