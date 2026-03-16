/**
 * ================================================================
 * Weapons Module - מודול נשקים
 * ================================================================
 * מבנה גיליון נשקים (כל הרשומות):
 * A(0)=תאריך ושעה | B(1)=שם מלא | C(2)=מספר אישי | D(3)=טלפון | E(4)=מייל
 * F(5)=מסגרת | G(6)=צוות
 * H(7)-BM(64) = 58 פריטי ציוד (ראה WEAPONS_ITEM_LIST)
 * גיליון זיכויים: A-BM + BN=פריטים שזוכו + BO=תאריך זיכוי + BP=זוכה על ידי
 * גיליון העברות: תאריך | מקור PN | שם מקור | יעד PN | שם יעד | פריטים | בוצע ע"י
 *
 * כל הפונקציות מחזירות plain object { success, message?, error? }
 * (הניתוב ל-HTTP response נעשה ב-Main.js)
 * ================================================================
 */

// רשימת פריטי הציוד — מקור האמת היחיד (מפה key→label→col)
const WEAPONS_ITEM_LIST = [
  { key: 'roskM16',         label: 'רוס"ק M16',        col: 7  },
  { key: 'roskM4',          label: 'רוס"ק M4',         col: 8  },
  { key: 'negev',           label: 'נגב',               col: 9  },
  { key: 'mag',             label: 'מאג',               col: 10 },
  { key: 'matol',           label: 'מטול',              col: 11 },
  { key: 'baret',           label: 'בארט',              col: 12 },
  { key: 'trig',            label: 'טריג',              col: 13 },
  { key: 'm5',              label: 'כוונת M5',          col: 14 },
  { key: 'pictini',         label: 'פיקטיני',           col: 15 },
  { key: 'mepro',           label: 'מפרו',              col: 16 },
  { key: 'zayinNegev',      label: 'ציין נגב',          col: 17 },
  { key: 'shacha',          label: 'שח"ע',              col: 18 },
  { key: 'lior',            label: 'ליאור',             col: 19 },
  { key: 'zavon',           label: 'זאבון',             col: 20 },
  { key: 'akila6',          label: 'אקילה*6',           col: 21 },
  { key: 'binoculars',      label: 'משקפת',             col: 22 },
  { key: 'compass',         label: 'מצפן',              col: 23 },
  { key: 'armon',           label: 'ערמון',             col: 24 },
  { key: 'thermalMarker',   label: 'סמן טרמי לחיר',    col: 25 },
  { key: 'achbar',          label: 'עכבר',              col: 26 },
  { key: 'lpl',             label: 'LPL',               col: 27 },
  { key: 'yarour',          label: 'יראור',             col: 28 },
  { key: 'adi',             label: 'עדי',               col: 29 },
  { key: 'matolHandasi',    label: 'מט"ל הנדסי',       col: 30 },
  { key: 'matolSarug',      label: 'מט"ל סרוג',        col: 31 },
  { key: 'makabim',         label: 'מכבים',             col: 32 },
  { key: 'shabang',         label: 'שבנג',              col: 33 },
  { key: 'pagion',          label: 'פגיון',             col: 34 },
  { key: 'sightPagion',     label: 'כוונת לפגיון',     col: 35 },
  { key: 'ido',             label: 'עידו',              col: 36 },
  { key: 'leopold',         label: 'לאופולד',           col: 37 },
  { key: 'noa',             label: 'נועה',              col: 38 },
  { key: 'amit',            label: 'עמית',              col: 39 },
  { key: 'yarin',           label: 'ירין',              col: 40 },
  { key: 'shabshavet',      label: 'שבשבת',             col: 41 },
  { key: 'laserMatol',      label: 'סמן לייזר למטול',  col: 42 },
  { key: 'metzitzan',       label: 'מציצן',             col: 43 },
  { key: 'rigit',           label: 'ריגיט',             col: 44 },
  { key: 'magenOz',         label: 'מגן עוז',           col: 45 },
  { key: 'boresight',       label: 'בורסייט',           col: 46 },
  { key: 'kundson',         label: 'קונדסון',           col: 47 },
  { key: 'makhpal',         label: 'מכפל',              col: 48 },
  { key: 'negavon',         label: 'נגבון',             col: 49 },
  { key: 'pakZayinNegavon', label: 'פק ציין לנגבון',   col: 50 },
  { key: 'sightAyotek',     label: 'כוונת איוטק',      col: 51 },
  { key: 'binocularsPugi',  label: 'משקפת פוגי',       col: 52 },
  { key: 'ironBall',        label: 'כדור ברזל',         col: 53 },
  { key: 'mkh',             label: 'מק"ח',              col: 54 },
  { key: 'kneeNight',       label: 'ברך לילה',          col: 55 },
  { key: 'kneeDay',         label: 'ברך יום',           col: 56 },
  { key: 'merkavaCurtain',  label: 'וילון מרכבה',       col: 57 },
  { key: 'kitBaz',          label: 'ערכת באז',          col: 58 },
  { key: 'amaSoch',         label: 'אמה סוך',           col: 59 },
  { key: 'dotSmall',        label: 'נקודה קטנה',        col: 60 },
  { key: 'dotEnhanced',     label: 'נקודה משופרת',      col: 61 },
  { key: 'droneIbu',        label: 'רחפן איבו',         col: 62 },
  { key: 'droneAvatah',     label: 'רחפן אבטה',         col: 63 },
  { key: 'droneFlycard',    label: 'רחפן פלייקארד',     col: 64 }
];

// נגזרים מ-WEAPONS_ITEM_LIST
const WEAPONS_ITEM_NAMES_HE = (function() {
  var m = {};
  WEAPONS_ITEM_LIST.forEach(function(item) { m[item.key] = item.label; });
  return m;
})();

const WEAPONS_ITEM_COLUMN_MAP = (function() {
  var m = {};
  WEAPONS_ITEM_LIST.forEach(function(item) { m[item.key] = [item.col]; });
  return m;
})();

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
        data: (function() {
          var d = {
            personalNumber: rows[i][2],
            fullName:       rows[i][1],
            phone:          '0' + rows[i][3],
            email:          rows[i][4],
            unit:           rows[i][5],
            team:           rows[i][6] || ''
          };
          WEAPONS_ITEM_LIST.forEach(function(item) {
            d[item.key] = rows[i][item.col] || '';
          });
          return d;
        })()
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
  weapons_saveToZivudSheet(ss, data, ts);
  weapons_saveToMainZivudSheet(ss, data, ts);
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

// ================================================================
// Zivud Sheet (הערות לציוד)
// ================================================================

/**
 * שומר לגליון זיווד של המסגרת — אותה מבנה כמו צלם אבל עמודות פריט מכילות הערות
 */
function weapons_saveToZivudSheet(ss, data, timestamp) {
  const sheetName = (data.unit || CONFIG.WEAPONS.DEFAULT_UNIT) + ' זיווד';
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) sheet = weapons_createZivudSheet(ss, sheetName);

  const existingRow = findExistingRow(sheet, data.personalNumber, CONFIG.WEAPONS.PN_COLUMN);
  const rowData = weapons_prepareZivudRowData(data, timestamp);

  if (existingRow) {
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
  } else {
    sheet.appendRow(rowData);
  }
  Logger.log('✓ [Weapons] Saved to zivud sheet: ' + sheetName);
}

/**
 * שומר לגליון זיווד ראשי "כל הרשומות זיווד" — אותה לוגיקה כמו weapons_saveToMainSheet
 */
function weapons_saveToMainZivudSheet(ss, data, timestamp) {
  const mainZivudName = CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד';
  let sheet = ss.getSheetByName(mainZivudName);
  if (!sheet) sheet = weapons_createZivudSheet(ss, mainZivudName);

  const existingRow = findExistingRow(sheet, data.personalNumber, CONFIG.WEAPONS.PN_COLUMN);
  const rowData = weapons_prepareZivudRowData(data, timestamp);

  if (existingRow) {
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
  } else {
    sheet.appendRow(rowData);
  }
  Logger.log('✓ [Weapons] Saved to main zivud sheet: ' + mainZivudName);
}

function weapons_createZivudSheet(ss, sheetName) {
  const sheet = ss.insertSheet(sheetName);
  var headers = ['תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות'];
  WEAPONS_ITEM_LIST.forEach(function(item) { headers.push(item.label); });
  sheet.appendRow(headers);
  const hr = sheet.getRange(1, 1, 1, headers.length);
  hr.setBackground('#7B5E00');
  hr.setFontColor('#FFFFFF');
  hr.setFontWeight('bold');
  hr.setHorizontalAlignment('right');
  Logger.log('✓ [Weapons] Created zivud sheet: ' + sheetName);
  return sheet;
}

/**
 * מכין שורת נתונים לגליון זיווד — עמודות פריטים מכילות הערה (note_KEY)
 */
function weapons_prepareZivudRowData(data, timestamp) {
  var row = [
    timestamp,
    data.fullName,
    data.personalNumber,
    data.phone,
    data.email,
    data.unit || '',
    data.team || ''
  ];
  WEAPONS_ITEM_LIST.forEach(function(item) {
    // כתוב הערה אם קיימת, אחרת השאר ריק
    row.push(data[item.key] ? (data['note_' + item.key] || '') : '');
  });
  return row;
}

// ================================================================
// Async Email Queue
// ================================================================

/**
 * מכניס משימת מייל לתור ב-PropertiesService ומפעיל טריגר
 * (לא מחכה לשליחת המייל — חוזר מיידית)
 */
function weapons_queueEmail(data) {
  try {
    const key = 'wepEmail_' + data.personalNumber + '_' + Date.now();
    PropertiesService.getScriptProperties().setProperty(key, JSON.stringify({
      pn:        String(data.personalNumber),
      email:     data.email     || '',
      fullName:  data.fullName  || '',
      unit:      data.unit      || '',
      submittedAt: data.submittedAt || new Date().toISOString()
    }));
    // יצירת טריגר חד-פעמי רק אם אין כבר אחד ממתין
    const exists = ScriptApp.getProjectTriggers().some(function(t) {
      return t.getHandlerFunction() === 'weapons_sendQueuedEmails';
    });
    if (!exists) {
      ScriptApp.newTrigger('weapons_sendQueuedEmails').timeBased().after(3000).create();
    }
    Logger.log('📧 [Weapons] Email queued for PN: ' + data.personalNumber);
  } catch(e) {
    Logger.log('⚠️ [Weapons] Failed to queue email: ' + e);
  }
}

/**
 * מופעל ע"י טריגר — שולח מיילים ממתינים מהתור
 */
function weapons_sendQueuedEmails() {
  const props = PropertiesService.getScriptProperties();
  const all   = props.getProperties();
  const ss    = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);

  for (var key in all) {
    if (!key.startsWith('wepEmail_')) continue;
    var job;
    try { job = JSON.parse(all[key]); } catch(e) { props.deleteProperty(key); continue; }
    props.deleteProperty(key);

    try {
      if (!mainSheet || !job.email) continue;
      // קרא נתונים עדכניים מהגיליון
      var rows = mainSheet.getDataRange().getValues();
      var rowData = null;
      for (var i = 1; i < rows.length; i++) {
        if (String(rows[i][2]) === String(job.pn)) { rowData = rows[i]; break; }
      }
      if (!rowData) continue;

      var emailData = {
        fullName:       rowData[1],
        personalNumber: rowData[2],
        phone:          rowData[3],
        email:          rowData[4],
        unit:           rowData[5] || '',
        team:           rowData[6] || ''
      };
      WEAPONS_ITEM_LIST.forEach(function(item) {
        emailData[item.key] = rowData[item.col] || '';
      });

      weapons_generateAndSendPDF(emailData);
      Logger.log('✅ [Weapons] Queued email sent for PN: ' + job.pn);
    } catch(e) {
      Logger.log('⚠️ [Weapons] Queued email failed for PN ' + (job && job.pn) + ': ' + e);
    }
  }

  // נקה את הטריגר הזה לאחר הרצה
  ScriptApp.getProjectTriggers().forEach(function(t) {
    if (t.getHandlerFunction() === 'weapons_sendQueuedEmails') {
      try { ScriptApp.deleteTrigger(t); } catch(e) {}
    }
  });
}

function weapons_createUnitSheet(ss, sheetName) {
  const sheet = ss.insertSheet(sheetName);
  var headers = ['תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות'];
  WEAPONS_ITEM_LIST.forEach(function(item) { headers.push(item.label); });
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
  var row = [
    timestamp,
    data.fullName,
    data.personalNumber,
    data.phone,
    data.email,
    data.unit || '',
    data.team || ''
  ];
  WEAPONS_ITEM_LIST.forEach(function(item) {
    row.push(data[item.key] || '');
  });
  return row;
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
    var headers = ['תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות'];
    WEAPONS_ITEM_LIST.forEach(function(item) { headers.push(item.label); });
    headers.push('פריטים שזוכו', 'תאריך זיכוי', 'זוכה על ידי');
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
    // עמודה 66: מיזוג רשימת פריטים שזוכו
    const prev = creditSheet.getRange(existingCreditRow, 66).getValue() || '';
    creditSheet.getRange(existingCreditRow, 66).setValue(
      prev ? prev + ', ' + selectedItems.join(', ') : selectedItems.join(', ')
    );
    // עמודות 67, 68: עדכון תאריך ומבצע
    creditSheet.getRange(existingCreditRow, 67).setValue(creditAt || new Date().toISOString());
    creditSheet.getRange(existingCreditRow, 68).setValue(creditBy || 'unknown');
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
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var itemRows = WEAPONS_ITEM_LIST.filter(function(item) { return rowData[item.col]; })
    .map(function(item) { return f(item.label, rowData[item.col] === '1' ? 'כן' : rowData[item.col]); }).join('');

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
    itemRows +
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
  var ITEM_DEFS = (function() {
    var m = {};
    WEAPONS_ITEM_LIST.forEach(function(item) {
      m[item.key] = { label: item.label, cols: [item.col] };
    });
    return m;
  })();
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

/**
 * שליחת מייל מהירה ללא PDF — HTML ישירות (חוסך 3-5 שניות של המרת PDF)
 */
function weapons_sendEmailFast(data) {
  if (!data.email) return;
  const ts = formatTimestamp();
  MailApp.sendEmail({
    to:       data.email,
    subject:  'אישור חתימה על נשק - ' + data.fullName,
    body:     'שלום ' + data.fullName + ',\nאישור חתימתך על נשק ואמצעי לחימה נקלט במערכת בהצלחה.\n\nתאריך: ' + ts + '\nמספר אישי: ' + data.personalNumber + (data.unit ? '\nמסגרת: ' + data.unit : '') + '\n\nבברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
    htmlBody: weapons_createPdfHtml(data, ts)
  });
  Logger.log('✅ [Weapons] Fast email sent to: ' + data.email);
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
    WEAPONS_ITEM_LIST.map(function(item) {
      var val = data[item.key];
      return val ? '<div class="field"><div class="field-label">' + item.label + ':</div><div class="field-value">' + (val === '1' ? 'כן' : val) + '</div></div>' : '';
    }).join('') +
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
                 (data.unit ? 'מסגרת: ' + data.unit + '\n' : '') +
                 '\nמצורף אישור PDF מפורט.\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
    attachments: [pdf]
  });
  Logger.log('✅ [Weapons] Email sent to: ' + data.email);
}
