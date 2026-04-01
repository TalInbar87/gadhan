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
  { key: 'droneFlycard',    label: 'רחפן פלייקארד',     col: 64 },
  { key: 'robotRoni',       label: 'רובוט רוני',         col: 65 },
  { key: 'pinkLady',        label: 'פינק ליידי',          col: 66 },
  { key: 'robotAlon',       label: 'רובוט אלון',          col: 67 },
  { key: 'other',           label: 'אחר',               col: 68 }
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
          // שלוף הערות מגיליון זיווד ראשי
          try {
            var zSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
            if (zSheet) {
              var zRows = zSheet.getDataRange().getValues();
              for (var zi = 1; zi < zRows.length; zi++) {
                if (zRows[zi][2] == personalNumber) {
                  WEAPONS_ITEM_LIST.forEach(function(item) {
                    if (zRows[zi][item.col]) d['note_' + item.key] = zRows[zi][item.col];
                  });
                  break;
                }
              }
            }
          } catch(e) { Logger.log('⚠️ note fetch error: ' + e); }
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

function weapons_getOrCreateCreditZivudSheet(ss) {
  let sheet = ss.getSheetByName('זיכויים זיווד');
  if (!sheet) {
    sheet = ss.insertSheet('זיכויים זיווד');
    var headers = ['תאריך ושעה', 'שם מלא', 'מספר אישי', 'טלפון', 'מייל', 'מסגרת', 'צוות'];
    WEAPONS_ITEM_LIST.forEach(function(item) { headers.push(item.label); });
    headers.push('פריטים שזוכו', 'תאריך זיכוי', 'זוכה על ידי');
    sheet.appendRow(headers);
    const hr = sheet.getRange(1, 1, 1, headers.length);
    hr.setBackground('#5B0000');
    hr.setFontColor('#FFFFFF');
    hr.setFontWeight('bold');
    hr.setHorizontalAlignment('right');
  }
  return sheet;
}

/**
 * שומר שורת זיווד של חייל לגיליון "זיכויים זיווד" לפני מחיקתה
 */
function weapons_archiveZivudToCredit(ss, personalNumber, creditAt, creditBy, creditedItems) {
  const mainZivud = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
  if (!mainZivud) return;
  const rows = mainZivud.getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    if (rows[i][2] == personalNumber) {
      const creditZivud = weapons_getOrCreateCreditZivudSheet(ss);
      creditZivud.appendRow([...rows[i], creditedItems || 'הכל', creditAt || new Date().toISOString(), creditBy || 'unknown']);
      Logger.log('✓ [Weapons] Zivud row archived to credit zivud sheet');
      break;
    }
  }
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

  // שלוף הערות לפני המחיקה (הזיווד יימחק בהמשך)
  const notesMapCredit = weapons_readNotesMap(ss, personalNumber);

  // ארכב זיווד לגיליון זיכויים זיווד לפני המחיקה
  weapons_archiveZivudToCredit(ss, personalNumber, creditAt, creditBy, 'הכל');

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
    // מחק גם מגיליון זיווד של המסגרת
    const unitZivud = ss.getSheetByName(unit + ' זיווד');
    if (unitZivud) {
      const uzd = unitZivud.getDataRange().getValues();
      for (let i = 1; i < uzd.length; i++) {
        if (uzd[i][2] == personalNumber) { unitZivud.deleteRow(i + 1); break; }
      }
    }
  }

  // מחק מגיליון זיווד ראשי
  const mainZivud = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
  if (mainZivud) {
    const mzd = mainZivud.getDataRange().getValues();
    for (let i = 1; i < mzd.length; i++) {
      if (mzd[i][2] == personalNumber) { mainZivud.deleteRow(i + 1); break; }
    }
  }

  // מחק טופס נוכחי (החייל הוסר מהמערכת)
  weapons_updateCurrentPdf(personalNumber);

  // צור PDF ושמור ל-Drive (תמיד), שלח מייל רק אם קיים
  try {
    const email    = rowData[4];
    const fullName = rowData[1];
    const ts       = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    const html     = weapons_createCreditPdfHtml(rowData, creditBy, data.creditSignature, ts, notesMapCredit);
    const blob     = Utilities.newBlob(html, 'text/html', 'credit.html');
    const pdf      = blob.getAs('application/pdf');
    pdf.setName('זיכוי_' + fullName + '_' + weapons_driveTimestamp() + '.pdf');
    weapons_savePdfToDrive(pdf, rowData[5], null, 'זיכויים');
    Logger.log('✅ [Weapons] Credit PDF saved to Drive');
    if (email) {
      weapons_sendEmailWithRotation({
        to:      email,
        subject: 'אישור זיכוי נשק - ' + fullName,
        body:    'שלום ' + fullName + ',\n' +
                 'הציוד זוכה במערכת\n' +
                 'ע"י: ' + (creditBy || 'לא ידוע') + '\n\n' +
                 'מצ"ב קובץ אישור חתום',
        pdfBlob: pdf
      });
      Logger.log('✅ [Weapons] Credit email sent to: ' + email);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Credit PDF/email failed: ' + emailErr);
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
  const { personalNumber, selectedItems, selectedNoteItems, creditBy, creditAt } = data;
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
    // עמודות metadata: אחרי 7 שדות בסיס + כל הפריטים (דינמי)
    const META_COL = 7 + WEAPONS_ITEM_LIST.length + 1; // 1-indexed
    const prev = creditSheet.getRange(existingCreditRow, META_COL).getValue() || '';
    creditSheet.getRange(existingCreditRow, META_COL).setValue(
      prev ? prev + ', ' + selectedItems.join(', ') : selectedItems.join(', ')
    );
    creditSheet.getRange(existingCreditRow, META_COL + 1).setValue(creditAt || new Date().toISOString());
    creditSheet.getRange(existingCreditRow, META_COL + 2).setValue(creditBy || 'unknown');
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

  // ארכב זיווד לגיליון זיכויים זיווד לפני ניקוי
  if (selectedNoteItems && selectedNoteItems.length > 0) {
    weapons_archiveZivudToCredit(ss, personalNumber, creditAt, creditBy, selectedNoteItems.map(function(k) { return WEAPONS_ITEM_NAMES_HE[k] || k; }).join(', '));
    weapons_clearNoteItems(ss, personalNumber, selectedNoteItems);
  }

  // עדכן טופס נוכחי (החייל עדיין קיים, ציוד עודכן)
  weapons_updateCurrentPdf(personalNumber);

  // צור PDF ושמור ל-Drive (תמיד), שלח מייל רק אם קיים
  try {
    const email    = rowData[4];
    const fullName = rowData[1];
    const ts       = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    const notesMap = weapons_readNotesMap(ss, personalNumber);
    const html     = weapons_createPartialCreditPdfHtml(rowData, selectedItems, selectedNoteItems, creditBy, data.creditSignature, ts, notesMap);
    const blob     = Utilities.newBlob(html, 'text/html', 'partial_credit.html');
    const pdf      = blob.getAs('application/pdf');
    pdf.setName('זיכוי_חלקי_' + fullName + '_' + weapons_driveTimestamp() + '.pdf');
    weapons_savePdfToDrive(pdf, rowData[5], null, 'זיכויים');
    Logger.log('✅ [Weapons] Partial credit PDF saved to Drive');
    if (email) {
      weapons_sendEmailWithRotation({
        to:      email,
        subject: 'אישור זיכוי נשק - ' + fullName,
        body:    'שלום ' + fullName + ',\n' +
                 'הציוד זוכה במערכת\n' +
                 'ע"י: ' + (creditBy || 'לא ידוע') + '\n\n' +
                 'מצ"ב קובץ אישור חתום',
        pdfBlob: pdf
      });
      Logger.log('✅ [Weapons] Partial credit email sent to: ' + email);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Partial credit PDF/email failed: ' + emailErr);
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
  const { sourcePersonalNumber, targetPersonalNumber, selectedItems, selectedNoteItems, transferBy, transferAt } = data;
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

  // בדוק שהמסגרות זהות
  if (sourceData[5] !== targetData[5]) {
    return { success: false, error: 'לא ניתן להעביר בין מסגרות שונות (' + sourceData[5] + ' → ' + targetData[5] + ')' };
  }

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

  // עדכן גיליון מסגרת יעד (יצירת שורה חדשה אם לא קיים)
  const tgtUnit = targetData[5];
  if (tgtUnit) {
    let tgtSheet = ss.getSheetByName(tgtUnit);
    if (!tgtSheet) tgtSheet = weapons_createUnitSheet(ss, tgtUnit);
    const td = tgtSheet.getDataRange().getValues();
    let tgtUnitRow = -1;
    for (let i = 1; i < td.length; i++) {
      if (td[i][2] == targetPersonalNumber) { tgtUnitRow = i + 1; break; }
    }
    if (tgtUnitRow !== -1) {
      // קיים — עדכן פריטים
      selectedItems.forEach(key => {
        const cols = WEAPONS_ITEM_COLUMN_MAP[key];
        if (!cols) return;
        cols.forEach(ci => {
          tgtSheet.getRange(tgtUnitRow, ci + 1).setValue(sourceData[ci]);
        });
      });
    } else {
      // לא קיים — צור שורה חדשה מנתוני היעד עם הפריטים שהועברו
      const newRow = [...targetData];
      selectedItems.forEach(key => {
        const cols = WEAPONS_ITEM_COLUMN_MAP[key];
        if (!cols) return;
        cols.forEach(ci => { newRow[ci] = sourceData[ci]; });
      });
      tgtSheet.appendRow(newRow);
      Logger.log('✓ [Weapons] Created new row in target unit sheet: ' + tgtUnit);
    }
  }

  // העבר ציוד נלווה בגיליונות זיווד
  if (selectedNoteItems && selectedNoteItems.length > 0) {
    weapons_transferNoteItems(ss, sourcePersonalNumber, targetPersonalNumber, selectedNoteItems);
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
    selectedItems.map(function(k) { return WEAPONS_ITEM_NAMES_HE[k] || k; }).concat(
      (selectedNoteItems || []).map(function(k) { return 'ציוד נלווה: ' + (WEAPONS_ITEM_NAMES_HE[k] || k); })
    ).join(', '),
    transferBy || 'unknown'
  ]);

  // שלח מיילים למקור וליעד עם PDF מצורף
  try {
    const ts       = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    const notesMap = weapons_readNotesMap(ss, sourcePersonalNumber);
    const itemsHe  = selectedItems.map(function(k) {
      var label = WEAPONS_ITEM_NAMES_HE[k] || k;
      var note  = notesMap[k];
      return note ? label + ' (' + note + ')' : label;
    }).concat(
      (selectedNoteItems || []).map(function(k) {
        return 'ציוד נלווה - ' + (WEAPONS_ITEM_NAMES_HE[k] || k) + (notesMap[k] ? ' (' + notesMap[k] + ')' : '');
      })
    ).join(', ');

    // יצירת PDF העברה
    const transferHtml = weapons_createTransferPdfHtml(sourceData, targetData, selectedItems, selectedNoteItems, notesMap, transferBy, ts);
    const transferBlob = Utilities.newBlob(transferHtml, 'text/html', 'transfer.html');
    const transferPdf  = transferBlob.getAs('application/pdf');
    transferPdf.setName('העברה_' + targetData[1] + '_' + sourceData[1] + '_' + weapons_driveTimestamp() + '.pdf');
    weapons_savePdfToDrive(transferPdf, sourceData[5], null, 'העברות');

    if (sourceData[4]) {
      weapons_sendEmailWithRotation({
        to:      sourceData[4],
        subject: 'אישור העברת ציוד - ' + sourceData[1],
        body:    'שלום ' + sourceData[1] + ',\n\n' +
                 'הציוד הבא הועבר ממשקך לחייל ' + targetData[1] +
                 ' (מ"א ' + targetPersonalNumber + '):\n' + itemsHe + '\n\n' +
                 'בוצע על ידי: ' + (transferBy || 'לא ידוע') + '\n' +
                 'תאריך: ' + ts + '\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
        pdfBlob: transferPdf
      });
      Logger.log('✅ [Weapons] Transfer email sent to source: ' + sourceData[4]);
    }

    if (targetData[4]) {
      weapons_sendEmailWithRotation({
        to:      targetData[4],
        subject: 'קבלת ציוד מועבר - ' + targetData[1],
        body:    'שלום ' + targetData[1] + ',\n\n' +
                 'הציוד הבא הועבר אליך מחייל ' + sourceData[1] +
                 ' (מ"א ' + sourcePersonalNumber + '):\n' + itemsHe + '\n\n' +
                 'בוצע על ידי: ' + (transferBy || 'לא ידוע') + '\n' +
                 'תאריך: ' + ts + '\n\n' +
                 'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
        pdfBlob: transferPdf
      });
      Logger.log('✅ [Weapons] Transfer email sent to target: ' + targetData[4]);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Weapons] Transfer email failed: ' + emailErr);
  }

  // עדכן טפסים נוכחיים לשני החיילים
  weapons_updateCurrentPdf(sourcePersonalNumber);
  weapons_updateCurrentPdf(targetPersonalNumber);

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
function weapons_createCreditPdfHtml(rowData, creditBy, creditSignature, ts, notesMap) {
  notesMap = notesMap || {};
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var itemRows = WEAPONS_ITEM_LIST.filter(function(item) { return rowData[item.col]; })
    .map(function(item) {
      return f(item.label, rowData[item.col]);
    }).join('');
  var noteRows = WEAPONS_ITEM_LIST.filter(function(item) { return notesMap[item.key]; })
    .map(function(item) {
      return f('ציוד נלווה — ' + item.label, notesMap[item.key]);
    }).join('');

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
    itemRows + noteRows +
    f('זוכה על ידי', creditBy || '') +
    '</div>' +
    (creditSignature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת המאשר:</div><img src="' + creditSignature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

/**
 * מייצר HTML לPDF זיכוי חלקי — מציג רק את הפריטים שנבחרו
 */
function weapons_createPartialCreditPdfHtml(rowData, selectedItems, selectedNoteItems, creditBy, creditSignature, ts, notesMap) {
  notesMap = notesMap || {};
  selectedNoteItems = selectedNoteItems || [];
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
    return f(def.label, vals.join(' — '));
  }).join('');
  var noteRows = selectedNoteItems.map(function(key) {
    var def = ITEM_DEFS[key];
    if (!def) return '';
    return f('ציוד נלווה — ' + def.label, notesMap[key] || '');
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
    itemRows + noteRows +
    f('זוכה על ידי', creditBy || '') +
    '</div>' +
    (creditSignature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת המאשר:</div><img src="' + creditSignature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

/**
 * מייצר HTML לPDF העברת ציוד — מוסר, מקבל, פריטים
 */
function weapons_createTransferPdfHtml(sourceData, targetData, selectedItems, selectedNoteItems, notesMap, transferBy, ts) {
  notesMap = notesMap || {};
  selectedNoteItems = selectedNoteItems || [];
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var itemRows = selectedItems.map(function(key) {
    var cols = WEAPONS_ITEM_COLUMN_MAP[key] || [];
    var vals = cols.map(function(ci) { return sourceData[ci]; }).filter(function(v) { return v && v !== ''; });
    return f(WEAPONS_ITEM_NAMES_HE[key] || key, vals.join(' — '));
  }).join('');
  var noteRows = selectedNoteItems.map(function(key) {
    var label = WEAPONS_ITEM_NAMES_HE[key] || key;
    var note  = notesMap[key] || '';
    return f('ציוד נלווה — ' + label, note);
  }).join('');

  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #1a3a6b; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.header p { font-size: 14px; opacity: 0.9; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.section-title { font-weight: bold; font-size: 15px; color: #1a3a6b; margin: 15px 0 6px; border-bottom: 2px solid #1a3a6b; padding-bottom: 3px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #1a3a6b; }' +
    '.field-value { flex: 1; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>↔ אישור העברת ציוד</h1>' +
    '<p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    f('תאריך העברה', ts) +
    '<div class="section-title">מוסר</div>' +
    f('שם מלא',    sourceData[1]) +
    f('מספר אישי', String(sourceData[2])) +
    f('מסגרת',     sourceData[5]) +
    '<div class="section-title">מקבל</div>' +
    f('שם מלא',    targetData[1]) +
    f('מספר אישי', String(targetData[2])) +
    f('מסגרת',     targetData[5]) +
    '<div class="section-title">פריטים מועברים</div>' +
    itemRows + noteRows +
    f('בוצע על ידי', transferBy || '') +
    '</div>' +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

// ================================================================
// Swap (ראש בראש)
// ================================================================

/**
 * החלפת מספרי סידורי של אותו סוג ציוד בין שני חיילים
 */
function weapons_handleSwap(data) {
  var sourcePN   = data.sourcePN;
  var targetPN   = data.targetPN;
  var itemKey    = data.itemKey;
  var swapBy     = data.swapBy;
  var swapAt     = data.swapAt;

  if (!itemKey) return { success: false, error: 'לא צוין סוג ציוד להחלפה' };

  var cols = WEAPONS_ITEM_COLUMN_MAP[itemKey];
  if (!cols) return { success: false, error: 'פריט לא מוכר: ' + itemKey };

  var ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  var mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!mainSheet) return { success: false, error: 'Main sheet not found' };

  var allData = mainSheet.getDataRange().getValues();
  var sourceRow = -1, sourceData = null;
  var targetRow = -1, targetData = null;

  for (var i = 1; i < allData.length; i++) {
    if (String(allData[i][2]) === String(sourcePN)) { sourceRow = i + 1; sourceData = allData[i]; }
    if (String(allData[i][2]) === String(targetPN)) { targetRow = i + 1; targetData = allData[i]; }
  }

  if (sourceRow === -1) return { success: false, error: 'חייל א׳ לא נמצא במערכת' };
  if (targetRow === -1) return { success: false, error: 'חייל ב׳ לא נמצא במערכת' };

  // החלף ערכים בגיליון הראשי
  cols.forEach(function(ci) {
    var srcVal = sourceData[ci];
    var tgtVal = targetData[ci];
    mainSheet.getRange(sourceRow, ci + 1).setValue(tgtVal);
    mainSheet.getRange(targetRow, ci + 1).setValue(srcVal);
  });

  // עדכן גיליון מסגרת מקור
  var srcUnit = sourceData[5];
  if (srcUnit) {
    var srcSheet = ss.getSheetByName(srcUnit);
    if (srcSheet) {
      var sd = srcSheet.getDataRange().getValues();
      for (var si = 1; si < sd.length; si++) {
        if (String(sd[si][2]) === String(sourcePN)) {
          cols.forEach(function(ci) { srcSheet.getRange(si + 1, ci + 1).setValue(targetData[ci]); });
          break;
        }
      }
    }
  }

  // עדכן גיליון מסגרת יעד (צור אם לא קיים)
  var tgtUnit = targetData[5];
  if (tgtUnit) {
    var tgtSheet = ss.getSheetByName(tgtUnit);
    if (!tgtSheet) tgtSheet = weapons_createUnitSheet(ss, tgtUnit);
    var td = tgtSheet.getDataRange().getValues();
    var tgtUnitRow = -1;
    for (var ti = 1; ti < td.length; ti++) {
      if (String(td[ti][2]) === String(targetPN)) { tgtUnitRow = ti + 1; break; }
    }
    if (tgtUnitRow !== -1) {
      cols.forEach(function(ci) { tgtSheet.getRange(tgtUnitRow, ci + 1).setValue(sourceData[ci]); });
    } else {
      var newRow = targetData.slice();
      cols.forEach(function(ci) { newRow[ci] = sourceData[ci]; });
      tgtSheet.appendRow(newRow);
    }
  }

  // החלף הערות זיווד בגיליון זיווד ראשי
  var mainZivud = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
  if (mainZivud) {
    var zrows = mainZivud.getDataRange().getValues();
    var srcZivudRow = -1, tgtZivudRow = -1;
    for (var zi = 1; zi < zrows.length; zi++) {
      if (String(zrows[zi][2]) === String(sourcePN)) srcZivudRow = zi + 1;
      if (String(zrows[zi][2]) === String(targetPN)) tgtZivudRow = zi + 1;
    }
    cols.forEach(function(ci) {
      var srcNote = (srcZivudRow !== -1) ? zrows[srcZivudRow - 1][ci] : '';
      var tgtNote = (tgtZivudRow !== -1) ? zrows[tgtZivudRow - 1][ci] : '';
      if (srcZivudRow !== -1) mainZivud.getRange(srcZivudRow, ci + 1).setValue(tgtNote);
      if (tgtZivudRow !== -1) mainZivud.getRange(tgtZivudRow, ci + 1).setValue(srcNote);
    });
  }

  // עדכן גיליונות זיווד מסגרת
  var srcZivudSheet = srcUnit ? ss.getSheetByName(srcUnit + ' זיווד') : null;
  var tgtZivudSheet = tgtUnit ? ss.getSheetByName(tgtUnit + ' זיווד') : null;
  if (srcZivudSheet) {
    var szrows = srcZivudSheet.getDataRange().getValues();
    for (var szi = 1; szi < szrows.length; szi++) {
      if (String(szrows[szi][2]) === String(sourcePN)) {
        var srcZivudVal = szrows[szi][cols[0]] || '';
        cols.forEach(function(ci) { srcZivudSheet.getRange(szi + 1, ci + 1).setValue(''); });
        if (tgtZivudSheet) {
          var tzrows = tgtZivudSheet.getDataRange().getValues();
          for (var tzi = 1; tzi < tzrows.length; tzi++) {
            if (String(tzrows[tzi][2]) === String(targetPN)) {
              var tgtZivudVal = tzrows[tzi][cols[0]] || '';
              cols.forEach(function(ci) { tgtZivudSheet.getRange(tzi + 1, ci + 1).setValue(srcZivudVal); });
              cols.forEach(function(ci) { srcZivudSheet.getRange(szi + 1, ci + 1).setValue(tgtZivudVal); });
              break;
            }
          }
        }
        break;
      }
    }
  }

  // רשום בגיליון העברות
  var transferSheet = ss.getSheetByName('העברות');
  if (!transferSheet) {
    transferSheet = ss.insertSheet('העברות');
    var headers = ['תאריך העברה', 'מספר אישי מקור', 'שם מקור', 'מספר אישי יעד', 'שם יעד', 'פריטים שהועברו', 'בוצע על ידי'];
    transferSheet.appendRow(headers);
    var hr = transferSheet.getRange(1, 1, 1, headers.length);
    hr.setBackground('#1e3a5f'); hr.setFontColor('#FFFFFF'); hr.setFontWeight('bold'); hr.setHorizontalAlignment('right');
  }
  var itemLabel = WEAPONS_ITEM_NAMES_HE[itemKey] || itemKey;
  transferSheet.appendRow([
    swapAt || new Date().toISOString(),
    sourcePN, sourceData[1],
    targetPN, targetData[1],
    'ראש בראש: ' + itemLabel,
    swapBy || 'unknown'
  ]);

  // צור PDF ושמור ל-Drive, שלח מיילים אם קיימים
  try {
    var ts  = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    var html = weapons_createSwapPdfHtml(sourceData, targetData, itemKey, swapBy, ts);
    var blob = Utilities.newBlob(html, 'text/html', 'swap.html');
    var pdf  = blob.getAs('application/pdf');
    pdf.setName('ראשבראש_' + sourceData[1] + '_' + targetData[1] + '_' + weapons_driveTimestamp() + '.pdf');
    weapons_savePdfToDrive(pdf, sourceData[5], null, 'ראש בראש');
    Logger.log('✅ [Weapons] Swap PDF saved to Drive');
    var swapBody = function(name, otherName) {
      return 'שלום ' + name + ',\nבוצעה החלפת ציוד ראש בראש\nפריט: ' + itemLabel + '\nמול: ' + otherName + '\nע"י: ' + (swapBy || 'לא ידוע') + '\nמצ"ב אישור PDF';
    };
    if (sourceData[4]) {
      weapons_sendEmailWithRotation({ to: sourceData[4], subject: 'אישור החלפת ציוד ראש בראש - ' + itemLabel, body: swapBody(sourceData[1], targetData[1]), pdfBlob: pdf });
    }
    if (targetData[4]) {
      weapons_sendEmailWithRotation({ to: targetData[4], subject: 'אישור החלפת ציוד ראש בראש - ' + itemLabel, body: swapBody(targetData[1], sourceData[1]), pdfBlob: pdf });
    }
  } catch(e) {
    Logger.log('⚠️ [Weapons] Swap PDF/email failed: ' + e);
  }

  // עדכן טפסים נוכחיים לשני החיילים
  weapons_updateCurrentPdf(sourcePN);
  weapons_updateCurrentPdf(targetPN);

  return { success: true, message: 'Swap completed' };
}

function weapons_createSwapPdfHtml(sourceData, targetData, itemKey, swapBy, ts) {
  var itemLabel = WEAPONS_ITEM_NAMES_HE[itemKey] || itemKey;
  var cols = WEAPONS_ITEM_COLUMN_MAP[itemKey] || [];
  var srcVal = cols.map(function(ci) { return sourceData[ci]; }).filter(function(v) { return v; }).join(' — ') || '—';
  var tgtVal = cols.map(function(ci) { return targetData[ci]; }).filter(function(v) { return v; }).join(' — ') || '—';
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #0f766e; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.section-title { font-weight: bold; font-size: 15px; color: #0f766e; margin: 15px 0 6px; border-bottom: 2px solid #0f766e; padding-bottom: 3px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #0f766e; }' +
    '.field-value { flex: 1; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>⇄ אישור החלפת ציוד ראש בראש</h1>' +
    '<p>מערכת דוח צלם מקוון - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    f('תאריך', ts) + f('פריט', itemLabel) +
    '<div class="section-title">חייל א׳</div>' +
    f('שם מלא', sourceData[1]) + f('מספר אישי', String(sourceData[2])) + f('מסגרת', sourceData[5]) +
    f('מ.ס לפני', srcVal) + f('מ.ס אחרי', tgtVal) +
    '<div class="section-title">חייל ב׳</div>' +
    f('שם מלא', targetData[1]) + f('מספר אישי', String(targetData[2])) + f('מסגרת', targetData[5]) +
    f('מ.ס לפני', tgtVal) + f('מ.ס אחרי', srcVal) +
    f('בוצע על ידי', swapBy || '') +
    '</div>' +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

/**
 * מנקה הערות (ציוד נלווה) מגיליונות זיווד עבור פריטים נבחרים — ללא נגיעה בגיליון הראשי
 */
function weapons_clearNoteItems(ss, personalNumber, noteKeys) {
  if (!noteKeys || noteKeys.length === 0) return;
  var mainZivudName = CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד';
  var mainZivud = ss.getSheetByName(mainZivudName);
  if (mainZivud) {
    var rows = mainZivud.getDataRange().getValues();
    for (var i = 1; i < rows.length; i++) {
      if (rows[i][2] == personalNumber) {
        noteKeys.forEach(function(key) {
          var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
          if (item) mainZivud.getRange(i + 1, item.col + 1).setValue('');
        });
        break;
      }
    }
  }
  // נקה גם מגיליון מסגרת זיווד
  var mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (mainSheet) {
    var mainRows = mainSheet.getDataRange().getValues();
    for (var mi = 1; mi < mainRows.length; mi++) {
      if (mainRows[mi][2] == personalNumber) {
        var unit = mainRows[mi][5];
        if (unit) {
          var unitZivud = ss.getSheetByName(unit + ' זיווד');
          if (unitZivud) {
            var urows = unitZivud.getDataRange().getValues();
            for (var j = 1; j < urows.length; j++) {
              if (urows[j][2] == personalNumber) {
                noteKeys.forEach(function(key) {
                  var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
                  if (item) unitZivud.getRange(j + 1, item.col + 1).setValue('');
                });
                break;
              }
            }
          }
        }
        break;
      }
    }
  }
  Logger.log('✓ [Weapons] Cleared note items: ' + noteKeys.join(', '));
}

/**
 * מעביר הערות (ציוד נלווה) מחייל מקור לחייל יעד בגיליונות הזיווד
 */
function weapons_transferNoteItems(ss, sourcePN, targetPN, noteKeys) {
  if (!noteKeys || noteKeys.length === 0) return;
  var mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);

  // קבל נתוני חייל היעד מהגליון הראשי — ישמש ליצירת שורה חדשה בגליוני זיווד אם נדרש
  var tgtData = null;
  if (mainSheet) {
    var allMainRows = mainSheet.getDataRange().getValues();
    for (var k = 1; k < allMainRows.length; k++) {
      if (allMainRows[k][2] == targetPN) { tgtData = allMainRows[k]; break; }
    }
  }

  // מוצא שורת יעד בגליון, ואם לא קיימת — יוצר אחת מנתוני הגליון הראשי
  function ensureTgtRow(sheet) {
    var rows = sheet.getDataRange().getValues();
    for (var r = 1; r < rows.length; r++) {
      if (rows[r][2] == targetPN) return r + 1;
    }
    if (!tgtData) return -1;
    sheet.appendRow(tgtData);
    Logger.log('✓ [Weapons] Created zivud row for target ' + targetPN + ' in sheet: ' + sheet.getName());
    return sheet.getLastRow();
  }

  // עדכן גיליון זיווד ראשי
  var mainZivud = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
  if (mainZivud) {
    var rows = mainZivud.getDataRange().getValues();
    var srcRow = -1;
    for (var i = 1; i < rows.length; i++) {
      if (rows[i][2] == sourcePN) { srcRow = i + 1; break; }
    }
    if (srcRow !== -1) {
      var tgtRow = ensureTgtRow(mainZivud);
      noteKeys.forEach(function(key) {
        var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
        if (!item) return;
        var noteVal = mainZivud.getRange(srcRow, item.col + 1).getValue();
        mainZivud.getRange(srcRow, item.col + 1).setValue('');
        if (tgtRow !== -1) mainZivud.getRange(tgtRow, item.col + 1).setValue(noteVal);
      });
    }
  }

  // עדכן גיליונות זיווד של מסגרת מקור ויעד
  if (mainSheet) {
    var mainRows = mainSheet.getDataRange().getValues();
    var srcUnit = null, tgtUnit = null;
    for (var mi = 1; mi < mainRows.length; mi++) {
      if (mainRows[mi][2] == sourcePN) srcUnit = mainRows[mi][5];
      if (mainRows[mi][2] == targetPN) tgtUnit = mainRows[mi][5];
    }

    // קרא ערכי הערות מגיליון מסגרת מקור לפני ניקוי
    var noteVals = {};
    if (srcUnit) {
      var srcZivud = ss.getSheetByName(srcUnit + ' זיווד');
      if (srcZivud) {
        var srows = srcZivud.getDataRange().getValues();
        for (var si = 1; si < srows.length; si++) {
          if (srows[si][2] == sourcePN) {
            noteKeys.forEach(function(key) {
              var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
              if (item) {
                noteVals[key] = srows[si][item.col];
                srcZivud.getRange(si + 1, item.col + 1).setValue('');
              }
            });
            break;
          }
        }
      }
    }

    // כתוב לגיליון מסגרת יעד (אם שונה ממקור)
    if (tgtUnit && tgtUnit !== srcUnit) {
      var tgtZivud = ss.getSheetByName(tgtUnit + ' זיווד');
      if (!tgtZivud) tgtZivud = weapons_createZivudSheet(ss, tgtUnit + ' זיווד');
      if (tgtZivud) {
        var ti = ensureTgtRow(tgtZivud);
        if (ti !== -1) {
          noteKeys.forEach(function(key) {
            var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
            if (item && noteVals[key]) tgtZivud.getRange(ti, item.col + 1).setValue(noteVals[key]);
          });
        }
      }
    } else if (srcUnit && srcUnit === tgtUnit) {
      // אותה מסגרת — עדכן ישירות
      var unitZivud = ss.getSheetByName(srcUnit + ' זיווד');
      if (unitZivud) {
        var ui = ensureTgtRow(unitZivud);
        if (ui !== -1) {
          noteKeys.forEach(function(key) {
            var item = WEAPONS_ITEM_LIST.filter(function(it) { return it.key === key; })[0];
            if (item && noteVals[key]) unitZivud.getRange(ui, item.col + 1).setValue(noteVals[key]);
          });
        }
      }
    }
  }

  Logger.log('✓ [Weapons] Transferred notes ' + sourcePN + '→' + targetPN + ': ' + noteKeys.join(', '));
}

/**
 * קורא מפת הערות (key→note) מגיליון "כל הרשומות זיווד" לפי מספר אישי
 */
function weapons_readNotesMap(ss, personalNumber) {
  var map = {};
  try {
    var sheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME + ' זיווד');
    if (!sheet) return map;
    var rows = sheet.getDataRange().getValues();
    for (var i = 1; i < rows.length; i++) {
      if (rows[i][2] == personalNumber) {
        WEAPONS_ITEM_LIST.forEach(function(item) {
          if (rows[i][item.col]) map[item.key] = rows[i][item.col];
        });
        break;
      }
    }
  } catch(e) { Logger.log('⚠️ weapons_readNotesMap: ' + e); }
  return map;
}

// ================================================================
// Current PDF — טפסים/מסגרת/[צוות]/{pn}.pdf
// ================================================================

/**
 * שומר/מחליף PDF נוכחי של חייל בנתיב טפסים/מסגרת/[צוות]/
 * מחפש ומוחק כל קובץ ישן עם אותו שם (גלובלי) לפני שמירה חדשה.
 * @param {Blob}          pdfBlob
 * @param {string|number} personalNumber  — שם הקובץ: {pn}.pdf
 * @param {string}        unit
 * @param {string}        team
 */
function weapons_saveCurrentPdf(pdfBlob, personalNumber, unit, team) {
  var rootId = (CONFIG.DRIVE || {}).ROOT_FOLDER_ID || '';
  if (!rootId) return;
  var filename = String(personalNumber) + '.pdf';
  try {
    // מחק ישנים בכל מקום
    var old = DriveApp.searchFiles('title = "' + filename + '" and trashed = false');
    while (old.hasNext()) { old.next().setTrashed(true); }

    var root       = DriveApp.getFolderById(rootId);
    var unitName   = unit || 'ללא מסגרת';
    var formsIter  = root.getFoldersByName('טפסים');
    var formsDir   = formsIter.hasNext() ? formsIter.next() : root.createFolder('טפסים');
    var unitIter   = formsDir.getFoldersByName(unitName);
    var unitDir    = unitIter.hasNext() ? unitIter.next() : formsDir.createFolder(unitName);
    var targetDir  = unitDir;
    if (team) {
      var teamIter = unitDir.getFoldersByName(team);
      targetDir = teamIter.hasNext() ? teamIter.next() : unitDir.createFolder(team);
    }
    pdfBlob.setName(filename);
    targetDir.createFile(pdfBlob);
    Logger.log('✅ [Weapons] Current PDF saved: טפסים/' + unitName + (team ? '/' + team : '') + '/' + filename);
  } catch(e) {
    Logger.log('⚠️ [Weapons] saveCurrentPdf failed: ' + e);
  }
}

/**
 * מחדש PDF נוכחי לחייל מתוך נתוני הגיליון (ללא חתימה).
 * אם החייל לא קיים — מוחק את הטופס הישן שלו.
 * משמש: העברה, ראש בראש, זיכוי חלקי, זיכוי מלא (מחיקה).
 */
function weapons_updateCurrentPdf(personalNumber) {
  try {
    var ss        = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
    var mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
    if (!mainSheet) return;

    var rows = mainSheet.getDataRange().getValues();
    var rowData = null;
    for (var i = 1; i < rows.length; i++) {
      if (String(rows[i][2]) === String(personalNumber)) { rowData = rows[i]; break; }
    }

    if (!rowData) {
      // חייל הוסר — מחק טופס ישן בלבד
      var rootId = (CONFIG.DRIVE || {}).ROOT_FOLDER_ID || '';
      if (rootId) {
        var old = DriveApp.searchFiles('title = "' + String(personalNumber) + '.pdf" and trashed = false');
        while (old.hasNext()) { old.next().setTrashed(true); }
        Logger.log('✅ [Weapons] Deleted current PDF for removed soldier: ' + personalNumber);
      }
      return;
    }

    var unit = rowData[5] || '', team = rowData[6] || '';
    var ts   = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
    var data = { fullName: rowData[1], personalNumber: rowData[2], phone: rowData[3], email: rowData[4], unit: unit, team: team };
    WEAPONS_ITEM_LIST.forEach(function(item) { data[item.key] = rowData[item.col] || ''; });
    var notesMap = weapons_readNotesMap(ss, personalNumber);
    Object.keys(notesMap).forEach(function(k) { data['note_' + k] = notesMap[k]; });

    var blob = Utilities.newBlob(weapons_createPdfHtml(data, ts), 'text/html', 'upd.html');
    var pdf  = blob.getAs('application/pdf');
    weapons_saveCurrentPdf(pdf, personalNumber, unit, team);
  } catch(e) {
    Logger.log('⚠️ [Weapons] updateCurrentPdf failed for ' + personalNumber + ': ' + e);
  }
}


function weapons_generateAndSendPDF(data) {
  const ts = formatTimestamp();
  const blob = Utilities.newBlob(weapons_createPdfHtml(data, ts), 'text/html', 'checkout.html');
  const pdf  = blob.getAs('application/pdf');
  pdf.setName('חתימה_' + data.fullName + '_' + weapons_driveTimestamp() + '.pdf');
  weapons_saveCurrentPdf(pdf.copyBlob(), data.personalNumber, data.unit, data.team);
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
      if (!val) return '';
      var display = val;
      var note = data['note_' + item.key];
      if (note) display += ' <span style="color:#78716c;font-size:0.9em">— ' + note + '</span>';
      return '<div class="field"><div class="field-label">' + item.label + ':</div><div class="field-value">' + display + '</div></div>';
    }).join('') +
    '</div>' +
    '<div class="disclaimer"><strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את אמצעי הלחימה והציוד המפורטים במסמך זה, וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.</div>' +
    (data.signature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת החייל:</div><img src="' + data.signature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

function weapons_sendEmail(data, pdf, timestamp) {
  if (!data.email) { Logger.log('⚠️ [Weapons] No email — skipping'); return; }
  weapons_sendEmailWithRotation({
    to:      data.email,
    subject: 'אישור חתימה על נשק - ' + data.fullName,
    body:    'שלום ' + data.fullName + ',\n\n' +
             'אישור חתימתך על נשק ואמצעי לחימה נקלט במערכת בהצלחה.\n\n' +
             'תאריך: ' + timestamp + '\n' +
             'מספר אישי: ' + data.personalNumber + '\n' +
             (data.unit ? 'מסגרת: ' + data.unit + '\n' : '') +
             '\nמצורף אישור PDF מפורט.\n\n' +
             'בברכה,\nמערכת דוח צלם מקוון\nגדחה"ו קומנדו 8219',
    pdfBlob: pdf
  });
  Logger.log('✅ [Weapons] Email sent to: ' + data.email);
}

// ================================================================
// Google Drive — PDF Archive
// ================================================================

/**
 * שומר PDF בתיקיית Drive לפי היררכיית מסגרת/צוות.
 * Root (מ-Config) / מסגרת / צוות (אופציונלי) / file.pdf
 * אם ROOT_FOLDER_ID ריק — פעולה מדולגת.
 */
/** מחזיר timestamp בפורמט DD-MM-YYYY_HH-MM לשמות קבצים */
function weapons_driveTimestamp() {
  var d   = new Date();
  var pad = function(n) { return n < 10 ? '0' + n : String(n); };
  return pad(d.getDate()) + '-' + pad(d.getMonth() + 1) + '-' + d.getFullYear() +
         '_' + pad(d.getHours()) + '-' + pad(d.getMinutes());
}

/**
 * שומר PDF בתיקיית Drive.
 * @param {Blob}   pdf
 * @param {string} unit       — מסגרת
 * @param {string} team       — צוות (אופציונלי)
 * @param {string} typeFolder — תת-תיקייה ראשית (למשל "זיכויים"), אופציונלי
 */
function weapons_savePdfToDrive(pdf, unit, team, typeFolder) {
  var rootId = (CONFIG.DRIVE || {}).ROOT_FOLDER_ID || '';
  if (!rootId) return;
  try {
    var root = DriveApp.getFolderById(rootId);

    // תת-תיקייה לפי סוג (זיכויים / העברות / ...)
    var base = root;
    if (typeFolder) {
      var typeIter = root.getFoldersByName(typeFolder);
      base = typeIter.hasNext() ? typeIter.next() : root.createFolder(typeFolder);
    }

    var unitName   = unit || 'ללא מסגרת';
    var unitIter   = base.getFoldersByName(unitName);
    var unitFolder = unitIter.hasNext() ? unitIter.next() : base.createFolder(unitName);

    var target = unitFolder;
    if (team) {
      var teamIter = unitFolder.getFoldersByName(team);
      target = teamIter.hasNext() ? teamIter.next() : unitFolder.createFolder(team);
    }

    target.createFile(pdf);
    Logger.log('✅ [Drive] Saved: ' + pdf.getName());
  } catch (e) {
    Logger.log('⚠️ [Drive] Failed to save PDF: ' + e);
  }
}

// ================================================================
// Email Rotation Helper
// ================================================================

/**
 * שולח מייל עם רוטציה בין עד 5 חשבונות Gmail + CC קבוע ל-gadhan.
 *
 * options: { to, subject, body, htmlBody?, pdfBlob? }
 *
 * רוטציה: idx=0 → MailApp ישיר (חשבון ראשי)
 *          idx=1..4 → relay GAS web app (חשבונות 2-5)
 * Fallback: אם relay נכשל → נסיון ישיר
 */
function weapons_sendEmailWithRotation(options) {
  var emailCfg  = CONFIG.EMAIL || {};
  var gadhan    = emailCfg.GADHAN || '';
  var relayUrls = [
    emailCfg.RELAY_URL_2 || '',
    emailCfg.RELAY_URL_3 || '',
    emailCfg.RELAY_URL_4 || '',
    emailCfg.RELAY_URL_5 || ''
  ].filter(function(u) { return !!u; });

  // בנה רשימת נמענים: חייל + gadhan (אם שונה)
  var recipients = [options.to];
  if (gadhan && gadhan !== options.to) recipients.push(gadhan);
  var toStr = recipients.filter(Boolean).join(',');

  // בחר חשבון בסיבוב
  var totalAccounts = 1 + relayUrls.length;
  var props = PropertiesService.getScriptProperties();
  var idx   = parseInt(props.getProperty('EMAIL_ROTATION_IDX') || '0') % totalAccounts;
  props.setProperty('EMAIL_ROTATION_IDX', String((idx + 1) % totalAccounts));

  if (idx === 0 || relayUrls.length === 0) {
    // ── שליחה ישירה (חשבון 1) ────────────────────────────────
    var directOpts = { to: toStr, subject: options.subject, body: options.body || '' };
    if (options.htmlBody) directOpts.htmlBody = options.htmlBody;
    if (options.pdfBlob)  directOpts.attachments = [options.pdfBlob];
    MailApp.sendEmail(directOpts);
    Logger.log('✅ [Email] Direct (account 1) → ' + toStr);
    return;
  }

  // ── שליחה דרך relay (חשבונות 2-5) ──────────────────────────
  var relayUrl = relayUrls[idx - 1];
  var payload  = { to: toStr, subject: options.subject, body: options.body || '' };
  if (options.htmlBody) payload.htmlBody = options.htmlBody;
  if (options.pdfBlob) {
    payload.attachmentBase64 = Utilities.base64Encode(options.pdfBlob.getBytes());
    payload.attachmentName   = options.pdfBlob.getName();
    payload.attachmentMime   = options.pdfBlob.getContentType();
  }

  try {
    var resp   = UrlFetchApp.fetch(relayUrl, {
      method:           'post',
      contentType:      'application/json',
      payload:          JSON.stringify(payload),
      muteHttpExceptions: true
    });
    var result = JSON.parse(resp.getContentText());
    if (!result.success) throw new Error(result.error || 'relay error');
    Logger.log('✅ [Email] Relay ' + idx + ' → ' + toStr);
  } catch (relayErr) {
    // Fallback: ישיר
    Logger.log('⚠️ [Email] Relay ' + idx + ' failed (' + relayErr + '), falling back to direct');
    var fbOpts = { to: toStr, subject: options.subject, body: options.body || '' };
    if (options.htmlBody) fbOpts.htmlBody = options.htmlBody;
    if (options.pdfBlob)  fbOpts.attachments = [options.pdfBlob];
    MailApp.sendEmail(fbOpts);
  }
}

// ================================================================
// Inventory Summary - סיכום מלאי
// ================================================================

/**
 * מחזיר סיכום כמויות לכל 58 פריטים, מפוצל לפי מסגרת וסה"כ
 * @returns {{ success: boolean, data?: { units, items, counts, totals }, error?: string }}
 */
function weapons_getInventorySummary() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  const sheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!sheet) return { success: false, error: 'Main sheet not found' };

  const rows = sheet.getDataRange().getValues();

  // טעינת גיליון האיפסון לצורך סימון
  var apsonSet = {}; // { 'pn_itemKey': true }
  try {
    var apsonSheet = ss.getSheetByName('איפסון');
    if (apsonSheet) {
      var apsonRows = apsonSheet.getDataRange().getValues();
      for (var a = 1; a < apsonRows.length; a++) {
        var apsonPn  = String(apsonRows[a][1] || '').trim();
        var apsonKey = String(apsonRows[a][4] || '').trim();
        if (apsonPn && apsonKey) apsonSet[apsonPn + '_' + apsonKey] = true;
      }
    }
  } catch (apsonErr) { /* גיליון לא קיים עדיין */ }

  // איסוף מסגרות ייחודיות + ספירה + שמות
  const unitsSet = {};
  const counts   = {};
  const names    = {};
  WEAPONS_ITEM_LIST.forEach(function(item) { counts[item.key] = {}; names[item.key] = {}; });

  for (var i = 1; i < rows.length; i++) {
    var unit     = (rows[i][5] || '').toString().trim();
    var fullName = (rows[i][1] || '').toString().trim();
    var pn       = (rows[i][2] || '').toString().trim();
    if (!unit) continue;
    unitsSet[unit] = true;

    WEAPONS_ITEM_LIST.forEach(function(item) {
      var val = rows[i][item.col];
      if (val) {
        counts[item.key][unit] = (counts[item.key][unit] || 0) + 1;
        if (!names[item.key][unit]) names[item.key][unit] = [];
        names[item.key][unit].push({
          name:    fullName,
          value:   val.toString(),
          pn:      pn,
          inApson: !!(apsonSet[pn + '_' + item.key])
        });
      }
    });
  }

  var units = Object.keys(unitsSet).sort();

  // סה"כ לכל פריט
  var totals = {};
  WEAPONS_ITEM_LIST.forEach(function(item) {
    totals[item.key] = units.reduce(function(sum, unit) {
      return sum + (counts[item.key][unit] || 0);
    }, 0);
  });

  return {
    success: true,
    data: {
      units:  units,
      items:  WEAPONS_ITEM_LIST.map(function(item) { return { key: item.key, label: item.label }; }),
      counts: counts,
      totals: totals,
      names:  names
    }
  };
}

// ================================================================
// APSON (איפסון) — שמירת פריטים בגיליון האיפסון
// ================================================================

var APSON_SHEET_NAME = 'איפסון';
var APSON_HEADERS    = ['תאריך', 'מספר אישי', 'שם מלא', 'מסגרת', 'מפתח פריט', 'תווית פריט', 'ערך', 'בוצע ע"י'];

function weapons_apson_ensureSheet() {
  var ss    = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  var sheet = ss.getSheetByName(APSON_SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(APSON_SHEET_NAME);
    sheet.appendRow(APSON_HEADERS);
    sheet.setFrozenRows(1);
  }
  return sheet;
}

function weapons_apson_get(pn) {
  var sheet = weapons_apson_ensureSheet();
  var rows  = sheet.getDataRange().getValues();
  var result = [];
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][1]).trim() === String(pn).trim()) {
      result.push({ key: rows[i][4], label: rows[i][5], value: rows[i][6] });
    }
  }
  return result;
}

function weapons_apson_add(data) {
  var sheet    = weapons_apson_ensureSheet();
  var now      = new Date();
  var items    = (data.selectedItems      || []);
  var noteItems= (data.selectedNoteItems  || []);
  var values   = data.itemsWithValues     || {};

  items.forEach(function(key) {
    var label = (WEAPONS_ITEM_LIST.find(function(i) { return i.key === key; }) || {}).label || key;
    var val   = values[key] || '';
    sheet.appendRow([now, data.personalNumber, data.fullName, data.unit, key, label, val, data.doneBy]);
  });
  noteItems.forEach(function(key) {
    var label = (WEAPONS_ITEM_LIST.find(function(i) { return i.key === key; }) || {}).label || key;
    var val   = 'ציוד נלווה';
    sheet.appendRow([now, data.personalNumber, data.fullName, data.unit, key + '_note', label + ' (נלווה)', val, data.doneBy]);
  });

  return { success: true, added: items.length + noteItems.length };
}

function weapons_apson_remove(pn, itemKeys) {
  var sheet = weapons_apson_ensureSheet();
  var rows  = sheet.getDataRange().getValues();
  var toDelete = [];
  for (var i = rows.length - 1; i >= 1; i--) {
    if (String(rows[i][1]).trim() === String(pn).trim() &&
        itemKeys.indexOf(rows[i][4]) !== -1) {
      toDelete.push(i + 1);
    }
  }
  toDelete.forEach(function(rowNum) { sheet.deleteRow(rowNum); });
  return { success: true, removed: toDelete.length };
}

// ================================================================
// מסגרות — רשימה ייחודית מגליון הנשקים
// ================================================================
function weapons_getUnits() {
  var ss    = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
  var sheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
  if (!sheet) return { success: false, error: 'גיליון לא נמצא' };
  var rows  = sheet.getDataRange().getValues();
  var seen  = {};
  for (var i = 1; i < rows.length; i++) {
    var unit = (rows[i][5] || '').toString().trim();
    if (unit) seen[unit] = true;
  }
  return { success: true, data: Object.keys(seen).sort() };
}


// ================================================================
// Inspections (מעקב בדיקות)
// ================================================================
// גיליון מעקב בדיקות:
//   A=שם מלא | B=מספר אישי | C=טלפון | D=מייל | E=מסגרת | F=צוות
//   G..N+6 = עמודה לכל פריט שנבדק (header = label הפריט, ערך = תאריך או "לא נדרש")
// שורה אחת לחייל — upsert לפי B (מספר אישי)

var INSP_OVERDUE_MS  = 14 * 86400000;
var INSP_DATE_SUFFIX = ' תאריך בדיקה';

// ── helpers ───────────────────────────────────────────────────────

/** מחזיר מפה label → אינדקס עמודה (1-based) */
function _insp_headerMap(sheet) {
  var lastCol = sheet.getLastColumn();
  if (lastCol < 1) return {};
  var headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  var map = {};
  for (var i = 0; i < headers.length; i++) {
    var h = (headers[i] || '').toString().trim();
    if (h) map[h] = i + 1;
  }
  return map;
}

/** מוודא קיום עמודת כותרת — מחזיר אינדקס (1-based) */
function _insp_ensureCol(sheet, headerMap, label) {
  if (headerMap[label]) return headerMap[label];
  var newCol = sheet.getLastColumn() + 1;
  sheet.getRange(1, newCol).setValue(label);
  headerMap[label] = newCol;
  return newCol;
}

/** מוודא שורת כותרת בסיסית */
function _insp_ensureBase(sheet) {
  if (!(sheet.getRange(1, 1).getValue() || '').toString().trim()) {
    sheet.getRange(1, 1, 1, 6).setValues([['שם מלא','מספר אישי','טלפון','מייל','מסגרת','צוות']]);
  }
}

// ── public functions ──────────────────────────────────────────────

/**
 * מחזיר מסגרות ייחודיות מגיליון הנשקים
 */
function inspections_getUnits() {
  try {
    var ss    = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
    var sheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
    if (!sheet) return { success: false, error: 'גיליון לא נמצא' };
    var rows = sheet.getDataRange().getValues();
    var unitsSet = {};
    for (var i = 1; i < rows.length; i++) {
      var u = (rows[i][5] || '').toString().trim();
      if (u) unitsSet[u] = true;
    }
    return { success: true, data: Object.keys(unitsSet).sort() };
  } catch (e) {
    Logger.log('❌ [Inspections] getUnits: ' + e);
    return { success: false, error: e.toString() };
  }
}

/**
 * מחזיר חיילים במסגרת מגליון המסגרת הספציפי (fallback: כל הרשומות)
 * לכל חייל מחושב: totalItems, checkedRecent (< 14 יום), notRequired
 */
function inspections_getSoldiersByUnit(unit) {
  try {
    var ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);

    // נסה גליון מסגרת ספציפי → fallback לגליון הראשי
    var srcSheet     = ss.getSheetByName(unit);
    var filterByUnit = !srcSheet;
    if (!srcSheet) srcSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
    if (!srcSheet)  return { success: false, error: 'גליון לא נמצא' };

    var rows     = srcSheet.getDataRange().getValues();
    var soldiers = {};
    for (var i = 1; i < rows.length; i++) {
      if (filterByUnit && (rows[i][5] || '').toString().trim() !== unit) continue;
      var pn = (rows[i][2] || '').toString().trim();
      if (!pn) continue;
      if (!soldiers[pn]) {
        var itemCount = 0;
        WEAPONS_ITEM_LIST.forEach(function(item) {
          var v = rows[i][item.col];
          if (v && v.toString().trim() !== '' && v.toString().trim() !== '0') itemCount++;
        });
        soldiers[pn] = {
          pn:         pn,
          name:       (rows[i][1] || '').toString().trim(),
          phone:      (rows[i][3] || '').toString().trim(),
          email:      (rows[i][4] || '').toString().trim(),
          unit:       (rows[i][5] || '').toString().trim() || unit,
          team:       (rows[i][6] || '').toString().trim(),
          totalItems: itemCount,
          checkedRecent: 0,
          notRequired:   0
        };
      }
    }

    // טען סטטוס בדיקות מגליון מעקב בדיקות
    var inspSheet = ss.getSheetByName(CONFIG.WEAPONS.INSPECTIONS_SHEET);
    if (inspSheet && inspSheet.getLastRow() > 1) {
      var inspData    = inspSheet.getDataRange().getValues();
      var inspHeaders = inspData[0];
      var now         = Date.now();

      for (var k = 1; k < inspData.length; k++) {
        var irPn = (inspData[k][1] || '').toString().trim(); // B=מספר אישי
        if (!soldiers[irPn]) continue;
        var chk = 0, nreq = 0;
        for (var c = 6; c < inspHeaders.length; c++) {   // G ואילך = עמודות פריטים
          var val = inspData[k][c];
          if (!val) continue;
          if (val.toString().trim() === 'לא נדרש') {
            nreq++;
          } else {
            try {
              var d = new Date(val);
              if (!isNaN(d.getTime()) && (now - d.getTime()) / 86400000 <= 14) chk++;
            } catch (e) { /* ignore */ }
          }
        }
        soldiers[irPn].checkedRecent = chk;
        soldiers[irPn].notRequired   = nreq;
      }
    }

    var result = Object.values(soldiers);
    result.sort(function(a, b) {
      var tc = a.team.localeCompare(b.team, 'he');
      return tc !== 0 ? tc : a.name.localeCompare(b.name, 'he');
    });
    return { success: true, data: result };
  } catch (e) {
    Logger.log('❌ [Inspections] getSoldiersByUnit: ' + e);
    return { success: false, error: e.toString() };
  }
}

/**
 * מחזיר פריטי חייל + סטטוס בדיקה לכל פריט בנפרד
 */
function inspections_getSoldierData(pn) {
  try {
    var ss        = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
    var mainSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
    if (!mainSheet) return { success: false, error: 'גיליון לא נמצא' };

    var rows  = mainSheet.getDataRange().getValues();
    var items = [];
    for (var i = 1; i < rows.length; i++) {
      if ((rows[i][2] || '').toString().trim() !== pn.toString().trim()) continue;
      WEAPONS_ITEM_LIST.forEach(function(item) {
        var v = rows[i][item.col];
        if (v && v.toString().trim() !== '' && v.toString().trim() !== '0') {
          if (!items.some(function(it) { return it.key === item.key; })) {
            items.push({ key: item.key, label: item.label, value: v.toString(),
                         lastCheck: null, notRequired: false });
          }
        }
      });
      break;
    }

    // תאריכי בדיקה לפי עמודת פריט
    var inspSheet = ss.getSheetByName(CONFIG.WEAPONS.INSPECTIONS_SHEET);
    if (inspSheet && inspSheet.getLastRow() > 1) {
      var inspData    = inspSheet.getDataRange().getValues();
      var inspHeaders = inspData[0];
      // בנה מפה label → ערך לחייל זה
      for (var k = 1; k < inspData.length; k++) {
        if ((inspData[k][1] || '').toString().trim() !== pn.toString().trim()) continue;
        var labelToVal = {};
        for (var c = 6; c < inspHeaders.length; c++) {
          var lbl = (inspHeaders[c] || '').toString().trim();
          if (lbl && inspData[k][c] !== undefined && inspData[k][c] !== '') {
            labelToVal[lbl] = inspData[k][c];
          }
        }
        items.forEach(function(item) {
          var val = labelToVal[item.label];
          if (!val) return;
          if (val.toString().trim() === 'לא נדרש') {
            item.notRequired = true;
          } else {
            try { item.lastCheck = new Date(val).toISOString(); } catch (e) { /* ignore */ }
          }
        });
        break;
      }
    }
    return { success: true, data: { items: items } };
  } catch (e) {
    Logger.log('❌ [Inspections] getSoldierData: ' + e);
    return { success: false, error: e.toString() };
  }
}

/**
 * מסמן בדיקה/לא-נדרש לפריט ספציפי — upsert שורת חייל
 * type: 'check' → תאריך היום | 'skip' → 'לא נדרש'
 */
/**
 * מחזיר את כל חיילי המסגרת + פריטיהם + סטטוס בדיקות — קריאה אחת
 * גיליון מעקב בדיקות: [label] = מספר סידורי, [label תאריך בדיקה] = תאריך/"לא נדרש"
 */
function inspections_getUnitData(unit) {
  try {
    var ss = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);

    // ── קריאת גיליון נשקים ──
    var srcSheet     = ss.getSheetByName(unit);
    var filterByUnit = !srcSheet;
    if (!srcSheet) srcSheet = ss.getSheetByName(CONFIG.WEAPONS.MAIN_SHEET_NAME);
    if (!srcSheet)  return { success: false, error: 'גיליון לא נמצא' };

    var weapRows = srcSheet.getDataRange().getValues();
    var soldiers = {};
    for (var i = 1; i < weapRows.length; i++) {
      if (filterByUnit && (weapRows[i][5] || '').toString().trim() !== unit) continue;
      var pn = (weapRows[i][2] || '').toString().trim();
      if (!pn) continue;
      if (!soldiers[pn]) {
        soldiers[pn] = {
          pn:    pn,
          name:  (weapRows[i][1] || '').toString().trim(),
          phone: (weapRows[i][3] || '').toString().trim(),
          email: (weapRows[i][4] || '').toString().trim(),
          unit:  (weapRows[i][5] || '').toString().trim() || unit,
          team:  (weapRows[i][6] || '').toString().trim(),
          items: []
        };
        WEAPONS_ITEM_LIST.forEach(function(item) {
          var v = weapRows[i][item.col];
          if (v && v.toString().trim() !== '' && v.toString().trim() !== '0') {
            soldiers[pn].items.push({
              key: item.key, label: item.label, value: v.toString(),
              lastCheck: null, notRequired: false
            });
          }
        });
      }
    }

    // ── קריאת גיליון מעקב בדיקות ──
    var inspSheet = ss.getSheetByName(CONFIG.WEAPONS.INSPECTIONS_SHEET);
    if (inspSheet && inspSheet.getLastRow() > 1) {
      var inspData    = inspSheet.getDataRange().getValues();
      var inspHeaders = inspData[0];

      // בנה מפה: label → אינדקס עמודת תאריך (0-based)
      var dateIdxByLabel = {};
      for (var c = 0; c < inspHeaders.length; c++) {
        var h = (inspHeaders[c] || '').toString().trim();
        if (h.length > INSP_DATE_SUFFIX.length &&
            h.slice(-INSP_DATE_SUFFIX.length) === INSP_DATE_SUFFIX) {
          dateIdxByLabel[h.slice(0, h.length - INSP_DATE_SUFFIX.length)] = c;
        }
      }

      for (var k = 1; k < inspData.length; k++) {
        var irPn = (inspData[k][1] || '').toString().trim();
        if (!soldiers[irPn]) continue;
        soldiers[irPn].items.forEach(function(item) {
          var idx = dateIdxByLabel[item.label];
          if (idx === undefined) return;
          var val = inspData[k][idx];
          if (!val) return;
          if (val.toString().trim() === 'לא נדרש') {
            item.notRequired = true;
          } else {
            try { item.lastCheck = new Date(val).toISOString(); } catch (e) { /* ignore */ }
          }
        });
      }
    }

    // ── סיכום לכל חייל + מיון ──
    var now    = Date.now();
    var result = Object.values(soldiers);
    result.forEach(function(s) {
      s.totalItems    = s.items.length;
      s.checkedRecent = s.items.filter(function(i) {
        return i.lastCheck && !i.notRequired &&
               (now - new Date(i.lastCheck).getTime()) <= INSP_OVERDUE_MS;
      }).length;
      s.notRequired = s.items.filter(function(i) { return i.notRequired; }).length;
    });
    result.sort(function(a, b) {
      var tc = a.team.localeCompare(b.team, 'he');
      return tc !== 0 ? tc : a.name.localeCompare(b.name, 'he');
    });
    return { success: true, data: result };
  } catch (e) {
    Logger.log('❌ [Inspections] getUnitData: ' + e);
    return { success: false, error: e.toString() };
  }
}

/**
 * מסמן בדיקה/לא-נדרש לפריט ספציפי
 * גיליון: [label] = מספר סידורי | [label תאריך בדיקה] = תאריך/"לא נדרש"
 * serial ו-itemLabel מגיעים מה-frontend (ללא קריאת גיליון נוסף)
 */
function inspections_markItem(pn, name, phone, email, unit, team, itemKey, itemLabel, serial, type) {
  try {
    var ss    = SpreadsheetApp.openById(CONFIG.SHEETS.WEAPONS);
    var sheet = ss.getSheetByName(CONFIG.WEAPONS.INSPECTIONS_SHEET);
    if (!sheet) return { success: false, error: 'גיליון מעקב בדיקות לא נמצא' };

    // fallback: חפש label ב-WEAPONS_ITEM_LIST אם לא הועבר
    if (!itemLabel) {
      for (var j = 0; j < WEAPONS_ITEM_LIST.length; j++) {
        if (WEAPONS_ITEM_LIST[j].key === itemKey) { itemLabel = WEAPONS_ITEM_LIST[j].label; break; }
      }
    }
    if (!itemLabel) return { success: false, error: 'פריט לא נמצא: ' + itemKey };

    _insp_ensureBase(sheet);
    var headerMap = _insp_headerMap(sheet);

    // שתי עמודות: [label] = מספר סידורי | [label תאריך בדיקה] = תאריך
    var serialCol = _insp_ensureCol(sheet, headerMap, itemLabel);
    var dateCol   = _insp_ensureCol(sheet, headerMap, itemLabel + INSP_DATE_SUFFIX);
    var value     = (type === 'skip') ? 'לא נדרש' : new Date();

    var lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      var pnVals = sheet.getRange(2, 2, lastRow - 1, 1).getValues();
      for (var i = 0; i < pnVals.length; i++) {
        if ((pnVals[i][0] || '').toString().trim() !== pn.toString().trim()) continue;
        var rowIdx = i + 2;
        sheet.getRange(rowIdx, 1, 1, 6).setValues([[name, pn, phone, email, unit, team]]);
        if (serial) sheet.getRange(rowIdx, serialCol).setValue(serial);
        sheet.getRange(rowIdx, dateCol).setValue(value);
        return { success: true };
      }
    }

    // שורה חדשה
    var maxCol = Math.max(serialCol, dateCol);
    var newRow  = [name, pn, phone, email, unit, team];
    while (newRow.length < maxCol) newRow.push('');
    if (serial) newRow[serialCol - 1] = serial;
    newRow[dateCol - 1] = value;
    sheet.appendRow(newRow);
    return { success: true };
  } catch (e) {
    Logger.log('❌ [Inspections] markItem: ' + e);
    return { success: false, error: e.toString() };
  }
}
