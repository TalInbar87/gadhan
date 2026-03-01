/**
 * ================================================================
 * Radio Module - מודול קשר
 * ================================================================
 * מבנה גיליון קשר (כל הרשומות):
 * A(0)=מספר אישי | B(1)=תאריך ושעה | C(2)=שם מלא
 * D(3)=טלפון | E(4)=מייל | F(5)=מסגרת
 * G(6)=624 | H(7)=91 | I(8)=עמוד | J(9)=מספר עמוד
 * K(10)=מגבר | L(11)=מתאם קשיח | M(12)=אנטנה לונג | N(13)=מעד
 * O(14)=מתאם גמיש | P(15)=אנטנה שורט | Q(16)=רמק
 * R(17)=מדונה | S(18)=תפוח | T(19)=אגס
 *
 * גיליון זיכויים: אותן עמודות A-T + U=תאריך זיכוי + V=זוכה על ידי
 *
 * כל הפונקציות מחזירות plain object { success, message?, error? }
 * (הניתוב ל-HTTP response נעשה ב-Main.js)
 * ================================================================
 */

// ================================================================
// Check Personal Number
// ================================================================

/**
 * בדיקת קיום מספר אישי בגיליון קשר
 * מחזיר JSONP response ישירות (נקרא מ-doGet)
 */
function radio_checkPersonalNumber(personalNumber, callback) {
  Logger.log('🔍 [Radio] Checking PN: ' + personalNumber);
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.RADIO);
  const mainSheet = ss.getSheetByName(CONFIG.RADIO.MAIN_SHEET_NAME);
  if (!mainSheet) return createJsonpResponse({ exists: false }, callback);

  const rows = mainSheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i][0] == personalNumber) { // עמודה A = מספר אישי
      return createJsonpResponse({
        exists: true,
        data: {
          personalNumber:  rows[i][0],
          fullName:        rows[i][2],
          phone:           '0' + rows[i][3],
          email:           rows[i][4],
          unit:            rows[i][5],
          radio624:        rows[i][6],
          radio91:         rows[i][7],
          hasColumn:       rows[i][8] === '1',
          columnNumber:    rows[i][9],
          amplifier:       rows[i][10],
          rigidAdapter:    rows[i][11],
          longAntenna:     rows[i][12],
          mad:             rows[i][13],
          flexibleAdapter: rows[i][14],
          shortAntenna:    rows[i][15],
          speaker:         rows[i][16],
          madona:          rows[i][17],
          apple:           rows[i][18],
          pear:            rows[i][19]
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
 * שמירת נתוני חתימה בגיליון הקשר (גיליון מסגרת + גיליון ראשי)
 */
function radio_saveToSheet(data) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.RADIO);
  const ts = formatTimestamp();
  radio_saveToUnitSheet(ss, data, ts);
  radio_saveToMainSheet(ss, data, ts);
}

function radio_saveToUnitSheet(ss, data, timestamp) {
  const sheetName = data.unit || CONFIG.RADIO.DEFAULT_UNIT;
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) sheet = radio_createUnitSheet(ss, sheetName);

  const existingRow = findExistingRow(sheet, data.personalNumber, CONFIG.RADIO.PN_COLUMN);
  const rowData = radio_prepareRowData(data, timestamp);

  if (existingRow) {
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ [Radio] Updated unit sheet: ' + sheetName);
  } else {
    sheet.appendRow(rowData);
    Logger.log('✓ [Radio] Added to unit sheet: ' + sheetName);
  }
}

function radio_saveToMainSheet(ss, data, timestamp) {
  let mainSheet = ss.getSheetByName(CONFIG.RADIO.MAIN_SHEET_NAME);
  if (!mainSheet) mainSheet = radio_createUnitSheet(ss, CONFIG.RADIO.MAIN_SHEET_NAME);

  const existingRow = findExistingRow(mainSheet, data.personalNumber, CONFIG.RADIO.PN_COLUMN);
  const rowData = radio_prepareRowData(data, timestamp);

  if (existingRow) {
    mainSheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    Logger.log('✓ [Radio] Updated main sheet');
  } else {
    mainSheet.appendRow(rowData);
    Logger.log('✓ [Radio] Added to main sheet');
  }
}

function radio_createUnitSheet(ss, sheetName) {
  const sheet = ss.insertSheet(sheetName);
  const headers = [
    'מספר אישי', 'תאריך ושעה', 'שם מלא', 'טלפון', 'מייל', 'מסגרת',
    '624', '91', 'עמוד', 'מספר עמוד', 'מגבר', 'מתאם קשיח', 'אנטנה לונג',
    'מעד', 'מתאם גמיש', 'אנטנה שורט', 'רמק', 'מדונה', 'תפוח', 'אגס'
  ];
  sheet.appendRow(headers);
  const hr = sheet.getRange(1, 1, 1, headers.length);
  hr.setBackground(CONFIG.RADIO.HEADER_COLOR);
  hr.setFontColor('#FFFFFF');
  hr.setFontWeight('bold');
  hr.setHorizontalAlignment('right');
  Logger.log('✓ [Radio] Created sheet: ' + sheetName);
  return sheet;
}

function radio_prepareRowData(data, timestamp) {
  return [
    data.personalNumber,
    timestamp,
    data.fullName,
    data.phone,
    data.email,
    data.unit            || '',
    data.radio624        || '',
    data.radio91         || '',
    data.hasColumn ? '1' : '',
    data.columnNumber    || '',
    data.amplifier       || '',
    data.rigidAdapter    || '',
    data.longAntenna     || '',
    data.mad             || '',
    data.flexibleAdapter || '',
    data.shortAntenna    || '',
    data.speaker         || '',
    data.madona          || '',
    data.apple           || '',
    data.pear            || ''
  ];
}

// ================================================================
// Full Credit
// ================================================================

/**
 * זיכוי מלא - העברת רשומה לגיליון זיכויים + מחיקה מגיליונות
 * @returns {{ success: boolean, message?: string, error?: string }}
 */
function radio_handleCredit(data) {
  const { personalNumber, creditAt, creditBy } = data;
  Logger.log('💳 [Radio] Full credit: ' + personalNumber);

  const ss = SpreadsheetApp.openById(CONFIG.SHEETS.RADIO);
  const mainSheet = ss.getSheetByName(CONFIG.RADIO.MAIN_SHEET_NAME);
  if (!mainSheet) return { success: false, error: 'Main sheet not found' };

  const allData = mainSheet.getDataRange().getValues();
  let foundRow = -1, rowData = null;
  for (let i = 1; i < allData.length; i++) {
    if (allData[i][0] == personalNumber) { // עמודה A
      foundRow = i + 1;
      rowData = allData[i];
      break;
    }
  }
  if (foundRow === -1) return { success: false, error: 'Record not found' };

  // יצירת/קבלת גיליון זיכויים
  let creditSheet = ss.getSheetByName('זיכויים');
  if (!creditSheet) {
    creditSheet = ss.insertSheet('זיכויים');
    const headers = [
      'מספר אישי', 'תאריך ושעה', 'שם מלא', 'טלפון', 'מייל', 'מסגרת',
      '624', '91', 'עמוד', 'מספר עמוד', 'מגבר', 'מתאם קשיח', 'אנטנה לונג',
      'מעד', 'מתאם גמיש', 'אנטנה שורט', 'רמק', 'מדונה', 'תפוח', 'אגס',
      'תאריך זיכוי', 'זוכה על ידי'
    ];
    creditSheet.appendRow(headers);
    const hr = creditSheet.getRange(1, 1, 1, headers.length);
    hr.setBackground('#8B0000');
    hr.setFontColor('#FFFFFF');
    hr.setFontWeight('bold');
    hr.setHorizontalAlignment('right');
  }

  // בדוק כפילות (מספר אישי בעמודה A של גיליון זיכויים)
  let alreadyExists = false;
  if (creditSheet.getLastRow() >= 2) {
    const cd = creditSheet.getDataRange().getValues();
    for (let i = 1; i < cd.length; i++) {
      if (cd[i][0] == personalNumber) { alreadyExists = true; break; }
    }
  }

  if (!alreadyExists) {
    creditSheet.appendRow([...rowData, creditAt || new Date().toISOString(), creditBy || 'unknown']);
    Logger.log('✓ Added to credit sheet');
  } else {
    Logger.log('⚠️ Already in credit sheet - skipping duplicate');
  }

  // מחק מהגיליון הראשי
  mainSheet.deleteRow(foundRow);
  Logger.log('✓ Deleted from main sheet');

  // מחק מגיליון המסגרת
  const unit = rowData[5]; // column F
  if (unit) {
    const unitSheet = ss.getSheetByName(unit);
    if (unitSheet) {
      const ud = unitSheet.getDataRange().getValues();
      for (let i = 1; i < ud.length; i++) {
        if (ud[i][0] == personalNumber) { unitSheet.deleteRow(i + 1); break; }
      }
    }
  }

  // שלח מייל אישור זיכוי לחייל
  try {
    const email    = rowData[4];           // עמודה E
    const fullName = rowData[2];           // עמודה C
    if (email) {
      const ts = new Date().toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });

      // בנה רשימת ציוד שהוחזר
      const equipmentMap = [
        { label: 'קשר 624',    val: rowData[6]  },
        { label: 'קשר 91',     val: rowData[7]  },
        { label: 'עמוד',       val: (rowData[8] == '1' || rowData[8] == 1) ? ('כן — מספר ' + (rowData[9] || '')) : '' },
        { label: 'מגבר',       val: rowData[10] },
        { label: 'מתאם קשיח',  val: rowData[11] },
        { label: 'אנטנה לונג', val: rowData[12] },
        { label: 'מעד',        val: rowData[13] },
        { label: 'מתאם גמיש',  val: rowData[14] },
        { label: 'אנטנה שורט', val: rowData[15] },
        { label: 'רמקול',      val: rowData[16] },
        { label: 'מדונה',      val: rowData[17] },
        { label: 'תפוח',       val: rowData[18] },
        { label: 'אגס',        val: rowData[19] }
      ];
      const equipmentLines = equipmentMap
        .filter(e => e.val && e.val !== '' && e.val !== '0')
        .map(e => '• ' + e.label + ': ' + e.val)
        .join('\n');

      const html = radio_createCreditPdfHtml(rowData, creditBy, data.creditSignature, ts);
      const blob = Utilities.newBlob(html, 'text/html', 'credit.html');
      const pdf  = blob.getAs('application/pdf');
      pdf.setName('אישור_זיכוי_קשר_' + personalNumber + '_' + Date.now() + '.pdf');
      MailApp.sendEmail({
        to:          email,
        subject:     'אישור זיכוי ציוד קשר - ' + fullName,
        body:        'שלום ' + fullName + ',\n\n' +
                     'ציוד הקשר שלך הוחזר ורשומך זוכתה במערכת.\n\n' +
                     (equipmentLines ? 'ציוד שהוחזר:\n' + equipmentLines + '\n\n' : '') +
                     'מספר אישי: ' + personalNumber + '\n' +
                     (unit ? 'מסגרת: ' + unit + '\n' : '') +
                     'בוצע על ידי: ' + (creditBy || 'לא ידוע') + '\n' +
                     'תאריך: ' + ts + '\n\n' +
                     'מצורף אישור PDF מפורט.\n\n' +
                     'בברכה,\nמערכת ניהול מכשירי קשר\nגדחה"ו קומנדו 8219',
        attachments: [pdf]
      });
      Logger.log('✅ [Radio] Credit email with PDF sent to: ' + email);
    }
  } catch (emailErr) {
    Logger.log('⚠️ [Radio] Credit email failed: ' + emailErr);
  }

  return { success: true, message: 'Credit completed' };
}

// ================================================================
// PDF & Email
// ================================================================

/**
 * מייצר HTML לPDF זיכוי קשר — בנוי מנתוני rowData של הגיליון
 */
function radio_createCreditPdfHtml(rowData, creditBy, creditSignature, ts) {
  var equipmentDefs = [
    { label: 'קשר 624',    col: 6  }, { label: 'קשר 91',     col: 7  },
    { label: 'עמוד',       col: 8, extraCol: 9 },
    { label: 'מגבר',       col: 10 }, { label: 'מתאם קשיח',  col: 11 },
    { label: 'אנטנה לונג', col: 12 }, { label: 'מעד',        col: 13 },
    { label: 'מתאם גמיש',  col: 14 }, { label: 'אנטנה שורט', col: 15 },
    { label: 'רמקול',      col: 16 }, { label: 'מדונה',      col: 17 },
    { label: 'תפוח',       col: 18 }, { label: 'אגס',        col: 19 }
  ];
  var f = function(label, val) {
    return val ? '<div class="field"><div class="field-label">' + label + ':</div><div class="field-value">' + val + '</div></div>' : '';
  };
  var equipRows = equipmentDefs.map(function(d) {
    var val = rowData[d.col];
    if (!val || val === '' || val == 0) return '';
    // עמוד — מציג מספר סידורי אם קיים
    var display = (d.extraCol && rowData[d.extraCol]) ? 'כן — ' + rowData[d.extraCol] : String(val);
    return f(d.label, display);
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
    '<div class="header"><h1>✓ אישור זיכוי ציוד קשר</h1>' +
    '<p>מערכת ניהול מכשירי קשר - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    f('תאריך זיכוי', ts) +
    f('שם מלא',      rowData[2]) +
    f('מספר אישי',   String(rowData[0])) +
    f('מסגרת',       rowData[5]) +
    equipRows +
    f('זוכה על ידי', creditBy || '') +
    '</div>' +
    (creditSignature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת המאשר:</div><img src="' + creditSignature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

function radio_generateAndSendPDF(data) {
  const ts = formatTimestamp();
  const blob = Utilities.newBlob(radio_createPdfHtml(data, ts), 'text/html', 'checkout.html');
  const pdf  = blob.getAs('application/pdf');
  pdf.setName('אישור_קבלת_ציוד_' + data.personalNumber + '_' + Date.now() + '.pdf');
  radio_sendEmail(data, pdf, ts);
}

function radio_createPdfHtml(data, timestamp) {
  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; }' +
    'body { padding: 20px; background: #f5f5f5; }' +
    '.header { background: #1e40af; color: white; padding: 20px; text-align: center; margin-bottom: 20px; }' +
    '.header h1 { font-size: 24px; margin-bottom: 5px; }' +
    '.header p { font-size: 14px; opacity: 0.9; }' +
    '.content { background: white; padding: 20px; border-radius: 8px; }' +
    '.field { display: flex; padding: 10px 0; border-bottom: 1px solid #eee; }' +
    '.field-label { font-weight: bold; min-width: 150px; color: #1e40af; }' +
    '.field-value { flex: 1; }' +
    '.disclaimer { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }' +
    '.sig { margin-top: 20px; text-align: center; }' +
    '.sig img { max-width: 250px; border: 1px solid #ccc; padding: 3px; }' +
    '.footer { text-align: center; margin-top: 15px; color: #666; font-size: 10px; }' +
    '</style></head><body>' +
    '<div class="header"><h1>✓ אישור קבלת ציוד קשר</h1>' +
    '<p>מערכת ניהול מכשירי קשר - גדחה"ו קומנדו 8219</p></div>' +
    '<div class="content">' +
    '<div class="field"><div class="field-label">תאריך ושעה:</div><div class="field-value">' + timestamp + '</div></div>' +
    '<div class="field"><div class="field-label">שם מלא:</div><div class="field-value">' + data.fullName + '</div></div>' +
    '<div class="field"><div class="field-label">מספר אישי:</div><div class="field-value">' + data.personalNumber + '</div></div>' +
    '<div class="field"><div class="field-label">טלפון:</div><div class="field-value">' + data.phone + '</div></div>' +
    (data.unit            ? '<div class="field"><div class="field-label">מסגרת:</div><div class="field-value">'          + data.unit            + '</div></div>' : '') +
    (data.radio624        ? '<div class="field"><div class="field-label">מ.ק 624:</div><div class="field-value">'         + data.radio624        + '</div></div>' : '') +
    (data.radio91         ? '<div class="field"><div class="field-label">מ.ק 91:</div><div class="field-value">'          + data.radio91         + '</div></div>' : '') +
    (data.hasColumn       ? '<div class="field"><div class="field-label">עמוד:</div><div class="field-value">כן'         + (data.columnNumber ? ' - ' + data.columnNumber : '') + '</div></div>' : '') +
    (data.amplifier       ? '<div class="field"><div class="field-label">מגבר:</div><div class="field-value">'            + data.amplifier       + '</div></div>' : '') +
    (data.rigidAdapter    ? '<div class="field"><div class="field-label">מתאם קשיח:</div><div class="field-value">'       + data.rigidAdapter    + '</div></div>' : '') +
    (data.longAntenna     ? '<div class="field"><div class="field-label">אנטנה לונג:</div><div class="field-value">'      + data.longAntenna     + '</div></div>' : '') +
    (data.mad             ? '<div class="field"><div class="field-label">מעד:</div><div class="field-value">'             + data.mad             + '</div></div>' : '') +
    (data.flexibleAdapter ? '<div class="field"><div class="field-label">מתאם גמיש:</div><div class="field-value">'       + data.flexibleAdapter + '</div></div>' : '') +
    (data.shortAntenna    ? '<div class="field"><div class="field-label">אנטנה שורט:</div><div class="field-value">'      + data.shortAntenna    + '</div></div>' : '') +
    (data.speaker         ? '<div class="field"><div class="field-label">רמק:</div><div class="field-value">'             + data.speaker         + '</div></div>' : '') +
    (data.madona          ? '<div class="field"><div class="field-label">מדונה:</div><div class="field-value">'           + data.madona          + '</div></div>' : '') +
    (data.apple           ? '<div class="field"><div class="field-label">תפוח:</div><div class="field-value">'            + data.apple           + '</div></div>' : '') +
    (data.pear            ? '<div class="field"><div class="field-label">אגס:</div><div class="field-value">'             + data.pear            + '</div></div>' : '') +
    '</div>' +
    '<div class="disclaimer"><strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את ציוד הקשר המפורט במסמך זה, וכי כל הפרטים שמסרתי נכונים ומדויקים. אני מתחייב/ת לשמור על הציוד ולהחזירו במצב תקין.</div>' +
    (data.signature ? '<div class="sig"><div class="field-label" style="display:block;margin-bottom:5px">חתימת החייל:</div><img src="' + data.signature + '" alt="חתימה"/></div>' : '') +
    '<div class="footer"><p>מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות</p></div>' +
    '</body></html>';
}

function radio_sendEmail(data, pdf, timestamp) {
  MailApp.sendEmail({
    to:          data.email,
    subject:     'אישור קבלת ציוד קשר - ' + data.fullName,
    body:        'שלום ' + data.fullName + ',\n\n' +
                 'אישור קבלת ציוד הקשר נקלט במערכת בהצלחה.\n\n' +
                 'תאריך: ' + timestamp + '\n' +
                 'מספר אישי: ' + data.personalNumber + '\n' +
                 (data.unit ? 'מסגרת: ' + data.unit + '\n' : '') +
                 '\nמצורף אישור PDF מפורט.\n\n' +
                 'בברכה,\nמערכת ניהול מכשירי קשר\nגדחה"ו קומנדו 8219',
    attachments: [pdf]
  });
  Logger.log('✅ [Radio] Email sent to: ' + data.email);
}
