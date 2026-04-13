/**
 * ================================================================
 * Apsnaut Module — מודול אפסנאות
 * ================================================================
 * גליון "פריטים":
 *   A = שם פריט  |  B = יחידת מידה  |  C = חשוב (true/false)
 *
 * גליון "חתימות" — שורה אחת לחתימה, פריטים כעמודות דינמיות:
 *   A = מזהה  |  B = תאריך  |  C = שם מלא  |  D = מספר אישי
 *   E = פלוגה  |  F = על ידי  |  G+ = שם פריט (כמות בתא)
 * ================================================================
 */

var APSNAUT_ITEMS_SHEET    = 'פריטים';
var APSNAUT_CHECKOUT_SHEET = 'חתימות';
var APSNAUT_ITEMS_HEADERS  = ['שם פריט', 'יחידת מידה', 'חשוב'];

// עמודות קבועות בגליון חתימות — שאר העמודות הן פריטים דינמיים
var APSNAUT_CHECKOUT_FIXED   = ['מזהה', 'תאריך', 'שם מלא', 'מספר אישי', 'פלוגה', 'על ידי'];
var APSNAUT_CHECKOUT_FIXED_N = 6;

// ── עזר ──
function apsnaut_ss() {
  return SpreadsheetApp.openById(CONFIG.SHEETS.APSNAUT);
}

function apsnaut_ensureSheet(ss, name, headers) {
  var sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    if (headers && headers.length) {
      sh.getRange(1, 1, 1, headers.length).setValues([headers]);
      sh.getRange(1, 1, 1, headers.length)
        .setBackground('#1a3a1a').setFontColor('#ffffff').setFontWeight('bold');
    }
  }
  return sh;
}

function apsnaut_uid() {
  return Utilities.getUuid().split('-')[0].toUpperCase();
}

function apsnaut_ts() {
  return Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'dd/MM/yyyy HH:mm');
}

function apsnaut_driveTimestamp() {
  var d   = new Date();
  var pad = function(n) { return n < 10 ? '0' + n : String(n); };
  return pad(d.getDate()) + '-' + pad(d.getMonth()+1) + '-' + d.getFullYear() +
         '_' + pad(d.getHours()) + '-' + pad(d.getMinutes());
}

// ================================================================
// 1. שליפת רשימת פריטים
// ================================================================
function apsnaut_getItems() {
  var ss = apsnaut_ss();
  var sh = apsnaut_ensureSheet(ss, APSNAUT_ITEMS_SHEET, APSNAUT_ITEMS_HEADERS);
  if (sh.getLastRow() < 2) return { success: true, data: [] };

  var rows  = sh.getRange(2, 1, sh.getLastRow()-1, 3).getValues();
  var items = [];
  rows.forEach(function(r) {
    var name = String(r[0] || '').trim();
    if (!name) return;
    items.push({
      name:      name,
      unit:      String(r[1] || '').trim(),
      important: (r[2] === true || String(r[2]).toLowerCase() === 'true')
    });
  });
  return { success: true, data: items };
}

// ================================================================
// 2. הוספת פריט חדש
// ================================================================
function apsnaut_addItem(data) {
  if (!data || !String(data.name || '').trim())
    return { success: false, error: 'חסר שם פריט' };

  var ss = apsnaut_ss();
  var sh = apsnaut_ensureSheet(ss, APSNAUT_ITEMS_SHEET, APSNAUT_ITEMS_HEADERS);

  // בדיקת כפילות
  if (sh.getLastRow() > 1) {
    var existing = sh.getRange(2, 1, sh.getLastRow()-1, 1).getValues();
    for (var i = 0; i < existing.length; i++) {
      if (String(existing[i][0] || '').trim() === data.name.trim())
        return { success: false, error: 'פריט בשם זה כבר קיים' };
    }
  }

  sh.appendRow([data.name.trim(), (data.unit || '').trim(), data.important ? true : false]);
  return { success: true };
}

// ================================================================
// 3. החתמה — שורה אחת לחתימה, פריטים כעמודות דינמיות
// ================================================================

// עזר: מוודא שכל פריט מיוצג בעמודה. מחזיר מפה itemName → col (1-based)
function apsnaut_ensureItemCols(sh, itemNames) {
  var lastCol = Math.max(sh.getLastColumn(), APSNAUT_CHECKOUT_FIXED_N);
  var headers = sh.getRange(1, 1, 1, lastCol).getValues()[0];

  var colMap = {};
  headers.forEach(function(h, i) {
    var name = String(h || '').trim();
    if (i >= APSNAUT_CHECKOUT_FIXED_N && name) colMap[name] = i + 1;
  });

  itemNames.forEach(function(name) {
    if (!name || colMap[name]) return;
    var newCol = sh.getLastColumn() + 1;
    sh.getRange(1, newCol).setValue(name)
      .setBackground('#1a3a1a').setFontColor('#ffffff').setFontWeight('bold');
    colMap[name] = newCol;
  });

  return colMap;
}

function apsnaut_checkout(data) {
  if (!data || !data.fullName || !data.personalNumber || !data.unit
      || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לחתימה' };

  var ss  = apsnaut_ss();
  var sh  = apsnaut_ensureSheet(ss, APSNAUT_CHECKOUT_SHEET, APSNAUT_CHECKOUT_FIXED);
  var uid = apsnaut_uid();
  var ts  = apsnaut_ts();

  // וודא שלכל פריט יש עמודה
  var itemNames = data.items.map(function(i) { return (i.name || '').trim(); });
  var colMap    = apsnaut_ensureItemCols(sh, itemNames);

  // בנה שורה: עמודות קבועות + כמויות לפי עמודת פריט
  var totalCols = sh.getLastColumn();
  var row = new Array(totalCols).fill('');
  row[0] = uid;
  row[1] = ts;
  row[2] = data.fullName;
  row[3] = data.personalNumber;
  row[4] = data.unit;
  row[5] = data.by || '';

  data.items.forEach(function(item) {
    var name = (item.name || '').trim();
    var col  = colMap[name];
    if (!col) return;
    row[col - 1] = Number(item.qty) || 0;
  });

  sh.appendRow(row);

  try { apsnaut_generateAndSavePDF(data, uid, ts); }
  catch(e) { Logger.log('⚠️ [Apsnaut] PDF error: ' + e); }

  return { success: true, id: uid };
}

// ================================================================
// 4. בדיקת מספר אישי מגליון חתימות (JSONP — נקרא מ-doGet)
// ================================================================
function apsnaut_checkPersonalNumber(personalNumber, callback) {
  var pn = String(personalNumber || '').trim();
  if (!pn) return createJsonpResponse({ exists: false }, callback);

  var ss = apsnaut_ss();
  var sh = ss.getSheetByName(APSNAUT_CHECKOUT_SHEET);
  if (!sh || sh.getLastRow() < 2)
    return createJsonpResponse({ exists: false }, callback);

  var rows = sh.getRange(2, 1, sh.getLastRow()-1, 5).getValues();
  // מצא את הרשומה האחרונה לפי מ"א (עמודה D = index 3)
  var found = null;
  rows.forEach(function(r) {
    if (String(r[3] || '').trim() === pn) found = r;
  });

  if (!found) return createJsonpResponse({ exists: false }, callback);

  return createJsonpResponse({
    exists: true,
    data: {
      personalNumber: String(found[3] || '').trim(),
      fullName:       String(found[2] || '').trim(),
      unit:           String(found[4] || '').trim()
    }
  }, callback);
}

// ================================================================
// 4b. שליפת רשימת חיילים ייחודיים מגליון חתימות (לחיפוש לפי שם)
// ================================================================
function apsnaut_getSoldiers() {
  var ss = apsnaut_ss();
  var sh = ss.getSheetByName(APSNAUT_CHECKOUT_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, data: [] };

  var rows = sh.getRange(2, 1, sh.getLastRow()-1, 5).getValues();
  var seen   = {};
  var result = [];
  rows.forEach(function(r) {
    var pn   = String(r[3] || '').trim();
    var name = String(r[2] || '').trim();
    var unit = String(r[4] || '').trim();
    if (!pn || seen[pn]) return;
    seen[pn] = true;
    result.push({ pn: pn, name: name, unit: unit });
  });
  result.sort(function(a, b) { return a.name.localeCompare(b.name, 'he'); });
  return { success: true, data: result };
}

// ================================================================
// 5b. שליפת פריטי החתימה האחרונה לחייל לפי מ"א
// ================================================================
function apsnaut_getSoldierItems(personalNumber) {
  var pn = String(personalNumber || '').trim();
  if (!pn) return { success: true, data: [] };

  var ss = apsnaut_ss();
  var sh = ss.getSheetByName(APSNAUT_CHECKOUT_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, data: [] };

  var lastCol = sh.getLastColumn();
  var headers = sh.getRange(1, 1, 1, lastCol).getValues()[0];
  var rows    = sh.getRange(2, 1, sh.getLastRow()-1, lastCol).getValues();

  // השורה האחרונה לפי מ"א (appendRow — האחרונה שנמצאה היא הכי עדכנית)
  var latestRow = null;
  rows.forEach(function(r) {
    if (String(r[3] || '').trim() === pn) latestRow = r;
  });
  if (!latestRow) return { success: true, data: [] };

  var items = [];
  for (var i = APSNAUT_CHECKOUT_FIXED_N; i < headers.length; i++) {
    var name = String(headers[i] || '').trim();
    var qty  = Number(latestRow[i]) || 0;
    if (name && qty) items.push({ name: name, unit: '', qty: qty, notes: '' });
  }
  return { success: true, data: items };
}

// ================================================================
// 5. שליפת היסטוריית חתימות
// ================================================================
function apsnaut_getCheckouts() {
  var ss = apsnaut_ss();
  var sh = ss.getSheetByName(APSNAUT_CHECKOUT_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, data: [] };

  var lastCol = sh.getLastColumn();
  var headers = sh.getRange(1, 1, 1, lastCol).getValues()[0];
  var rows    = sh.getRange(2, 1, sh.getLastRow()-1, lastCol).getValues();

  var result = rows
    .filter(function(r) { return String(r[0] || '').trim(); })
    .map(function(r) {
      var items = [];
      for (var i = APSNAUT_CHECKOUT_FIXED_N; i < headers.length; i++) {
        var name = String(headers[i] || '').trim();
        var qty  = Number(r[i]) || 0;
        if (name && qty) items.push({ name: name, qty: qty });
      }
      return {
        id:             String(r[0] || '').trim(),
        date:           r[1] instanceof Date
                          ? Utilities.formatDate(r[1], CONFIG.TIMEZONE, 'dd/MM/yyyy HH:mm')
                          : String(r[1] || '').trim(),
        fullName:       String(r[2] || '').trim(),
        personalNumber: String(r[3] || '').trim(),
        unit:           String(r[4] || '').trim(),
        by:             String(r[5] || '').trim(),
        items:          items
      };
    }).reverse();

  return { success: true, data: result };
}

// ================================================================
// PDF — יצירה ושמירה
// ================================================================
function apsnaut_generateAndSavePDF(data, uid, ts) {
  var html = apsnaut_createPdfHtml(data, uid, ts);
  var blob = Utilities.newBlob(html, 'text/html', 'apsnaut.html');
  var pdf  = blob.getAs('application/pdf');
  apsnaut_saveCurrentPdf(pdf, data.fullName, data.unit);
}

/**
 * שומר PDF אחד בלבד לכל חייל (העדכני ביותר).
 * שם קובץ: {fullName}.pdf
 * מחיקה גלובלית של כל קובץ בשם זה לפני שמירה.
 * מיקום: Root / אפסנאות / {unit} / {fullName}.pdf
 */
function apsnaut_saveCurrentPdf(pdfBlob, fullName, unit) {
  var rootId = (CONFIG.DRIVE || {}).ROOT_FOLDER_ID || '';
  if (!rootId) { Logger.log('⚠️ [Apsnaut] No ROOT_FOLDER_ID — skipping Drive save'); return; }

  var filename = String(fullName || '').trim() + '.pdf';
  try {
    // מחק את כל הקבצים הישנים בשם זה (בכל מיקום ב-Drive)
    var old = DriveApp.searchFiles('title = "' + filename + '" and trashed = false');
    while (old.hasNext()) { old.next().setTrashed(true); }

    // שמור את החדש
    var root       = DriveApp.getFolderById(rootId);
    var typeIter   = root.getFoldersByName('אפסנאות');
    var typeFolder = typeIter.hasNext() ? typeIter.next() : root.createFolder('אפסנאות');
    var unitName   = (unit || '').trim() || 'ללא פלוגה';
    var unitIter   = typeFolder.getFoldersByName(unitName);
    var unitFolder = unitIter.hasNext() ? unitIter.next() : typeFolder.createFolder(unitName);

    pdfBlob.setName(filename);
    unitFolder.createFile(pdfBlob);
    Logger.log('✅ [Apsnaut] PDF saved: אפסנאות/' + unitName + '/' + filename);
  } catch(e) {
    Logger.log('⚠️ [Apsnaut] saveCurrentPdf failed: ' + e);
  }
}

function apsnaut_createPdfHtml(data, uid, ts) {
  var itemsHtml = (data.items || []).map(function(item, idx) {
    return '<tr style="background:' + (idx % 2 === 0 ? '#fff' : '#f7f9f5') + '">' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e0e0e0;">' + (item.name  || '') + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e0e0e0;text-align:center;">' + (item.unit  || '') + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e0e0e0;text-align:center;font-weight:bold;">' + (Number(item.qty) || 0) + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e0e0e0;color:#555;font-size:0.9em;">' + (item.notes || '') + '</td>' +
    '</tr>';
  }).join('');

  return '<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><style>' +
    '* { font-family: Arial, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }' +
    'body { padding: 24px; background: #f0f4ee; }' +
    '.header { background: linear-gradient(135deg,#2d5a2d,#4a8f4a); color: white; padding: 22px 24px;' +
    '  text-align: center; margin-bottom: 22px; border-radius: 8px; }' +
    '.header h1 { font-size: 22px; margin-bottom: 4px; }' +
    '.header .sub { font-size: 13px; opacity: 0.85; }' +
    '.box { background: white; padding: 20px; border-radius: 8px; margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }' +
    '.field { display: flex; padding: 7px 0; border-bottom: 1px solid #f0f0f0; }' +
    '.flabel { font-weight: bold; min-width: 130px; color: #2d5a2d; font-size: 0.9em; }' +
    '.fval { flex: 1; font-size: 0.9em; }' +
    'table { width: 100%; border-collapse: collapse; margin-top: 4px; }' +
    'th { background: #2d5a2d; color: white; padding: 10px 12px; text-align: right; font-size: 0.88em; }' +
    '.disclaimer { background: #f0f7e8; border: 1px solid #a5c98b; padding: 13px; border-radius: 5px; font-size: 0.87em; line-height: 1.5; margin-bottom: 4px; }' +
    '.sig-img { border: 1px solid #ccc; padding: 3px; max-width: 220px; display: block; margin-top: 8px; }' +
    '.footer { text-align: center; margin-top: 14px; color: #999; font-size: 10px; }' +
    '</style></head><body>' +

    '<div class="header">' +
    '<h1>✓ אישור קבלת אפסנאות</h1>' +
    '<div class="sub">גדחה"ו קומנדו 8219 &nbsp;|&nbsp; מזהה: ' + uid + ' &nbsp;|&nbsp; ' + ts + '</div>' +
    '</div>' +

    '<div class="box">' +
    '<div class="field"><div class="flabel">שם מלא:</div><div class="fval">' + (data.fullName       || '') + '</div></div>' +
    '<div class="field"><div class="flabel">מספר אישי:</div><div class="fval">' + (data.personalNumber || '') + '</div></div>' +
    '<div class="field"><div class="flabel">פלוגה:</div><div class="fval">' + (data.unit           || '') + '</div></div>' +
    '</div>' +

    '<div class="box">' +
    '<table>' +
    '<thead><tr><th>פריט</th><th style="width:80px">יח"מ</th><th style="width:70px">כמות</th><th>הערות</th></tr></thead>' +
    '<tbody>' + itemsHtml + '</tbody>' +
    '</table>' +
    '</div>' +

    '<div class="box">' +
    '<div class="disclaimer">' +
    '<strong>הצהרה:</strong> אני מאשר/ת בזאת כי קיבלתי את הציוד המפורט ברשימה זו, וכי כל הפרטים שמסרתי נכונים ומדויקים. ' +
    'אני מתחייב/ת לשמור על הציוד, להשתמש בו באופן מסודר ולהחזירו במצב תקין לאחר הצורך.' +
    '</div>' +
    (data.signature
      ? '<div style="margin-top:12px;"><div style="font-weight:bold;color:#2d5a2d;margin-bottom:4px;font-size:0.9em;">חתימת החייל:</div>' +
        '<img src="' + data.signature + '" class="sig-img" alt="חתימה"/></div>'
      : '') +
    '</div>' +

    '<div class="footer">מסמך זה נוצר אוטומטית | © 2026 כל הזכויות שמורות | גדחה"ו קומנדו 8219</div>' +
    '</body></html>';
}
