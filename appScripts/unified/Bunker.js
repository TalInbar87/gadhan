/**
 * ================================================================
 * Bunker Module — מודול בונקר
 * ================================================================
 * גליון "מלאים" (CONFIG.SHEETS.BUNKER):
 *   שורה 1 = headers
 *   A = שם פריט
 *   B = מחסן א — נפתלי (מלאי נוכחי)
 *   C = מחסן ב — בילו  (מלאי נוכחי)
 *   D = פלוגה א | E = פלוגה ב | F = פלוגה ג | G = צמה
 *   H = ניוד | I = מחסר | J = חפק
 *   K = סה"כ נופק מנפתלי | L = סה"כ נופק מבילו
 *
 * גליון "ניפוקים" (היסטוריית עסקאות):
 *   A=id | B=timestamp | C=warehouse | D=unit | E=item | F=qty
 *   G=by | H=status (פעיל/זוכה) | I=credited_at | J=credited_by
 * ================================================================
 */

// ── מיפוי עמודות (1-indexed לשימוש ב-getRange) ──
var BUNKER_WAREHOUSE_COLS = { 'נפתלי': 2, 'בילו': 3 };
var BUNKER_UNIT_COLS = {
  'פלוגה א': 4,
  'פלוגה ב': 5,
  'פלוגה ג': 6,
  'צמה':     7,
  'ניוד':    8,
  'מחסר':    9,
  'חפק':    10
};
var BUNKER_TOTAL_COLS    = { 'נפתלי': 11, 'בילו': 12 };
var BUNKER_CREDITS_SHEET = 'זיכויים';

// ── עזר: פתח גליון ──
function bunker_ss() {
  return SpreadsheetApp.openById(CONFIG.SHEETS.BUNKER);
}

// ── עזר: צור גליון אם לא קיים ──
function bunker_ensureSheet(ss, name, headers) {
  var sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    if (headers && headers.length) {
      sh.getRange(1, 1, 1, headers.length).setValues([headers]);
      sh.getRange(1, 1, 1, headers.length)
        .setBackground('#1a1a2e')
        .setFontColor('#ffffff')
        .setFontWeight('bold');
    }
  }
  return sh;
}

// ── עזר: ID ייחודי ──
function bunker_uid() {
  return Utilities.getUuid().split('-')[0].toUpperCase();
}

// ── עזר: timestamp ──
function bunker_ts() {
  return Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'dd/MM/yyyy HH:mm');
}

// ── עזר: פורמט תאריך — מטפל גם ב-Date object וגם במחרוזת ──
function bunker_formatDate(val) {
  if (!val) return '';
  if (val instanceof Date) {
    return Utilities.formatDate(val, CONFIG.TIMEZONE, 'dd/MM/yyyy HH:mm');
  }
  return String(val).trim();
}

// ── עזר: parse "DD/MM/YYYY [HH:mm]" → Date object (ימנע פרשנות US locale של Sheets) ──
function bunker_parseLocalDate(str) {
  var m = String(str || '').match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (!m) return null;
  return new Date(parseInt(m[3]), parseInt(m[2]) - 1, parseInt(m[1]));
}

// ── עזר: מצא שורה לפי שם פריט בגליון מלאים ──
function bunker_findItemRow(sheet, itemName) {
  var rows = sheet.getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][0] || '').trim() === itemName.trim()) return i + 1; // 1-indexed
  }
  return -1;
}

// ================================================================
// 1. קרא רשימת פריטים מגליון מלאים
// ================================================================
function bunker_getItems() {
  var ss   = bunker_ss();
  var sh   = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!sh) return { success: false, error: 'גליון מלאים לא נמצא' };

  var rows  = sh.getDataRange().getValues();
  var items = [];
  for (var i = 1; i < rows.length; i++) {
    var name = String(rows[i][0] || '').trim();
    if (name) items.push({ key: name, label: name });
  }
  return { success: true, data: items };
}

// ================================================================
// 2. קרא מלאי נוכחי (נפתלי + בילו + כמויות לפי מסגרת)
// ================================================================
function bunker_getInventory() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!sh) return { success: false, error: 'גליון מלאים לא נמצא' };

  var rows  = sh.getDataRange().getValues();
  var items = [];

  for (var i = 1; i < rows.length; i++) {
    var name = String(rows[i][0] || '').trim();
    if (!name) continue;
    var entry = {
      label:   name,
      key:     name,
      nafatli: Number(rows[i][1]) || 0,
      bilo:    Number(rows[i][2]) || 0
    };
    items.push(entry);
  }
  return { success: true, data: items };
}

// ================================================================
// 2b. שמור מלאי — עדכן עמודות B (נפתלי) ו-C (בילו) בגליון מלאים
// ================================================================
function bunker_saveInventory(data) {
  if (!data || (!data.nafatli && !data.bilo)) return { success: false, error: 'חסרים נתונים' };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  var rows = main.getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    var key = String(rows[i][0] || '').trim();
    if (!key) continue;
    if (data.nafatli && data.nafatli[key] !== undefined)
      main.getRange(i + 1, 2).setValue(Number(data.nafatli[key]) || 0);
    if (data.bilo && data.bilo[key] !== undefined)
      main.getRange(i + 1, 3).setValue(Number(data.bilo[key]) || 0);
  }
  return { success: true };
}

// ================================================================
// 3. ניפוק — רשום עסקה + הפחת מלאי מחסן
// ================================================================
function bunker_dispense(data) {
  if (!data || !data.warehouse || !data.unit || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לניפוק' };

  var warehouseCol = BUNKER_WAREHOUSE_COLS[data.warehouse];
  if (!warehouseCol) return { success: false, error: 'מחסן לא מזוהה: ' + data.warehouse };
  if (!BUNKER_UNIT_COLS[data.unit]) return { success: false, error: 'מסגרת לא מזוהה: ' + data.unit };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  var disp = bunker_ensureSheet(ss, CONFIG.BUNKER.DISPENSES_SHEET,
    ['מזהה', 'תאריך', 'מחסן', 'מסגרת', 'פריט', 'כמות', 'מנפק', 'סטטוס', 'תאריך זיכוי', 'מזכה']);

  // שלב 1: ולידציה מלאה לכל הפריטים — לא כותבים כלום עד שהכל תקין
  var errors    = [];
  var validated = [];

  data.items.forEach(function(item) {
    var qty    = Number(item.qty) || 0;
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }

    var currentStock = Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0;
    if (qty > currentStock) {
      errors.push('אין מספיק מלאי — ' + item.key + ' (נדרש: ' + qty + ', קיים: ' + currentStock + ')');
      return;
    }
    validated.push({ item: item, rowIdx: rowIdx, qty: qty, stock: currentStock });
  });

  if (errors.length) return { success: false, error: errors.join(', ') };

  // שלב 2: כתיבה — רק אחרי שכל הולידציות עברו
  var ts = bunker_ts();

  validated.forEach(function(v) {
    main.getRange(v.rowIdx, warehouseCol).setValue(v.stock - v.qty);
    disp.appendRow([bunker_uid(), ts, data.warehouse, data.unit, v.item.key, v.qty, data.by || 'לא ידוע', 'פעיל', '', '']);
    bunker_schemaUpdateDispense(ss, v.item.key, data.unit, v.qty);
  });

  return { success: true, dispensed: validated.length };
}

// ================================================================
// 4. קרא ניפוקים פעילים מגליון "ניפוקים"
// ================================================================
function bunker_getDispenses(unit) {
  var ss   = bunker_ss();
  var disp = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (!disp) return { success: true, data: [] };

  var rows   = disp.getDataRange().getValues();
  var result = [];

  for (var i = 1; i < rows.length; i++) {
    var rowUnit = String(rows[i][3] || '').trim();
    if (unit && rowUnit !== unit) continue;
    result.push({
      id:        String(rows[i][0] || '').trim(),
      timestamp: bunker_formatDate(rows[i][1]),
      warehouse: String(rows[i][2] || '').trim(),
      unit:      rowUnit,
      itemKey:   String(rows[i][4] || '').trim(),
      itemLabel: String(rows[i][4] || '').trim(),
      qty:       Number(rows[i][5]) || 0,
      by:        String(rows[i][6] || '').trim()
    });
  }
  return { success: true, data: result };
}

// ================================================================
// 5. זיכוי — עדכון מלאים + לוג בלבד (ללא תלות בגליון ניפוקים)
// ================================================================
function bunker_credit(data) {
  if (!data || !data.unit || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לזיכוי' };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  if (!BUNKER_UNIT_COLS[data.unit]) return { success: false, error: 'מסגרת לא מזוהה: ' + data.unit };

  var warehouse    = data.warehouse || '';
  var warehouseCol = BUNKER_WAREHOUSE_COLS[warehouse];

  var creditsSheet = bunker_ensureSheet(ss, BUNKER_CREDITS_SHEET,
    ['תאריך זיכוי', 'מזכה', 'מחסן', 'מסגרת', 'פריט', 'כמות']);

  // שלב 1: ולידציה — בדוק שהפריט קיים במלאים
  var errors    = [];
  var validated = [];
  data.items.forEach(function(item) {
    var qty = Number(item.qty) || 0;
    if (qty <= 0) return;
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }
    validated.push({ key: item.key, qty: qty, rowIdx: rowIdx });
  });
  if (errors.length) return { success: false, error: errors.join(', ') };

  // שלב 2: כתיבה — רק אחרי שכל הולידציות עברו
  var ts = bunker_ts();
  validated.forEach(function(v) {
    // מלאים: מחסן בלבד (מסגרות מנוהלות בסכימה)
    if (warehouseCol) {
      var wStock = Number(main.getRange(v.rowIdx, warehouseCol).getValue()) || 0;
      main.getRange(v.rowIdx, warehouseCol).setValue(wStock + v.qty);
    }
    // זיכויים (לוג בלבד)
    creditsSheet.appendRow([ts, data.by || 'לא ידוע', warehouse, data.unit, v.key, v.qty]);
    // סכימה — מקור האמת למסגרות
    bunker_schemaUpdateDispense(ss, v.key, data.unit, -v.qty);
  });

  return { success: true, credited: validated.length };
}

// ================================================================
// 6. קבלה — הוסף למלאי מחסן
// ================================================================
function bunker_receive(data) {
  if (!data || !data.warehouse || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לקבלה' };

  var warehouseCol = BUNKER_WAREHOUSE_COLS[data.warehouse];
  if (!warehouseCol) return { success: false, error: 'מחסן לא מזוהה' };

  var ss      = bunker_ss();
  var main    = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  var recSheet = bunker_ensureSheet(ss, 'קבלות',
    ['תאריך', 'מחסן', 'מקבל', 'מקור', 'פריט', 'כמות']);

  // שלב 1: ולידציה
  var errors    = [];
  var validated = [];

  data.items.forEach(function(item) {
    var qty    = Number(item.qty) || 0;
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }
    validated.push({ rowIdx: rowIdx, qty: qty, key: item.key,
                     current: Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0 });
  });

  if (errors.length) return { success: false, error: errors.join(', ') };

  // שלב 2: כתיבה
  var ts = bunker_ts();
  validated.forEach(function(v) {
    main.getRange(v.rowIdx, warehouseCol).setValue(v.current + v.qty);
    recSheet.appendRow([ts, data.warehouse, data.by || '', data.source || '', v.key, v.qty]);
  });

  return { success: true };
}

// ================================================================
// 7. הוספת פריט חדש לגליון מלאים
// ================================================================
function bunker_addItem(name) {
  if (!name) return { success: false, error: 'חסר שם פריט' };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  if (bunker_findItemRow(main, name) !== -1)
    return { success: false, error: 'פריט בשם זה כבר קיים' };

  main.appendRow([name, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  return { success: true };
}

// ================================================================
// 8. העברה בין מחסנים
// ================================================================
function bunker_transfer(data) {
  var from  = (data.from  || '').trim();
  var to    = (data.to    || '').trim();
  var by    = (data.by    || '').trim();
  var items = data.items  || [];

  if (!from || !to || from === to || !items.length) {
    return { success: false, error: 'חסרים נתונים' };
  }

  var fromCol = BUNKER_WAREHOUSE_COLS[from];
  var toCol   = BUNKER_WAREHOUSE_COLS[to];
  if (!fromCol || !toCol) return { success: false, error: 'מחסן לא מוכר' };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  // שלב 1: ולידציה מלאה — לא כותבים לפני שכל הפריטים תקינים
  var errors    = [];
  var validated = [];

  items.forEach(function(item) {
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx < 0) { errors.push(item.key + ': לא נמצא'); return; }
    var currentFrom = Number(main.getRange(rowIdx, fromCol).getValue()) || 0;
    var qty         = Number(item.qty) || 0;
    if (qty > currentFrom) { errors.push(item.label + ': אין מספיק מלאי (יש ' + currentFrom + ')'); return; }
    validated.push({ rowIdx: rowIdx, qty: qty, currentFrom: currentFrom });
  });

  if (errors.length) return { success: false, error: errors.join(' | ') };

  // שלב 2: כתיבה — רק אחרי שכל הולידציות עברו
  validated.forEach(function(v) {
    main.getRange(v.rowIdx, fromCol).setValue(v.currentFrom - v.qty);
    var currentTo = Number(main.getRange(v.rowIdx, toCol).getValue()) || 0;
    main.getRange(v.rowIdx, toCol).setValue(currentTo + v.qty);
  });

  return { success: true };
}

// ================================================================
// 9. וויסות תחמושת (יציאה למחוץ)
// ================================================================
var REGULATE_SHEET   = 'וויסותים';
var REGULATE_HEADERS = ['מזהה', 'תאריך', 'מחסן מקור', 'יעד', 'אחראי', 'פריט', 'כמות'];

function bunker_regulate(data) {
  if (!data.warehouse || !data.target || !data.responsible || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לוויסות' };

  var warehouseCol = BUNKER_WAREHOUSE_COLS[data.warehouse];
  if (!warehouseCol) return { success: false, error: 'מחסן לא מזוהה: ' + data.warehouse };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  // בדוק מלאי לכל הפריטים לפני שמשנים דבר
  var errors = [];
  data.items.forEach(function(item) {
    var qty  = Number(item.qty) || 0;
    var row  = bunker_findItemRow(main, item.key);
    if (row === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }
    var stock = Number(main.getRange(row, warehouseCol).getValue()) || 0;
    if (qty > stock) errors.push(item.label + ': נדרש ' + qty + ', קיים ' + stock);
  });
  if (errors.length) return { success: false, error: errors.join(' | ') };

  var reg = bunker_ensureSheet(ss, REGULATE_SHEET, REGULATE_HEADERS);
  var ts  = bunker_ts();

  data.items.forEach(function(item) {
    var qty   = Number(item.qty) || 0;
    var row   = bunker_findItemRow(main, item.key);
    var stock = Number(main.getRange(row, warehouseCol).getValue()) || 0;
    main.getRange(row, warehouseCol).setValue(stock - qty);
    reg.appendRow([bunker_uid(), ts, data.warehouse, data.target, data.responsible, item.key, qty]);
  });

  return { success: true };
}

function bunker_getRegulations() {
  var ss  = bunker_ss();
  var reg = ss.getSheetByName(REGULATE_SHEET);
  if (!reg || reg.getLastRow() < 2) return { success: true, data: [] };
  var rows = reg.getRange(2, 1, reg.getLastRow() - 1, REGULATE_HEADERS.length).getValues();
  var result = rows.map(function(r) {
    return { id: r[0], date: bunker_formatDate(r[1]), warehouse: r[2], target: r[3], responsible: r[4], itemKey: r[5], qty: r[6] };
  }).reverse();
  return { success: true, data: result };
}

// ================================================================
// 10. שצ״ל — דיווח שימוש בתחמושת בשטח
// ================================================================
var SHATSAL_SHEET   = 'שצ״ל';
// עמודות: מזהה | תאריך ביצוע | מסגרת | אחראי | פריט | כמות | תאריך דיווח
// תאריך דיווח נוסף בסוף (עמודה G) — תואם לאחור עם נתונים ישנים (6 עמודות)
var SHATSAL_HEADERS = ['מזהה', 'תאריך ביצוע', 'מסגרת', 'אחראי', 'פריט', 'כמות', 'תאריך דיווח'];

function bunker_shatsalReport(data) {
  if (!data.unit || !data.responsible || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לשצ״ל' };

  var ss        = bunker_ss();
  var sh        = bunker_ensureSheet(ss, SHATSAL_SHEET, SHATSAL_HEADERS);
  var reportTs  = bunker_ts(); // תאריך דיווח — תמיד עכשיו
  // תאריך ביצוע: מאחסן כ-Date object כדי למנוע פרשנות US-locale של Google Sheets
  var execDate  = (data.date && data.date.trim())
    ? (bunker_parseLocalDate(data.date.trim()) || new Date())
    : new Date();
  var reportId  = bunker_uid(); // מזהה משותף לכל הפריטים בדיווח זה

  // מיגרציה: עדכן כותרות אם הגליון הישן עדיין עם 6 עמודות
  if (sh.getLastColumn() < SHATSAL_HEADERS.length) {
    sh.getRange(1, 1, 1, SHATSAL_HEADERS.length).setValues([SHATSAL_HEADERS]);
  }

  data.items.forEach(function(item) {
    sh.appendRow([reportId, execDate, data.unit, data.responsible, item.key, Number(item.qty) || 0, reportTs]);
    bunker_schemaUpdateShatsal(ss, item.key, data.unit, Number(item.qty) || 0);
  });

  return { success: true };
}

// תקן תאריכי ביצוע שנשמרו עם DD/MM הפוך (Sheets US-locale bug)
// הלוגיקה: תאריך ביצוע שצ״ל אמור תמיד להיות בעבר. אם הוא בעתיד → כנראה DD/MM הוחלפו.
function bunker_fixShatsalDates() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(SHATSAL_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, fixed: 0 };

  var numCols = Math.max(sh.getLastColumn(), SHATSAL_HEADERS.length);
  var rows    = sh.getRange(2, 1, sh.getLastRow() - 1, numCols).getValues();
  var today   = new Date(); today.setHours(23, 59, 59, 999); // סוף היום
  var fixed   = 0;

  rows.forEach(function(r, i) {
    var execVal = r[1];
    if (!(execVal instanceof Date)) return; // כבר מחרוזת — לא מושפע
    if (execVal <= today) return;           // בעבר/היום — סביר, לא נוגעים

    // תאריך ביצוע בעתיד → כנראה MM/DD שנשמר במקום DD/MM
    var storedMonth = execVal.getMonth() + 1; // 1–12
    var storedDay   = execVal.getDate();       // 1–31
    if (storedDay < 1 || storedDay > 12) return; // החלפה תייצר חודש לא-חוקי

    var corrected = new Date(execVal.getFullYear(), storedDay - 1, storedMonth);
    sh.getRange(i + 2, 2).setValue(corrected);
    fixed++;
  });

  return { success: true, fixed: fixed };
}

function bunker_getShatsal() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(SHATSAL_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, data: [] };
  var numCols = Math.max(sh.getLastColumn(), SHATSAL_HEADERS.length);
  var rows    = sh.getRange(2, 1, sh.getLastRow() - 1, numCols).getValues();
  return {
    success: true,
    data: rows.map(function(r) {
      return {
        id:         r[0],
        date:       bunker_formatDate(r[1]), // תאריך ביצוע
        unit:       r[2],
        responsible:r[3],
        itemKey:    r[4],
        qty:        r[5],
        reportDate: bunker_formatDate(r[6] || r[1]) // תאריך דיווח — fallback לתאריך ביצוע בנתונים ישנים
      };
    }).reverse()
  };
}

// ================================================================
// 11. סיכום ניפוקים מול שצ״ל
// ================================================================
var UNIT_ORDER = Object.keys(BUNKER_UNIT_COLS); // ['פלוגה א','פלוגה ב',...]

function bunker_dispenseSummary(filterUnit) {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(SCHEMA_SHEET);

  // fallback: אם גליון סכימה לא קיים, בנה מחדש
  if (!sh || sh.getLastRow() < 2) {
    bunker_rebuildSchema();
    sh = ss.getSheetByName(SCHEMA_SHEET);
  }

  var dispByItem    = {};
  var shatsalByItem = {};

  if (sh && sh.getLastRow() > 1) {
    var schemaRows = sh.getRange(2, 1, sh.getLastRow() - 1, 1 + UNIT_ORDER.length * 2).getValues();
    schemaRows.forEach(function(r) {
      var itemKey = String(r[0] || '').trim();
      if (!itemKey) return;
      dispByItem[itemKey]    = {};
      shatsalByItem[itemKey] = {};
      UNIT_ORDER.forEach(function(u, i) {
        dispByItem[itemKey][u]    = Number(r[1 + i]) || 0;
        shatsalByItem[itemKey][u] = Number(r[1 + UNIT_ORDER.length + i]) || 0;
      });
    });
  }

  var activeUnits = filterUnit ? [filterUnit] : UNIT_ORDER.filter(function(u) {
    return Object.values(dispByItem).some(function(d) { return d[u] > 0; }) ||
           Object.values(shatsalByItem).some(function(s) { return s[u] > 0; });
  });

  var rows = Object.keys(dispByItem).map(function(itemKey) {
    var dispenses = {}, shatsalPerUnit = {}, totalDisp = 0, totalShatsal = 0;
    activeUnits.forEach(function(u) {
      var dq = (dispByItem[itemKey] && dispByItem[itemKey][u]) || 0;
      var sq = (shatsalByItem[itemKey] && shatsalByItem[itemKey][u]) || 0;
      dispenses[u]      = dq;
      shatsalPerUnit[u] = sq;
      totalDisp         += dq;
      totalShatsal      += sq;
    });
    return { item: itemKey, dispenses: dispenses, shatsalPerUnit: shatsalPerUnit,
             totalDisp: totalDisp, shatsal: totalShatsal,
             remaining: totalDisp - totalShatsal };
  }).filter(function(r) { return r.totalDisp > 0 || r.shatsal > 0; });

  rows.sort(function(a, b) { return String(a.item).localeCompare(String(b.item), 'he'); });
  return { success: true, data: { units: activeUnits, rows: rows } };
}

// ================================================================
// 12. סכימה — Materialized View
// ================================================================
var SCHEMA_SHEET   = 'סכימה';
var SCHEMA_HEADERS = ['פריט'].concat(
  UNIT_ORDER.map(function(u) { return 'ניפוק ' + u; }),
  UNIT_ORDER.map(function(u) { return 'שצ״ל ' + u; })
);
var SCHEMA_DISP_COL    = {}; // unit → 1-indexed col (2–8)
var SCHEMA_SHATSAL_COL = {}; // unit → 1-indexed col (9–15)
(function() {
  UNIT_ORDER.forEach(function(u, i) {
    SCHEMA_DISP_COL[u]    = i + 2;
    SCHEMA_SHATSAL_COL[u] = i + 2 + UNIT_ORDER.length;
  });
})();

// עזר: מצא/צור שורה בסכימה לפריט נתון, החזר אינדקס 1-based
function bunker_schemaEnsureRow(sh, itemKey) {
  var rowIdx = bunker_findItemRow(sh, itemKey);
  if (rowIdx === -1) {
    sh.appendRow([itemKey].concat(new Array(UNIT_ORDER.length * 2).fill(0)));
    rowIdx = sh.getLastRow();
  }
  return rowIdx;
}

// עדכן ניפוק פעיל בסכימה (delta חיובי=ניפוק, שלילי=זיכוי)
function bunker_schemaUpdateDispense(ss, itemKey, unit, delta) {
  var col = SCHEMA_DISP_COL[unit];
  if (!col) return;
  var sh     = bunker_ensureSheet(ss, SCHEMA_SHEET, SCHEMA_HEADERS);
  var rowIdx = bunker_schemaEnsureRow(sh, itemKey);
  var cur    = Number(sh.getRange(rowIdx, col).getValue()) || 0;
  sh.getRange(rowIdx, col).setValue(Math.max(0, cur + delta));
}

// עדכן שצ״ל בסכימה
function bunker_schemaUpdateShatsal(ss, itemKey, unit, delta) {
  var col = SCHEMA_SHATSAL_COL[unit];
  if (!col) return;
  var sh     = bunker_ensureSheet(ss, SCHEMA_SHEET, SCHEMA_HEADERS);
  var rowIdx = bunker_schemaEnsureRow(sh, itemKey);
  var cur    = Number(sh.getRange(rowIdx, col).getValue()) || 0;
  sh.getRange(rowIdx, col).setValue(Math.max(0, cur + delta));
}

// בנה מחדש את גליון הסכימה מהנתונים הגולמיים (קריאה בלבד מהמקורות)
function bunker_rebuildSchema() {
  var ss = bunker_ss();

  var existing = ss.getSheetByName(SCHEMA_SHEET);
  if (existing) ss.deleteSheet(existing);
  var sh = bunker_ensureSheet(ss, SCHEMA_SHEET, SCHEMA_HEADERS);

  // ניפוקים — כל השורות (לוג גולמי; מחסר זיכויים בהמשך)
  var dispAgg = {};
  var dispSheet = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (dispSheet && dispSheet.getLastRow() > 1) {
    var dRows = dispSheet.getRange(2, 1, dispSheet.getLastRow() - 1, 6).getValues();
    dRows.forEach(function(r) {
      var itemKey = String(r[4] || '').trim();
      var unit    = String(r[3] || '').trim();
      var qty     = Number(r[5]) || 0;
      if (!itemKey || !unit || !qty) return;
      if (!dispAgg[itemKey]) dispAgg[itemKey] = {};
      dispAgg[itemKey][unit] = (dispAgg[itemKey][unit] || 0) + qty;
    });
  }

  // זיכויים — הפחת מניפוקים (עמודות: [ts, by, warehouse, unit, itemKey, qty])
  var credSheet = ss.getSheetByName(BUNKER_CREDITS_SHEET);
  if (credSheet && credSheet.getLastRow() > 1) {
    var cRows = credSheet.getRange(2, 1, credSheet.getLastRow() - 1, 6).getValues();
    cRows.forEach(function(r) {
      var unit    = String(r[3] || '').trim();
      var itemKey = String(r[4] || '').trim();
      var qty     = Number(r[5]) || 0;
      if (!itemKey || !unit || !qty) return;
      if (!dispAgg[itemKey]) dispAgg[itemKey] = {};
      dispAgg[itemKey][unit] = Math.max(0, (dispAgg[itemKey][unit] || 0) - qty);
    });
  }

  // שצ״ל
  var shAgg = {};
  var shSheet = ss.getSheetByName(SHATSAL_SHEET);
  if (shSheet && shSheet.getLastRow() > 1) {
    var sRows = shSheet.getRange(2, 1, shSheet.getLastRow() - 1, 6).getValues();
    sRows.forEach(function(r) {
      var itemKey = String(r[4] || '').trim();
      var unit    = String(r[2] || '').trim();
      var qty     = Number(r[5]) || 0;
      if (!itemKey || !qty) return;
      if (!shAgg[itemKey]) shAgg[itemKey] = {};
      shAgg[itemKey][unit] = (shAgg[itemKey][unit] || 0) + qty;
    });
  }

  var allKeys = {};
  Object.keys(dispAgg).forEach(function(k) { allKeys[k] = true; });
  Object.keys(shAgg).forEach(function(k)   { allKeys[k] = true; });

  Object.keys(allKeys).forEach(function(itemKey) {
    var row = [itemKey];
    UNIT_ORDER.forEach(function(u) { row.push((dispAgg[itemKey] && dispAgg[itemKey][u]) || 0); });
    UNIT_ORDER.forEach(function(u) { row.push((shAgg[itemKey]  && shAgg[itemKey][u])   || 0); });
    sh.appendRow(row);
  });

  return { success: true, rebuilt: Object.keys(allKeys).length };
}
