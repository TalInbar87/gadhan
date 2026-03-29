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
      label:    name,
      key:      name,
      nafatli:  Number(rows[i][1]) || 0,
      bilo:     Number(rows[i][2]) || 0,
      units:    {},
      totalNafatli: Number(rows[i][10]) || 0,
      totalBilo:    Number(rows[i][11]) || 0
    };
    Object.keys(BUNKER_UNIT_COLS).forEach(function(unit) {
      entry.units[unit] = Number(rows[i][BUNKER_UNIT_COLS[unit] - 1]) || 0;
    });
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
// 3. ניפוק — רשום עסקה + עדכן גליון מלאים
// ================================================================
function bunker_dispense(data) {
  if (!data || !data.warehouse || !data.unit || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לניפוק' };

  var warehouseCol = BUNKER_WAREHOUSE_COLS[data.warehouse];
  var unitCol      = BUNKER_UNIT_COLS[data.unit];
  var totalCol     = BUNKER_TOTAL_COLS[data.warehouse];

  if (!warehouseCol) return { success: false, error: 'מחסן לא מזוהה: ' + data.warehouse };
  if (!unitCol)      return { success: false, error: 'מסגרת לא מזוהה: ' + data.unit };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  var disp = bunker_ensureSheet(ss, CONFIG.BUNKER.DISPENSES_SHEET,
    ['מזהה', 'תאריך', 'מחסן', 'מסגרת', 'פריט', 'כמות', 'מנפק', 'סטטוס', 'תאריך זיכוי', 'מזכה']);

  var ts      = bunker_ts();
  var errors  = [];

  data.items.forEach(function(item) {
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }

    var qty = Number(item.qty) || 0;

    // ── ולידציית מלאי ──
    var currentStock = Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0;
    if (qty > currentStock) {
      errors.push('אין מספיק מלאי — ' + item.key + ' (נדרש: ' + qty + ', קיים: ' + currentStock + ')');
      return;
    }

    // הפחת ממלאי המחסן
    main.getRange(rowIdx, warehouseCol).setValue(currentStock - qty);

    // הוסף לעמודת המסגרת
    var currentUnit = Number(main.getRange(rowIdx, unitCol).getValue()) || 0;
    main.getRange(rowIdx, unitCol).setValue(currentUnit + qty);

    // עדכן סה"כ
    var currentTotal = Number(main.getRange(rowIdx, totalCol).getValue()) || 0;
    main.getRange(rowIdx, totalCol).setValue(currentTotal + qty);

    // רשום היסטוריה
    disp.appendRow([bunker_uid(), ts, data.warehouse, data.unit, item.key, qty, data.by || 'לא ידוע', 'פעיל', '', '']);
  });

  if (errors.length) return { success: false, error: errors.join(', ') };
  return { success: true, dispensed: data.items.length };
}

// ================================================================
// 4. קרא ניפוקים נוכחיים מעמודות D-J של גליון מלאים
// ================================================================
function bunker_getDispenses(unit) {
  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) return { success: false, error: 'גליון מלאים לא נמצא' };

  var rows         = main.getDataRange().getValues();
  var result       = [];
  var unitsToCheck = unit ? [unit] : Object.keys(BUNKER_UNIT_COLS);

  for (var i = 1; i < rows.length; i++) {
    var itemName = String(rows[i][0] || '').trim();
    if (!itemName) continue;

    unitsToCheck.forEach(function(u) {
      var col = BUNKER_UNIT_COLS[u];
      if (!col) return;
      var qty = Number(rows[i][col - 1]) || 0;
      if (qty > 0) {
        result.push({
          unit:      u,
          itemKey:   itemName,
          itemLabel: itemName,
          qty:       qty
        });
      }
    });
  }
  return { success: true, data: result };
}

// ================================================================
// 5. זיכוי — זכה ניפוקים לפי מזהה + עדכן גליון מלאים
// ================================================================
function bunker_credit(data) {
  if (!data || !data.ids || !data.ids.length)
    return { success: false, error: 'חסרים מזהי ניפוק לזיכוי' };

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  var disp = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (!disp) return { success: false, error: 'גליון ניפוקים לא נמצא' };

  var rows   = disp.getDataRange().getValues();
  var idsSet = {};
  data.ids.forEach(function(id) { idsSet[id] = true; });
  var ts       = bunker_ts();
  var credited = 0;
  var creditsSheet = bunker_ensureSheet(ss, BUNKER_CREDITS_SHEET,
    ['תאריך זיכוי', 'מזכה', 'מחסן', 'מסגרת', 'פריט', 'כמות', 'מזהה ניפוק מקורי']);

  for (var i = 1; i < rows.length; i++) {
    var rowId = String(rows[i][0] || '').trim();
    if (!idsSet[rowId] || String(rows[i][7]).trim() !== 'פעיל') continue;

    var warehouse = String(rows[i][2]).trim();
    var unit      = String(rows[i][3]).trim();
    var itemKey   = String(rows[i][4]).trim();
    var qty       = Number(rows[i][5]) || 0;

    var warehouseCol = BUNKER_WAREHOUSE_COLS[warehouse];
    var unitCol      = BUNKER_UNIT_COLS[unit];
    var totalCol     = BUNKER_TOTAL_COLS[warehouse];

    // החזר למלאי המחסן + הפחת ממסגרת + עדכן סה"כ
    if (main && warehouseCol && unitCol) {
      var rowIdx = bunker_findItemRow(main, itemKey);
      if (rowIdx !== -1) {
        var stock = Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0;
        main.getRange(rowIdx, warehouseCol).setValue(stock + qty);

        var unitQty = Number(main.getRange(rowIdx, unitCol).getValue()) || 0;
        main.getRange(rowIdx, unitCol).setValue(Math.max(0, unitQty - qty));

        var total = Number(main.getRange(rowIdx, totalCol).getValue()) || 0;
        main.getRange(rowIdx, totalCol).setValue(Math.max(0, total - qty));
      }
    }

    // רשום לגליון זיכויים
    creditsSheet.appendRow([ts, data.by || 'לא ידוע', warehouse, unit, itemKey, qty, rowId]);

    // עדכן סטטוס בגליון ניפוקים
    disp.getRange(i + 1, 8).setValue('זוכה');
    disp.getRange(i + 1, 9).setValue(ts);
    disp.getRange(i + 1, 10).setValue(data.by || 'לא ידוע');
    credited++;
  }

  return { success: true, credited: credited };
}
