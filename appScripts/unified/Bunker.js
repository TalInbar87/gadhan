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

  var ts     = bunker_ts();
  var errors = [];

  data.items.forEach(function(item) {
    var qty    = Number(item.qty) || 0;
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) { errors.push('פריט לא נמצא: ' + item.key); return; }

    // ולידציית מלאי
    var currentStock = Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0;
    if (qty > currentStock) {
      errors.push('אין מספיק מלאי — ' + item.key + ' (נדרש: ' + qty + ', קיים: ' + currentStock + ')');
      return;
    }

    // הפחת ממלאי המחסן
    main.getRange(rowIdx, warehouseCol).setValue(currentStock - qty);

    // עדכן עמודת מסגרת (D-J)
    var unitCol = BUNKER_UNIT_COLS[data.unit];
    if (unitCol) {
      var currentUnitQty = Number(main.getRange(rowIdx, unitCol).getValue()) || 0;
      main.getRange(rowIdx, unitCol).setValue(currentUnitQty + qty);
    }

    // רשום בגליון ניפוקים
    disp.appendRow([bunker_uid(), ts, data.warehouse, data.unit, item.key, qty, data.by || 'לא ידוע', 'פעיל', '', '']);
  });

  if (errors.length) return { success: false, error: errors.join(', ') };
  return { success: true, dispensed: data.items.length };
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
    var status = String(rows[i][7] || '').trim();
    if (status !== 'פעיל') continue;
    var rowUnit = String(rows[i][3] || '').trim();
    if (unit && rowUnit !== unit) continue;
    result.push({
      id:        String(rows[i][0] || '').trim(),
      timestamp: String(rows[i][1] || '').trim(),
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
// 5. זיכוי — לפי מזהי ניפוק + עדכן מלאי מחסן
// ================================================================
function bunker_credit(data) {
  // תמיכה בפורמט חדש: credits:[{id,qty}] ובפורמט ישן: ids:[]
  var credits;
  if (data.credits && data.credits.length) {
    credits = data.credits;
  } else if (data.ids && data.ids.length) {
    credits = data.ids.map(function(id) { return { id: id, qty: null }; });
  } else {
    return { success: false, error: 'חסרים מזהי ניפוק לזיכוי' };
  }

  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  var disp = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (!disp) return { success: false, error: 'גליון ניפוקים לא נמצא' };

  var creditsSheet = bunker_ensureSheet(ss, BUNKER_CREDITS_SHEET,
    ['תאריך זיכוי', 'מזכה', 'מחסן', 'מסגרת', 'פריט', 'כמות', 'מזהה ניפוק']);

  var rows      = disp.getDataRange().getValues();
  var creditMap = {};
  credits.forEach(function(c) { creditMap[String(c.id)] = c.qty; });
  var ts       = bunker_ts();
  var credited = 0;

  for (var i = 1; i < rows.length; i++) {
    var rowId = String(rows[i][0] || '').trim();
    if (!(rowId in creditMap) || String(rows[i][7]).trim() !== 'פעיל') continue;

    var warehouse    = (data.warehouse && BUNKER_WAREHOUSE_COLS[data.warehouse])
                         ? data.warehouse
                         : String(rows[i][2]).trim();
    var unit         = String(rows[i][3]).trim();
    var itemKey      = String(rows[i][4]).trim();
    var originalQty  = Number(rows[i][5]) || 0;
    var creditQty    = (creditMap[rowId] !== null && creditMap[rowId] !== undefined)
                         ? Number(creditMap[rowId]) : originalQty;
    if (creditQty <= 0) continue;
    var warehouseCol = BUNKER_WAREHOUSE_COLS[warehouse];

    // החזר למלאי המחסן + הפחת מעמודת מסגרת
    if (main) {
      var rowIdx2 = bunker_findItemRow(main, itemKey);
      if (rowIdx2 !== -1) {
        if (warehouseCol) {
          var stock = Number(main.getRange(rowIdx2, warehouseCol).getValue()) || 0;
          main.getRange(rowIdx2, warehouseCol).setValue(stock + creditQty);
        }
        var unitCol2 = BUNKER_UNIT_COLS[unit];
        if (unitCol2) {
          var unitQty = Number(main.getRange(rowIdx2, unitCol2).getValue()) || 0;
          main.getRange(rowIdx2, unitCol2).setValue(Math.max(0, unitQty - creditQty));
        }
      }
    }

    // רשום לגליון זיכויים
    creditsSheet.appendRow([ts, data.by || 'לא ידוע', warehouse, unit, itemKey, creditQty, rowId]);

    // זיכוי חלקי — עדכן כמות ושמור פעיל; זיכוי מלא/עודף — סגור שורה
    if (creditQty < originalQty) {
      disp.getRange(i + 1, 6).setValue(originalQty - creditQty); // עדכן כמות נותרת
    } else {
      disp.getRange(i + 1, 8).setValue('זוכה');
      disp.getRange(i + 1, 9).setValue(ts);
      disp.getRange(i + 1, 10).setValue(data.by || 'לא ידוע');
    }
    credited++;
  }

  return { success: true, credited: credited };
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

  var ts = bunker_ts();

  data.items.forEach(function(item) {
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx === -1) return;
    var current = Number(main.getRange(rowIdx, warehouseCol).getValue()) || 0;
    main.getRange(rowIdx, warehouseCol).setValue(current + (Number(item.qty) || 0));
    recSheet.appendRow([ts, data.warehouse, data.by || '', data.source || '', item.key, Number(item.qty) || 0]);
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

  var errors = [];

  items.forEach(function(item) {
    var rowIdx = bunker_findItemRow(main, item.key);
    if (rowIdx < 0) { errors.push(item.key + ': לא נמצא'); return; }

    var currentFrom = Number(main.getRange(rowIdx, fromCol).getValue()) || 0;
    var qty         = Number(item.qty) || 0;
    if (qty > currentFrom) { errors.push(item.label + ': אין מספיק מלאי (יש ' + currentFrom + ')'); return; }

    main.getRange(rowIdx, fromCol).setValue(currentFrom - qty);
    var currentTo = Number(main.getRange(rowIdx, toCol).getValue()) || 0;
    main.getRange(rowIdx, toCol).setValue(currentTo + qty);
  });

  if (errors.length) return { success: false, error: errors.join(' | ') };
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
    return { id: r[0], date: r[1], warehouse: r[2], target: r[3], responsible: r[4], itemKey: r[5], qty: r[6] };
  }).reverse();
  return { success: true, data: result };
}

// ================================================================
// 10. שצ״ל — דיווח שימוש בתחמושת בשטח
// ================================================================
var SHATSAL_SHEET   = 'שצ״ל';
var SHATSAL_HEADERS = ['מזהה', 'תאריך', 'מסגרת', 'אחראי', 'פריט', 'כמות'];

function bunker_shatsalReport(data) {
  if (!data.unit || !data.responsible || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לשצ״ל' };

  var ss = bunker_ss();
  var sh = bunker_ensureSheet(ss, SHATSAL_SHEET, SHATSAL_HEADERS);
  var ts = bunker_ts();

  data.items.forEach(function(item) {
    sh.appendRow([bunker_uid(), ts, data.unit, data.responsible, item.key, Number(item.qty) || 0]);
  });

  return { success: true };
}

function bunker_getShatsal() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(SHATSAL_SHEET);
  if (!sh || sh.getLastRow() < 2) return { success: true, data: [] };
  var rows = sh.getRange(2, 1, sh.getLastRow() - 1, SHATSAL_HEADERS.length).getValues();
  return {
    success: true,
    data: rows.map(function(r) {
      return { id: r[0], date: r[1], unit: r[2], responsible: r[3], itemKey: r[4], qty: r[5] };
    }).reverse()
  };
}
