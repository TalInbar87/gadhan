/**
 * ================================================================
 * Bunker Module — מודול בונקר
 * ================================================================
 * גיליון: CONFIG.SHEETS.BUNKER
 * טאבים:
 *   פריטים   — A=key | B=label
 *   מלאי     — A=timestamp | B=by | C=counts_json
 *   ניפוקים  — A=id | B=timestamp | C=unit | D=key | E=label | F=qty | G=by | H=status | I=credited_at | J=credited_by
 *
 * status: 'פעיל' | 'זוכה'
 * ================================================================
 */

// ── עזר: פתח גיליון בונקר ──
function bunker_ss() {
  return SpreadsheetApp.openById(CONFIG.SHEETS.BUNKER);
}

// ── עזר: צור טאב אם לא קיים ──
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

// ================================================================
// 1. פריטים — קרא רשימת פריטים
// ================================================================
function bunker_getItems() {
  var ss = bunker_ss();
  bunker_ensureSheet(ss, CONFIG.BUNKER.ITEMS_SHEET, ['key', 'label']);
  var sh   = ss.getSheetByName(CONFIG.BUNKER.ITEMS_SHEET);
  var rows = sh.getDataRange().getValues();
  var items = [];
  for (var i = 1; i < rows.length; i++) {
    var key   = String(rows[i][0] || '').trim();
    var label = String(rows[i][1] || '').trim();
    if (key && label) items.push({ key: key, label: label });
  }
  return { success: true, data: items };
}

// ================================================================
// 2. מלאי — קרא ספירה אחרונה
// ================================================================
function bunker_getInventory() {
  var ss = bunker_ss();
  bunker_ensureSheet(ss, CONFIG.BUNKER.INVENTORY_SHEET, ['תאריך', 'בוצע ע"י', 'ספירה (JSON)']);
  var sh   = ss.getSheetByName(CONFIG.BUNKER.INVENTORY_SHEET);
  var rows = sh.getDataRange().getValues();

  var lastCount = null;
  var counts    = {};

  if (rows.length > 1) {
    var last = rows[rows.length - 1];
    try {
      counts    = JSON.parse(last[2] || '{}');
      lastCount = { timestamp: last[0], by: last[1] };
    } catch (e) { counts = {}; }
  }

  return { success: true, data: { counts: counts, lastCount: lastCount } };
}

// ================================================================
// 3. מלאי — שמור ספירה חדשה
// ================================================================
function bunker_saveInventory(data) {
  if (!data || !data.counts) return { success: false, error: 'חסרים נתונים' };
  var ss = bunker_ss();
  var sh = bunker_ensureSheet(ss, CONFIG.BUNKER.INVENTORY_SHEET, ['תאריך', 'בוצע ע"י', 'ספירה (JSON)']);
  sh.appendRow([bunker_ts(), data.by || 'לא ידוע', JSON.stringify(data.counts)]);
  return { success: true };
}

// ================================================================
// 4. ניפוקים — קרא ניפוקים פעילים (אופציונלי: לפי מסגרת)
// ================================================================
function bunker_getDispenses(unit) {
  var ss = bunker_ss();
  bunker_ensureSheet(ss, CONFIG.BUNKER.DISPENSES_SHEET,
    ['מזהה', 'תאריך', 'מסגרת', 'מפתח', 'פריט', 'כמות', 'מנפק', 'סטטוס', 'תאריך זיכוי', 'מזכה']);
  var sh   = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  var rows = sh.getDataRange().getValues();

  var result = [];
  for (var i = 1; i < rows.length; i++) {
    var status = String(rows[i][7] || '').trim();
    if (status !== 'פעיל') continue;
    if (unit && String(rows[i][2] || '').trim() !== unit) continue;
    result.push({
      id:        String(rows[i][0]),
      timestamp: String(rows[i][1]),
      unit:      String(rows[i][2]),
      itemKey:   String(rows[i][3]),
      itemLabel: String(rows[i][4]),
      qty:       Number(rows[i][5]) || 0,
      by:        String(rows[i][6])
    });
  }
  return { success: true, data: result };
}

// ================================================================
// 5. ניפוקים — בצע ניפוק
// ================================================================
function bunker_dispense(data) {
  if (!data || !data.unit || !data.items || !data.items.length)
    return { success: false, error: 'חסרים נתונים לניפוק' };

  var ss = bunker_ss();
  var sh = bunker_ensureSheet(ss, CONFIG.BUNKER.DISPENSES_SHEET,
    ['מזהה', 'תאריך', 'מסגרת', 'מפתח', 'פריט', 'כמות', 'מנפק', 'סטטוס', 'תאריך זיכוי', 'מזכה']);
  var ts = bunker_ts();

  data.items.forEach(function(item) {
    sh.appendRow([
      bunker_uid(),
      ts,
      data.unit,
      item.key,
      item.label,
      item.qty,
      data.by || 'לא ידוע',
      'פעיל',
      '',
      ''
    ]);
  });

  return { success: true, dispensed: data.items.length };
}

// ================================================================
// 6. זיכוי — זכה ניפוקים לפי מזהה
// ================================================================
function bunker_credit(data) {
  if (!data || !data.ids || !data.ids.length)
    return { success: false, error: 'חסרים מזהי ניפוק לזיכוי' };

  var ss     = bunker_ss();
  var sh     = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (!sh)   return { success: false, error: 'גיליון ניפוקים לא נמצא' };

  var rows   = sh.getDataRange().getValues();
  var idsSet = {};
  data.ids.forEach(function(id) { idsSet[id] = true; });
  var ts     = bunker_ts();
  var credited = 0;

  for (var i = 1; i < rows.length; i++) {
    var rowId = String(rows[i][0] || '').trim();
    if (idsSet[rowId] && String(rows[i][7]).trim() === 'פעיל') {
      sh.getRange(i + 1, 8).setValue('זוכה');
      sh.getRange(i + 1, 9).setValue(ts);
      sh.getRange(i + 1, 10).setValue(data.by || 'לא ידוע');
      credited++;
    }
  }

  return { success: true, credited: credited };
}
