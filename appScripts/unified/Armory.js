/**
 * ================================================================
 * Armory Module - מודול נשקייה (מלאי פיזי)
 * ================================================================
 * מבנה גיליון נשקייה (ספירות מלאי):
 * A(0)=תאריך ושעה | B(1)=מבצע הספירה
 * C(2)..BN(63) = 58 פריטים (אותו סדר כמו WEAPONS_ITEM_LIST) — כמות מספרית
 *
 * כל שורה = ספירת מלאי אחת (נשמרת לצורך היסטוריה)
 * הספירה הנוכחית = השורה האחרונה
 * ================================================================
 */

// ================================================================
// Init Sheet
// ================================================================

/**
 * יוצר את טאב "ספירות מלאי" אם אינו קיים ומוסיף שורת כותרות
 */
function armory_ensureSheet() {
  const ss    = SpreadsheetApp.openById(CONFIG.SHEETS.ARMORY);
  var sheet   = ss.getSheetByName(CONFIG.ARMORY.SHEET_NAME);

  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.ARMORY.SHEET_NAME);
    // כותרות
    var headers = ['תאריך ושעה', 'מבצע הספירה'];
    WEAPONS_ITEM_LIST.forEach(function(item) { headers.push(item.label); });
    sheet.appendRow(headers);

    // עיצוב שורת כותרות
    var headerRange = sheet.getRange(1, 1, 1, headers.length);
    headerRange.setBackground('#2F5233');
    headerRange.setFontColor('#ffffff');
    headerRange.setFontWeight('bold');
    sheet.setFrozenRows(1);
    Logger.log('✅ [Armory] Sheet created: ' + CONFIG.ARMORY.SHEET_NAME);
  }

  return sheet;
}

// ================================================================
// Get Latest Count
// ================================================================

/**
 * מחזיר את ספירת המלאי האחרונה (שורה אחרונה)
 * אם אין ספירות — מחזיר אובייקט ריק עם 0 לכל פריט
 */
function armory_getLatestCount() {
  const sheet = armory_ensureSheet();
  const lastRow = sheet.getLastRow();

  var counts = {};
  WEAPONS_ITEM_LIST.forEach(function(item) { counts[item.key] = 0; });

  if (lastRow < 2) {
    return { success: true, data: { counts: counts, timestamp: null, performedBy: null } };
  }

  var row = sheet.getRange(lastRow, 1, 1, 2 + WEAPONS_ITEM_LIST.length).getValues()[0];

  WEAPONS_ITEM_LIST.forEach(function(item, idx) {
    var val = row[2 + idx];
    counts[item.key] = (val !== '' && !isNaN(val)) ? parseInt(val, 10) : 0;
  });

  return {
    success: true,
    data: {
      counts:      counts,
      timestamp:   row[0] ? new Date(row[0]).toISOString() : null,
      performedBy: row[1] || null
    }
  };
}

// ================================================================
// Save Count
// ================================================================

/**
 * שומר ספירת מלאי חדשה (מוסיף שורה)
 * @param {{ counts: Object, performedBy: string }} data
 */
function armory_saveCount(data) {
  const { counts, performedBy } = data;
  const sheet = armory_ensureSheet();

  var ts  = Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'yyyy-MM-dd HH:mm:ss');
  var row = [ts, performedBy || 'לא ידוע'];

  WEAPONS_ITEM_LIST.forEach(function(item) {
    var val = counts[item.key];
    row.push((val !== undefined && val !== null && val !== '') ? parseInt(val, 10) : 0);
  });

  sheet.appendRow(row);
  Logger.log('✅ [Armory] Count saved by ' + performedBy + ' at ' + ts);

  return { success: true, message: 'ספירה נשמרה בהצלחה', timestamp: ts };
}
