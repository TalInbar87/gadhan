/**
 * ================================================================
 * מערכת גיבוי אוטומטית — גדחה"ו קומנדו 8219
 * ================================================================
 * גיבוי יומי פעמיים:
 *   08:00 → "גיבוי בוקר - <שם>.xlsx"
 *   21:00 → "גיבוי ערב  - <שם>.xlsx"
 *
 * מבנה Drive:
 *   ROOT_FOLDER / גיבוי / DD.MM.YYYY / גיבוי בוקר - נשקים.xlsx
 *                                      גיבוי בוקר - קשר.xlsx
 *                                      ...
 *
 * ⚠️  הרץ backup_setupTriggers() פעם אחת ידנית לאחר פריסה ראשונה
 * ================================================================
 */

// ── Entry points (מופעלים ע"י Triggers) ──────────────────────────

function backup_morning() { backup_run('בוקר'); }
function backup_evening() { backup_run('ערב');  }

// ── הלוגיקה המרכזית ──────────────────────────────────────────────

function backup_run(timeLabel) {
  var sheetList = [
    { id: CONFIG.SHEETS.WEAPONS, name: 'נשקים'  },
    { id: CONFIG.SHEETS.ARMORY,  name: 'נשקייה' }
  ];

  var tz      = CONFIG.TIMEZONE;
  var now     = new Date();
  var dateStr = Utilities.formatDate(now, tz, 'dd.MM.yyyy');

  // Drive: ROOT → גיבוי → DD.MM.YYYY
  var rootFolder  = DriveApp.getFolderById(CONFIG.DRIVE.ROOT_FOLDER_ID);
  var backupRoot  = backup_getOrCreateFolder(rootFolder, 'גיבוי');
  var dateFolder  = backup_getOrCreateFolder(backupRoot, dateStr);

  var errors = [];

  sheetList.forEach(function(sheet) {
    try {
      var fileName = 'גיבוי ' + timeLabel + ' - ' + sheet.name + '.xlsx';
      var url      = 'https://docs.google.com/spreadsheets/d/' + sheet.id +
                     '/export?format=xlsx';

      var response = UrlFetchApp.fetch(url, {
        headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() }
      });

      var blob = response.getBlob().setName(fileName);

      // החלף קובץ ישן באותו שם אם קיים
      var existing = dateFolder.getFilesByName(fileName);
      while (existing.hasNext()) existing.next().setTrashed(true);

      dateFolder.createFile(blob);

    } catch (e) {
      errors.push(sheet.name + ': ' + e.message);
    }
  });

  if (errors.length > 0) {
    Logger.log('[Backup] שגיאות ב' + timeLabel + ' (' + dateStr + '): ' + errors.join(' | '));
  } else {
    Logger.log('[Backup] גיבוי ' + timeLabel + ' הושלם — ' + dateStr);
  }
}

// ── הגדרת Triggers (הרץ פעם אחת ידנית) ─────────────────────────

function backup_setupTriggers() {
  // מחק triggers קיימים של גיבוי
  ScriptApp.getProjectTriggers().forEach(function(t) {
    var fn = t.getHandlerFunction();
    if (fn === 'backup_morning' || fn === 'backup_evening') {
      ScriptApp.deleteTrigger(t);
    }
  });

  // בוקר — 08:00
  ScriptApp.newTrigger('backup_morning')
    .timeBased()
    .everyDays(1)
    .atHour(8)
    .inTimezone(CONFIG.TIMEZONE)
    .create();

  // ערב — 21:00
  ScriptApp.newTrigger('backup_evening')
    .timeBased()
    .everyDays(1)
    .atHour(21)
    .inTimezone(CONFIG.TIMEZONE)
    .create();

  Logger.log('[Backup] Triggers הוגדרו: בוקר 08:00 + ערב 21:00');
}

// ── עזר ──────────────────────────────────────────────────────────

function backup_getOrCreateFolder(parent, name) {
  var iter = parent.getFoldersByName(name);
  if (iter.hasNext()) return iter.next();
  return parent.createFolder(name);
}
