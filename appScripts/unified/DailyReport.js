// ================================================================
// DailyReport.js — דוח יומי צלם למייל
// ================================================================
// הרצה: setupDailyInventoryTrigger() — פעם אחת מהעורך של GAS
// ================================================================

var DAILY_REPORT_EMAIL     = 'shporn14@gmail.com';
var DAILY_REPORT_HOUR      = 8; // 08:00 שעון ישראל

// מפתחות פריטים שלא נכללים בדוח
var DAILY_REPORT_EXCLUDED = [
  'roskM16', 'roskM4', 'negev', 'mag', 'matol', 'baret',
  'trig', 'm5', 'mepro', 'zavon', 'akila6', 'zayinNegev', 'lior'
];

// ── פונקציה ראשית (מופעלת ע"י ה-trigger) ──────────────────────
function sendDailyInventoryEmail() {
  var result = weapons_getInventorySummary();
  if (!result.success) {
    Logger.log('DailyReport: failed to get inventory — ' + (result.error || ''));
    return;
  }

  var data    = result.data;
  var units   = data.units;
  var counts  = data.counts;
  var totals  = data.totals;

  // סינון פריטים לא רצויים
  var items = data.items.filter(function(item) {
    return DAILY_REPORT_EXCLUDED.indexOf(item.key) === -1;
  });

  var today   = Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'dd/MM/yyyy');
  var html    = buildReportHtml(items, units, counts, totals, today);
  var text    = buildReportText(items, units, counts, totals, today);
  var pdfBlob = buildReportPdf(html, today);

  MailApp.sendEmail({
    to:          DAILY_REPORT_EMAIL,
    subject:     'סיכום מלאי צלם — ' + today,
    htmlBody:    '<p>מצורף סיכום מלאי צלם לתאריך ' + today + '</p>',
    body:        text,
    attachments: [pdfBlob]
  });

  Logger.log('DailyReport: sent to ' + DAILY_REPORT_EMAIL);
}

// ── בנה HTML ─────────────────────────────────────────────────────
function buildReportHtml(items, units, counts, totals, today) {
  var thStyle  = 'background:#ff6600;color:#000;font-weight:700;padding:8px 12px;text-align:center;white-space:nowrap;border:1px solid #cc5200;';
  var thFirst  = 'background:#cc4400;color:#fff;font-weight:700;padding:8px 12px;text-align:right;border:1px solid #aa3300;';
  var thTotal  = 'background:#cc5200;color:#fff;font-weight:700;padding:8px 12px;text-align:center;border:1px solid #aa3300;';
  var tdStyle  = 'padding:7px 12px;text-align:center;border:1px solid #ddd;';
  var tdFirst  = 'padding:7px 12px;text-align:right;font-weight:600;border:1px solid #ddd;background:#fafafa;';
  var tdZero   = 'padding:7px 12px;text-align:center;border:1px solid #ddd;color:#bbb;';
  var tdTotal  = 'padding:7px 12px;text-align:center;border:1px solid #ddd;font-weight:700;color:#cc4400;';

  var html = '<!DOCTYPE html><html dir="rtl" lang="he"><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;direction:rtl;">';

  // כותרת
  html += '<div style="background:linear-gradient(135deg,#ff6600,#ff8c00);padding:20px 24px;border-radius:10px;margin-bottom:20px;">';
  html += '<h2 style="margin:0;color:#000;font-size:1.3em;">📦 סיכום מלאי צלם</h2>';
  html += '<div style="color:#1a1a1a;margin-top:4px;font-size:0.9em;">גדחה"ו קומנדו 8219 | ' + today + '</div>';
  html += '</div>';

  // טבלה
  html += '<div style="overflow-x:auto;"><table style="border-collapse:collapse;width:100%;font-size:13px;background:#fff;border-radius:8px;overflow:hidden;">';

  // כותרת טבלה
  html += '<thead><tr>';
  html += '<th style="' + thFirst + '">פריט</th>';
  units.forEach(function(u) { html += '<th style="' + thStyle + '">' + u + '</th>'; });
  html += '<th style="' + thTotal + '">סה"כ</th>';
  html += '</tr></thead>';

  // שורות
  html += '<tbody>';
  items.forEach(function(item, idx) {
    var bg = idx % 2 === 0 ? '#fff' : '#f9f9f9';
    html += '<tr style="background:' + bg + ';">';
    html += '<td style="' + tdFirst + 'background:' + bg + ';">' + item.label + '</td>';

    units.forEach(function(u) {
      var c = (counts[item.key] && counts[item.key][u]) || 0;
      if (c > 0) {
        html += '<td style="' + tdStyle + 'background:' + bg + ';color:#cc4400;font-weight:700;">' + c + '</td>';
      } else {
        html += '<td style="' + tdZero + 'background:' + bg + ';">–</td>';
      }
    });

    var tot = totals[item.key] || 0;
    html += tot > 0
      ? '<td style="' + tdTotal + 'background:' + bg + ';">' + tot + '</td>'
      : '<td style="' + tdZero + 'background:' + bg + ';">–</td>';

    html += '</tr>';
  });
  html += '</tbody></table></div>';

  // footer
  html += '<div style="margin-top:16px;color:#999;font-size:0.8em;text-align:center;">🔒 הדוח נשלח אוטומטית כל יום ב-08:00</div>';
  html += '</body></html>';

  return html;
}

// ── המר HTML ל-PDF דרך DriveApp ──────────────────────────────────
function buildReportPdf(html, today) {
  var htmlBlob = Utilities.newBlob(html, 'text/html', 'report.html');
  var tempFile = DriveApp.createFile(htmlBlob);
  var pdfBlob  = tempFile.getAs('application/pdf').setName('סיכום_מלאי_צלם_' + today.replace(/\//g, '-') + '.pdf');
  tempFile.setTrashed(true);
  return pdfBlob;
}

// ── בנה טקסט פשוט (fallback) ─────────────────────────────────────
function buildReportText(items, units, counts, totals, today) {
  var lines = ['סיכום מלאי צלם — ' + today, ''];
  var header = 'פריט\t' + units.join('\t') + '\tסה"כ';
  lines.push(header);
  lines.push(new Array(header.length + 1).join('-'));

  items.forEach(function(item) {
    var parts = [item.label];
    units.forEach(function(u) {
      parts.push((counts[item.key] && counts[item.key][u]) || 0);
    });
    parts.push(totals[item.key] || 0);
    lines.push(parts.join('\t'));
  });

  return lines.join('\n');
}

// ── הגדרת trigger יומי — הרץ פעם אחת מהעורך של GAS ──────────────
function setupDailyInventoryTrigger() {
  // מחק trigger קיים אם יש
  ScriptApp.getProjectTriggers().forEach(function(t) {
    if (t.getHandlerFunction() === 'sendDailyInventoryEmail') {
      ScriptApp.deleteTrigger(t);
    }
  });

  ScriptApp.newTrigger('sendDailyInventoryEmail')
    .timeBased()
    .atHour(DAILY_REPORT_HOUR)
    .everyDays(1)
    .inTimezone('Asia/Jerusalem')
    .create();

  Logger.log('Trigger created: sendDailyInventoryEmail every day at ' + DAILY_REPORT_HOUR + ':00');
}
