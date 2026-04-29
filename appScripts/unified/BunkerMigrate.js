/**
 * BunkerMigrate.js — מיגרציה חד-פעמית של נתוני בונקר מ-Sheets ל-Supabase
 * הרץ כל פונקציה בנפרד מה-GAS Editor לפי הסדר:
 *   1. bunkerMigrate_items()
 *   2. bunkerMigrate_inventory()
 *   3. bunkerMigrate_dispenses()
 *   4. bunkerMigrate_credits()
 *   5. bunkerMigrate_shatsal()
 */

var SUPABASE_URL      = 'https://<REF>.supabase.co';
var SUPABASE_ANON_KEY = '<ANON_KEY>';  // מה-Supabase Dashboard → Settings → API

function _sbPost(path, body) {
  var res = UrlFetchApp.fetch(SUPABASE_URL + path, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
      'Prefer':        'resolution=merge-duplicates',
    },
    payload:              JSON.stringify(body),
    muteHttpExceptions:   true,
  });
  var code = res.getResponseCode();
  if (code >= 300) Logger.log('❌ ' + path + ' → ' + code + ': ' + res.getContentText());
  return code;
}

// ── 1. פריטים ──
function bunkerMigrate_items() {
  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) { Logger.log('❌ גליון מלאים לא נמצא'); return; }

  var rows  = main.getRange(2, 1, main.getLastRow() - 1, 1).getValues();
  var items = rows.map(r => ({ name: String(r[0]).trim() })).filter(r => r.name);

  var code = _sbPost('/rest/v1/bunker_items', items);
  Logger.log('✅ items → ' + items.length + ' שורות (HTTP ' + code + ')');
}

// ── 2. מלאי מחסנים ──
function bunkerMigrate_inventory() {
  var ss   = bunker_ss();
  var main = ss.getSheetByName(CONFIG.BUNKER.MAIN_SHEET);
  if (!main) { Logger.log('❌ גליון מלאים לא נמצא'); return; }

  // שלוף item IDs מ-Supabase
  var itemsRes = UrlFetchApp.fetch(SUPABASE_URL + '/rest/v1/bunker_items?select=id,name', {
    headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': 'Bearer ' + SUPABASE_ANON_KEY }
  });
  var itemMap = {};
  JSON.parse(itemsRes.getContentText()).forEach(function(r) { itemMap[r.name] = r.id; });

  var rows = main.getRange(2, 1, main.getLastRow() - 1, 3).getValues();
  var inv  = [];
  rows.forEach(function(r) {
    var name = String(r[0]).trim();
    var id   = itemMap[name];
    if (!id) return;
    if (r[1]) inv.push({ item_id: id, warehouse: 'נפתלי', qty: Number(r[1]) || 0 });
    if (r[2]) inv.push({ item_id: id, warehouse: 'בילו',  qty: Number(r[2]) || 0 });
  });

  var code = _sbPost('/rest/v1/bunker_inventory', inv);
  Logger.log('✅ inventory → ' + inv.length + ' שורות (HTTP ' + code + ')');
}

// ── 3. ניפוקים ──
function bunkerMigrate_dispenses() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName(CONFIG.BUNKER.DISPENSES_SHEET);
  if (!sh || sh.getLastRow() < 2) { Logger.log('אין ניפוקים'); return; }

  var itemMap = _getItemMap();
  var unitMap = _getUnitMap();

  var rows = sh.getRange(2, 1, sh.getLastRow() - 1, 7).getValues();
  var out  = [];
  rows.forEach(function(r) {
    var itemName = String(r[4]).trim();
    var unitName = String(r[3]).trim();
    var itemId   = itemMap[itemName];
    var unitId   = unitMap[unitName];
    if (!itemId || !unitId) return;
    out.push({
      ts:           r[1] instanceof Date ? r[1].toISOString() : new Date().toISOString(),
      warehouse:    String(r[2]).trim(),
      unit_id:      unitId,
      unit_name:    unitName,
      item_id:      itemId,
      qty:          Number(r[5]) || 1,
      dispensed_by: String(r[6] || '').trim() || null,
    });
  });

  // שלח ב-chunks של 500
  _sendChunks('/rest/v1/bunker_dispenses', out, 'ניפוקים');
}

// ── 4. זיכויים ──
function bunkerMigrate_credits() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName('זיכויים');
  if (!sh || sh.getLastRow() < 2) { Logger.log('אין זיכויים'); return; }

  var itemMap = _getItemMap();
  var unitMap = _getUnitMap();

  var rows = sh.getRange(2, 1, sh.getLastRow() - 1, 6).getValues();
  var out  = [];
  rows.forEach(function(r) {
    var unitName = String(r[3]).trim();
    var itemName = String(r[4]).trim();
    var itemId   = itemMap[itemName];
    var unitId   = unitMap[unitName];
    if (!itemId || !unitId) return;
    out.push({
      ts:          r[0] instanceof Date ? r[0].toISOString() : new Date().toISOString(),
      credited_by: String(r[1] || '').trim() || null,
      warehouse:   String(r[2] || '').trim() || null,
      unit_id:     unitId,
      unit_name:   unitName,
      item_id:     itemId,
      qty:         Number(r[5]) || 1,
    });
  });

  _sendChunks('/rest/v1/bunker_credits', out, 'זיכויים');
}

// ── 5. שצ"ל ──
function bunkerMigrate_shatsal() {
  var ss = bunker_ss();
  var sh = ss.getSheetByName('שצ״ל');
  if (!sh || sh.getLastRow() < 2) { Logger.log('אין שצ"ל'); return; }

  var itemMap = _getItemMap();
  var unitMap = _getUnitMap();

  var rows = sh.getRange(2, 1, sh.getLastRow() - 1, 7).getValues();
  var out  = [];
  rows.forEach(function(r) {
    var unitName = String(r[2]).trim();
    var itemName = String(r[4]).trim();
    var itemId   = itemMap[itemName];
    var unitId   = unitMap[unitName];
    if (!itemId || !unitId) return;
    out.push({
      exec_date:   r[1] instanceof Date ? Utilities.formatDate(r[1], CONFIG.TIMEZONE, 'yyyy-MM-dd') : null,
      unit_id:     unitId,
      unit_name:   unitName,
      responsible: String(r[3] || '').trim() || null,
      item_id:     itemId,
      qty:         Number(r[5]) || 1,
      reported_at: r[6] instanceof Date ? r[6].toISOString() : new Date().toISOString(),
    });
  });

  _sendChunks('/rest/v1/bunker_shatsal', out, 'שצ"ל');
}

// ── אחרי הכל: בנה סכימה ──
function bunkerMigrate_rebuildSchema() {
  var res = UrlFetchApp.fetch(SUPABASE_URL + '/rest/v1/rpc/bunker_rebuild_schema', {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
    },
    payload:            '{}',
    muteHttpExceptions: true,
  });
  Logger.log('✅ rebuild schema → ' + res.getContentText());
}

// ── עזר: שלוף item map מ-Supabase ──
function _getItemMap() {
  var r   = UrlFetchApp.fetch(SUPABASE_URL + '/rest/v1/bunker_items?select=id,name',
    { headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': 'Bearer ' + SUPABASE_ANON_KEY } });
  var map = {};
  JSON.parse(r.getContentText()).forEach(function(row) { map[row.name] = row.id; });
  return map;
}

// ── עזר: שלוף unit map מ-Supabase ──
function _getUnitMap() {
  var r   = UrlFetchApp.fetch(SUPABASE_URL + '/rest/v1/units?select=id,name',
    { headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': 'Bearer ' + SUPABASE_ANON_KEY } });
  var map = {};
  JSON.parse(r.getContentText()).forEach(function(row) { map[row.name] = row.id; });
  return map;
}

// ── עזר: שלח ב-chunks ──
function _sendChunks(path, rows, label) {
  var CHUNK = 500;
  var total = 0;
  for (var i = 0; i < rows.length; i += CHUNK) {
    var chunk = rows.slice(i, i + CHUNK);
    var code  = _sbPost(path, chunk);
    total += chunk.length;
    Logger.log('  chunk ' + Math.ceil(i/CHUNK + 1) + ': ' + chunk.length + ' שורות (HTTP ' + code + ')');
  }
  Logger.log('✅ ' + label + ' → ' + total + ' שורות סה"כ');
}
