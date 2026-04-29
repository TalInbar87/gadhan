#!/usr/bin/env node
/**
 * bunker-migrate.js — מיגרציה חד-פעמית של נתוני בונקר מ-CSV ל-Supabase
 *
 * הכנה:
 *   1. ייצא מה-Google Sheet את הגליונות הבאים כ-CSV לתיקיית scripts/data/ :
 *        מלאים.csv | ניפוקים.csv | זיכויים.csv | שצל.csv
 *   2. מלא SUPABASE_URL + SUPABASE_SERVICE_KEY למטה (או .env)
 *   3. הרץ:  node scripts/bunker-migrate.js
 */

import { createClient } from '@supabase/supabase-js';
import fs               from 'fs';
import path             from 'path';
import { fileURLToPath } from 'url';

const __dir = path.dirname(fileURLToPath(import.meta.url));

// ── הגדרות — מלא לפני ריצה ──
const SUPABASE_URL         = process.env.SUPABASE_URL         || 'https://<REF>.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '<SERVICE_ROLE_KEY>';

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ================================================================
// עזר: קרא CSV
// ================================================================
function readCsv(filename) {
  const file = path.join(__dir, 'data', filename);
  if (!fs.existsSync(file)) { console.error(`❌ קובץ לא נמצא: ${file}`); return []; }

  const lines  = fs.readFileSync(file, 'utf8').split('\n');
  const header = parseCsvLine(lines[0]);
  return lines.slice(1)
    .filter(l => l.trim())
    .map(l => {
      const vals = parseCsvLine(l);
      const obj  = {};
      header.forEach((h, i) => { obj[h.trim()] = (vals[i] ?? '').trim(); });
      return obj;
    });
}

function parseCsvLine(line) {
  const result = [];
  let cur = '', inQ = false;
  for (const ch of line) {
    if (ch === '"') { inQ = !inQ; }
    else if (ch === ',' && !inQ) { result.push(cur); cur = ''; }
    else cur += ch;
  }
  result.push(cur);
  return result;
}

function parseDate(str) {
  if (!str) return null;
  // DD/MM/YYYY HH:mm or DD/MM/YYYY
  const m = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2}))?/);
  if (!m) return null;
  return new Date(+m[3], +m[2]-1, +m[1], +(m[4]||0), +(m[5]||0)).toISOString();
}

async function sbInsert(table, rows, label) {
  const CHUNK = 500;
  let total = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const { error } = await sb.from(table).insert(chunk);
    if (error) { console.error(`  ❌ chunk ${Math.ceil(i/CHUNK)+1}: ${error.message}`); }
    else { total += chunk.length; process.stdout.write('.'); }
  }
  console.log(`\n✅ ${label} → ${total} שורות`);
}

// ================================================================
// 1. פריטים
// ================================================================
async function migrateItems() {
  console.log('\n── 1. פריטים ──');
  const rows = readCsv('מלאים.csv');
  const items = [...new Set(rows.map(r => Object.values(r)[0]).filter(Boolean))]
    .map(name => ({ name }));

  const { error } = await sb.from('bunker_items').upsert(items, { onConflict: 'name' });
  if (error) console.error('❌', error.message);
  else console.log(`✅ פריטים → ${items.length}`);
}

// ================================================================
// 2. מלאי מחסנים
// ================================================================
async function migrateInventory() {
  console.log('\n── 2. מלאי מחסנים ──');
  const rows = readCsv('מלאים.csv');

  const { data: itemsDb } = await sb.from('bunker_items').select('id, name');
  const itemMap = Object.fromEntries(itemsDb.map(r => [r.name, r.id]));

  const inv = [];
  for (const r of rows) {
    const vals = Object.values(r);
    const name = vals[0];
    const id   = itemMap[name];
    if (!id) { console.warn(`  ⚠️ פריט לא נמצא: ${name}`); continue; }
    const nafatli = Number(vals[1]) || 0;
    const bilo    = Number(vals[2]) || 0;
    if (nafatli) inv.push({ item_id: id, warehouse: 'נפתלי', qty: nafatli });
    if (bilo)    inv.push({ item_id: id, warehouse: 'בילו',  qty: bilo });
  }

  const { error } = await sb.from('bunker_inventory')
    .upsert(inv, { onConflict: 'item_id,warehouse' });
  if (error) console.error('❌', error.message);
  else console.log(`✅ מלאי → ${inv.length} שורות`);
}

// ================================================================
// 3. ניפוקים
// ================================================================
async function migrateDispenses() {
  console.log('\n── 3. ניפוקים ──');
  const rows = readCsv('ניפוקים.csv');

  const { data: itemsDb } = await sb.from('bunker_items').select('id, name');
  const { data: unitsDb } = await sb.from('units').select('id, name');
  const itemMap = Object.fromEntries(itemsDb.map(r => [r.name, r.id]));
  const unitMap = Object.fromEntries(unitsDb.map(r => [r.name, r.id]));

  const out = [];
  for (const r of rows) {
    // עמודות: מזהה | תאריך | מחסן | מסגרת | פריט | כמות | מנפק
    const vals      = Object.values(r);
    const unitName  = vals[3];
    const itemName  = vals[4];
    const itemId    = itemMap[itemName];
    const unitId    = unitMap[unitName];
    if (!itemId || !unitId) continue;
    out.push({
      ts:           parseDate(vals[1]) ?? new Date().toISOString(),
      warehouse:    vals[2] || '',
      unit_id:      unitId,
      unit_name:    unitName,
      item_id:      itemId,
      qty:          Number(vals[5]) || 1,
      dispensed_by: vals[6] || null,
    });
  }
  await sbInsert('bunker_dispenses', out, 'ניפוקים');
}

// ================================================================
// 4. זיכויים
// ================================================================
async function migrateCredits() {
  console.log('\n── 4. זיכויים ──');
  const rows = readCsv('זיכויים.csv');

  const { data: itemsDb } = await sb.from('bunker_items').select('id, name');
  const { data: unitsDb } = await sb.from('units').select('id, name');
  const itemMap = Object.fromEntries(itemsDb.map(r => [r.name, r.id]));
  const unitMap = Object.fromEntries(unitsDb.map(r => [r.name, r.id]));

  const out = [];
  for (const r of rows) {
    // עמודות: תאריך | מזכה | מחסן | מסגרת | פריט | כמות
    const vals     = Object.values(r);
    const unitName = vals[3];
    const itemName = vals[4];
    const itemId   = itemMap[itemName];
    const unitId   = unitMap[unitName];
    if (!itemId || !unitId) continue;
    out.push({
      ts:          parseDate(vals[0]) ?? new Date().toISOString(),
      credited_by: vals[1] || null,
      warehouse:   vals[2] || null,
      unit_id:     unitId,
      unit_name:   unitName,
      item_id:     itemId,
      qty:         Number(vals[5]) || 1,
    });
  }
  await sbInsert('bunker_credits', out, 'זיכויים');
}

// ================================================================
// 5. שצ"ל
// ================================================================
async function migrateShatsal() {
  console.log('\n── 5. שצ"ל ──');
  const rows = readCsv('שצל.csv');

  const { data: itemsDb } = await sb.from('bunker_items').select('id, name');
  const { data: unitsDb } = await sb.from('units').select('id, name');
  const itemMap = Object.fromEntries(itemsDb.map(r => [r.name, r.id]));
  const unitMap = Object.fromEntries(unitsDb.map(r => [r.name, r.id]));

  const out = [];
  for (const r of rows) {
    // עמודות: מזהה | תאריך ביצוע | מסגרת | אחראי | פריט | כמות | תאריך דיווח
    const vals     = Object.values(r);
    const unitName = vals[2];
    const itemName = vals[4];
    const itemId   = itemMap[itemName];
    const unitId   = unitMap[unitName];
    if (!itemId || !unitId) continue;
    out.push({
      exec_date:   parseDate(vals[1])?.slice(0,10) ?? new Date().toISOString().slice(0,10),
      unit_id:     unitId,
      unit_name:   unitName,
      responsible: vals[3] || null,
      item_id:     itemId,
      qty:         Number(vals[5]) || 1,
      reported_at: parseDate(vals[6]) ?? new Date().toISOString(),
    });
  }
  await sbInsert('bunker_shatsal', out, 'שצ"ל');
}

// ================================================================
// 6. rebuild schema
// ================================================================
async function rebuildSchema() {
  console.log('\n── 6. בניית סכימה ──');
  const { data, error } = await sb.rpc('bunker_rebuild_schema');
  if (error) console.error('❌', error.message);
  else console.log(`✅ סכימה נבנתה — ${data} שורות`);
}

// ================================================================
// main
// ================================================================
(async () => {
  console.log('🚀 מתחיל מיגרציה...\n');
  await migrateItems();
  await migrateInventory();
  await migrateDispenses();
  await migrateCredits();
  await migrateShatsal();
  await rebuildSchema();
  console.log('\n🎉 מיגרציה הושלמה!');
})();
