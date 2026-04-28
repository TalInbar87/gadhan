// ================================================================
// bunker.ts — כל פעולות מודול הבונקר
// תואם לחלוטין לממשק הנוכחי של Bunker.js ב-GAS
// ================================================================

import { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { createResponse }  from './_shared/response.ts';
import { JwtPayload }      from './_shared/jwt.ts';

const UNIT_ORDER = ['פלוגה א','פלוגה ב','פלוגה ג','צמה','ניוד','מחסר','חפק'];

// ── עזר: מצא item_id לפי שם ──
async function findItemId(sb: SupabaseClient, name: string): Promise<number | null> {
  const { data } = await sb.from('bunker_items').select('id').eq('name', name).single();
  return data?.id ?? null;
}

// ── עזר: עדכן bunker_schema ──
async function schemaUpdateDispense(
  sb: SupabaseClient, itemId: number, unit: string, delta: number
): Promise<void> {
  // upsert + increment atomically
  await sb.rpc('bunker_schema_update_dispense', { p_item_id: itemId, p_unit: unit, p_delta: delta });
}

async function schemaUpdateShatsal(
  sb: SupabaseClient, itemId: number, unit: string, delta: number
): Promise<void> {
  await sb.rpc('bunker_schema_update_shatsal', { p_item_id: itemId, p_unit: unit, p_delta: delta });
}

// ================================================================
// bunker_get_items
// ================================================================
export async function handleBunkerGetItems(sb: SupabaseClient, _data: Record<string, unknown>, _payload: JwtPayload) {
  const { data, error } = await sb.from('bunker_items').select('id, name').order('name');
  if (error) return createResponse(500, error.message, null);
  return createResponse(200, 'OK', data.map((r: { id: number; name: string }) => ({ id: r.id, key: r.name, label: r.name })));
}

// ================================================================
// bunker_get_inventory
// ================================================================
export async function handleBunkerGetInventory(sb: SupabaseClient, _data: Record<string, unknown>, _payload: JwtPayload) {
  const { data: items, error: ie } = await sb.from('bunker_items').select('id, name').order('name');
  if (ie) return createResponse(500, ie.message, null);

  const { data: inv, error: ie2 } = await sb.from('bunker_inventory').select('item_id, warehouse, qty');
  if (ie2) return createResponse(500, ie2.message, null);

  const invMap: Record<number, Record<string, number>> = {};
  for (const row of (inv as { item_id: number; warehouse: string; qty: number }[])) {
    if (!invMap[row.item_id]) invMap[row.item_id] = {};
    invMap[row.item_id][row.warehouse] = row.qty;
  }

  const result = (items as { id: number; name: string }[]).map(item => ({
    key:     item.name,
    label:   item.name,
    nafatli: invMap[item.id]?.['נפתלי'] ?? 0,
    bilo:    invMap[item.id]?.['בילו']  ?? 0,
  }));

  return createResponse(200, 'OK', result);
}

// ================================================================
// bunker_save_inventory
// ================================================================
export async function handleBunkerSaveInventory(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const items = data.items as { key: string; nafatli: number; bilo: number }[] | undefined;
  if (!items?.length) return createResponse(400, 'חסרים נתונים', null);

  for (const item of items) {
    const itemId = await findItemId(sb, item.key);
    if (!itemId) continue;
    await sb.from('bunker_inventory').upsert([
      { item_id: itemId, warehouse: 'נפתלי', qty: Math.max(0, item.nafatli || 0) },
      { item_id: itemId, warehouse: 'בילו',  qty: Math.max(0, item.bilo    || 0) },
    ], { onConflict: 'item_id,warehouse' });
  }

  return createResponse(200, 'מלאי עודכן', null);
}

// ================================================================
// bunker_add_item
// ================================================================
export async function handleBunkerAddItem(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const name = (data.name as string | undefined)?.trim();
  if (!name) return createResponse(400, 'שם פריט חסר', null);

  const { error } = await sb.from('bunker_items').insert({ name });
  if (error) return createResponse(500, error.message, null);
  return createResponse(200, 'פריט נוסף', null);
}

// ================================================================
// bunker_get_dispenses
// ================================================================
export async function handleBunkerGetDispenses(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const unit = data.unit as string | undefined;

  let query = sb
    .from('bunker_dispenses')
    .select('id, ts, warehouse, unit, qty, dispensed_by, bunker_items(name)')
    .order('ts', { ascending: false })
    .limit(500);

  if (unit) query = query.eq('unit', unit);

  const { data: rows, error } = await query;
  if (error) return createResponse(500, error.message, null);

  const result = (rows as {
    id: string; ts: string; warehouse: string; unit: string; qty: number;
    dispensed_by: string; bunker_items: { name: string };
  }[]).map(r => ({
    id:          r.id,
    timestamp:   formatDate(r.ts),
    warehouse:   r.warehouse,
    unit:        r.unit,
    item:        r.bunker_items?.name ?? '',
    qty:         r.qty,
    dispensedBy: r.dispensed_by,
  }));

  return createResponse(200, 'OK', result);
}

// ================================================================
// bunker_dispense
// ================================================================
export async function handleBunkerDispense(sb: SupabaseClient, data: Record<string, unknown>, payload: JwtPayload) {
  const warehouse = data.warehouse as string | undefined;
  const unit      = data.unit      as string | undefined;
  const items     = data.items     as { key: string; qty: number }[] | undefined;
  const by        = (data.by as string | undefined) || payload.fullName || 'לא ידוע';

  if (!warehouse || !unit || !items?.length)
    return createResponse(400, 'חסרים נתונים לניפוק', null);

  // ── ולידציה ──
  const validated: { itemId: number; key: string; qty: number; stock: number }[] = [];
  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (qty <= 0) continue;

    const itemId = await findItemId(sb, item.key);
    if (!itemId) return createResponse(400, `פריט לא נמצא: ${item.key}`, null);

    const { data: inv } = await sb
      .from('bunker_inventory').select('qty')
      .eq('item_id', itemId).eq('warehouse', warehouse).single();
    const stock = inv?.qty ?? 0;
    if (stock < qty) return createResponse(400, `מלאי לא מספיק: ${item.key} (יש ${stock}, נדרש ${qty})`, null);

    validated.push({ itemId, key: item.key, qty, stock });
  }

  // ── כתיבה בתוך transaction (RPC) ──
  const { error } = await sb.rpc('bunker_dispense_tx', {
    p_warehouse: warehouse,
    p_unit:      unit,
    p_by:        by,
    p_items:     validated.map(v => ({ item_id: v.itemId, qty: v.qty, stock: v.stock })),
  });

  if (error) return createResponse(500, `שגיאת כתיבה: ${error.message}`, null);
  return createResponse(200, 'ניפוק בוצע', { dispensed: validated.length });
}

// ================================================================
// bunker_credit
// ================================================================
export async function handleBunkerCredit(sb: SupabaseClient, data: Record<string, unknown>, payload: JwtPayload) {
  const unit      = data.unit      as string | undefined;
  const warehouse = data.warehouse as string | undefined;
  const items     = data.items     as { key: string; qty: number }[] | undefined;
  const by        = (data.by as string | undefined) || payload.fullName || 'לא ידוע';

  if (!unit || !items?.length)
    return createResponse(400, 'חסרים נתונים לזיכוי', null);

  const validated: { itemId: number; key: string; qty: number }[] = [];
  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (qty <= 0) continue;
    const itemId = await findItemId(sb, item.key);
    if (!itemId) return createResponse(400, `פריט לא נמצא: ${item.key}`, null);
    validated.push({ itemId, key: item.key, qty });
  }

  const { error } = await sb.rpc('bunker_credit_tx', {
    p_unit:      unit,
    p_warehouse: warehouse ?? '',
    p_by:        by,
    p_items:     validated.map(v => ({ item_id: v.itemId, qty: v.qty })),
  });

  if (error) return createResponse(500, `שגיאת כתיבה: ${error.message}`, null);
  return createResponse(200, 'זיכוי בוצע', { credited: validated.length });
}

// ================================================================
// bunker_get_credits
// ================================================================
export async function handleBunkerGetCredits(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const unit = data.unit as string | undefined;

  let query = sb
    .from('bunker_credits')
    .select('id, ts, credited_by, warehouse, unit, qty, bunker_items(name)')
    .order('ts', { ascending: false })
    .limit(500);

  if (unit) query = query.eq('unit', unit);

  const { data: rows, error } = await query;
  if (error) return createResponse(500, error.message, null);

  const result = (rows as {
    id: string; ts: string; credited_by: string; warehouse: string;
    unit: string; qty: number; bunker_items: { name: string };
  }[]).map(r => ({
    timestamp: formatDate(r.ts),
    by:        r.credited_by,
    warehouse: r.warehouse,
    unit:      r.unit,
    itemKey:   r.bunker_items?.name ?? '',
    qty:       r.qty,
  }));

  return createResponse(200, 'OK', result);
}

// ================================================================
// bunker_shatsal_report
// ================================================================
export async function handleBunkerShatsalReport(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const unit        = data.unit        as string | undefined;
  const responsible = data.responsible as string | undefined;
  const execDate    = data.date        as string | undefined;
  const items       = data.items       as { key: string; qty: number }[] | undefined;

  if (!unit || !items?.length)
    return createResponse(400, 'חסרים נתונים לשצ"ל', null);

  const validated: { itemId: number; key: string; qty: number }[] = [];
  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (qty <= 0) continue;
    const itemId = await findItemId(sb, item.key);
    if (!itemId) return createResponse(400, `פריט לא נמצא: ${item.key}`, null);
    validated.push({ itemId, key: item.key, qty });
  }

  const { error } = await sb.rpc('bunker_shatsal_tx', {
    p_unit:        unit,
    p_responsible: responsible ?? '',
    p_exec_date:   execDate ?? new Date().toISOString().slice(0, 10),
    p_items:       validated.map(v => ({ item_id: v.itemId, qty: v.qty })),
  });

  if (error) return createResponse(500, `שגיאת כתיבה: ${error.message}`, null);
  return createResponse(200, 'דיווח שצ"ל נשמר', { items: validated.length });
}

// ================================================================
// bunker_get_shatsal
// ================================================================
export async function handleBunkerGetShatsal(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const unit = data.unit as string | undefined;

  let query = sb
    .from('bunker_shatsal')
    .select('id, exec_date, unit, responsible, qty, reported_at, bunker_items(name)')
    .order('reported_at', { ascending: false })
    .limit(500);

  if (unit) query = query.eq('unit', unit);

  const { data: rows, error } = await query;
  if (error) return createResponse(500, error.message, null);

  const result = (rows as {
    id: string; exec_date: string; unit: string; responsible: string;
    qty: number; reported_at: string; bunker_items: { name: string };
  }[]).map(r => ({
    id:          r.id,
    execDate:    r.exec_date,
    unit:        r.unit,
    responsible: r.responsible,
    item:        r.bunker_items?.name ?? '',
    qty:         r.qty,
    reportedAt:  formatDate(r.reported_at),
  }));

  return createResponse(200, 'OK', result);
}

// ================================================================
// bunker_dispense_summary (קריאה מסכימה)
// ================================================================
export async function handleBunkerDispenseSummary(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const filterUnit = data.filterUnit as string | undefined;

  const { data: schema, error } = await sb
    .from('bunker_schema')
    .select('item_id, unit, dispenses, shatsal, bunker_items(name)');
  if (error) return createResponse(500, error.message, null);

  // צבור לפי פריט
  const byItem: Record<string, { item: string; dispenses: Record<string, number>; shatsalPerUnit: Record<string, number> }> = {};

  for (const row of (schema as {
    item_id: number; unit: string; dispenses: number; shatsal: number; bunker_items: { name: string };
  }[])) {
    const itemName = row.bunker_items?.name ?? String(row.item_id);
    if (!byItem[itemName]) byItem[itemName] = { item: itemName, dispenses: {}, shatsalPerUnit: {} };
    byItem[itemName].dispenses[row.unit]     = row.dispenses;
    byItem[itemName].shatsalPerUnit[row.unit] = row.shatsal;
  }

  let rows = Object.values(byItem);

  if (filterUnit) {
    rows = rows.filter(r => (r.dispenses[filterUnit] || 0) > 0 || (r.shatsalPerUnit[filterUnit] || 0) > 0);
  }

  const activeUnits = filterUnit
    ? [filterUnit]
    : UNIT_ORDER.filter(u => rows.some(r => (r.dispenses[u] || 0) > 0));

  return createResponse(200, 'OK', { rows, units: activeUnits });
}

// ================================================================
// bunker_rebuild_schema
// ================================================================
export async function handleBunkerRebuildSchema(sb: SupabaseClient, _data: Record<string, unknown>, _payload: JwtPayload) {
  const { error } = await sb.rpc('bunker_rebuild_schema');
  if (error) return createResponse(500, error.message, null);

  const { count } = await sb.from('bunker_schema').select('*', { count: 'exact', head: true });
  return createResponse(200, 'ok', { rebuilt: count ?? 0 });
}

// ================================================================
// bunker_receive
// ================================================================
export async function handleBunkerReceive(sb: SupabaseClient, data: Record<string, unknown>, payload: JwtPayload) {
  const warehouse  = data.warehouse  as string | undefined;
  const fromSource = data.from       as string | undefined;
  const items      = data.items      as { key: string; qty: number }[] | undefined;
  const by         = (data.by as string | undefined) || payload.fullName;

  if (!warehouse || !items?.length) return createResponse(400, 'חסרים נתונים', null);

  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (qty <= 0) continue;
    const itemId = await findItemId(sb, item.key);
    if (!itemId) continue;

    await sb.from('bunker_receipts').insert({ from_source: fromSource, warehouse, item_id: itemId, qty, received_by: by });
    await sb.rpc('bunker_inventory_add', { p_item_id: itemId, p_warehouse: warehouse, p_delta: qty });
  }

  return createResponse(200, 'קבלה נרשמה', null);
}

// ================================================================
// bunker_transfer
// ================================================================
export async function handleBunkerTransfer(sb: SupabaseClient, data: Record<string, unknown>, _payload: JwtPayload) {
  const from  = data.from  as string | undefined;
  const to    = data.to    as string | undefined;
  const items = data.items as { key: string; qty: number }[] | undefined;

  if (!from || !to || !items?.length) return createResponse(400, 'חסרים נתונים להעברה', null);

  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (qty <= 0) continue;
    const itemId = await findItemId(sb, item.key);
    if (!itemId) continue;

    await sb.rpc('bunker_inventory_add', { p_item_id: itemId, p_warehouse: from, p_delta: -qty });
    await sb.rpc('bunker_inventory_add', { p_item_id: itemId, p_warehouse: to,   p_delta:  qty });
  }

  return createResponse(200, 'העברה בוצעה', null);
}

// ================================================================
// bunker_regulate
// ================================================================
export async function handleBunkerRegulate(sb: SupabaseClient, data: Record<string, unknown>, payload: JwtPayload) {
  const warehouse  = data.warehouse  as string | undefined;
  const responsible = data.responsible as string | undefined;
  const items      = data.items      as { key: string; qty: number }[] | undefined;
  const by         = (data.by as string | undefined) || payload.fullName;

  if (!warehouse || !items?.length) return createResponse(400, 'חסרים נתונים לוויסות', null);

  for (const item of items) {
    const qty = Number(item.qty);
    if (!qty) continue;
    const itemId = await findItemId(sb, item.key);
    if (!itemId) continue;

    await sb.from('bunker_regulations').insert({ responsible, warehouse, item_id: itemId, qty, regulated_by: by });
    await sb.rpc('bunker_inventory_add', { p_item_id: itemId, p_warehouse: warehouse, p_delta: qty });
  }

  return createResponse(200, 'וויסות בוצע', null);
}

// ================================================================
// bunker_get_regulations
// ================================================================
export async function handleBunkerGetRegulations(sb: SupabaseClient, _data: Record<string, unknown>, _payload: JwtPayload) {
  const { data: rows, error } = await sb
    .from('bunker_regulations')
    .select('id, ts, responsible, warehouse, qty, regulated_by, bunker_items(name)')
    .order('ts', { ascending: false })
    .limit(200);

  if (error) return createResponse(500, error.message, null);

  return createResponse(200, 'OK', (rows as {
    id: string; ts: string; responsible: string; warehouse: string;
    qty: number; regulated_by: string; bunker_items: { name: string };
  }[]).map(r => ({
    timestamp:   formatDate(r.ts),
    responsible: r.responsible,
    warehouse:   r.warehouse,
    item:        r.bunker_items?.name ?? '',
    qty:         r.qty,
    regulatedBy: r.regulated_by,
  })));
}

// ── עזר: פורמט תאריך ──
function formatDate(ts: string): string {
  if (!ts) return '';
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
