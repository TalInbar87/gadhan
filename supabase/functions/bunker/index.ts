// supabase/functions/bunker/index.ts
// מודול בונקר — כל פעולות התחמושת והציוד
// Auth: custom JWT (גדחן) — פאזה ב' תעבור ל-Supabase Auth
// DB:   service role (bypasses RLS)

// deno-lint-ignore-file no-explicit-any
import { serve }        from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';

const corsHeaders = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// ── תשובה — תואם פורמט GAS הנוכחי ──
function res(statusCode: number, message: string, data: unknown, httpStatus = 200) {
  return new Response(
    JSON.stringify({ statusCode, message, data, timestamp: new Date().toISOString() }),
    { status: httpStatus, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  );
}

// ── פורמט תאריך עברי ──
function fmtDate(ts: string | null): string {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ── אימות custom JWT של גדחן (HS256) ──
async function verifyGadhanJwt(token: string): Promise<Record<string, any> | null> {
  try {
    const secret = Deno.env.get('GADHAN_JWT_SECRET') ??
      'BagadHatzamKomando8219SecretKey2026XyZ_STATIC_2026';
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, payload, sig] = parts;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key,
      sigBytes, new TextEncoder().encode(`${header}.${payload}`));
    if (!valid) return null;

    const decoded = JSON.parse(atob(payload.replace(/-/g,'+').replace(/_/g,'/')));
    if (decoded.exp < Math.floor(Date.now() / 1000)) return null;
    return decoded;
  } catch { return null; }
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
  if (req.method !== 'POST')   return res(405, 'Method not allowed', null, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const serviceKey  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  // ── 1. אמת JWT ──
  const auth = req.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return res(401, 'Missing Authorization header', null);
  const token = auth.slice(7);

  const jwtPayload = await verifyGadhanJwt(token);
  if (!jwtPayload) return res(401, 'Invalid or expired token', null);

  const isAdmin = jwtPayload.role === 'admin';
  const by      = jwtPayload.fullName ?? jwtPayload.username ?? 'לא ידוע';

  const sb = createClient(supabaseUrl, serviceKey);

  // ── 3. קרא body ──
  let body: Record<string, any>;
  try { body = await req.json(); } catch { return res(400, 'Invalid JSON', null); }

  const action = body.action as string | undefined;
  if (!action) return res(400, 'Missing action', null);

  // ================================================================
  try {
    switch (action) {

      // ── קריאות (כולם) ──────────────────────────────────────────

      case 'bunker_get_items': {
        const { data, error } = await sb.from('bunker_items').select('id, name').eq('active', true).order('name');
        if (error) return res(500, error.message, null);
        return res(200, 'OK', data.map((r: any) => ({ id: r.id, key: r.name, label: r.name })));
      }

      case 'bunker_get_inventory': {
        const { data: items, error: e1 } = await sb.from('bunker_items').select('id, name').eq('active', true).order('name');
        if (e1) return res(500, e1.message, null);
        const { data: inv,   error: e2 } = await sb.from('bunker_inventory').select('item_id, warehouse, qty');
        if (e2) return res(500, e2.message, null);

        const map: Record<string, Record<string, number>> = {};
        for (const r of (inv as any[])) {
          if (!map[r.item_id]) map[r.item_id] = {};
          map[r.item_id][r.warehouse] = r.qty;
        }
        return res(200, 'OK', (items as any[]).map(item => ({
          key:     item.name,
          label:   item.name,
          nafatli: map[item.id]?.['נפתלי'] ?? 0,
          bilo:    map[item.id]?.['בילו']  ?? 0,
        })));
      }

      case 'bunker_get_dispenses': {
        const unit = body.unit as string | undefined;
        let query = sb.from('bunker_dispenses')
          .select('id, ts, warehouse, unit_name, qty, dispensed_by, bunker_items(name)')
          .order('ts', { ascending: false }).limit(500);
        if (unit) query = query.eq('unit_name', unit);
        const { data, error } = await query;
        if (error) return res(500, error.message, null);
        return res(200, 'OK', (data as any[]).map(r => ({
          id:          r.id,
          timestamp:   fmtDate(r.ts),
          warehouse:   r.warehouse,
          unit:        r.unit_name,
          item:        r.bunker_items?.name ?? '',
          qty:         r.qty,
          dispensedBy: r.dispensed_by,
        })));
      }

      case 'bunker_get_credits': {
        const unit = body.unit as string | undefined;
        let query = sb.from('bunker_credits')
          .select('id, ts, credited_by, warehouse, unit_name, qty, bunker_items(name)')
          .order('ts', { ascending: false }).limit(500);
        if (unit) query = query.eq('unit_name', unit);
        const { data, error } = await query;
        if (error) return res(500, error.message, null);
        return res(200, 'OK', (data as any[]).map(r => ({
          timestamp: fmtDate(r.ts),
          by:        r.credited_by,
          warehouse: r.warehouse,
          unit:      r.unit_name,
          itemKey:   r.bunker_items?.name ?? '',
          qty:       r.qty,
        })));
      }

      case 'bunker_get_shatsal': {
        const unit = body.unit as string | undefined;
        let query = sb.from('bunker_shatsal')
          .select('id, exec_date, unit_name, responsible, qty, reported_at, bunker_items(name)')
          .order('reported_at', { ascending: false }).limit(500);
        if (unit) query = query.eq('unit_name', unit);
        const { data, error } = await query;
        if (error) return res(500, error.message, null);
        return res(200, 'OK', (data as any[]).map(r => ({
          id:          r.id,
          execDate:    r.exec_date,
          unit:        r.unit_name,
          responsible: r.responsible,
          item:        r.bunker_items?.name ?? '',
          qty:         r.qty,
          reportedAt:  fmtDate(r.reported_at),
        })));
      }

      case 'bunker_dispense_summary': {
        const filterUnit = body.filterUnit as string | undefined;
        const { data: schema, error } = await sb
          .from('bunker_schema')
          .select('unit_name, dispenses, shatsal, bunker_items(name)');
        if (error) return res(500, error.message, null);

        const byItem: Record<string, any> = {};
        for (const r of (schema as any[])) {
          const name = r.bunker_items?.name ?? '';
          if (!byItem[name]) byItem[name] = { item: name, dispenses: {}, shatsalPerUnit: {} };
          byItem[name].dispenses[r.unit_name]     = r.dispenses;
          byItem[name].shatsalPerUnit[r.unit_name] = r.shatsal;
        }

        let rows = Object.values(byItem);
        if (filterUnit) rows = rows.filter(r => (r.dispenses[filterUnit] || 0) > 0 || (r.shatsalPerUnit[filterUnit] || 0) > 0);

        const UNIT_ORDER = ['פלוגה א','פלוגה ב','פלוגה ג','צמה','ניוד','מחסר','חפק'];
        const units = filterUnit ? [filterUnit] : UNIT_ORDER.filter(u => rows.some(r => (r.dispenses[u] || 0) > 0));
        return res(200, 'OK', { rows, units });
      }

      // ── כתיבות (admin בלבד) ──────────────────────────────────

      case 'bunker_save_inventory': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const items = body.items as { key: string; nafatli: number; bilo: number }[] | undefined;
        if (!items?.length) return res(400, 'חסרים נתונים', null);
        for (const item of items) {
          const { data: found } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!found) continue;
          await sb.from('bunker_inventory').upsert([
            { item_id: found.id, warehouse: 'נפתלי', qty: Math.max(0, item.nafatli || 0) },
            { item_id: found.id, warehouse: 'בילו',  qty: Math.max(0, item.bilo    || 0) },
          ], { onConflict: 'item_id,warehouse' });
        }
        return res(200, 'מלאי עודכן', null);
      }

      case 'bunker_add_item': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const name = (body.name as string | undefined)?.trim();
        if (!name) return res(400, 'שם פריט חסר', null);
        const { error } = await sb.from('bunker_items').insert({ name });
        if (error) return res(500, error.message, null);
        return res(200, 'פריט נוסף', null);
      }

      case 'bunker_dispense': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { warehouse, unit: unitName, items, by: byOverride } = body;
        if (!warehouse || !unitName || !items?.length) return res(400, 'חסרים נתונים לניפוק', null);

        // שלוף unit_id
        const { data: unitRow } = await sb.from('units').select('id').eq('name', unitName).single();
        if (!unitRow) return res(400, `מסגרת לא נמצאה: ${unitName}`, null);

        // ולידציה + בניית items לtransaction
        const txItems: { item_id: string; qty: number }[] = [];
        for (const item of items) {
          const qty = Number(item.qty) || 0;
          if (qty <= 0) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) return res(400, `פריט לא נמצא: ${item.key}`, null);
          const { data: inv } = await sb.from('bunker_inventory').select('qty').eq('item_id', itemRow.id).eq('warehouse', warehouse).single();
          if ((inv?.qty ?? 0) < qty) return res(400, `מלאי לא מספיק: ${item.key} (יש ${inv?.qty ?? 0}, נדרש ${qty})`, null);
          txItems.push({ item_id: itemRow.id, qty });
        }

        const { error } = await sb.rpc('bunker_dispense_tx', {
          p_warehouse: warehouse,
          p_unit_id:   unitRow.id,
          p_unit_name: unitName,
          p_by:        byOverride || by,
          p_items:     txItems,
        });
        if (error) return res(500, `שגיאת כתיבה: ${error.message}`, null);
        return res(200, 'ניפוק בוצע', { dispensed: txItems.length });
      }

      case 'bunker_credit': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { unit: unitName, warehouse, items, by: byOverride } = body;
        if (!unitName || !items?.length) return res(400, 'חסרים נתונים לזיכוי', null);

        const { data: unitRow } = await sb.from('units').select('id').eq('name', unitName).single();
        if (!unitRow) return res(400, `מסגרת לא נמצאה: ${unitName}`, null);

        const txItems: { item_id: string; qty: number }[] = [];
        for (const item of items) {
          const qty = Number(item.qty) || 0;
          if (qty <= 0) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) return res(400, `פריט לא נמצא: ${item.key}`, null);
          txItems.push({ item_id: itemRow.id, qty });
        }

        const { error } = await sb.rpc('bunker_credit_tx', {
          p_unit_id:   unitRow.id,
          p_unit_name: unitName,
          p_warehouse: warehouse || '',
          p_by:        byOverride || by,
          p_items:     txItems,
        });
        if (error) return res(500, `שגיאת כתיבה: ${error.message}`, null);
        return res(200, 'זיכוי בוצע', { credited: txItems.length });
      }

      case 'bunker_shatsal_report': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { unit: unitName, responsible, date: execDate, items } = body;
        if (!unitName || !items?.length) return res(400, 'חסרים נתונים לשצ"ל', null);

        const { data: unitRow } = await sb.from('units').select('id').eq('name', unitName).single();
        if (!unitRow) return res(400, `מסגרת לא נמצאה: ${unitName}`, null);

        const txItems: { item_id: string; qty: number }[] = [];
        for (const item of items) {
          const qty = Number(item.qty) || 0;
          if (qty <= 0) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) return res(400, `פריט לא נמצא: ${item.key}`, null);
          txItems.push({ item_id: itemRow.id, qty });
        }

        const { error } = await sb.rpc('bunker_shatsal_tx', {
          p_unit_id:     unitRow.id,
          p_unit_name:   unitName,
          p_responsible: responsible || '',
          p_exec_date:   execDate || new Date().toISOString().slice(0, 10),
          p_items:       txItems,
        });
        if (error) return res(500, `שגיאת כתיבה: ${error.message}`, null);
        return res(200, 'דיווח שצ"ל נשמר', { items: txItems.length });
      }

      case 'bunker_rebuild_schema': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { data: count, error } = await sb.rpc('bunker_rebuild_schema');
        if (error) return res(500, error.message, null);
        return res(200, 'ok', { rebuilt: count ?? 0 });
      }

      case 'bunker_receive': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { warehouse, from: fromSource, items, by: byOverride } = body;
        if (!warehouse || !items?.length) return res(400, 'חסרים נתונים', null);
        for (const item of items) {
          const qty = Number(item.qty) || 0;
          if (qty <= 0) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) continue;
          await sb.from('bunker_receipts').insert({ from_source: fromSource, warehouse, item_id: itemRow.id, qty, received_by: byOverride || by });
          await sb.rpc('bunker_inventory_add', { p_item_id: itemRow.id, p_warehouse: warehouse, p_delta: qty });
        }
        return res(200, 'קבלה נרשמה', null);
      }

      case 'bunker_transfer': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { from, to, items } = body;
        if (!from || !to || !items?.length) return res(400, 'חסרים נתונים להעברה', null);
        for (const item of items) {
          const qty = Number(item.qty) || 0;
          if (qty <= 0) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) continue;
          await sb.rpc('bunker_inventory_add', { p_item_id: itemRow.id, p_warehouse: from, p_delta: -qty });
          await sb.rpc('bunker_inventory_add', { p_item_id: itemRow.id, p_warehouse: to,   p_delta:  qty });
        }
        return res(200, 'העברה בוצעה', null);
      }

      case 'bunker_regulate': {
        if (!isAdmin) return res(403, 'Admin only', null);
        const { warehouse, responsible, items, by: byOverride } = body;
        if (!warehouse || !items?.length) return res(400, 'חסרים נתונים לוויסות', null);
        for (const item of items) {
          const qty = Number(item.qty);
          if (!qty) continue;
          const { data: itemRow } = await sb.from('bunker_items').select('id').eq('name', item.key).single();
          if (!itemRow) continue;
          await sb.from('bunker_regulations').insert({ responsible, warehouse, item_id: itemRow.id, qty, regulated_by: byOverride || by });
          await sb.rpc('bunker_inventory_add', { p_item_id: itemRow.id, p_warehouse: warehouse, p_delta: qty });
        }
        return res(200, 'וויסות בוצע', null);
      }

      case 'bunker_get_regulations': {
        const { data, error } = await sb
          .from('bunker_regulations')
          .select('id, ts, responsible, warehouse, qty, regulated_by, bunker_items(name)')
          .order('ts', { ascending: false }).limit(200);
        if (error) return res(500, error.message, null);
        return res(200, 'OK', (data as any[]).map(r => ({
          timestamp:   fmtDate(r.ts),
          responsible: r.responsible,
          warehouse:   r.warehouse,
          item:        r.bunker_items?.name ?? '',
          qty:         r.qty,
          regulatedBy: r.regulated_by,
        })));
      }

      default:
        return res(404, `Unknown action: ${action}`, null);
    }
  } catch (err: any) {
    return res(500, `Server error: ${err.message}`, null);
  }
});
