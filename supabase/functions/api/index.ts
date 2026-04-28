// ================================================================
// index.ts — Router ראשי
// מחליף את doPost ב-GAS. אותו פורמט request/response.
// ================================================================

import { createClient }        from 'https://esm.sh/@supabase/supabase-js@2';
import { corsOptions, createResponse } from './_shared/response.ts';
import { requireAuth }         from './_shared/auth-middleware.ts';
import {
  handleBunkerGetItems,
  handleBunkerGetInventory,
  handleBunkerSaveInventory,
  handleBunkerAddItem,
  handleBunkerGetDispenses,
  handleBunkerDispense,
  handleBunkerCredit,
  handleBunkerGetCredits,
  handleBunkerShatsalReport,
  handleBunkerGetShatsal,
  handleBunkerDispenseSummary,
  handleBunkerRebuildSchema,
  handleBunkerReceive,
  handleBunkerTransfer,
  handleBunkerRegulate,
  handleBunkerGetRegulations,
} from './bunker.ts';

// ── Supabase client (service role — full access) ──
function getSupabase() {
  return createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  );
}

// ── פעולות שדורשות auth ──
const BUNKER_ACTIONS = new Set([
  'bunker_get_items', 'bunker_get_inventory', 'bunker_save_inventory',
  'bunker_add_item', 'bunker_get_dispenses', 'bunker_dispense',
  'bunker_credit', 'bunker_get_credits', 'bunker_shatsal_report',
  'bunker_get_shatsal', 'bunker_dispense_summary', 'bunker_rebuild_schema',
  'bunker_receive', 'bunker_transfer', 'bunker_regulate', 'bunker_get_regulations',
]);

Deno.serve(async (req: Request) => {
  // CORS preflight
  if (req.method === 'OPTIONS') return corsOptions();

  if (req.method !== 'POST')
    return createResponse(405, 'Method not allowed', null);

  let data: Record<string, unknown>;
  try {
    data = await req.json();
  } catch {
    return createResponse(400, 'Invalid JSON body', null);
  }

  const action = data.action as string | undefined;
  if (!action) return createResponse(400, 'Missing action', null);

  const sb = getSupabase();

  // ── auth check ──
  const authResult = await requireAuth(data, action);
  if ('error' in authResult) return authResult.error;
  const { payload } = authResult;

  // ── ניתוב ──
  if (BUNKER_ACTIONS.has(action)) {
    switch (action) {
      case 'bunker_get_items':        return handleBunkerGetItems(sb, data, payload);
      case 'bunker_get_inventory':    return handleBunkerGetInventory(sb, data, payload);
      case 'bunker_save_inventory':   return handleBunkerSaveInventory(sb, data, payload);
      case 'bunker_add_item':         return handleBunkerAddItem(sb, data, payload);
      case 'bunker_get_dispenses':    return handleBunkerGetDispenses(sb, data, payload);
      case 'bunker_dispense':         return handleBunkerDispense(sb, data, payload);
      case 'bunker_credit':           return handleBunkerCredit(sb, data, payload);
      case 'bunker_get_credits':      return handleBunkerGetCredits(sb, data, payload);
      case 'bunker_shatsal_report':   return handleBunkerShatsalReport(sb, data, payload);
      case 'bunker_get_shatsal':      return handleBunkerGetShatsal(sb, data, payload);
      case 'bunker_dispense_summary': return handleBunkerDispenseSummary(sb, data, payload);
      case 'bunker_rebuild_schema':   return handleBunkerRebuildSchema(sb, data, payload);
      case 'bunker_receive':          return handleBunkerReceive(sb, data, payload);
      case 'bunker_transfer':         return handleBunkerTransfer(sb, data, payload);
      case 'bunker_regulate':         return handleBunkerRegulate(sb, data, payload);
      case 'bunker_get_regulations':  return handleBunkerGetRegulations(sb, data, payload);
    }
  }

  return createResponse(404, `Unknown action: ${action}`, null);
});
