-- ================================================================
-- 0015_bunker_functions.sql — PostgreSQL functions לפעולות בונקר
-- כל כתיבה בונקר עוברת דרך transactions אטומיות
-- ================================================================

-- ── עדכן bunker_schema — dispenses ──
create or replace function bunker_schema_update_dispense(
  p_item_id uuid, p_unit_id uuid, p_unit_name text, p_delta int
) returns void language plpgsql security definer as $$
begin
  insert into bunker_schema (item_id, unit_id, unit_name, dispenses, shatsal)
    values (p_item_id, p_unit_id, p_unit_name, greatest(0, p_delta), 0)
  on conflict (item_id, unit_id) do update
    set dispenses = greatest(0, bunker_schema.dispenses + p_delta),
        unit_name = p_unit_name;
end;
$$;

-- ── עדכן bunker_schema — shatsal ──
create or replace function bunker_schema_update_shatsal(
  p_item_id uuid, p_unit_id uuid, p_unit_name text, p_delta int
) returns void language plpgsql security definer as $$
begin
  insert into bunker_schema (item_id, unit_id, unit_name, dispenses, shatsal)
    values (p_item_id, p_unit_id, p_unit_name, 0, greatest(0, p_delta))
  on conflict (item_id, unit_id) do update
    set shatsal  = greatest(0, bunker_schema.shatsal + p_delta),
        unit_name = p_unit_name;
end;
$$;

-- ── עדכן מלאי מחסן ──
create or replace function bunker_inventory_add(
  p_item_id uuid, p_warehouse text, p_delta int
) returns void language plpgsql security definer as $$
begin
  insert into bunker_inventory (item_id, warehouse, qty)
    values (p_item_id, p_warehouse, greatest(0, p_delta))
  on conflict (item_id, warehouse) do update
    set qty = greatest(0, bunker_inventory.qty + p_delta);
end;
$$;

-- ── ניפוק — transaction אטומי ──
create or replace function bunker_dispense_tx(
  p_warehouse text,
  p_unit_id   uuid,
  p_unit_name text,
  p_by        text,
  p_items     jsonb   -- [{item_id, qty}]
) returns void language plpgsql security definer as $$
declare
  item   jsonb;
  v_id   uuid;
  v_qty  int;
begin
  for item in select * from jsonb_array_elements(p_items) loop
    v_id  := (item->>'item_id')::uuid;
    v_qty := (item->>'qty')::int;

    -- הפחת מלאי — אם אין מספיק, raise exception → rollback
    update bunker_inventory
      set qty = qty - v_qty
      where item_id = v_id
        and warehouse = p_warehouse
        and qty >= v_qty;

    if not found then
      raise exception 'מלאי לא מספיק לפריט %', v_id;
    end if;

    -- לוג ניפוק
    insert into bunker_dispenses (warehouse, unit_id, unit_name, item_id, qty, dispensed_by)
      values (p_warehouse, p_unit_id, p_unit_name, v_id, v_qty, p_by);

    -- עדכן סכימה
    perform bunker_schema_update_dispense(v_id, p_unit_id, p_unit_name, v_qty);
  end loop;
end;
$$;

-- ── זיכוי — transaction אטומי ──
create or replace function bunker_credit_tx(
  p_unit_id   uuid,
  p_unit_name text,
  p_warehouse text,
  p_by        text,
  p_items     jsonb   -- [{item_id, qty}]
) returns void language plpgsql security definer as $$
declare
  item   jsonb;
  v_id   uuid;
  v_qty  int;
begin
  for item in select * from jsonb_array_elements(p_items) loop
    v_id  := (item->>'item_id')::uuid;
    v_qty := (item->>'qty')::int;

    -- הוסף מלאי למחסן
    if p_warehouse != '' then
      perform bunker_inventory_add(v_id, p_warehouse, v_qty);
    end if;

    -- לוג זיכוי
    insert into bunker_credits (credited_by, warehouse, unit_id, unit_name, item_id, qty)
      values (p_by, p_warehouse, p_unit_id, p_unit_name, v_id, v_qty);

    -- עדכן סכימה (הפחת ניפוק נטו)
    perform bunker_schema_update_dispense(v_id, p_unit_id, p_unit_name, -v_qty);
  end loop;
end;
$$;

-- ── שצ"ל — transaction אטומי ──
create or replace function bunker_shatsal_tx(
  p_unit_id     uuid,
  p_unit_name   text,
  p_responsible text,
  p_exec_date   date,
  p_items       jsonb   -- [{item_id, qty}]
) returns void language plpgsql security definer as $$
declare
  item   jsonb;
  v_id   uuid;
  v_qty  int;
begin
  for item in select * from jsonb_array_elements(p_items) loop
    v_id  := (item->>'item_id')::uuid;
    v_qty := (item->>'qty')::int;

    insert into bunker_shatsal (exec_date, unit_id, unit_name, responsible, item_id, qty)
      values (p_exec_date, p_unit_id, p_unit_name, p_responsible, v_id, v_qty);

    perform bunker_schema_update_shatsal(v_id, p_unit_id, p_unit_name, v_qty);
  end loop;
end;
$$;

-- ── בנה סכימה מחדש מהלוגים הגולמיים ──
create or replace function bunker_rebuild_schema()
returns int language plpgsql security definer as $$
declare v_count int;
begin
  delete from bunker_schema;

  -- ניפוקים
  insert into bunker_schema (item_id, unit_id, unit_name, dispenses, shatsal)
  select item_id, unit_id, unit_name, sum(qty), 0
    from bunker_dispenses
    where unit_id is not null
    group by item_id, unit_id, unit_name
  on conflict (item_id, unit_id) do update
    set dispenses = excluded.dispenses;

  -- זיכויים — הפחת
  update bunker_schema bs
    set dispenses = greatest(0, bs.dispenses - sub.total)
    from (
      select item_id, unit_id, sum(qty) as total
        from bunker_credits
        where unit_id is not null
        group by item_id, unit_id
    ) sub
    where bs.item_id = sub.item_id and bs.unit_id = sub.unit_id;

  -- שצ"ל
  insert into bunker_schema (item_id, unit_id, unit_name, dispenses, shatsal)
  select item_id, unit_id, unit_name, 0, sum(qty)
    from bunker_shatsal
    where unit_id is not null
    group by item_id, unit_id, unit_name
  on conflict (item_id, unit_id) do update
    set shatsal = excluded.shatsal;

  select count(*) into v_count from bunker_schema;
  return v_count;
end;
$$;
