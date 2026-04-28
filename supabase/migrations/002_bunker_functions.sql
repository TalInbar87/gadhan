-- ================================================================
-- bunker_functions.sql — PostgreSQL functions לפעולות אטומיות
-- transaction אמיתי — אם משהו נכשל, הכל מתבטל
-- ================================================================

-- ── עדכן bunker_schema — dispenses ──
CREATE OR REPLACE FUNCTION bunker_schema_update_dispense(
  p_item_id int, p_unit text, p_delta int
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO bunker_schema (item_id, unit, dispenses, shatsal)
    VALUES (p_item_id, p_unit, GREATEST(0, p_delta), 0)
  ON CONFLICT (item_id, unit) DO UPDATE
    SET dispenses = GREATEST(0, bunker_schema.dispenses + p_delta);
END;
$$;

-- ── עדכן bunker_schema — shatsal ──
CREATE OR REPLACE FUNCTION bunker_schema_update_shatsal(
  p_item_id int, p_unit text, p_delta int
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO bunker_schema (item_id, unit, dispenses, shatsal)
    VALUES (p_item_id, p_unit, 0, GREATEST(0, p_delta))
  ON CONFLICT (item_id, unit) DO UPDATE
    SET shatsal = GREATEST(0, bunker_schema.shatsal + p_delta);
END;
$$;

-- ── עדכן מלאי מחסן ──
CREATE OR REPLACE FUNCTION bunker_inventory_add(
  p_item_id int, p_warehouse text, p_delta int
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO bunker_inventory (item_id, warehouse, qty)
    VALUES (p_item_id, p_warehouse, GREATEST(0, p_delta))
  ON CONFLICT (item_id, warehouse) DO UPDATE
    SET qty = GREATEST(0, bunker_inventory.qty + p_delta);
END;
$$;

-- ── ניפוק — transaction מלא ──
CREATE OR REPLACE FUNCTION bunker_dispense_tx(
  p_warehouse text,
  p_unit      text,
  p_by        text,
  p_items     jsonb   -- [{item_id, qty, stock}]
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  item   jsonb;
  v_id   int;
  v_qty  int;
BEGIN
  FOR item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
    v_id  := (item->>'item_id')::int;
    v_qty := (item->>'qty')::int;

    -- הפחת מלאי
    UPDATE bunker_inventory
      SET qty = qty - v_qty
      WHERE item_id = v_id AND warehouse = p_warehouse AND qty >= v_qty;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'מלאי לא מספיק לפריט %', v_id;
    END IF;

    -- לוג ניפוק
    INSERT INTO bunker_dispenses (warehouse, unit, item_id, qty, dispensed_by)
      VALUES (p_warehouse, p_unit, v_id, v_qty, p_by);

    -- עדכן סכימה
    PERFORM bunker_schema_update_dispense(v_id, p_unit, v_qty);
  END LOOP;
END;
$$;

-- ── זיכוי — transaction מלא ──
CREATE OR REPLACE FUNCTION bunker_credit_tx(
  p_unit      text,
  p_warehouse text,
  p_by        text,
  p_items     jsonb   -- [{item_id, qty}]
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  item   jsonb;
  v_id   int;
  v_qty  int;
BEGIN
  FOR item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
    v_id  := (item->>'item_id')::int;
    v_qty := (item->>'qty')::int;

    -- הוסף מלאי למחסן
    IF p_warehouse != '' THEN
      PERFORM bunker_inventory_add(v_id, p_warehouse, v_qty);
    END IF;

    -- לוג זיכוי
    INSERT INTO bunker_credits (credited_by, warehouse, unit, item_id, qty)
      VALUES (p_by, p_warehouse, p_unit, v_id, v_qty);

    -- עדכן סכימה (הפחת ניפוק נטו)
    PERFORM bunker_schema_update_dispense(v_id, p_unit, -v_qty);
  END LOOP;
END;
$$;

-- ── שצ"ל — transaction מלא ──
CREATE OR REPLACE FUNCTION bunker_shatsal_tx(
  p_unit        text,
  p_responsible text,
  p_exec_date   date,
  p_items       jsonb   -- [{item_id, qty}]
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  item   jsonb;
  v_id   int;
  v_qty  int;
BEGIN
  FOR item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
    v_id  := (item->>'item_id')::int;
    v_qty := (item->>'qty')::int;

    INSERT INTO bunker_shatsal (exec_date, unit, responsible, item_id, qty)
      VALUES (p_exec_date, p_unit, p_responsible, v_id, v_qty);

    PERFORM bunker_schema_update_shatsal(v_id, p_unit, v_qty);
  END LOOP;
END;
$$;

-- ── בנה סכימה מחדש מהלוגים הגולמיים ──
CREATE OR REPLACE FUNCTION bunker_rebuild_schema() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM bunker_schema;

  -- ניפוקים
  INSERT INTO bunker_schema (item_id, unit, dispenses, shatsal)
  SELECT item_id, unit, SUM(qty), 0
    FROM bunker_dispenses
    GROUP BY item_id, unit
  ON CONFLICT (item_id, unit) DO UPDATE
    SET dispenses = EXCLUDED.dispenses;

  -- זיכויים — הפחת
  UPDATE bunker_schema bs
    SET dispenses = GREATEST(0, bs.dispenses - sub.total)
    FROM (
      SELECT item_id, unit, SUM(qty) AS total
        FROM bunker_credits
        GROUP BY item_id, unit
    ) sub
    WHERE bs.item_id = sub.item_id AND bs.unit = sub.unit;

  -- שצ"ל
  INSERT INTO bunker_schema (item_id, unit, dispenses, shatsal)
  SELECT item_id, unit, 0, SUM(qty)
    FROM bunker_shatsal
    GROUP BY item_id, unit
  ON CONFLICT (item_id, unit) DO UPDATE
    SET shatsal = EXCLUDED.shatsal;
END;
$$;
