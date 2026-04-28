-- ================================================================
-- gadhan — Initial Schema Migration
-- ================================================================

-- ── הרחבות ──
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ================================================================
-- משתמשים
-- ================================================================
CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username        text UNIQUE NOT NULL,
  password_hash   text NOT NULL,
  role            text NOT NULL CHECK (role IN ('admin','sergeant','himush')),
  personal_number text,
  full_name       text,
  email           text,
  created_at      timestamptz DEFAULT now(),
  last_login      timestamptz
);

-- ================================================================
-- לוג ביקורת
-- ================================================================
CREATE TABLE audit_log (
  id              bigserial PRIMARY KEY,
  ts              timestamptz DEFAULT now(),
  username        text,
  action          text,
  resource        text,
  personal_number text,
  details         jsonb,
  ip_address      text,
  user_agent      text
);
CREATE INDEX ON audit_log (ts DESC);

-- ================================================================
-- בונקר
-- ================================================================

CREATE TABLE bunker_items (
  id   serial PRIMARY KEY,
  name text UNIQUE NOT NULL
);

CREATE TABLE bunker_inventory (
  item_id   int NOT NULL REFERENCES bunker_items(id) ON DELETE CASCADE,
  warehouse text NOT NULL,   -- 'נפתלי' | 'בילו'
  qty       int NOT NULL DEFAULT 0 CHECK (qty >= 0),
  PRIMARY KEY (item_id, warehouse)
);

CREATE TABLE bunker_dispenses (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts           timestamptz DEFAULT now(),
  warehouse    text NOT NULL,
  unit         text NOT NULL,
  item_id      int NOT NULL REFERENCES bunker_items(id),
  qty          int NOT NULL CHECK (qty > 0),
  dispensed_by text
);
CREATE INDEX ON bunker_dispenses (unit, item_id);
CREATE INDEX ON bunker_dispenses (ts DESC);

CREATE TABLE bunker_credits (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts        timestamptz DEFAULT now(),
  credited_by text,
  warehouse text,
  unit      text NOT NULL,
  item_id   int NOT NULL REFERENCES bunker_items(id),
  qty       int NOT NULL CHECK (qty > 0)
);
CREATE INDEX ON bunker_credits (unit, item_id);

CREATE TABLE bunker_shatsal (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  exec_date   date NOT NULL,
  unit        text NOT NULL,
  responsible text,
  item_id     int NOT NULL REFERENCES bunker_items(id),
  qty         int NOT NULL CHECK (qty > 0),
  reported_at timestamptz DEFAULT now()
);
CREATE INDEX ON bunker_shatsal (unit, item_id);

-- סכימה: materialized counter (ניפוק נטו + שצ"ל לכל פריט×מסגרת)
CREATE TABLE bunker_schema (
  item_id   int NOT NULL REFERENCES bunker_items(id) ON DELETE CASCADE,
  unit      text NOT NULL,
  dispenses int NOT NULL DEFAULT 0,
  shatsal   int NOT NULL DEFAULT 0,
  PRIMARY KEY (item_id, unit)
);

CREATE TABLE bunker_receipts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts          timestamptz DEFAULT now(),
  from_source text,
  warehouse   text NOT NULL,
  item_id     int NOT NULL REFERENCES bunker_items(id),
  qty         int NOT NULL CHECK (qty > 0),
  received_by text
);

CREATE TABLE bunker_regulations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts           timestamptz DEFAULT now(),
  responsible  text,
  warehouse    text NOT NULL,
  item_id      int NOT NULL REFERENCES bunker_items(id),
  qty          int NOT NULL,
  regulated_by text
);

-- ================================================================
-- נשקים
-- ================================================================
CREATE TABLE weapons_records (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts              timestamptz DEFAULT now(),
  personal_number text NOT NULL,
  full_name       text,
  phone           text,
  email           text,
  unit            text,
  team            text,
  items           jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON weapons_records (personal_number);

CREATE TABLE weapons_inspections (
  personal_number text PRIMARY KEY,
  last_optical    date,
  last_weapons    date,
  updated_at      timestamptz DEFAULT now()
);

-- ================================================================
-- קשר
-- ================================================================
CREATE TABLE radio_records (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts              timestamptz DEFAULT now(),
  personal_number text NOT NULL,
  full_name       text,
  phone           text,
  email           text,
  unit            text,
  items           jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON radio_records (personal_number);

-- ================================================================
-- אפסנאות
-- ================================================================
CREATE TABLE apsnaut_items (
  id              serial PRIMARY KEY,
  name            text UNIQUE NOT NULL,
  unit_of_measure text,
  important       boolean DEFAULT false
);

CREATE TABLE apsnaut_checkouts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts              timestamptz DEFAULT now(),
  full_name       text,
  personal_number text,
  unit            text,
  issued_by       text,
  items           jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON apsnaut_checkouts (personal_number);

-- ================================================================
-- מחסנאות
-- ================================================================
CREATE TABLE armory_counts (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ts           timestamptz DEFAULT now(),
  performed_by text,
  items        jsonb NOT NULL DEFAULT '{}'
);
