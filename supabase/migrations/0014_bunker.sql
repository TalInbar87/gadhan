-- ================================================================
-- 0014_bunker.sql — מודול בונקר (תחמושת וציוד)
-- ================================================================

-- ── הוסף מסגרות בונקר שלא קיימות עדיין ──
insert into units (name) values
  ('צמה'),
  ('ניוד'),
  ('מחסר'),
  ('חפק')
on conflict (name) do nothing;

-- ================================================================
-- bunker_items — רשימת פריטים
-- ================================================================
create table if not exists bunker_items (
  id         uuid primary key default gen_random_uuid(),
  name       text not null unique,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

alter table bunker_items enable row level security;

drop policy if exists "bunker_items: authenticated read" on bunker_items;
create policy "bunker_items: authenticated read"
  on bunker_items for select
  to authenticated
  using (true);

drop policy if exists "bunker_items: admin write" on bunker_items;
create policy "bunker_items: admin write"
  on bunker_items for all
  to authenticated
  using (is_admin())
  with check (is_admin());

-- ================================================================
-- bunker_inventory — מלאי מחסנים (נפתלי / בילו)
-- ================================================================
create table if not exists bunker_inventory (
  item_id   uuid not null references bunker_items(id) on delete cascade,
  warehouse text not null,
  qty       int  not null default 0 check (qty >= 0),
  primary key (item_id, warehouse)
);

alter table bunker_inventory enable row level security;

drop policy if exists "bunker_inventory: authenticated read" on bunker_inventory;
create policy "bunker_inventory: authenticated read"
  on bunker_inventory for select
  to authenticated
  using (true);

drop policy if exists "bunker_inventory: admin write" on bunker_inventory;
create policy "bunker_inventory: admin write"
  on bunker_inventory for all
  to authenticated
  using (is_admin())
  with check (is_admin());

-- ================================================================
-- bunker_dispenses — ניפוקים (לוג)
-- ================================================================
create table if not exists bunker_dispenses (
  id           uuid primary key default gen_random_uuid(),
  ts           timestamptz not null default now(),
  warehouse    text not null,
  unit_id      uuid references units(id) on delete set null,
  unit_name    text not null,
  item_id      uuid not null references bunker_items(id),
  qty          int  not null check (qty > 0),
  dispensed_by text
);

create index if not exists bunker_dispenses_unit_item on bunker_dispenses (unit_id, item_id);
create index if not exists bunker_dispenses_ts        on bunker_dispenses (ts desc);

alter table bunker_dispenses enable row level security;

drop policy if exists "bunker_dispenses: authenticated read" on bunker_dispenses;
create policy "bunker_dispenses: authenticated read"
  on bunker_dispenses for select
  to authenticated
  using (true);

drop policy if exists "bunker_dispenses: admin write" on bunker_dispenses;
create policy "bunker_dispenses: admin write"
  on bunker_dispenses for insert
  to authenticated
  with check (is_admin());

-- ================================================================
-- bunker_credits — זיכויים (לוג)
-- ================================================================
create table if not exists bunker_credits (
  id          uuid primary key default gen_random_uuid(),
  ts          timestamptz not null default now(),
  credited_by text,
  warehouse   text,
  unit_id     uuid references units(id) on delete set null,
  unit_name   text not null,
  item_id     uuid not null references bunker_items(id),
  qty         int  not null check (qty > 0)
);

create index if not exists bunker_credits_unit_item on bunker_credits (unit_id, item_id);

alter table bunker_credits enable row level security;

drop policy if exists "bunker_credits: authenticated read" on bunker_credits;
create policy "bunker_credits: authenticated read"
  on bunker_credits for select
  to authenticated
  using (true);

drop policy if exists "bunker_credits: admin write" on bunker_credits;
create policy "bunker_credits: admin write"
  on bunker_credits for insert
  to authenticated
  with check (is_admin());

-- ================================================================
-- bunker_shatsal — שצ"ל (לוג)
-- ================================================================
create table if not exists bunker_shatsal (
  id          uuid primary key default gen_random_uuid(),
  exec_date   date not null,
  unit_id     uuid references units(id) on delete set null,
  unit_name   text not null,
  responsible text,
  item_id     uuid not null references bunker_items(id),
  qty         int  not null check (qty > 0),
  reported_at timestamptz not null default now()
);

create index if not exists bunker_shatsal_unit_item on bunker_shatsal (unit_id, item_id);

alter table bunker_shatsal enable row level security;

drop policy if exists "bunker_shatsal: authenticated read" on bunker_shatsal;
create policy "bunker_shatsal: authenticated read"
  on bunker_shatsal for select
  to authenticated
  using (true);

drop policy if exists "bunker_shatsal: admin write" on bunker_shatsal;
create policy "bunker_shatsal: admin write"
  on bunker_shatsal for insert
  to authenticated
  with check (is_admin());

-- ================================================================
-- bunker_schema — סכימה (materialized counter)
-- ================================================================
create table if not exists bunker_schema (
  item_id   uuid not null references bunker_items(id) on delete cascade,
  unit_id   uuid not null references units(id) on delete cascade,
  unit_name text not null,
  dispenses int  not null default 0,
  shatsal   int  not null default 0,
  primary key (item_id, unit_id)
);

alter table bunker_schema enable row level security;

drop policy if exists "bunker_schema: authenticated read" on bunker_schema;
create policy "bunker_schema: authenticated read"
  on bunker_schema for select
  to authenticated
  using (true);

drop policy if exists "bunker_schema: admin write" on bunker_schema;
create policy "bunker_schema: admin write"
  on bunker_schema for all
  to authenticated
  using (is_admin())
  with check (is_admin());

-- ================================================================
-- bunker_receipts — קבלות
-- ================================================================
create table if not exists bunker_receipts (
  id          uuid primary key default gen_random_uuid(),
  ts          timestamptz not null default now(),
  from_source text,
  warehouse   text not null,
  item_id     uuid not null references bunker_items(id),
  qty         int  not null check (qty > 0),
  received_by text
);

alter table bunker_receipts enable row level security;

drop policy if exists "bunker_receipts: authenticated read" on bunker_receipts;
create policy "bunker_receipts: authenticated read"
  on bunker_receipts for select to authenticated using (true);

drop policy if exists "bunker_receipts: admin write" on bunker_receipts;
create policy "bunker_receipts: admin write"
  on bunker_receipts for insert to authenticated with check (is_admin());

-- ================================================================
-- bunker_regulations — וויסותים
-- ================================================================
create table if not exists bunker_regulations (
  id           uuid primary key default gen_random_uuid(),
  ts           timestamptz not null default now(),
  responsible  text,
  warehouse    text not null,
  item_id      uuid not null references bunker_items(id),
  qty          int  not null,
  regulated_by text
);

alter table bunker_regulations enable row level security;

drop policy if exists "bunker_regulations: authenticated read" on bunker_regulations;
create policy "bunker_regulations: authenticated read"
  on bunker_regulations for select to authenticated using (true);

drop policy if exists "bunker_regulations: admin write" on bunker_regulations;
create policy "bunker_regulations: admin write"
  on bunker_regulations for insert to authenticated with check (is_admin());
