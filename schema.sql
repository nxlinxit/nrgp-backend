-- NRGP database schema (PostgreSQL / Neon)
-- Safe to run repeatedly, including against a database where these tables
-- already exist from an earlier version of the app: every statement uses
-- IF NOT EXISTS, and ALTER TABLE ... ADD COLUMN IF NOT EXISTS backfills any
-- columns a pre-existing table is missing (CREATE TABLE IF NOT EXISTS alone
-- does NOT add columns to a table that already exists).
--   psql "$DATABASE_URL" -f schema.sql

CREATE TABLE IF NOT EXISTS receivers (
  id         SERIAL PRIMARY KEY,
  code       VARCHAR(50)  NOT NULL UNIQUE,
  name       VARCHAR(255) NOT NULL,
  address    TEXT,
  email      VARCHAR(255) NOT NULL,
  active     BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

ALTER TABLE receivers ADD COLUMN IF NOT EXISTS address TEXT;
-- Not marked NOT NULL here: adding a NOT NULL column with no default would
-- fail on a table that already has rows. The application always supplies
-- it going forward; the CREATE TABLE above already enforces NOT NULL for
-- any brand-new database.
ALTER TABLE receivers ADD COLUMN IF NOT EXISTS email VARCHAR(255);
ALTER TABLE receivers ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE receivers ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  name          VARCHAR(255) NOT NULL,
  email         VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(20)  NOT NULL CHECK (role IN ('ADMIN', 'NX', 'RECEIVER', 'SUPPLIER')),
  phone         VARCHAR(50),
  receiver_id   INTEGER      REFERENCES receivers(id),
  active        BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS receiver_id INTEGER REFERENCES receivers(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS dispatches (
  id                     SERIAL PRIMARY KEY,
  transaction_id         VARCHAR(50)  NOT NULL UNIQUE,
  receiver_id            INTEGER      NOT NULL REFERENCES receivers(id),
  dispatch_date_time     TIMESTAMPTZ  NOT NULL,
  dispatch_submitted_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  receiving_date_time    TIMESTAMPTZ,
  receipt_submitted_at   TIMESTAMPTZ,
  vehicle_no             VARCHAR(50),
  driver_details         VARCHAR(255),
  warehouse_pic          VARCHAR(255),
  status                 VARCHAR(20)  NOT NULL DEFAULT 'pending',
  resolution_note        TEXT,
  created_by             INTEGER      REFERENCES users(id),
  created_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

ALTER TABLE dispatches ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id);
ALTER TABLE dispatches ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_dispatches_receiver_id ON dispatches (receiver_id);
CREATE INDEX IF NOT EXISTS idx_dispatches_status ON dispatches (status);

CREATE TABLE IF NOT EXISTS dispatch_lines (
  id             SERIAL PRIMARY KEY,
  dispatch_id    INTEGER      NOT NULL REFERENCES dispatches(id) ON DELETE CASCADE,
  package_code   VARCHAR(100) NOT NULL,
  dispatched_qty INTEGER      NOT NULL DEFAULT 0,
  received_qty   INTEGER,
  confirm_status VARCHAR(20),
  remark         TEXT,
  description    TEXT
);

ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS received_qty INTEGER;
ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS confirm_status VARCHAR(20);
ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS remark TEXT;
-- Free-text detail for a package line (used by the "Others" package type
-- to record what the item actually is).
ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS description TEXT;

CREATE INDEX IF NOT EXISTS idx_dispatch_lines_dispatch_id ON dispatch_lines (dispatch_id);

-- Per-year counter used to generate transaction IDs (NRGP-YYYY-####) atomically,
-- avoiding the race condition of a COUNT(*)-based approach.
CREATE TABLE IF NOT EXISTS dispatch_counters (
  year     INTEGER PRIMARY KEY,
  last_num INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------
-- Dispute workflow: Disputed -> (NX reply) -> Open ticket -> Resolved
-- ------------------------------------------------------------------
-- Databases created before schema.sql existed may have dispatches.status
-- as the enum type dispatch_status instead of VARCHAR; the workflow needs
-- its 'open' value there too.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dispatch_status') THEN
    ALTER TYPE dispatch_status ADD VALUE IF NOT EXISTS 'open';
  END IF;
END $$;

-- NX's latest answer to a dispute: 'accept_mismatch' ("Yes, we accept the
-- mismatch entry") or 'dispatched_correct' ("No, we dispatched the right
-- quantity as per the entry").
ALTER TABLE dispatches ADD COLUMN IF NOT EXISTS nx_decision VARCHAR(30);
ALTER TABLE dispatches ADD COLUMN IF NOT EXISTS resolved_by INTEGER REFERENCES users(id);
ALTER TABLE dispatches ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- Shown once in the supplier's pop-up: NX activity newer than this.
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_notified_at TIMESTAMPTZ;

-- Append-only history of everything that happened to a dispatch.
-- actor_name is a snapshot so history survives renames.
CREATE TABLE IF NOT EXISTS dispatch_events (
  id          SERIAL PRIMARY KEY,
  dispatch_id INTEGER      NOT NULL REFERENCES dispatches(id) ON DELETE CASCADE,
  user_id     INTEGER      REFERENCES users(id),
  actor_role  VARCHAR(20)  NOT NULL,
  actor_name  VARCHAR(255),
  event_type  VARCHAR(30)  NOT NULL, -- created | receipt_confirmed | mismatch_reported | nx_reply | remark | resolved
  decision    VARCHAR(30),
  remark      TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  -- TRUE for entries reconstructed from data saved before history existed;
  -- their times are approximate and they never count as unread.
  backfilled  BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_dispatch_events_dispatch_id ON dispatch_events (dispatch_id);

-- When each user last opened each dispatch (drives the unread badges).
CREATE TABLE IF NOT EXISTS dispatch_reads (
  user_id      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  dispatch_id  INTEGER     NOT NULL REFERENCES dispatches(id) ON DELETE CASCADE,
  last_read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, dispatch_id)
);

-- Backfill history for dispatches created before dispatch_events existed.
-- Each statement only touches dispatches that lack that kind of entry, so
-- re-running this file is safe.
INSERT INTO dispatch_events (dispatch_id, user_id, actor_role, actor_name, event_type, created_at, backfilled)
SELECT d.id, d.created_by, COALESCE(u.role, 'NX'), COALESCE(u.name, d.warehouse_pic), 'created', d.dispatch_submitted_at, TRUE
FROM dispatches d
LEFT JOIN users u ON u.id = d.created_by
WHERE NOT EXISTS (SELECT 1 FROM dispatch_events e WHERE e.dispatch_id = d.id AND e.event_type = 'created');

INSERT INTO dispatch_events (dispatch_id, actor_role, actor_name, event_type, remark, created_at, backfilled)
SELECT d.id, 'RECEIVER', r.name,
       CASE WHEN d.status::text IN ('disputed', 'open', 'resolved') THEN 'mismatch_reported' ELSE 'receipt_confirmed' END,
       (SELECT string_agg(
                 CASE l.package_code
                   WHEN 'BIN-001' THEN 'Bin' WHEN 'PAL-001' THEN 'Pallet' WHEN 'STP-001' THEN 'Steel pallet'
                   WHEN 'TRO-001' THEN 'Trolley' WHEN 'CB-001' THEN 'Carton box' WHEN 'OTH-001' THEN 'Others'
                   ELSE l.package_code END
                 || ': sent ' || l.dispatched_qty || ', received ' || l.received_qty
                 || COALESCE(' - ' || l.remark, ''),
                 '; ' ORDER BY l.id)
          FROM dispatch_lines l
         WHERE l.dispatch_id = d.id AND l.confirm_status = 'Disputed'),
       d.receipt_submitted_at, TRUE
FROM dispatches d
JOIN receivers r ON r.id = d.receiver_id
WHERE d.receipt_submitted_at IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM dispatch_events e WHERE e.dispatch_id = d.id AND e.event_type IN ('receipt_confirmed', 'mismatch_reported'));

INSERT INTO dispatch_events (dispatch_id, actor_role, event_type, remark, created_at, backfilled)
SELECT d.id, 'NX', 'resolved', d.resolution_note, COALESCE(d.resolved_at, d.receipt_submitted_at, d.dispatch_submitted_at), TRUE
FROM dispatches d
WHERE d.status::text = 'resolved'
  AND NOT EXISTS (SELECT 1 FROM dispatch_events e WHERE e.dispatch_id = d.id AND e.event_type = 'resolved');
