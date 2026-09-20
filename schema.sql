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
  remark         TEXT
);

ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS received_qty INTEGER;
ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS confirm_status VARCHAR(20);
ALTER TABLE dispatch_lines ADD COLUMN IF NOT EXISTS remark TEXT;

CREATE INDEX IF NOT EXISTS idx_dispatch_lines_dispatch_id ON dispatch_lines (dispatch_id);

-- Per-year counter used to generate transaction IDs (NRGP-YYYY-####) atomically,
-- avoiding the race condition of a COUNT(*)-based approach.
CREATE TABLE IF NOT EXISTS dispatch_counters (
  year     INTEGER PRIMARY KEY,
  last_num INTEGER NOT NULL DEFAULT 0
);
