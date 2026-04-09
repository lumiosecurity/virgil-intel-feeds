-- Virgil D1 Schema — New Tables for Agent Ecosystem
-- Run via: wrangler d1 execute virgil-telemetry --remote --file schema-new-tables.sql

-- IoC Registry (A12: IoC Extractor)
CREATE TABLE IF NOT EXISTS ioc_registry (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  issue_number          INTEGER NOT NULL,
  primary_domain        TEXT,
  all_domains           TEXT,    -- JSON array
  ip_addresses          TEXT,    -- JSON array
  asns                  TEXT,    -- JSON array
  hashes                TEXT,    -- JSON array
  brand_targeted        TEXT,
  vertical              TEXT,
  phishkit_family       TEXT,
  campaign_tag          TEXT,
  registrar             TEXT,
  hosting_provider      TEXT,
  nameserver_pattern    TEXT,
  rule_outcome          TEXT,
  extraction_confidence TEXT,
  extracted_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ioc_issue   ON ioc_registry(issue_number);
CREATE INDEX IF NOT EXISTS idx_ioc_domain  ON ioc_registry(primary_domain);
CREATE INDEX IF NOT EXISTS idx_ioc_brand   ON ioc_registry(brand_targeted);
CREATE INDEX IF NOT EXISTS idx_ioc_kit     ON ioc_registry(phishkit_family);

-- Verdict Labels (A16: Corpus Labeler)
CREATE TABLE IF NOT EXISTS verdict_labels (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  verdict_id   TEXT NOT NULL UNIQUE,
  ground_truth TEXT NOT NULL,  -- TP | FP | UNKNOWN
  confidence   REAL NOT NULL,
  label_source TEXT NOT NULL,  -- phishtank | safelist | appeal | heuristic_band | human
  labeled_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vl_verdict_id   ON verdict_labels(verdict_id);
CREATE INDEX IF NOT EXISTS idx_vl_ground_truth ON verdict_labels(ground_truth);
CREATE INDEX IF NOT EXISTS idx_vl_source       ON verdict_labels(label_source);

-- Agent Run Log (A17/A26: health monitoring)
CREATE TABLE IF NOT EXISTS agent_runs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_name      TEXT NOT NULL,
  completed_at    TEXT NOT NULL,
  checks_run      INTEGER DEFAULT 0,
  anomalies_found INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ar_agent ON agent_runs(agent_name);
CREATE INDEX IF NOT EXISTS idx_ar_time  ON agent_runs(completed_at);

-- User Reports (A19: User Report Handler)
CREATE TABLE IF NOT EXISTS user_reports (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  registered_domain TEXT NOT NULL,
  url               TEXT,
  install_id        TEXT,
  outcome           TEXT NOT NULL,  -- filed | duplicate | safe_listed | already_covered
  submitted_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ur_domain ON user_reports(registered_domain);
CREATE INDEX IF NOT EXISTS idx_ur_time   ON user_reports(submitted_at);

-- Worker Errors (A26: SLA Monitor)
CREATE TABLE IF NOT EXISTS worker_errors (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint   TEXT,
  error_code INTEGER,
  error_msg  TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_we_time ON worker_errors(created_at);

-- Appeal Outcomes (A14/A16: FP tracking)
CREATE TABLE IF NOT EXISTS appeal_outcomes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain       TEXT NOT NULL,
  appeal_reason TEXT,
  outcome      TEXT NOT NULL,  -- approved | declined | escalated
  submitted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ao_domain ON appeal_outcomes(domain);

-- Safe-List Additions (A09/A14/A16: FP tracking)
CREATE TABLE IF NOT EXISTS safe_list_additions (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  domain  TEXT NOT NULL UNIQUE,
  reason  TEXT,
  added_by TEXT DEFAULT 'agent',
  added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sla_domain ON safe_list_additions(domain);
