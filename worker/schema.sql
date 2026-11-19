PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY, full_name TEXT NOT NULL, matric TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE, level TEXT NOT NULL,
  password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('president','election_chairman')),
  password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_type TEXT NOT NULL CHECK(user_type IN ('student','admin')),
  expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS elections (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'not_started'
    CHECK(status IN ('not_started','ongoing','completed')),
  results_mode TEXT NOT NULL DEFAULT 'after_publish'
    CHECK(results_mode IN ('live','after_publish')),
  results_published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS positions (
  id TEXT PRIMARY KEY, election_id TEXT NOT NULL REFERENCES elections(id),
  title TEXT NOT NULL, display_order INTEGER NOT NULL DEFAULT 0, UNIQUE(election_id,title)
);
CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY, election_id TEXT NOT NULL REFERENCES elections(id),
  position_id TEXT NOT NULL REFERENCES positions(id), full_name TEXT NOT NULL,
  political_name TEXT NOT NULL, department TEXT DEFAULT '', photo_key TEXT DEFAULT '',
  manifesto TEXT DEFAULT '', manifesto_key TEXT DEFAULT '',
  approval_status TEXT NOT NULL DEFAULT 'approved' CHECK(approval_status IN ('pending','approved')),
  registered_by TEXT NOT NULL, updated_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS candidates_position_idx ON candidates(position_id,approval_status);
-- Identity-to-position receipt is separate from the ballot table.
-- Ballot records intentionally contain no student ID or matric number.
CREATE TABLE IF NOT EXISTS vote_receipts (
  id TEXT PRIMARY KEY, election_id TEXT NOT NULL, voter_id TEXT NOT NULL,
  position_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(election_id,voter_id,position_id)
);
CREATE TABLE IF NOT EXISTS ballots (
  id TEXT PRIMARY KEY, election_id TEXT NOT NULL, position_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ballots_position_idx ON ballots(position_id,candidate_id);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY, admin_id TEXT NOT NULL, action TEXT NOT NULL,
  target_id TEXT DEFAULT '', details TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO settings(key,value) VALUES('active_election_id','');
