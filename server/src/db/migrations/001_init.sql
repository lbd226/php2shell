-- PHP2Shell ownership-scan schema.

CREATE TABLE IF NOT EXISTS verification (
  id                TEXT PRIMARY KEY,                 -- 128-bit random capability id (base64url)
  domain            TEXT NOT NULL,                    -- normalized lowercase punycode, no port/trailing dot
  method            TEXT NOT NULL CHECK(method IN ('email','dns')),
  email_address     TEXT,                             -- exact recipient (host == domain)
  selector          TEXT UNIQUE,                      -- public lookup key for the email token
  verifier_hash     BLOB,                             -- SHA-256(verifier); nulled on consume (single-use)
  dns_record_name   TEXT,                             -- _php2shell-verify.<domain>
  dns_token         TEXT,                             -- random challenge value (public in DNS)
  claim_secret_hash BLOB NOT NULL,                    -- SHA-256(claimSecret)
  status            TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','verified','consumed','expired','failed')),
  attempts          INTEGER NOT NULL DEFAULT 0,
  client_ip_hash    TEXT,                             -- HMAC(ip); no raw IPs at rest
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  verified_at       INTEGER,
  last_sent_at      INTEGER,
  send_count        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_verification_selector      ON verification(selector);
CREATE INDEX IF NOT EXISTS idx_verification_domain_status ON verification(domain, status);
CREATE INDEX IF NOT EXISTS idx_verification_expires       ON verification(expires_at);

CREATE TABLE IF NOT EXISTS scan_grant (
  id              TEXT PRIMARY KEY,
  verification_id TEXT NOT NULL UNIQUE REFERENCES verification(id) ON DELETE CASCADE,
  domain          TEXT NOT NULL,                      -- the ONLY host a scan may contact
  selector        TEXT UNIQUE NOT NULL,               -- public bearer lookup
  token_hash      BLOB NOT NULL,                      -- SHA-256(grant verifier)
  status          TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','exhausted','expired','revoked')),
  max_uses        INTEGER NOT NULL DEFAULT 3,
  used_count      INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grant_selector ON scan_grant(selector);

CREATE TABLE IF NOT EXISTS scan_result (
  id               TEXT PRIMARY KEY,
  grant_id         TEXT REFERENCES scan_grant(id) ON DELETE SET NULL,
  verification_id  TEXT,
  domain           TEXT,
  resolved_ip      TEXT,                              -- the pinned public IP actually contacted
  final_url        TEXT,
  http_status      INTEGER,
  server_header    TEXT,
  x_powered_by     TEXT,
  inferred_version TEXT,
  branch           TEXT,
  verdict          TEXT CHECK(verdict IN ('vulnerable','patched','eol','unknown_hidden','unknown_branch','error')),
  patched_version  TEXT,
  is_inference     INTEGER NOT NULL DEFAULT 1,        -- always 1: inference, never proof
  detail_json      TEXT,
  error_code       TEXT,
  duration_ms      INTEGER,
  created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_result_grant ON scan_result(grant_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id              TEXT PRIMARY KEY,
  ts              INTEGER NOT NULL,
  event           TEXT NOT NULL,
  verification_id TEXT,
  domain          TEXT,
  ip_hash         TEXT,
  outcome         TEXT,
  meta_json       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS rate_bucket (
  key          TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
