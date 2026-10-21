// better-sqlite3 connection + migration runner.
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function ensureDir(filePath) {
  const dir = path.dirname(path.resolve(filePath));
  fs.mkdirSync(dir, { recursive: true });
}

ensureDir(config.DB_PATH);

export const db = new Database(config.DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

export function migrate() {
  const sql = fs.readFileSync(path.join(__dirname, 'migrations', '001_init.sql'), 'utf8');
  db.exec(sql);
}

// Run migrations at import time, before any module prepares statements against these tables
// (services, rate limiter, audit all prepare at module load). Idempotent (CREATE IF NOT EXISTS).
migrate();

export function nowMs() {
  return Date.now();
}
