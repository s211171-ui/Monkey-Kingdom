import Database from 'better-sqlite3'
import bcrypt from 'bcrypt'
import { randomUUID } from 'uuid'

const db = new Database('./server/data.db')

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT,
  verified_email INTEGER DEFAULT 0,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS pockets (
  id TEXT PRIMARY KEY,
  activation_code TEXT UNIQUE,
  activation_password TEXT,
  capacity INTEGER DEFAULT 15,
  assigned_user_id TEXT,
  created_at INTEGER,
  deleted_at INTEGER
);
CREATE TABLE IF NOT EXISTS bindings (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  pocket_id TEXT,
  ip_address TEXT,
  full_name TEXT,
  hkid TEXT,
  bound_at INTEGER
);
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  pocket_id TEXT,
  name TEXT,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS purchases (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  pocket_id TEXT,
  package TEXT,
  slots INTEGER,
  price INTEGER,
  purchased_at INTEGER
);
CREATE TABLE IF NOT EXISTS email_verifications (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  email TEXT,
  code TEXT,
  expires_at INTEGER,
  consumed INTEGER DEFAULT 0
);
`)

function seedAdmin() {
  const row = db.prepare('SELECT id FROM admins WHERE username=?').get('MonkeyKingdomCEO')
  if (!row) {
    const id = randomUUID()
    const hash = bcrypt.hashSync('zzx070502ZZX070502', 10)
    db.prepare('INSERT INTO admins (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)').run(id, 'MonkeyKingdomCEO', hash, Date.now())
  }
}

seedAdmin()

export default db
export { db }
