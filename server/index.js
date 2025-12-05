import express from 'express'
import session from 'express-session'
import SQLiteStoreFactory from 'connect-sqlite3'
import cors from 'cors'
import bcrypt from 'bcrypt'
import nodemailer from 'nodemailer'
import { randomUUID } from 'uuid'
import db from './db.js'

const SQLiteStore = SQLiteStoreFactory(session)
const app = express()
app.use(express.json())
app.use(cors({ origin: 'http://localhost:5173', credentials: true }))
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './server' }),
  secret: 'monkey-pocket-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}))

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'unauthorized' })
  next()
}

function requireAdmin(req, res, next) {
  if (!req.session.adminId) return res.status(401).json({ error: 'unauthorized' })
  next()
}

function validateHKID(hkid) {
  const re = /^[A-Z]{1,2}[0-9]{6}\([0-9A]\)$/
  return re.test(hkid)
}

async function makeTransport() {
  const testAccount = await nodemailer.createTestAccount()
  return nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: { user: testAccount.user, pass: testAccount.pass }
  })
}

app.post('/api/auth/register', async (req, res) => {
  const { username, password, email } = req.body
  if (!username || !password || !email) return res.status(400).json({ error: 'missing' })
  const exists = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username, email)
  if (exists) return res.status(400).json({ error: 'exists' })
  const id = randomUUID()
  const hash = await bcrypt.hash(password, 10)
  db.prepare('INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)').run(id, username, email, hash, Date.now())
  const code = String(Math.floor(100000 + Math.random() * 900000))
  const verId = randomUUID()
  const expires = Date.now() + 300000
  db.prepare('INSERT INTO email_verifications (id, user_id, email, code, expires_at) VALUES (?, ?, ?, ?, ?)').run(verId, id, email, code, expires)
  try {
    const transporter = await makeTransport()
    await transporter.sendMail({ from: 'no-reply@monkey-pocket', to: email, subject: 'Verification Code', text: code })
    const previewUrl = nodemailer.getTestMessageUrl({ messageId: 'preview', response: code })
  } catch {}
  res.json({ ok: true, userId: id })
})

app.post('/api/auth/verify-email', (req, res) => {
  const { email, code } = req.body
  const ver = db.prepare('SELECT * FROM email_verifications WHERE email=? AND code=? AND consumed=0').get(email, code)
  if (!ver) return res.status(400).json({ error: 'invalid' })
  if (Date.now() > ver.expires_at) return res.status(400).json({ error: 'expired' })
  db.prepare('UPDATE users SET verified_email=1 WHERE id=?').run(ver.user_id)
  db.prepare('UPDATE email_verifications SET consumed=1 WHERE id=?').run(ver.id)
  res.json({ ok: true })
})

app.post('/api/auth/login', async (req, res) => {
  const { username, email, password } = req.body
  let user
  if (email) user = db.prepare('SELECT * FROM users WHERE email=?').get(email)
  else user = db.prepare('SELECT * FROM users WHERE username=?').get(username)
  if (!user) return res.status(400).json({ error: 'invalid' })
  const ok = await bcrypt.compare(password, user.password_hash)
  if (!ok) return res.status(400).json({ error: 'invalid' })
  req.session.userId = user.id
  res.json({ ok: true })
})

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }))
})

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body
  const admin = db.prepare('SELECT * FROM admins WHERE username=?').get(username)
  if (!admin) return res.status(400).json({ error: 'invalid' })
  const ok = await bcrypt.compare(password, admin.password_hash)
  if (!ok) return res.status(400).json({ error: 'invalid' })
  req.session.adminId = admin.id
  res.json({ ok: true })
})

app.get('/api/admin/activation-codes', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, activation_code, activation_password, capacity, assigned_user_id, created_at, deleted_at FROM pockets').all()
  res.json(rows)
})

app.post('/api/admin/activation-codes', requireAdmin, (req, res) => {
  const { activation_code, activation_password, capacity } = req.body
  if (!activation_code || !activation_password) return res.status(400).json({ error: 'missing' })
  const id = randomUUID()
  db.prepare('INSERT INTO pockets (id, activation_code, activation_password, capacity, created_at) VALUES (?, ?, ?, ?, ?)').run(id, activation_code, activation_password, capacity || 15, Date.now())
  res.json({ ok: true, id })
})

app.delete('/api/admin/activation-codes/:id', requireAdmin, (req, res) => {
  const id = req.params.id
  db.prepare('UPDATE pockets SET deleted_at=? WHERE id=?').run(Date.now(), id)
  res.json({ ok: true })
})

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, email, verified_email, created_at FROM users').all()
  res.json(rows)
})

app.get('/api/admin/pockets', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT p.id, p.activation_code, p.capacity, p.assigned_user_id, u.username FROM pockets p LEFT JOIN users u ON u.id=p.assigned_user_id').all()
  res.json(rows)
})

app.post('/api/pockets/activate', requireUser, (req, res) => {
  const { activation_code, activation_password } = req.body
  const pocket = db.prepare('SELECT * FROM pockets WHERE activation_code=? AND activation_password=? AND deleted_at IS NULL').get(activation_code, activation_password)
  if (!pocket) return res.status(400).json({ error: 'invalid' })
  if (pocket.assigned_user_id && pocket.assigned_user_id !== req.session.userId) return res.status(400).json({ error: 'owned' })
  db.prepare('UPDATE pockets SET assigned_user_id=? WHERE id=?').run(req.session.userId, pocket.id)
  res.json({ ok: true, pocketId: pocket.id, capacity: pocket.capacity })
})

app.post('/api/pockets/unbind', requireUser, (req, res) => {
  const { pocketId } = req.body
  const pocket = db.prepare('SELECT * FROM pockets WHERE id=?').get(pocketId)
  if (!pocket || pocket.assigned_user_id !== req.session.userId) return res.status(400).json({ error: 'invalid' })
  db.prepare('UPDATE pockets SET assigned_user_id=NULL WHERE id=?').run(pocketId)
  res.json({ ok: true })
})

app.post('/api/bind-ip', requireUser, (req, res) => {
  const { pocketId, ip, fullName, hkid } = req.body
  if (!validateHKID(hkid)) return res.status(400).json({ error: '添加IP地址失败' })
  const pocket = db.prepare('SELECT * FROM pockets WHERE id=? AND assigned_user_id=?').get(pocketId, req.session.userId)
  if (!pocket) return res.status(400).json({ error: 'invalid' })
  const id = randomUUID()
  db.prepare('INSERT INTO bindings (id, user_id, pocket_id, ip_address, full_name, hkid, bound_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, req.session.userId, pocketId, ip, fullName, hkid, Date.now())
  res.json({ ok: true })
})

app.get('/api/items', requireUser, (req, res) => {
  const { pocketId } = req.query
  const items = db.prepare('SELECT * FROM items WHERE pocket_id=?').all(pocketId)
  res.json(items)
})

app.post('/api/items', requireUser, (req, res) => {
  const { pocketId, name } = req.body
  const pocket = db.prepare('SELECT * FROM pockets WHERE id=? AND assigned_user_id=?').get(pocketId, req.session.userId)
  if (!pocket) return res.status(400).json({ error: 'invalid' })
  const count = db.prepare('SELECT COUNT(*) as c FROM items WHERE pocket_id=?').get(pocketId).c
  if (count >= pocket.capacity) return res.status(400).json({ error: 'full' })
  const id = randomUUID()
  db.prepare('INSERT INTO items (id, pocket_id, name, created_at) VALUES (?, ?, ?, ?)').run(id, pocketId, name, Date.now())
  res.json({ ok: true, id })
})

app.post('/api/items/retrieve', requireUser, (req, res) => {
  const { pocketId, itemId } = req.body
  const pocket = db.prepare('SELECT * FROM pockets WHERE id=? AND assigned_user_id=?').get(pocketId, req.session.userId)
  if (!pocket) return res.status(400).json({ error: 'invalid' })
  const count = db.prepare('SELECT COUNT(*) as c FROM items WHERE pocket_id=?').get(pocketId).c
  const newCap = pocket.capacity - 1
  if (newCap < count) return res.status(400).json({ error: 'capacity' })
  db.prepare('UPDATE pockets SET capacity=? WHERE id=?').run(newCap, pocketId)
  res.json({ ok: true })
})

app.post('/api/pockets/purchase', requireUser, (req, res) => {
  const { pocketId, packageType } = req.body
  const pocket = db.prepare('SELECT * FROM pockets WHERE id=? AND assigned_user_id=?').get(pocketId, req.session.userId)
  if (!pocket) return res.status(400).json({ error: 'invalid' })
  let slots = 0
  let price = 0
  if (packageType === '5') { slots = 5; price = 100 }
  else if (packageType === '13') { slots = 13; price = 200 }
  else if (packageType === '30') { slots = 30; price = 350 }
  else return res.status(400).json({ error: 'invalid' })
  const id = randomUUID()
  db.prepare('INSERT INTO purchases (id, user_id, pocket_id, package, slots, price, purchased_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, req.session.userId, pocketId, packageType, slots, price, Date.now())
  db.prepare('UPDATE pockets SET capacity=capacity+? WHERE id=?').run(slots, pocketId)
  res.json({ ok: true })
})

app.listen(4000, () => {})
