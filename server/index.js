import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import nodemailer from 'nodemailer'
import { Pool } from 'pg'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import path from 'path'
import { fileURLToPath } from 'url'

const app = express()
app.use(express.json())
app.use(cors({ origin: true, credentials: true }))

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET || 'insecure'
const DATA_DIR = process.env.DATA_DIR || __dirname

let db
async function initDb() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL })
  const toPg = (sql) => {
    let i = 0
    return sql.replace(/\?/g, () => { i++; return `$${i}` })
  }
  db = {
    exec: async (sql) => { await pool.query(sql) },
    run: async (sql, params=[]) => { await pool.query(toPg(sql), params) },
    get: async (sql, params=[]) => { const r = await pool.query(toPg(sql), params); return r.rows[0] },
    all: async (sql, params=[]) => { const r = await pool.query(toPg(sql), params); return r.rows }
  }
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_login TEXT
    );
    
    CREATE TABLE IF NOT EXISTS activation_codes (
      code TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      user_id TEXT,
      pocket_id TEXT,
      generated_at TEXT NOT NULL,
      expires_at TEXT,
      generated_by TEXT
    );
    CREATE TABLE IF NOT EXISTS pockets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      activation_code TEXT NOT NULL,
      name TEXT NOT NULL,
      ip_address TEXT,
      full_name TEXT,
      hkid TEXT,
      storage_slots INTEGER NOT NULL,
      used_slots INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY,
      pocket_id TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT,
      description TEXT,
      added_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS purchases (
      id TEXT PRIMARY KEY,
      pocket_id TEXT NOT NULL,
      slots INTEGER NOT NULL,
      price INTEGER NOT NULL,
      plan_name TEXT,
      date TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS activities (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
  `)
}

function uid(prefix='id') { return `${prefix}_${Date.now()}_${Math.floor(Math.random()*1e6)}` }

function authMiddleware(req,res,next){
  const h = req.headers['authorization']
  if(!h) return res.status(401).json({error:'unauthorized'})
  const token = h.replace('Bearer ','')
  try { const p = jwt.verify(token, JWT_SECRET); req.user = p; next() } catch(e){ return res.status(401).json({error:'invalid_token'}) }
}

function adminAuth(req,res,next){
  const h = req.headers['authorization']
  if(!h) return res.status(401).json({error:'unauthorized'})
  const token = h.replace('Bearer ','')
  try { const p = jwt.verify(token, JWT_SECRET); if(p.role!=='admin') throw new Error('not_admin'); req.admin = p; next() } catch(e){ return res.status(401).json({error:'invalid_token'}) }
}

function transporter(){
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT||'587',10),
    secure: process.env.SMTP_SECURE==='true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  })
}

// 移除验证码发送逻辑：邮箱注册不再需要验证码

app.post('/api/auth/register', async (req,res)=>{
  const { username,email,password } = req.body
  if(!username||!email||!password) return res.status(400).json({error:'missing_fields'})
  const existing = await db.get('SELECT id FROM users WHERE email=?',[email])
  if(existing) return res.status(400).json({error:'email_exists'})
  const id = uid('user')
  const hash = bcrypt.hashSync(password,10)
  await db.run('INSERT INTO users(id,username,email,password_hash,created_at) VALUES(?,?,?,?,?)',[id,username,email,hash,new Date().toISOString()])
  res.json({ ok:true })
})

app.post('/api/auth/login', async (req,res)=>{
  const { email,password } = req.body
  const user = await db.get('SELECT * FROM users WHERE email=?',[email])
  if(!user) return res.status(400).json({error:'invalid_credentials'})
  const ok = bcrypt.compareSync(password,user.password_hash)
  if(!ok) return res.status(400).json({error:'invalid_credentials'})
  await db.run('UPDATE users SET last_login=? WHERE id=?',[new Date().toISOString(), user.id])
  const token = jwt.sign({ sub:user.id, role:'user' }, JWT_SECRET, { expiresIn: '30d' })
  res.json({ token, user:{ id:user.id, username:user.username, email:user.email } })
})

app.post('/api/admin/login', (req,res)=>{
  const { username,password } = req.body
  if(username===process.env.ADMIN_USERNAME && password===process.env.ADMIN_PASSWORD){
    const token = jwt.sign({ sub:'admin', role:'admin' }, JWT_SECRET, { expiresIn:'12h' })
    return res.json({ token })
  }
  res.status(400).json({error:'invalid_admin_credentials'})
})

app.post('/api/codes/generate', adminAuth, async (req,res)=>{
  const { count=1, passwordLength=8, complexity='medium', expiryDate } = req.body
  const genPass = () => {
    let chars='0123456789';
    if(complexity==='medium') chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    if(complexity==='strong') chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    let p=''; for(let i=0;i<passwordLength;i++){ p+=chars.charAt(Math.floor(Math.random()*chars.length)) } return p
  }
  const genCode = () => {
    const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    let s='MK-';
    for(let i=0;i<12;i++){ if(i>0&&i%4===0) s+='-'; s+=chars.charAt(Math.floor(Math.random()*chars.length)) }
    return s
  }
  const list=[]
  for(let i=0;i<count;i++){
    const code = genCode()
    const pass = genPass()
    const exists = await db.get('SELECT code FROM activation_codes WHERE code=?',[code])
    if(exists){ i--; continue }
    await db.run('INSERT INTO activation_codes(code,password,used,user_id,pocket_id,generated_at,expires_at,generated_by) VALUES(?,?,?,?,?,?,?,?)',[
      code, pass, 0, null, null, new Date().toISOString(), expiryDate||null, process.env.ADMIN_USERNAME
    ])
    list.push({ code, password: pass, status:'未使用' })
  }
  res.json({ codes:list })
})

app.get('/api/codes', adminAuth, async (req,res)=>{
  const rows = await db.all('SELECT * FROM activation_codes ORDER BY generated_at DESC')
  res.json({ codes: rows })
})

app.delete('/api/codes/:code', adminAuth, async (req,res)=>{
  await db.run('DELETE FROM activation_codes WHERE code=?',[req.params.code])
  res.json({ ok:true })
})

app.post('/api/pockets/activate', authMiddleware, async (req,res)=>{
  const { activationCode, activationPassword, pocketName } = req.body
  if(!activationCode||!activationPassword||!pocketName) return res.status(400).json({error:'missing_fields'})
  const code = await db.get('SELECT * FROM activation_codes WHERE code=?',[activationCode])
  if(!code) return res.status(400).json({error:'code_not_found'})
  if(code.used) return res.status(400).json({error:'code_used'})
  if(code.password!==activationPassword) return res.status(400).json({error:'password_incorrect'})
  if(code.expires_at && new Date(code.expires_at)<new Date()) return res.status(400).json({error:'code_expired'})
  res.json({ ok:true })
})

app.post('/api/pockets/bind-ip', authMiddleware, async (req,res)=>{
  const { activationCode, pocketName, ipAddress, fullName, hkid } = req.body
  if(!activationCode||!pocketName||!ipAddress||!fullName||!hkid) return res.status(400).json({error:'missing_fields'})
  const code = await db.get('SELECT * FROM activation_codes WHERE code=?',[activationCode])
  if(!code) return res.status(400).json({error:'code_not_found'})
  if(code.used) return res.status(400).json({error:'code_used'})
  const pocketId = uid('pocket')
  await db.run('INSERT INTO pockets(id,user_id,activation_code,name,ip_address,full_name,hkid,storage_slots,used_slots,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',[
    pocketId, req.user.sub, activationCode, pocketName, ipAddress, fullName, hkid, 15, 0, new Date().toISOString()
  ])
  await db.run('UPDATE activation_codes SET used=1,user_id=?,pocket_id=?,generated_by=generated_by WHERE code=?',[req.user.sub,pocketId,activationCode])
  await db.run('INSERT INTO activities(id,user_id,type,description,timestamp) VALUES(?,?,?,?,?)',[uid('activity'), req.user.sub, 'add_pocket', `添加了新百宝袋: ${pocketName}`, new Date().toISOString()])
  res.json({ ok:true, pocketId })
})

app.get('/api/pockets', authMiddleware, async (req,res)=>{
  const rows = await db.all('SELECT * FROM pockets WHERE user_id=? ORDER BY created_at DESC',[req.user.sub])
  res.json({ pockets: rows })
})

app.delete('/api/pockets/:id', authMiddleware, async (req,res)=>{
  const pocket = await db.get('SELECT * FROM pockets WHERE id=? AND user_id=?',[req.params.id, req.user.sub])
  if(!pocket) return res.status(404).json({error:'not_found'})
  await db.run('DELETE FROM items WHERE pocket_id=?',[pocket.id])
  await db.run('DELETE FROM pockets WHERE id=?',[pocket.id])
  res.json({ ok:true })
})

app.post('/api/items', authMiddleware, async (req,res)=>{
  const { pocketId, name, category, description } = req.body
  const pocket = await db.get('SELECT * FROM pockets WHERE id=? AND user_id=?',[pocketId, req.user.sub])
  if(!pocket) return res.status(404).json({error:'pocket_not_found'})
  if(pocket.used_slots >= pocket.storage_slots) return res.status(400).json({error:'storage_full'})
  const id = uid('item')
  await db.run('INSERT INTO items(id,pocket_id,name,category,description,added_at) VALUES(?,?,?,?,?,?)',[id,pocketId,name,category,description||'',new Date().toISOString()])
  await db.run('UPDATE pockets SET used_slots=used_slots+1 WHERE id=?',[pocketId])
  await db.run('INSERT INTO activities(id,user_id,type,description,timestamp) VALUES(?,?,?,?,?)',[uid('activity'), req.user.sub, 'add_item', `添加了新物品: ${name}`, new Date().toISOString()])
  res.json({ ok:true, id })
})

app.delete('/api/items/:id', authMiddleware, async (req,res)=>{
  const item = await db.get('SELECT * FROM items WHERE id=?',[req.params.id])
  if(!item) return res.status(404).json({error:'item_not_found'})
  const pocket = await db.get('SELECT * FROM pockets WHERE id=? AND user_id=?',[item.pocket_id, req.user.sub])
  if(!pocket) return res.status(403).json({error:'forbidden'})
  await db.run('DELETE FROM items WHERE id=?',[item.id])
  await db.run('UPDATE pockets SET used_slots=CASE WHEN used_slots>0 THEN used_slots-1 ELSE 0 END WHERE id=?',[pocket.id])
  res.json({ ok:true })
})

app.post('/api/storage/purchase', authMiddleware, async (req,res)=>{
  const { pocketId, slots, price, planName } = req.body
  const pocket = await db.get('SELECT * FROM pockets WHERE id=? AND user_id=?',[pocketId, req.user.sub])
  if(!pocket) return res.status(404).json({error:'pocket_not_found'})
  await db.run('UPDATE pockets SET storage_slots=storage_slots+? WHERE id=?',[slots, pocketId])
  await db.run('INSERT INTO purchases(id,pocket_id,slots,price,plan_name,date) VALUES(?,?,?,?,?,?)',[uid('purchase'), pocketId, slots, price, planName || '', new Date().toISOString()])
  await db.run('INSERT INTO activities(id,user_id,type,description,timestamp) VALUES(?,?,?,?,?)',[uid('activity'), req.user.sub, 'purchase', `购买了 ${slots} 个存储格`, new Date().toISOString()])
  res.json({ ok:true })
})

app.post('/api/retrieve', authMiddleware, async (req,res)=>{
  const { pocketId, itemIds } = req.body
  const pocket = await db.get('SELECT * FROM pockets WHERE id=? AND user_id=?',[pocketId, req.user.sub])
  if(!pocket) return res.status(404).json({error:'pocket_not_found'})
  const ids = Array.isArray(itemIds)?itemIds:[]
  for(const id of ids){ await db.run('DELETE FROM items WHERE id=? AND pocket_id=?',[id,pocketId]) }
  const removedCount = ids.length
  await db.run('UPDATE pockets SET used_slots=CASE WHEN used_slots-?>=0 THEN used_slots-? ELSE 0 END WHERE id=?',[removedCount,removedCount,pocketId])
  await db.run('UPDATE pockets SET storage_slots=CASE WHEN storage_slots>0 THEN storage_slots-1 ELSE 0 END WHERE id=?',[pocketId])
  await db.run('INSERT INTO activities(id,user_id,type,description,timestamp) VALUES(?,?,?,?,?)',[uid('activity'), req.user.sub, 'retrieve', `远程取物 ${removedCount} 件`, new Date().toISOString()])
  res.json({ ok:true })
})

app.get('/api/user/data', authMiddleware, async (req,res)=>{
  const user = await db.get('SELECT id,username,email,created_at,last_login FROM users WHERE id=?',[req.user.sub])
  const pockets = await db.all('SELECT * FROM pockets WHERE user_id=?',[req.user.sub])
  const activities = await db.all('SELECT * FROM activities WHERE user_id=? ORDER BY timestamp DESC LIMIT 50',[req.user.sub])
  res.json({ user, pockets, recentActivity: activities })
})

app.get('/api/admin/users', adminAuth, async (req,res)=>{
  const users = await db.all('SELECT id,username,email,created_at,last_login FROM users ORDER BY created_at DESC')
  res.json({ users })
})

app.get('/api/admin/pockets', adminAuth, async (req,res)=>{
  const rows = await db.all('SELECT p.*, u.username, u.email AS userEmail FROM pockets p JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC')
  res.json({ pockets: rows })
})

app.use('/', express.static(path.join(__dirname, '..')))

initDb().then(()=>{
  app.listen(PORT, ()=>{})
})
