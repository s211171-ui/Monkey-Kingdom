import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom'
import axios from 'axios'
import { dict } from './i18n.js'

axios.defaults.baseURL = 'http://localhost:4000'
axios.defaults.withCredentials = true

function useLang() {
  const [lang, setLang] = useState('zh')
  return { t: dict[lang], lang, setLang }
}

function Auth() {
  const { t } = useLangCtx()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const nav = useNavigate()
  const register = async () => {
    const r = await axios.post('/api/auth/register', { username, password, email })
  }
  const verify = async () => {
    const r = await axios.post('/api/auth/verify-email', { email, code })
  }
  const login = async () => {
    const r = await axios.post('/api/auth/login', { username, email, password })
    nav('/activate')
  }
  return (
    <div>
      <div>
        <div>{t.username}</div>
        <input value={username} onChange={e=>setUsername(e.target.value)} />
      </div>
      <div>
        <div>{t.email}</div>
        <input value={email} onChange={e=>setEmail(e.target.value)} />
      </div>
      <div>
        <div>{t.password}</div>
        <input type="password" value={password} onChange={e=>setPassword(e.target.value)} />
      </div>
      <button onClick={register}>{t.register}</button>
      <div>
        <div>{t.verifyCode}</div>
        <input value={code} onChange={e=>setCode(e.target.value)} />
        <button onClick={verify}>{t.verifyEmail}</button>
      </div>
      <button onClick={login}>{t.login}</button>
    </div>
  )
}

function Activate() {
  const { t } = useLangCtx()
  const [activation_code, setCode] = useState('')
  const [activation_password, setPwd] = useState('')
  const [pocketId, setPocketId] = useState('')
  const [capacity, setCapacity] = useState(0)
  const nav = useNavigate()
  const activate = async () => {
    const r = await axios.post('/api/pockets/activate', { activation_code, activation_password })
    setPocketId(r.data.pocketId)
    setCapacity(r.data.capacity)
  }
  const unbind = async () => {
    await axios.post('/api/pockets/unbind', { pocketId })
    setPocketId('')
    setCapacity(0)
  }
  const toBind = () => nav('/bind-ip', { state: { pocketId } })
  return (
    <div>
      <div>
        <div>{t.activationCode}</div>
        <input value={activation_code} onChange={e=>setCode(e.target.value)} />
      </div>
      <div>
        <div>{t.activationPassword}</div>
        <input value={activation_password} onChange={e=>setPwd(e.target.value)} />
      </div>
      <button onClick={activate}>{t.activate}</button>
      {pocketId && <div>
        <div>{t.capacity}: {capacity}</div>
        <button onClick={toBind}>{t.bindIP}</button>
        <button onClick={unbind}>删除激活码绑定</button>
      </div>}
    </div>
  )
}

function BindIP() {
  const { t } = useLangCtx()
  const [ip, setIp] = useState('')
  const [fullName, setFullName] = useState('')
  const [hkid, setHkid] = useState('')
  const nav = useNavigate()
  const loc = useLocation()
  const pocketId = (loc.state && loc.state.pocketId) || ''
  const bind = async () => {
    const r = await axios.post('/api/bind-ip', { pocketId, ip, fullName, hkid })
    nav('/items', { state: { pocketId } })
  }
  return (
    <div>
      <div>
        <div>{t.ip}</div>
        <input value={ip} onChange={e=>setIp(e.target.value)} />
      </div>
      <div>
        <div>{t.fullName}</div>
        <input value={fullName} onChange={e=>setFullName(e.target.value)} />
      </div>
      <div>
        <div>{t.hkid}</div>
        <input value={hkid} onChange={e=>setHkid(e.target.value)} />
      </div>
      <button onClick={bind}>{t.bindIP}</button>
    </div>
  )
}

function Items() {
  const { t } = useLangCtx()
  const [items, setItems] = useState([])
  const [name, setName] = useState('')
  const [pocketId, setPocketId] = useState('')
  const [capacity, setCapacity] = useState(0)
  const loc = useLocation()
  useEffect(()=>{
    const pid = loc.state && loc.state.pocketId
    setPocketId(pid || '')
    if (pid) load(pid)
  },[])
  const load = async (pid) => {
    const r = await axios.get('/api/items', { params: { pocketId: pid } })
    setItems(r.data)
    const p = await axios.get('/api/admin/pockets')
    const me = p.data.find(x=>x.id===pid)
    setCapacity(me ? me.capacity : 0)
  }
  const add = async () => {
    await axios.post('/api/items', { pocketId, name })
    setName('')
    load(pocketId)
  }
  const retrieve = async (id) => {
    await axios.post('/api/items/retrieve', { pocketId, itemId: id })
    load(pocketId)
  }
  const nav = useNavigate()
  const toPurchase = () => nav('/purchase', { state: { pocketId } })
  return (
    <div>
      <div>{t.items}</div>
      <div>{t.capacity}: {capacity}</div>
      <div>
        <input value={name} onChange={e=>setName(e.target.value)} placeholder={t.itemName} />
        <button onClick={add}>{t.addItem}</button>
        <button onClick={toPurchase}>{t.purchaseSlots}</button>
      </div>
      <ul>
        {items.map(i=> (
          <li key={i.id}>
            <span>{i.name}</span>
            <button onClick={()=>retrieve(i.id)}>{t.retrieve}</button>
          </li>
        ))}
      </ul>
    </div>
  )
}

function Purchase() {
  const { t } = useLangCtx()
  const loc = useLocation()
  const pocketId = loc.state && loc.state.pocketId
  const buy = async (type) => {
    await axios.post('/api/pockets/purchase', { pocketId, packageType: type })
    window.location.href = '/items'
  }
  return (
    <div>
      <div>{t.purchaseSlots}</div>
      <button onClick={()=>buy('5')}>{t.package5}</button>
      <button onClick={()=>buy('13')}>{t.package13}</button>
      <button onClick={()=>buy('30')}>{t.package30}</button>
    </div>
  )
}

function Admin() {
  const { t } = useLangCtx()
  const [username, setUsername] = useState('MonkeyKingdomCEO')
  const [password, setPassword] = useState('zzx070502ZZX070502')
  const [list, setList] = useState([])
  const [users, setUsers] = useState([])
  const [pockets, setPockets] = useState([])
  const [code, setCode] = useState('')
  const [codePwd, setCodePwd] = useState('')
  const [cap, setCap] = useState(15)
  const login = async () => {
    await axios.post('/api/admin/login', { username, password })
    load()
  }
  const load = async () => {
    const r = await axios.get('/api/admin/activation-codes')
    setList(r.data)
    const u = await axios.get('/api/admin/users')
    setUsers(u.data)
    const p = await axios.get('/api/admin/pockets')
    setPockets(p.data)
  }
  const add = async () => {
    await axios.post('/api/admin/activation-codes', { activation_code: code, activation_password: codePwd, capacity: cap })
    setCode('')
    setCodePwd('')
    load()
  }
  const del = async (id) => {
    await axios.delete('/api/admin/activation-codes/'+id)
    load()
  }
  useEffect(()=>{ login() },[])
  return (
    <div>
      <div>
        <input value={code} onChange={e=>setCode(e.target.value)} placeholder={t.activationCode} />
        <input value={codePwd} onChange={e=>setCodePwd(e.target.value)} placeholder={t.activationPassword} />
        <input type="number" value={cap} onChange={e=>setCap(parseInt(e.target.value))} />
        <button onClick={add}>{t.activate}</button>
      </div>
      <ul>
        {list.map(i=> (
          <li key={i.id}>
            <span>{i.activation_code}</span>
            <button onClick={()=>del(i.id)}>删除</button>
          </li>
        ))}
      </ul>
      <div>
        <div>用户</div>
        <ul>
          {users.map(u=> (
            <li key={u.id}>{u.username} {u.email}</li>
          ))}
        </ul>
      </div>
      <div>
        <div>百宝袋</div>
        <ul>
          {pockets.map(p=> (
            <li key={p.id}>{p.activation_code} {p.username || ''}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

const LangContext = React.createContext()
function useLangCtx() { return React.useContext(LangContext) }

function Nav() {
  const { t, lang, setLang } = useLangCtx()
  const [logged, setLogged] = useState(false)
  useEffect(()=>{
    setLogged(true)
  },[])
  return (
    <div>
      <Link to="/">{t.login}</Link>
      <Link to="/activate">{t.activate}</Link>
      <Link to="/items">{t.items}</Link>
      <Link to="/admin">{t.admin}</Link>
      <div>
        <span>{t.language}:</span>
        <button onClick={()=>setLang('zh')}>{t.zh}</button>
        <button onClick={()=>setLang('en')}>{t.en}</button>
      </div>
    </div>
  )
}

export default function App() {
  const [lang, setLang] = useState('zh')
  const t = dict[lang]
  return (
    <LangContext.Provider value={{ t, lang, setLang }}>
      <BrowserRouter>
        <div style={{ fontFamily: lang==='zh' ? 'Microsoft YaHei, PingFang SC, Noto Sans CJK, sans-serif' : 'Segoe UI, Arial, Helvetica, sans-serif' }}>
          <Nav />
        </div>
        <Routes>
          <Route path="/" element={<Auth />} />
          <Route path="/activate" element={<Activate />} />
          <Route path="/bind-ip" element={<BindIP />} />
          <Route path="/items" element={<Items />} />
          <Route path="/purchase" element={<Purchase />} />
          <Route path="/admin" element={<Admin />} />
        </Routes>
      </BrowserRouter>
    </LangContext.Provider>
  )
}
