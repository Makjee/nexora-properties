const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_URL = (process.env.SITE_URL || 'http://localhost:3000').replace(/\/$/, '');
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE_ME';
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE_ME_SESSION_SECRET';
const sessions = new Map();

const db = new Database(path.join(__dirname, 'data', 'nexora.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS properties (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, country TEXT NOT NULL, region TEXT, city TEXT,
 type TEXT, purpose TEXT, price TEXT, bedrooms INTEGER, bathrooms INTEGER, size TEXT, image TEXT,
 description TEXT, owner_name TEXT, owner_email TEXT, owner_phone TEXT, status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS leads (
 id INTEGER PRIMARY KEY AUTOINCREMENT, property_id INTEGER, name TEXT NOT NULL, email TEXT, phone TEXT, message TEXT,
 status TEXT DEFAULT 'new', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS deals (
 id INTEGER PRIMARY KEY AUTOINCREMENT, property_id INTEGER, lead_name TEXT, partner_name TEXT, stage TEXT DEFAULT 'new',
 amount TEXT, compensation TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function seed() {
  if (db.prepare('SELECT COUNT(*) c FROM properties').get().c) return;
  const stmt = db.prepare(`INSERT INTO properties (title,country,region,city,type,purpose,price,bedrooms,bathrooms,size,image,description,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  stmt.run('Modern Family Villa', 'United States', 'Texas', 'Houston', 'Villa', 'Buy', '$485,000', 4, 3, '2,850 sq ft', 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1200&q=80', 'Demo listing. Replace with an authorized real property before publishing.', 'live');
  stmt.run('Luxury Apartment', 'Spain', 'Catalonia', 'Barcelona', 'Apartment', 'Rent', '€2,400/month', 2, 2, '110 m²', 'https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?auto=format&fit=crop&w=1200&q=80', 'Demo listing. Replace with an authorized real property before publishing.', 'live');
}
seed();

app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, 'public')));

function makeSession(email) {
  const raw = crypto.randomBytes(32).toString('hex');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(raw).digest('hex');
  sessions.set(raw, {email, expires: Date.now()+8*60*60*1000});
  return raw + '.' + sig;
}
function validSession(token) {
  if (!token) return false;
  const [raw,sig] = token.split('.');
  if (!raw || !sig) return false;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(raw).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const s = sessions.get(raw);
  if (!s || s.expires < Date.now()) { sessions.delete(raw); return false; }
  return true;
}
function auth(req,res,next) {
  if (!validSession(req.headers.cookie?.match(/nexora_session=([^;]+)/)?.[1])) return res.status(401).json({error:'Unauthorized'});
  next();
}
function cookieToken(req){ return req.headers.cookie?.match(/nexora_session=([^;]+)/)?.[1]; }

app.get('/health', (_,res)=>res.json({ok:true,service:'Nexora Properties'}));
app.get('/robots.txt', (_,res)=>{res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/admin\nSitemap: ${SITE_URL}/sitemap.xml\n`);});
app.get('/sitemap.xml', (_,res)=>{
  const rows = db.prepare("SELECT id,created_at FROM properties WHERE status='live' ORDER BY id DESC").all();
  const urls = [`<url><loc>${SITE_URL}/</loc></url>`].concat(rows.map(p=>`<url><loc>${SITE_URL}/property.html?id=${p.id}</loc><lastmod>${new Date(p.created_at).toISOString().slice(0,10)}</lastmod></url>`));
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.join('')}</urlset>`);
});

app.post('/api/login', async (req,res)=>{
  const {email,password} = req.body || {};
  if (email !== ADMIN_EMAIL || !password || ADMIN_PASSWORD === 'CHANGE_ME') return res.status(401).json({error:'Invalid credentials or admin password not configured'});
  const ok = await bcrypt.compare(password, await bcrypt.hash(ADMIN_PASSWORD, 10));
  if (!ok) return res.status(401).json({error:'Invalid credentials'});
  const token = makeSession(email);
  res.setHeader('Set-Cookie', `nexora_session=${token}; HttpOnly; Secure=${SITE_URL.startsWith('https://')}; SameSite=Lax; Path=/; Max-Age=28800`);
  res.json({ok:true});
});
app.post('/api/logout',(req,res)=>{ const t=cookieToken(req); if(t){const raw=t.split('.')[0];sessions.delete(raw);} res.setHeader('Set-Cookie','nexora_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); res.json({ok:true}); });
app.get('/api/session',(req,res)=>res.json({authenticated:validSession(cookieToken(req))}));

app.get('/api/properties',(req,res)=>{
  const {country,purpose,q} = req.query; let sql="SELECT * FROM properties WHERE status='live'"; const args=[];
  if(country){sql+=' AND country=?';args.push(country)} if(purpose){sql+=' AND purpose=?';args.push(purpose)}
  if(q){sql+=' AND (title LIKE ? OR city LIKE ? OR region LIKE ? OR country LIKE ?)';const x='%'+q+'%';args.push(x,x,x,x)}
  sql+=' ORDER BY id DESC'; res.json(db.prepare(sql).all(...args));
});
app.get('/api/properties/:id',(req,res)=>{const p=db.prepare("SELECT * FROM properties WHERE id=? AND status='live'").get(req.params.id); if(!p)return res.status(404).json({error:'Not found'});res.json(p)});
app.post('/api/properties',(req,res)=>{
  const p=req.body||{}; if(!p.title||!p.country||!p.owner_name||!p.owner_email)return res.status(400).json({error:'Title, country, owner name and owner email are required'});
  const r=db.prepare(`INSERT INTO properties (title,country,region,city,type,purpose,price,bedrooms,bathrooms,size,image,description,owner_name,owner_email,owner_phone,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(p.title,p.country,p.region||'',p.city||'',p.type||'',p.purpose||'Buy',p.price||'',p.bedrooms||0,p.bathrooms||0,p.size||'',p.image||'',p.description||'',p.owner_name,p.owner_email,p.owner_phone||'','pending');
  res.json({ok:true,id:r.lastInsertRowid,status:'pending'});
});
app.post('/api/leads',(req,res)=>{const p=req.body||{}; if(!p.name||!p.property_id)return res.status(400).json({error:'Name and property are required'});const r=db.prepare('INSERT INTO leads (property_id,name,email,phone,message) VALUES (?,?,?,?,?)').run(p.property_id,p.name,p.email||'',p.phone||'',p.message||'');res.json({ok:true,id:r.lastInsertRowid});});

app.get('/api/admin/properties',auth,(req,res)=>res.json(db.prepare('SELECT * FROM properties ORDER BY id DESC').all()));
app.get('/api/admin/leads',auth,(req,res)=>res.json(db.prepare('SELECT leads.*,properties.title property_title FROM leads LEFT JOIN properties ON properties.id=leads.property_id ORDER BY leads.id DESC').all()));
app.get('/api/admin/deals',auth,(req,res)=>res.json(db.prepare('SELECT * FROM deals ORDER BY id DESC').all()));
app.post('/api/admin/properties/:id/status',auth,(req,res)=>{const {status}=req.body||{};if(!['pending','live','rejected'].includes(status))return res.status(400).json({error:'Invalid status'});db.prepare('UPDATE properties SET status=? WHERE id=?').run(status,req.params.id);res.json({ok:true});});
app.post('/api/admin/leads/:id/status',auth,(req,res)=>{const {status}=req.body||{};if(!['new','contacted','qualified','sent_to_partner','viewing','offer','closed','lost'].includes(status))return res.status(400).json({error:'Invalid status'});db.prepare('UPDATE leads SET status=? WHERE id=?').run(status,req.params.id);res.json({ok:true});});
app.post('/api/admin/deals',auth,(req,res)=>{const d=req.body||{};const r=db.prepare('INSERT INTO deals (property_id,lead_name,partner_name,stage,amount,compensation,notes) VALUES (?,?,?,?,?,?,?)').run(d.property_id||null,d.lead_name||'',d.partner_name||'',d.stage||'new',d.amount||'',d.compensation||'',d.notes||'');res.json({ok:true,id:r.lastInsertRowid});});

app.get('/property.html',(req,res)=>res.sendFile(path.join(__dirname,'public','property.html')));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin-login.html')));
app.get('/admin.html',(req,res)=>res.sendFile(path.join(__dirname,'public','admin-login.html')));
app.get('/admin-dashboard.html',(req,res)=>res.sendFile(path.join(__dirname,'public','admin-dashboard.html')));
app.listen(PORT,()=>console.log(`Nexora Properties running on ${PORT}`));
