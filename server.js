/**
 * BADGEUSE PRO — Serveur auto-hébergé 100% RGPD
 * Données stockées localement, aucun tiers, NIP hashés SHA-256
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─────────────── DATABASE (sql.js = SQLite pur JS) ───────────────
const initSqlJs = require('sql.js');
const DB_FILE = path.join(__dirname, 'badgeuse.db');

let db, sqlJs;

async function initDb() {
  sqlJs = await initSqlJs();
  db = fs.existsSync(DB_FILE)
    ? new sqlJs.Database(fs.readFileSync(DB_FILE))
    : new sqlJs.Database();

  db.run(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, pin_hash TEXT NOT NULL,
      role TEXT DEFAULT 'employee', active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS pointings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('in','out')),
      timestamp TEXT,
      note TEXT
    );
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  const c = db.exec('SELECT COUNT(*) FROM admins')[0];
  if (c.values[0][0] === 0) {
    db.run('INSERT INTO admins (username,password_hash) VALUES (?,?)', ['admin', sha256('admin1234')]);
    console.log('Admin: admin / admin1234  (changez-le dans Parametres !)');
  }
  saveDb();
}

function saveDb() { fs.writeFileSync(DB_FILE, Buffer.from(db.export())); }

function qAll(sql, params=[]) {
  const s = db.prepare(sql); s.bind(params);
  const rows=[]; while(s.step()) rows.push(s.getAsObject()); s.free();
  return rows;
}
function qOne(sql, params=[]) { return qAll(sql, params)[0]||null; }
function run(sql, params=[]) { db.run(sql, params); saveDb(); }

// ─────────────── AUTH ───────────────
function sha256(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
const sessions = new Map();
function newSession() { const t=crypto.randomBytes(32).toString('hex'); sessions.set(t,Date.now()); return t; }
function okSession(t) {
  if(!t||!sessions.has(t)) return false;
  if(Date.now()-sessions.get(t)>28800000){sessions.delete(t);return false;}
  return true;
}
function getToken(req) { const m=(req.headers.cookie||'').match(/session=([a-f0-9]{64})/); return m?m[1]:null; }

// ─────────────── HELPERS ───────────────
function parseBody(req) {
  return new Promise(res=>{let b='';req.on('data',d=>b+=d);req.on('end',()=>{try{res(JSON.parse(b));}catch{res({});}});});
}
function json(res, data, code=200) {
  res.writeHead(code,{'Content-Type':'application/json;charset=utf-8','X-Frame-Options':'DENY','X-Content-Type-Options':'nosniff'});
  res.end(JSON.stringify(data));
}
function now() {
  const d=new Date(), pad=n=>String(n).padStart(2,'0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function today() { return now().slice(0,10); }

// ─────────────── SERVER ───────────────
const server = http.createServer(async (req,res)=>{
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p=url.pathname, m=req.method;

  if(p==='/'||p==='/index.html'){
    res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});
    res.end(fs.readFileSync(path.join(__dirname,'index.html')));
    return;
  }

  // ── POINTER (employé) ──
  if(p==='/api/point'&&m==='POST'){
    const b=await parseBody(req);
    if(!b.pin||!['in','out'].includes(b.type)) return json(res,{error:'Données invalides'},400);
    const emp=qOne('SELECT * FROM employees WHERE pin_hash=? AND active=1',[sha256(b.pin)]);
    if(!emp) return json(res,{error:'NIP incorrect ou compte inactif'},401);
    const last=qOne('SELECT type FROM pointings WHERE employee_id=? ORDER BY id DESC LIMIT 1',[emp.id]);
    if(last&&last.type===b.type) return json(res,{error:b.type==='in'?'Déjà en arrivée':'Déjà en départ'},409);
    const ts=now();
    run('INSERT INTO pointings (employee_id,type,timestamp) VALUES (?,?,?)',[emp.id,b.type,ts]);
    return json(res,{success:true,name:emp.name,type:b.type,time:ts.slice(11,16)});
  }

  // ── LOGIN / LOGOUT ──
  if(p==='/api/admin/login'&&m==='POST'){
    const b=await parseBody(req);
    const adm=qOne('SELECT * FROM admins WHERE username=?',[b.username]);
    if(!adm||sha256(b.password)!==adm.password_hash) return json(res,{error:'Identifiants incorrects'},401);
    const t=newSession();
    res.setHeader('Set-Cookie',`session=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
    return json(res,{success:true});
  }
  if(p==='/api/admin/logout'&&m==='POST'){
    sessions.delete(getToken(req));
    res.setHeader('Set-Cookie','session=; Max-Age=0; Path=/');
    return json(res,{success:true});
  }

  // ── AUTH GUARD ──
  if(p.startsWith('/api/admin/')&&!okSession(getToken(req))) return json(res,{error:'Non authentifié'},401);

  // ── EMPLOYEES ──
  if(p==='/api/admin/employees'&&m==='GET') return json(res,qAll('SELECT id,name,role,active,created_at FROM employees ORDER BY name'));
  if(p==='/api/admin/employees'&&m==='POST'){
    const b=await parseBody(req);
    if(!b.name||!b.pin||String(b.pin).length<4) return json(res,{error:'Nom et NIP (4+ chiffres) requis'},400);
    if(qOne('SELECT id FROM employees WHERE pin_hash=?',[sha256(b.pin)])) return json(res,{error:'NIP déjà utilisé'},409);
    run('INSERT INTO employees (name,pin_hash,role) VALUES (?,?,?)',[b.name.trim(),sha256(String(b.pin)),b.role||'employee']);
    return json(res,{success:true});
  }
  const em=p.match(/^\/api\/admin\/employees\/(\d+)$/);
  if(em){
    const id=parseInt(em[1]);
    if(m==='PATCH'){
      const b=await parseBody(req);
      if(b.active!==undefined) run('UPDATE employees SET active=? WHERE id=?',[b.active?1:0,id]);
      if(b.name) run('UPDATE employees SET name=? WHERE id=?',[b.name.trim(),id]);
      if(b.pin){
        if(qOne('SELECT id FROM employees WHERE pin_hash=? AND id!=?',[sha256(String(b.pin)),id])) return json(res,{error:'NIP déjà utilisé'},409);
        run('UPDATE employees SET pin_hash=? WHERE id=?',[sha256(String(b.pin)),id]);
      }
      return json(res,{success:true});
    }
    if(m==='DELETE'){run('DELETE FROM pointings WHERE employee_id=?',[id]);run('DELETE FROM employees WHERE id=?',[id]);return json(res,{success:true});}
  }

  // ── POINTINGS ──
  if(p==='/api/admin/pointings'&&m==='GET'){
    const from=url.searchParams.get('from')||today(), to=url.searchParams.get('to')||from;
    const eid=url.searchParams.get('employee_id');
    let sql=`SELECT p.id,e.name,p.type,p.timestamp,p.employee_id FROM pointings p JOIN employees e ON e.id=p.employee_id WHERE substr(p.timestamp,1,10) BETWEEN ? AND ?`;
    const params=[from,to];
    if(eid){sql+=' AND p.employee_id=?';params.push(parseInt(eid));}
    return json(res,qAll(sql+' ORDER BY p.timestamp DESC',params));
  }

  // ── SUMMARY ──
  if(p==='/api/admin/summary'&&m==='GET'){
    const from=url.searchParams.get('from')||today(), to=url.searchParams.get('to')||from;
    return json(res,qAll(`
      SELECT e.id,e.name,
        SUM(CASE WHEN p.type='in'  THEN 1 ELSE 0 END) as ins,
        SUM(CASE WHEN p.type='out' THEN 1 ELSE 0 END) as outs,
        MIN(CASE WHEN p.type='in'  THEN p.timestamp END) as first_in,
        MAX(CASE WHEN p.type='out' THEN p.timestamp END) as last_out
      FROM employees e
      LEFT JOIN pointings p ON p.employee_id=e.id AND substr(p.timestamp,1,10) BETWEEN ? AND ?
      WHERE e.active=1 GROUP BY e.id ORDER BY e.name
    `,[from,to]));
  }

  // ── EXPORT CSV ──
  if(p==='/api/admin/export/csv'&&m==='GET'){
    const from=url.searchParams.get('from')||today(), to=url.searchParams.get('to')||from;
    const rows=qAll(`SELECT e.name as nom,p.type,p.timestamp FROM pointings p JOIN employees e ON e.id=p.employee_id WHERE substr(p.timestamp,1,10) BETWEEN ? AND ? ORDER BY p.timestamp`,[from,to]);
    const csv=['Employé,Type,Date,Heure'].concat(rows.map(r=>{
      const[d,t]=(r.timestamp||'').split(' ');
      return `"${r.nom}","${r.type==='in'?'Arrivée':'Départ'}","${d||''}","${t?.slice(0,5)||''}"`;
    })).join('\n');
    res.writeHead(200,{'Content-Type':'text/csv;charset=utf-8','Content-Disposition':`attachment;filename="pointages_${from}_${to}.csv"`});
    res.end('\uFEFF'+csv); return;
  }

  // ── CHANGE PASSWORD ──
  if(p==='/api/admin/change-password'&&m==='POST'){
    const b=await parseBody(req);
    if(!b.current||!b.newPassword||b.newPassword.length<8) return json(res,{error:'Nouveau mot de passe trop court (8 min.)'},400);
    const adm=qOne('SELECT * FROM admins WHERE username=?',['admin']);
    if(sha256(b.current)!==adm.password_hash) return json(res,{error:'Mot de passe actuel incorrect'},401);
    run('UPDATE admins SET password_hash=? WHERE username=?',[sha256(b.newPassword),'admin']);
    return json(res,{success:true});
  }

  json(res,{error:'Route non trouvée'},404);
});

// ─────────────── START ───────────────
initDb().then(()=>{
  const PORT=process.env.PORT||3000;
  server.listen(PORT,'0.0.0.0',()=>{
    console.log(`\n Badgeuse Pro -> http://localhost:${PORT}`);
    console.log(' Donnees : badgeuse.db (local, 0 tiers)');
    console.log(' Admin   : onglet Administration > admin / admin1234\n');
  });
});
