/**
 * BADGEUSE PRO — Serveur auto-hébergé 100% RGPD
 * Sécurité renforcée : bcrypt, rate limiting, brute-force protection, logs
 */
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');

// ─────────────── DATABASE ───────────────
const initSqlJs = require('sql.js');
const DB_FILE   = path.join(__dirname, 'badgeuse.db');
const LOG_FILE  = path.join(__dirname, 'security.log');

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
      timestamp TEXT, note TEXT
    );
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT UNIQUE NOT NULL, label TEXT DEFAULT '',
      is_subnet INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime'))
    );
  `);

  // Admin par défaut (bcrypt)
  const c = db.exec('SELECT COUNT(*) FROM admins')[0];
  if (c.values[0][0] === 0) {
    const hash = bcrypt.hashSync('admin1234', 12);
    db.run('INSERT INTO admins (username,password_hash) VALUES (?,?)', ['admin', hash]);
    console.log('✅ Admin: admin / admin1234  ⚠️  Changez-le !');
  } else {
    // Migration SHA-256 → bcrypt si besoin
    const adm = qOne('SELECT * FROM admins WHERE username=?', ['admin']);
    if (adm && adm.password_hash.length === 64) {
      console.log('🔄 Migration mot de passe SHA-256 → bcrypt...');
      console.log('⚠️  Changez votre mot de passe admin dans Paramètres (l\'ancien ne fonctionnera plus).');
      const hash = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);
      db.run('UPDATE admins SET password_hash=? WHERE username=?', [hash, 'admin']);
    }
  }

  db.run(`INSERT OR IGNORE INTO allowed_ips (ip,label) VALUES ('127.0.0.1','Local'),('::1','Local IPv6')`);
  saveDb();
}

function saveDb() { fs.writeFileSync(DB_FILE, Buffer.from(db.export())); }
function qAll(sql, p=[]) { const s=db.prepare(sql); s.bind(p); const r=[]; while(s.step()) r.push(s.getAsObject()); s.free(); return r; }
function qOne(sql, p=[]) { return qAll(sql,p)[0]||null; }
function run(sql, p=[]) { db.run(sql,p); saveDb(); }

// ─────────────── LOGS SÉCURITÉ ───────────────
function secLog(level, event, ip, detail='') {
  const line = `[${now()}] [${level}] ${event} | ip=${ip} | ${detail}\n`;
  fs.appendFileSync(LOG_FILE, line);
  if (level === 'WARN' || level === 'BLOCK') console.warn(line.trim());
}

// ─────────────── RATE LIMITING ───────────────
// Structure : Map<ip, {count, firstAt, blockedUntil}>
const pinAttempts   = new Map(); // Tentatives NIP par IP
const loginAttempts = new Map(); // Tentatives login admin par IP

const PIN_LIMIT     = 10;  // max tentatives NIP par fenêtre
const PIN_WINDOW    = 60 * 1000;       // fenêtre 1 min
const PIN_BLOCK     = 5  * 60 * 1000; // blocage 5 min si dépassé

const LOGIN_LIMIT   = 5;              // max essais login admin
const LOGIN_WINDOW  = 5  * 60 * 1000; // fenêtre 5 min
const LOGIN_BLOCK   = 15 * 60 * 1000; // blocage 15 min

function checkRate(map, ip, limit, window, blockDuration) {
  const now = Date.now();
  const entry = map.get(ip) || { count: 0, firstAt: now, blockedUntil: 0 };

  // Bloqué ?
  if (entry.blockedUntil > now) {
    const remaining = Math.ceil((entry.blockedUntil - now) / 1000 / 60);
    return { blocked: true, remaining };
  }

  // Réinitialiser si fenêtre expirée
  if (now - entry.firstAt > window) {
    entry.count = 0;
    entry.firstAt = now;
    entry.blockedUntil = 0;
  }

  entry.count++;

  if (entry.count > limit) {
    entry.blockedUntil = now + blockDuration;
    map.set(ip, entry);
    return { blocked: true, remaining: Math.ceil(blockDuration / 1000 / 60) };
  }

  map.set(ip, entry);
  return { blocked: false, remaining: limit - entry.count };
}

function resetRate(map, ip) { map.delete(ip); }

// ─────────────── AUTH / SESSIONS ───────────────
function sha256(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }

const sessions = new Map();
function newSession() { const t=crypto.randomBytes(32).toString('hex'); sessions.set(t,Date.now()); return t; }
function okSession(t) {
  if(!t||!sessions.has(t)) return false;
  if(Date.now()-sessions.get(t)>28800000){sessions.delete(t);return false;}
  return true;
}
function getToken(req) { const m=(req.headers.cookie||'').match(/session=([a-f0-9]{64})/); return m?m[1]:null; }

// ─────────────── IP ───────────────
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || '';
}
function isAllowedIp(req) {
  const ip = getClientIp(req);
  const rules = qAll('SELECT ip, is_subnet FROM allowed_ips');
  return rules.some(rule => {
    if (rule.is_subnet) {
      // ex: "192.168.1" → autorise tout 192.168.1.*
      return ip.startsWith(rule.ip + '.');
    }
    return rule.ip === ip;
  });
}

// ─────────────── HELPERS ───────────────
function parseBody(req) {
  return new Promise(res=>{let b='';req.on('data',d=>b+=d);req.on('end',()=>{try{res(JSON.parse(b));}catch{res({});}});});
}
function json(res, data, code=200) {
  res.writeHead(code,{
    'Content-Type':'application/json;charset=utf-8',
    'X-Frame-Options':'DENY',
    'X-Content-Type-Options':'nosniff',
    'Strict-Transport-Security':'max-age=31536000'
  });
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
  const ip = getClientIp(req);

  // Headers sécurité sur toutes les réponses
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('X-Content-Type-Options','nosniff');

  // ── HTML ──
  if(p==='/'||p==='/index.html'){
    res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});
    res.end(fs.readFileSync(path.join(__dirname,'index.html')));
    return;
  }

  // ── MON IP ──
  if(p==='/api/my-ip'&&m==='GET') return json(res,{ip});

  // ══════════════════════════════════════
  //  POINTAGE — avec rate limiting
  // ══════════════════════════════════════
  if(p==='/api/point'&&m==='POST'){
    // 1. Vérif IP autorisée
    if(!isAllowedIp(req)){
      secLog('WARN','POINT_IP_BLOCKED',ip,'IP non autorisée');
      return json(res,{error:'Pointage non autorisé depuis ce réseau. Connectez-vous au WiFi du bureau.'},403);
    }

    // 2. Rate limiting NIP par IP
    const rate = checkRate(pinAttempts, ip, PIN_LIMIT, PIN_WINDOW, PIN_BLOCK);
    if(rate.blocked){
      secLog('BLOCK','PIN_RATE_BLOCKED',ip,`Bloqué ${rate.remaining} min`);
      return json(res,{error:`Trop de tentatives. Réessayez dans ${rate.remaining} minute(s).`},429);
    }

    const b=await parseBody(req);
    if(!b.pin||!['in','out'].includes(b.type)) return json(res,{error:'Données invalides'},400);

    const emp=qOne('SELECT * FROM employees WHERE pin_hash=? AND active=1',[sha256(b.pin)]);
    if(!emp){
      secLog('WARN','PIN_FAIL',ip,`NIP incorrect (${rate.remaining} tentatives restantes)`);
      return json(res,{error:`NIP incorrect ou compte inactif (${rate.remaining} tentatives restantes)`},401);
    }

    // NIP correct → reset compteur
    resetRate(pinAttempts, ip);

    const last=qOne('SELECT type FROM pointings WHERE employee_id=? ORDER BY id DESC LIMIT 1',[emp.id]);
    if(last&&last.type===b.type) return json(res,{error:b.type==='in'?'Déjà en arrivée':'Déjà en départ'},409);

    const ts=now();
    run('INSERT INTO pointings (employee_id,type,timestamp) VALUES (?,?,?)',[emp.id,b.type,ts]);
    secLog('INFO','POINT_OK',ip,`${emp.name} → ${b.type}`);
    return json(res,{success:true,name:emp.name,type:b.type,time:ts.slice(11,16)});
  }

  // ══════════════════════════════════════
  //  LOGIN ADMIN — avec brute-force protection
  // ══════════════════════════════════════
  if(p==='/api/admin/login'&&m==='POST'){
    const rate = checkRate(loginAttempts, ip, LOGIN_LIMIT, LOGIN_WINDOW, LOGIN_BLOCK);
    if(rate.blocked){
      secLog('BLOCK','LOGIN_BLOCKED',ip,`Brute-force bloqué ${rate.remaining} min`);
      return json(res,{error:`Trop de tentatives. Compte bloqué ${rate.remaining} minute(s).`},429);
    }

    const b=await parseBody(req);
    const adm=qOne('SELECT * FROM admins WHERE username=?',[b.username||'']);

    // Toujours comparer pour éviter timing attacks
    const validHash = adm ? adm.password_hash : '$2a$12$invalidhashfortimingreasons000000000000000000000000000';
    const ok = adm && bcrypt.compareSync(String(b.password||''), validHash);

    if(!ok){
      secLog('WARN','LOGIN_FAIL',ip,`Tentative échouée (${rate.remaining} restantes)`);
      return json(res,{error:`Identifiants incorrects (${rate.remaining} tentatives restantes)`},401);
    }

    resetRate(loginAttempts, ip);
    secLog('INFO','LOGIN_OK',ip,'Connexion admin réussie');
    const t=newSession();
    res.setHeader('Set-Cookie',`session=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);
    return json(res,{success:true});
  }

  if(p==='/api/admin/logout'&&m==='POST'){
    sessions.delete(getToken(req));
    res.setHeader('Set-Cookie','session=; Max-Age=0; Path=/');
    secLog('INFO','LOGOUT',ip,'');
    return json(res,{success:true});
  }

  // ── AUTH GUARD ──
  if(p.startsWith('/api/admin/')&&!okSession(getToken(req))){
    secLog('WARN','UNAUTH_ACCESS',ip,p);
    return json(res,{error:'Non authentifié'},401);
  }

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

  // ── IPs AUTORISÉES ──
  if(p==='/api/admin/ips'&&m==='GET') return json(res,qAll('SELECT * FROM allowed_ips ORDER BY created_at DESC'));
  if(p==='/api/admin/ips'&&m==='POST'){
    const b=await parseBody(req);
    const isSubnet = !!b.is_subnet;
    // Validation : IP normale (1.2.3.4) ou sous-réseau (1.2.3)
    const ipVal = (b.ip||'').trim();
    const validFull   = /^\d{1,3}(\.\d{1,3}){3}$/.test(ipVal);
    const validSubnet = /^\d{1,3}(\.\d{1,3}){2}$/.test(ipVal);
    if(!ipVal || (!validFull && !validSubnet))
      return json(res,{error:'IP invalide (ex: 192.168.1.10 ou sous-réseau: 192.168.1)'},400);
    if(qOne('SELECT id FROM allowed_ips WHERE ip=?',[ipVal]))
      return json(res,{error:'Cette entrée est déjà autorisée'},409);
    run('INSERT INTO allowed_ips (ip,label,is_subnet) VALUES (?,?,?)',[ipVal,(b.label||'').trim(),isSubnet?1:0]);
    secLog('INFO','IP_ADDED',ip,`Nouvelle règle: ${ipVal} (${isSubnet?'sous-réseau':'IP fixe'})`);
    return json(res,{success:true});
  }
  const ipMatch=p.match(/^\/api\/admin\/ips\/(\d+)$/);
  if(ipMatch&&m==='DELETE'){
    const id=parseInt(ipMatch[1]);
    const row=qOne('SELECT ip FROM allowed_ips WHERE id=?',[id]);
    if(row&&['127.0.0.1','::1'].includes(row.ip)) return json(res,{error:'Impossible de supprimer les IP locales'},400);
    run('DELETE FROM allowed_ips WHERE id=?',[id]);
    secLog('INFO','IP_REMOVED',ip,`IP supprimée: ${row?.ip}`);
    return json(res,{success:true});
  }

  // ── BACKUP ──
  if(p==='/api/admin/backup'&&m==='GET'){
    const data=Buffer.from(db.export());
    const d=new Date(), pad=n=>String(n).padStart(2,'0');
    const stamp=`${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}`;
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment;filename="badgeuse_backup_${stamp}.db"`,'Content-Length':data.length});
    res.end(data); return;
  }

  // ── RESTORE ──
  if(p==='/api/admin/restore'&&m==='POST'){
    const chunks=[]; await new Promise(resolve=>{req.on('data',c=>chunks.push(c));req.on('end',resolve);});
    const raw=Buffer.concat(chunks);
    const boundary=(req.headers['content-type']||'').split('boundary=')[1];
    if(!boundary) return json(res,{error:'Format invalide'},400);
    const sep=Buffer.from('\r\n\r\n'), endMark=Buffer.from(`\r\n--${boundary}--`);
    const startIdx=raw.indexOf(sep);
    if(startIdx===-1) return json(res,{error:'Fichier non trouvé'},400);
    const fileData=raw.slice(startIdx+sep.length, raw.lastIndexOf(endMark)>startIdx+sep.length?raw.lastIndexOf(endMark):undefined);
    if(fileData.length<16||fileData.slice(0,16).toString('ascii')!=='SQLite format 3\x00') return json(res,{error:'Fichier invalide'},400);
    try {
      const testDb=new sqlJs.Database(fileData);
      const tables=(testDb.exec("SELECT name FROM sqlite_master WHERE type='table'")[0]?.values||[]).map(r=>r[0]);
      if(!tables.includes('employees')||!tables.includes('pointings')) return json(res,{error:'Base incomplète'},400);
      testDb.close();
      fs.writeFileSync(DB_FILE+'.bak',Buffer.from(db.export()));
      db.close(); db=new sqlJs.Database(fileData); saveDb();
      secLog('INFO','RESTORE',ip,'Base restaurée depuis backup');
      return json(res,{success:true,message:'Base restaurée avec succès'});
    } catch(e){ return json(res,{error:'Fichier corrompu: '+e.message},400); }
  }

  // ── RESET ──
  if(p==='/api/admin/reset'&&m==='POST'){
    const b=await parseBody(req);
    const adm=qOne('SELECT * FROM admins WHERE username=?',['admin']);
    if(!b.password||!bcrypt.compareSync(String(b.password),adm.password_hash))
      return json(res,{error:'Mot de passe incorrect'},401);
    fs.writeFileSync(DB_FILE+'.before-reset.bak',Buffer.from(db.export()));
    run('DELETE FROM pointings'); run('DELETE FROM employees');
    secLog('WARN','RESET_TOTAL',ip,'Base effacée par admin');
    return json(res,{success:true});
  }

  // ── CHANGE PASSWORD (bcrypt) ──
  if(p==='/api/admin/change-password'&&m==='POST'){
    const b=await parseBody(req);
    if(!b.current||!b.newPassword||b.newPassword.length<8) return json(res,{error:'Nouveau mot de passe trop court (8 min.)'},400);
    const adm=qOne('SELECT * FROM admins WHERE username=?',['admin']);
    if(!bcrypt.compareSync(String(b.current),adm.password_hash)) return json(res,{error:'Mot de passe actuel incorrect'},401);
    const newHash=bcrypt.hashSync(String(b.newPassword),12);
    run('UPDATE admins SET password_hash=? WHERE username=?',[newHash,'admin']);
    secLog('INFO','PASSWORD_CHANGED',ip,'Mot de passe admin modifié');
    // Invalider toutes les sessions
    sessions.clear();
    return json(res,{success:true});
  }

  // ── LOGS (admin seulement) ──
  if(p==='/api/admin/logs'&&m==='GET'){
    try {
      const lines = fs.existsSync(LOG_FILE)
        ? fs.readFileSync(LOG_FILE,'utf8').split('\n').filter(Boolean).slice(-200).reverse()
        : [];
      return json(res,{lines});
    } catch { return json(res,{lines:[]}); }
  }

  json(res,{error:'Route non trouvée'},404);
});

// ─────────────── START ───────────────
initDb().then(()=>{
  const PORT=process.env.PORT||3000;
  server.listen(PORT,'0.0.0.0',()=>{
    console.log(`\n🏢  Badgeuse Pro → http://localhost:${PORT}`);
    console.log('🔒  Données  : badgeuse.db (local, zéro tiers)');
    console.log('📋  Logs     : security.log');
    console.log('🛡️   Sécurité : bcrypt + rate limiting + brute-force protection\n');
  });
});
