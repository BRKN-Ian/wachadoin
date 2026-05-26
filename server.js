const express = require('express');
const path    = require('path');
const fs      = require('fs');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;

// Catch all errors early
process.on('uncaughtException',  err => console.error('[uncaughtException]',  err));
process.on('unhandledRejection', err => console.error('[unhandledRejection]', err));

// ── Storage ────────────────────────────────────────────────────
// Try DATA_DIR env var first (Render persistent disk), fall back to local .data
let DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '.data');
try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const testFile = path.join(DATA_DIR, '.write-test');
  fs.writeFileSync(testFile, 'ok');
  fs.unlinkSync(testFile);
  console.log('[storage] Using DATA_DIR:', DATA_DIR);
} catch (e) {
  console.error('[storage] DATA_DIR not writable, falling back to .data:', e.message);
  DATA_DIR = path.join(__dirname, '.data');
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE       = path.join(DATA_DIR, 'timetrack.json');
const SHOTS_DIR     = path.join(DATA_DIR, 'screenshots');
const ACTIVITY_FILE = path.join(DATA_DIR, 'activity.json');

if (!fs.existsSync(SHOTS_DIR)) fs.mkdirSync(SHOTS_DIR, { recursive: true });

// ── Activity DB helpers ────────────────────────────────────────
function loadActivity() {
  if (!fs.existsSync(ACTIVITY_FILE)) return { heartbeats: [], apps: [], screenshots: [] };
  try { return JSON.parse(fs.readFileSync(ACTIVITY_FILE, 'utf8')); }
  catch { return { heartbeats: [], apps: [], screenshots: [] }; }
}

function saveActivity(data) {
  // Prune entries older than 7 days to keep file manageable
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  data.heartbeats  = (data.heartbeats  || []).filter(r => new Date(r.ts) > cutoff);
  data.apps        = (data.apps        || []).filter(r => new Date(r.ts) > cutoff);
  data.screenshots = (data.screenshots || []).filter(r => new Date(r.ts) > cutoff);
  fs.writeFileSync(ACTIVITY_FILE, JSON.stringify(data));
}

const JWT_SECRET = process.env.JWT_SECRET || 'timetrack-secret-please-change-me';

// ── DB helpers ─────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const blank = { users: [], entries: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(blank, null, 2));
    return blank;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], entries: [] }; }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ── Seed demo accounts on first run ───────────────────────────
async function maybeSeed() {
  const db = loadDB();
  if (db.users.length > 0) return;

  const manHash = await bcrypt.hash('admin123', 10);
  const empHash = await bcrypt.hash('employee123', 10);
  const today   = new Date().toISOString().split('T')[0];

  db.users = [
    { id:'u1', name:'Admin Manager',  email:'admin@timetrack.com',  passwordHash:manHash, role:'manager',  createdAt:new Date().toISOString() },
    { id:'u2', name:'Sarah Johnson',  email:'sarah@timetrack.com',  passwordHash:empHash, role:'employee', createdAt:new Date().toISOString() },
    { id:'u3', name:'Marcus Chen',    email:'marcus@timetrack.com', passwordHash:empHash, role:'employee', createdAt:new Date().toISOString() },
    { id:'u4', name:'Tom Walker',     email:'tom@timetrack.com',    passwordHash:empHash, role:'employee', createdAt:new Date().toISOString() },
  ];
  db.entries = [
    { id:'e1', userId:'u2', userName:'Sarah Johnson', project:'Acme Corp – Website Redesign', task:'Frontend Development', startTime:`${today}T08:02:00.000Z`, endTime:`${today}T10:45:00.000Z`, durationMs:9780000,  activityScore:91, screenshotCount:18, status:'completed' },
    { id:'e2', userId:'u3', userName:'Marcus Chen',   project:'Beta Ltd – Mobile App',        task:'iOS Development',      startTime:`${today}T08:15:00.000Z`, endTime:`${today}T12:00:00.000Z`, durationMs:13500000, activityScore:95, screenshotCount:22, status:'completed' },
    { id:'e3', userId:'u4', userName:'Tom Walker',    project:'Gamma Inc – Data Migration',   task:'ETL Development',      startTime:`${today}T07:55:00.000Z`, endTime:`${today}T11:30:00.000Z`, durationMs:12900000, activityScore:82, screenshotCount:20, status:'completed' },
    { id:'e4', userId:'u2', userName:'Sarah Johnson', project:'Acme Corp – Website Redesign', task:'Client Calls',         startTime:`${today}T11:00:00.000Z`, endTime:`${today}T11:45:00.000Z`, durationMs:2700000,  activityScore:65, screenshotCount:5,  status:'completed' },
    { id:'e5', userId:'u3', userName:'Marcus Chen',   project:'Beta Ltd – Mobile App',        task:'API Integration',      startTime:`${today}T12:30:00.000Z`, endTime:`${today}T14:45:00.000Z`, durationMs:8100000,  activityScore:88, screenshotCount:15, status:'completed' },
    { id:'e6', userId:'u4', userName:'Tom Walker',    project:'Gamma Inc – Data Migration',   task:'Testing',              startTime:`${today}T12:00:00.000Z`, endTime:`${today}T15:00:00.000Z`, durationMs:10800000, activityScore:74, screenshotCount:17, status:'completed' },
  ];
  saveDB(db);
  console.log('[Wachadoin] Demo data ready. Login: admin@timetrack.com / admin123');
}
maybeSeed();

// ── Middleware ─────────────────────────────────────────────────
app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}
function managerOnly(req, res, next) {
  if (req.user?.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
  next();
}

// ── Auth ───────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email already registered' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: Date.now().toString(), name: name.trim(), email: email.toLowerCase().trim(),
                 passwordHash, role: role === 'manager' ? 'manager' : 'employee', createdAt: new Date().toISOString() };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign({ id:user.id, name:user.name, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: { id:user.id, name:user.name, email:user.email, role:user.role } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db   = loadDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id:user.id, name:user.name, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: { id:user.id, name:user.name, email:user.email, role:user.role } });
});

// ── Users ──────────────────────────────────────────────────────
app.get('/api/users', auth, managerOnly, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({ id:u.id, name:u.name, email:u.email, role:u.role })));
});

// ── Entries ────────────────────────────────────────────────────
app.post('/api/entries', auth, (req, res) => {
  const { project, task } = req.body;
  if (!project || !task) return res.status(400).json({ error: 'Project and task required' });
  const db = loadDB();
  db.entries.filter(e => e.userId === req.user.id && e.status === 'running').forEach(e => {
    e.endTime = new Date().toISOString();
    e.durationMs = new Date(e.endTime) - new Date(e.startTime);
    e.status = 'completed';
  });
  const entry = { id:Date.now().toString(), userId:req.user.id, userName:req.user.name,
    project, task, startTime:new Date().toISOString(), endTime:null,
    durationMs:null, activityScore:null, screenshotCount:0, status:'running' };
  db.entries.push(entry);
  saveDB(db);
  res.json(entry);
});

app.put('/api/entries/:id', auth, (req, res) => {
  const { activityScore, activeMs, idleMs } = req.body;
  const db = loadDB();
  const e  = db.entries.find(e => e.id === req.params.id && e.userId === req.user.id);
  if (!e) return res.status(404).json({ error: 'Entry not found' });
  e.endTime       = new Date().toISOString();
  e.durationMs    = new Date(e.endTime) - new Date(e.startTime);
  e.activityScore = Math.round(activityScore ?? 0);
  e.activeMs      = activeMs ?? null;
  e.idleMs        = idleMs   ?? null;
  e.status        = 'completed';
  saveDB(db);
  res.json(e);
});

app.delete('/api/entries/:id', auth, (req, res) => {
  const db  = loadDB();
  const idx = db.entries.findIndex(e => e.id === req.params.id && e.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.entries.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/entries', auth, (req, res) => {
  const db   = loadDB();
  const date = req.query.date || new Date().toISOString().split('T')[0];
  let list   = db.entries.filter(e => e.startTime.startsWith(date));
  if (req.user.role !== 'manager') list = list.filter(e => e.userId === req.user.id);
  res.json(list.sort((a,b) => new Date(b.startTime) - new Date(a.startTime)));
});

app.get('/api/entries/all', auth, managerOnly, (req, res) => {
  const db = loadDB();
  res.json(db.entries.sort((a,b) => new Date(b.startTime) - new Date(a.startTime)));
});

// ── Screenshots ────────────────────────────────────────────────
app.post('/api/screenshots', auth, (req, res) => {
  const { entryId, base64, screenName, screenIndex } = req.body;
  if (!base64) return res.status(400).json({ error: 'No image data' });
  const safeScreen = `screen${screenIndex || 1}`;
  const filename = `${req.user.id}_${Date.now()}_${safeScreen}.jpg`;
  try {
    fs.writeFileSync(path.join(SHOTS_DIR, filename), Buffer.from(base64, 'base64'));
    if (entryId) {
      const db = loadDB();
      const e  = db.entries.find(e => e.id === entryId);
      if (e) { e.screenshotCount = (e.screenshotCount||0) + 1; saveDB(db); }
    }
    res.json({ filename });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save screenshot' });
  }
});

app.get('/api/screenshots', auth, (req, res) => {
  try {
    const db    = loadDB();
    const files = fs.readdirSync(SHOTS_DIR).filter(f => f.endsWith('.jpg'))
      .map(f => {
        const parts     = f.replace('.jpg','').split('_');
        const userId    = parts[0];
        const screenNum = parseInt((parts[2]||'screen1').replace('screen','')) || 1;
        return { filename:f, userId, ts: fs.statSync(path.join(SHOTS_DIR,f)).mtimeMs,
                 userName: db.users.find(u=>u.id===userId)?.name || 'Unknown',
                 screenNum, screenLabel: `Screen ${screenNum}` };
      })
      .filter(f => req.user.role === 'manager' || f.userId === req.user.id)
      .sort((a,b) => b.ts - a.ts).slice(0, 50);
    res.json(files);
  } catch { res.json([]); }
});

app.get('/api/screenshots/:filename', auth, (req, res) => {
  const fp = path.join(SHOTS_DIR, path.basename(req.params.filename));
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.sendFile(fp);
});

// ── Activity API ────────────────────────────────────────────────────────────

// POST /api/activity — receive heartbeat, app event, or screenshot from agent
app.post('/api/activity', auth, (req, res) => {
  const { type, ts } = req.body;
  if (!type) return res.status(400).json({ error: 'type required' });

  const activity = loadActivity();
  const userId   = req.user.id;
  const userName = req.user.name;
  const now      = ts || new Date().toISOString();

  if (type === 'heartbeat') {
    const { activityScore, idleSecs, isIdle } = req.body;
    activity.heartbeats.push({ userId, userName, activityScore, idleSecs, isIdle, ts: now });
    saveActivity(activity);
    return res.json({ ok: true });
  }

  if (type === 'app') {
    const { appName, title } = req.body;
    activity.apps.push({ userId, userName, appName, title, ts: now });
    saveActivity(activity);
    return res.json({ ok: true });
  }

  if (type === 'screenshot') {
    const { base64, screenIndex, screenName } = req.body;
    if (!base64) return res.status(400).json({ error: 'No image data' });
    const safeScreen = `screen${screenIndex || 1}`;
    const filename   = `${userId}_${Date.now()}_${safeScreen}.jpg`;
    try {
      fs.writeFileSync(path.join(SHOTS_DIR, filename), Buffer.from(base64, 'base64'));
      activity.screenshots.push({ userId, userName, filename, screenIndex: screenIndex || 1, screenName: screenName || `Screen ${screenIndex || 1}`, ts: now });
      saveActivity(activity);
      return res.json({ ok: true, filename });
    } catch (e) {
      return res.status(500).json({ error: 'Failed to save screenshot' });
    }
  }

  res.status(400).json({ error: 'Unknown type' });
});

// GET /api/activity/status — latest status per employee (manager only)
app.get('/api/activity/status', auth, managerOnly, (req, res) => {
  const activity = loadActivity();
  const db       = loadDB();

  const latest = {};
  for (const hb of activity.heartbeats) {
    if (!latest[hb.userId] || new Date(hb.ts) > new Date(latest[hb.userId].ts))
      latest[hb.userId] = hb;
  }

  const latestApp = {};
  for (const a of activity.apps) {
    if (!latestApp[a.userId] || new Date(a.ts) > new Date(latestApp[a.userId].ts))
      latestApp[a.userId] = a;
  }

  const employees = db.users.filter(u => u.role === 'employee');
  res.json(employees.map(u => {
    const hb  = latest[u.id];
    const ap  = latestApp[u.id];
    const online = hb && (Date.now() - new Date(hb.ts)) < 90 * 1000;
    return {
      userId: u.id, userName: u.name, email: u.email,
      online: !!online, lastSeen: hb?.ts || null,
      activityScore: hb?.activityScore ?? null, isIdle: hb?.isIdle ?? null, idleSecs: hb?.idleSecs ?? null,
      activeApp: ap?.appName || null, activeTitle: ap?.title || null, appTs: ap?.ts || null,
    };
  }));
});

// GET /api/activity/logs?date=YYYY-MM-DD&userId=xxx — heartbeat timeline
app.get('/api/activity/logs', auth, managerOnly, (req, res) => {
  const activity = loadActivity();
  const date     = req.query.date || new Date().toISOString().split('T')[0];
  let hbs = activity.heartbeats.filter(h => h.ts.startsWith(date));
  if (req.query.userId) hbs = hbs.filter(h => h.userId === req.query.userId);
  res.json(hbs.sort((a, b) => new Date(a.ts) - new Date(b.ts)));
});

// GET /api/activity/appusage?date=YYYY-MM-DD&userId=xxx — top apps
app.get('/api/activity/appusage', auth, managerOnly, (req, res) => {
  const activity = loadActivity();
  const date     = req.query.date || new Date().toISOString().split('T')[0];
  let apps = activity.apps.filter(a => a.ts.startsWith(date));
  if (req.query.userId) apps = apps.filter(a => a.userId === req.query.userId);
  const counts = {};
  for (const a of apps) {
    const key = `${a.userId}|||${a.appName}`;
    counts[key] = (counts[key] || 0) + 1;
  }
  res.json(Object.entries(counts)
    .map(([key, count]) => { const [uid, appName] = key.split('|||'); return { userId: uid, appName, count }; })
    .sort((a, b) => b.count - a.count));
});

// GET /api/activity/screenshots?date=YYYY-MM-DD&userId=xxx — screenshot list
app.get('/api/activity/screenshots', auth, managerOnly, (req, res) => {
  const activity = loadActivity();
  const date     = req.query.date || new Date().toISOString().split('T')[0];
  let shots = activity.screenshots.filter(s => s.ts.startsWith(date));
  if (req.query.userId) shots = shots.filter(s => s.userId === req.query.userId);
  res.json(shots.sort((a, b) => new Date(b.ts) - new Date(a.ts)));
});

// ── Start ──────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Wachadoin.com running on port ${PORT}`);
});

server.on('error', err => {
  console.error('[server error]', err);
  process.exit(1);
});
