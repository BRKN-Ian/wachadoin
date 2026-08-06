const express = require('express');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;

// Render (and most PaaS hosts) sit behind a reverse proxy that terminates HTTPS and
// forwards plain HTTP internally, setting an X-Forwarded-Proto header to say so. Without
// this, req.protocol always reports "http" even though the site is actually served over
// https — which showed up as an http:// Server URL in the Agent Key modal. Trusting the
// proxy header fixes req.protocol (and req.secure) to reflect the real public scheme.
app.set('trust proxy', true);

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

const RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days — keep this in sync with the POPIA staff notice

function saveActivity(data) {
  // Prune entries older than the retention window to keep the file manageable. For
  // screenshots this also deletes the actual JPEG from disk, not just the record —
  // otherwise old screenshots would keep existing as orphaned files forever even
  // though the dashboard no longer shows them, which would make the retention period
  // promised to staff untrue.
  const cutoff = Date.now() - RETENTION_MS;
  data.heartbeats = (data.heartbeats || []).filter(r => new Date(r.ts) > cutoff);
  data.apps       = (data.apps       || []).filter(r => new Date(r.ts) > cutoff);

  const keepShots = [];
  for (const s of (data.screenshots || [])) {
    if (new Date(s.ts) > cutoff) {
      keepShots.push(s);
    } else {
      try { fs.unlinkSync(path.join(SHOTS_DIR, s.filename)); } catch {}
    }
  }
  data.screenshots = keepShots;

  fs.writeFileSync(ACTIVITY_FILE, JSON.stringify(data));
}

// Belt-and-braces: also sweep SHOTS_DIR directly for any screenshot file older than the
// retention window whose record may have been lost (e.g. an old file from before this
// cleanup existed, or an activity.json write that didn't complete). Runs on boot and daily.
function sweepOldScreenshots() {
  try {
    const cutoff = Date.now() - RETENTION_MS;
    for (const f of fs.readdirSync(SHOTS_DIR)) {
      const fp = path.join(SHOTS_DIR, f);
      try { if (fs.statSync(fp).mtimeMs < cutoff) fs.unlinkSync(fp); } catch {}
    }
  } catch {}
}
sweepOldScreenshots();
setInterval(sweepOldScreenshots, 24 * 60 * 60 * 1000);

const JWT_SECRET = process.env.JWT_SECRET || 'timetrack-secret-please-change-me';

// Long-lived per-user token used by the desktop Agent (not the 7-day web login JWT).
// The agent authenticates with this so it can run indefinitely without anyone logging in.
function genAgentToken() {
  return 'wag_' + crypto.randomBytes(24).toString('hex');
}

// ── App/website rules ────────────────────────────────────────────────────────
// Managers classify apps & window titles (which, for a browser, usually include the
// page/site title) as "work" or "redflag" so the dashboard can highlight time spent
// off-task. Matching is a simple case-insensitive substring match against "<appName>
// <title>". Suggested starter list is deliberately generic — any office/knowledge-work
// business — and is fully editable/replaceable per-account from the Monitoring Rules page.
const SUGGESTED_RULES = [
  // Work-related — common business/productivity tools
  { pattern: 'slack',            category: 'work' },
  { pattern: 'microsoft teams',  category: 'work' },
  { pattern: 'zoom',             category: 'work' },
  { pattern: 'google meet',      category: 'work' },
  { pattern: 'outlook',          category: 'work' },
  { pattern: 'gmail',            category: 'work' },
  { pattern: 'microsoft word',   category: 'work' },
  { pattern: 'microsoft excel',  category: 'work' },
  { pattern: 'microsoft powerpoint', category: 'work' },
  { pattern: 'google docs',      category: 'work' },
  { pattern: 'google sheets',    category: 'work' },
  { pattern: 'google slides',    category: 'work' },
  { pattern: 'notion',           category: 'work' },
  { pattern: 'asana',            category: 'work' },
  { pattern: 'trello',           category: 'work' },
  { pattern: 'jira',             category: 'work' },
  { pattern: 'salesforce',       category: 'work' },
  { pattern: 'hubspot',          category: 'work' },
  { pattern: 'figma',            category: 'work' },
  { pattern: 'github',           category: 'work' },
  // Red flags — social/entertainment
  { pattern: 'youtube',          category: 'redflag' },
  { pattern: 'facebook',         category: 'redflag' },
  { pattern: 'instagram',        category: 'redflag' },
  { pattern: 'tiktok',           category: 'redflag' },
  { pattern: 'twitter',          category: 'redflag' },
  { pattern: 'reddit',           category: 'redflag' },
  { pattern: 'netflix',          category: 'redflag' },
  { pattern: 'twitch',           category: 'redflag' },
  // Red flags — job hunting (possible morale/retention issue worth a quiet check-in)
  { pattern: 'linkedin jobs',    category: 'redflag' },
  { pattern: 'indeed.com',       category: 'redflag' },
  { pattern: 'glassdoor',        category: 'redflag' },
  { pattern: 'ziprecruiter',     category: 'redflag' },
];

function ensureRules(db) {
  if (!db.rules) { db.rules = SUGGESTED_RULES.map(r => ({ id: crypto.randomUUID(), ...r })); return true; }
  return false;
}

function classify(db, appName, title) {
  const hay = `${appName || ''} ${title || ''}`.toLowerCase();
  for (const r of (db.rules || [])) {
    if (hay.includes(r.pattern.toLowerCase())) return r.category;
  }
  return 'neutral';
}

// ── DB helpers ─────────────────────────────────────────────────
// One-time lazy migration for installations that were already running before the
// Partner/Manager/Employee hierarchy existed. Those employee records predate
// `managerId`, so without this a manager on an existing deployment would suddenly
// see an EMPTY team the moment this version deploys (visibleEmployees() filters on
// managerId, which none of their existing staff would have). Assign every employee
// missing a managerId to the first manager account found, so nothing goes dark.
//
// It also bootstraps the very first Partner/Director account on installations that
// predate that role. There's deliberately no API path to create the first partner
// (only an existing partner can add a manager, and only a manager/partner can add
// anyone at all) — someone has to exist to start that chain. Uses bcrypt's sync API
// (rather than the async one used elsewhere) so this can stay a plain synchronous
// function; loadDB() is called synchronously from many places and making it async
// would ripple through the whole file.
function migrateHierarchy(db) {
  let changed = false;

  const firstManager = db.users.find(u => u.role === 'manager');
  if (firstManager) {
    for (const u of db.users) {
      if (u.role === 'employee' && !u.managerId) { u.managerId = firstManager.id; changed = true; }
    }
  }

  if (db.users.length > 0 && !db.users.some(u => u.role === 'partner')) {
    const email    = process.env.PARTNER_EMAIL    || 'director@timetrack.com';
    const password = process.env.PARTNER_PASSWORD || crypto.randomBytes(6).toString('hex');
    const passwordHash = bcrypt.hashSync(password, 10);
    db.users.push({ id: crypto.randomUUID(), name: 'Director', email, passwordHash,
      role: 'partner', agentToken: genAgentToken(), createdAt: new Date().toISOString() });
    changed = true;
    console.log(`[Wachadoin] Bootstrapped a Partner/Director account on first boot with the new role tier — email: ${email}, password: ${password}. This is only logged once; note it down (or set PARTNER_EMAIL/PARTNER_PASSWORD before this first runs to control it yourself).`);
  }

  return changed;
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const blank = { users: [], entries: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(blank, null, 2));
    return blank;
  }
  let db;
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], entries: [] }; }
  if (migrateHierarchy(db)) saveDB(db);
  return db;
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ── Seed demo accounts on first run ───────────────────────────
// Three tiers: 'partner' (sees every manager and every employee across the whole
// organization — for firms large enough to have more than one manager), 'manager'
// (sees only the employees assigned to them via managerId), and 'employee' (no
// dashboard login at all — tracked only through their Agent Key).
async function maybeSeed() {
  const db = loadDB();
  if (db.users.length > 0) return;

  const partnerHash = await bcrypt.hash('director123', 10);
  const manHash     = await bcrypt.hash('admin123', 10);
  const today       = new Date().toISOString().split('T')[0];

  db.users = [
    { id:'u0', name:'Director',       email:'director@timetrack.com', passwordHash:partnerHash, role:'partner',  agentToken:genAgentToken(), createdAt:new Date().toISOString() },
    { id:'u1', name:'Admin Manager',  email:'admin@timetrack.com',    passwordHash:manHash,     role:'manager',  agentToken:genAgentToken(), createdAt:new Date().toISOString() },
    { id:'u2', name:'Sarah Johnson',  email:'sarah@timetrack.com',    role:'employee', managerId:'u1', agentToken:genAgentToken(), createdAt:new Date().toISOString() },
    { id:'u3', name:'Marcus Chen',    email:'marcus@timetrack.com',   role:'employee', managerId:'u1', agentToken:genAgentToken(), createdAt:new Date().toISOString() },
    { id:'u4', name:'Tom Walker',     email:'tom@timetrack.com',      role:'employee', managerId:'u1', agentToken:genAgentToken(), createdAt:new Date().toISOString() },
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
  console.log('[Wachadoin] Demo data ready. Manager login: admin@timetrack.com / admin123. Director (partner) login: director@timetrack.com / director123');
}
maybeSeed();

// ── Middleware ─────────────────────────────────────────────────
app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// The dashboard/login single-page app lives at public/login.html (not public/index.html —
// that's now the marketing landing page served automatically at "/"). Express's static
// middleware only serves login.html at the literal "/login.html" URL, so this route adds
// the clean "/login" address the landing page's "Sign in" button links to.
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  // Long-lived Agent tokens (used by the desktop background agent, not a browser login)
  // look like "wag_...". They never expire, so the agent can run indefinitely with no
  // one logging in. Anything else is treated as a normal 7-day web-login JWT.
  if (token.startsWith('wag_')) {
    const db   = loadDB();
    const user = db.users.find(u => u.agentToken === token);
    if (!user) return res.status(401).json({ error: 'Invalid agent token' });
    // Deactivated staff (e.g. after leaving) stop being able to report activity
    // immediately, even though their key hasn't been regenerated.
    if (user.active === false) return res.status(401).json({ error: 'Account deactivated' });
    req.user = { id: user.id, name: user.name, email: user.email, role: user.role, viaAgent: true };
    return next();
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  // Staff (role 'employee') have no dashboard login at all — they're tracked only via
  // their wag_ Agent Key, handled above. A web-login JWT should never carry that role;
  // the only way one could is a token issued before this restriction existed, so reject
  // it defensively rather than trusting a stale 7-day-old token.
  if (req.user.role === 'employee') return res.status(403).json({ error: 'Staff accounts do not have dashboard access' });
  // A web session token stays "valid" for 7 days by design, but if the account was
  // deactivated mid-session it should be kicked out on its very next request rather
  // than waiting for the token to expire naturally.
  const db = loadDB();
  const u  = db.users.find(x => x.id === req.user.id);
  if (!u) return res.status(401).json({ error: 'Invalid or expired token' });
  if (u.active === false) return res.status(401).json({ error: 'Account deactivated' });
  next();
}

// Any logged-in dashboard role (manager or partner) — staff never reach here (see auth()).
function managerOrAbove(req, res, next) {
  if (!['manager', 'partner'].includes(req.user?.role)) return res.status(403).json({ error: 'Manager access required' });
  next();
}
function partnerOnly(req, res, next) {
  if (req.user?.role !== 'partner') return res.status(403).json({ error: 'Partner access required' });
  next();
}

// Org hierarchy: a partner/director sees every manager and every employee in the
// organization; a manager sees only the employees assigned to them (employee.managerId).
function visibleEmployees(db, actor) {
  const employees = db.users.filter(u => u.role === 'employee');
  if (actor.role === 'partner') return employees;
  return employees.filter(e => e.managerId === actor.id);
}
function visibleEmployeeIds(db, actor) {
  return new Set(visibleEmployees(db, actor).map(e => e.id));
}
// Can `actor` (manager/partner) view or act on `target`? Partners can manage everyone
// except other partners (to avoid partners locking each other out). Managers can only
// manage the employees assigned to them.
function canManage(actor, target) {
  if (actor.id === target.id) return true;
  if (actor.role === 'partner') return target.role !== 'partner';
  if (actor.role === 'manager') return target.role === 'employee' && target.managerId === actor.id;
  return false;
}

// Resolves either a single ?date=YYYY-MM-DD or a ?from=...&to=... range from the query
// string into a consistent {from, to} pair (inclusive), defaulting to just today. This
// lets every activity-reporting endpoint support both "one day" and "day/week/month/
// custom range" views without duplicating the parsing logic.
function resolveRange(req) {
  const today = new Date().toISOString().split('T')[0];
  if (req.query.from || req.query.to) {
    const from = req.query.from || req.query.to;
    const to   = req.query.to   || req.query.from;
    return from <= to ? { from, to } : { from: to, to: from };
  }
  const d = req.query.date || today;
  return { from: d, to: d };
}
function tsInRange(ts, from, to) {
  const day = (ts || '').slice(0, 10);
  return day >= from && day <= to;
}

// ── Auth ───────────────────────────────────────────────────────
// Creates a person in the org. This used to be an open public "register" endpoint (no
// auth required at all, which meant literally anyone could have created themselves a
// manager account) — it's now a manager/partner-only admin action, matching how it's
// actually used from the Team Members page. Staff (role 'employee') never get a
// password or a login token; they're only ever identified by their Agent Key.
// Managers can only create employees, auto-assigned to themselves. Partners can create
// employees (choosing which manager the employee reports to) or new managers.
app.post('/api/auth/register', auth, managerOrAbove, async (req, res) => {
  const { name, email, password, role, managerId } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email already registered' });

  const wantsManager = role === 'manager' && req.user.role === 'partner';
  if (role === 'manager' && req.user.role !== 'partner')
    return res.status(403).json({ error: 'Only a partner/director can add a manager' });
  if (wantsManager && !password) return res.status(400).json({ error: 'Password is required for a manager account' });

  let user;
  if (wantsManager) {
    const passwordHash = await bcrypt.hash(password, 10);
    user = { id: crypto.randomUUID(), name: name.trim(), email: email.toLowerCase().trim(),
             passwordHash, role: 'manager', agentToken: genAgentToken(), createdAt: new Date().toISOString() };
  } else {
    // Employee — no password, no login. Managers are auto-assigned to themselves;
    // partners must say which manager this person reports to.
    let assignedManagerId = req.user.role === 'manager' ? req.user.id : managerId;
    const mgr = db.users.find(u => u.id === assignedManagerId && u.role === 'manager');
    if (!mgr) return res.status(400).json({ error: 'A valid manager must be chosen for this employee' });
    user = { id: crypto.randomUUID(), name: name.trim(), email: email.toLowerCase().trim(),
             role: 'employee', managerId: mgr.id, agentToken: genAgentToken(), createdAt: new Date().toISOString() };
  }
  db.users.push(user);
  saveDB(db);
  res.json({ user: { id:user.id, name:user.name, email:user.email, role:user.role, managerId:user.managerId||null } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db   = loadDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  // Staff never had a password to begin with, so !user.passwordHash catches them too —
  // but check the role explicitly first so the message is actually helpful to them.
  if (user && user.role === 'employee')
    return res.status(403).json({ error: "Staff accounts don't have a dashboard login — ask your manager for your Agent Key instead." });
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Invalid email or password' });
  if (user.active === false)
    return res.status(403).json({ error: 'This account has been deactivated. Contact your manager.' });
  const token = jwt.sign({ id:user.id, name:user.name, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: { id:user.id, name:user.name, email:user.email, role:user.role, popiaAcknowledgedAt:user.popiaAcknowledgedAt||null } });
});

// Acknowledge the POPIA monitoring notice (shown once to new managers before they can
// start monitoring staff). Anyone can ack their own account.
app.post('/api/auth/popia-ack', auth, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.popiaAcknowledgedAt = new Date().toISOString();
  saveDB(db);
  res.json({ ok: true, popiaAcknowledgedAt: user.popiaAcknowledgedAt });
});

// ── Users ──────────────────────────────────────────────────────
// A manager sees themselves and only their own team; a partner sees every manager and
// every employee in the org (with each employee's managerName resolved, so the Team
// Members page can group them).
app.get('/api/users', auth, managerOrAbove, (req, res) => {
  const db = loadDB();
  const managers = db.users.filter(u => u.role === 'manager');
  const mgrName  = id => managers.find(m => m.id === id)?.name || null;

  let visible;
  if (req.user.role === 'partner') {
    visible = db.users.filter(u => u.role !== 'partner' || u.id === req.user.id);
  } else {
    visible = [req.user, ...visibleEmployees(db, req.user)].map(u => db.users.find(x => x.id === u.id) || u);
  }
  res.json(visible.map(u => ({
    id: u.id, name: u.name, email: u.email, role: u.role, active: u.active !== false,
    managerId: u.managerId || null, managerName: u.role === 'employee' ? mgrName(u.managerId) : null,
  })));
});

// GET the Agent setup key for a user — used to install the desktop background agent on
// their machine (Windows or Mac) so it can run without them ever logging in day-to-day.
app.get('/api/users/:id/agent-token', auth, managerOrAbove, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  if (!user.agentToken) { user.agentToken = genAgentToken(); saveDB(db); }
  res.json({ agentToken: user.agentToken, serverUrl: `${req.protocol}://${req.get('host')}` });
});

// Regenerate (invalidate + replace) a user's Agent key, e.g. if a laptop is lost/decommissioned.
app.post('/api/users/:id/agent-token/regenerate', auth, managerOrAbove, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  user.agentToken = genAgentToken();
  saveDB(db);
  res.json({ agentToken: user.agentToken, serverUrl: `${req.protocol}://${req.get('host')}` });
});

// Offboarding — deactivate: the recommended way to remove someone who has left.
// Blocks their web login and stops the background agent from reporting immediately,
// but keeps their name and historical time entries / activity summaries on file
// (useful for the firm's own audit trail, and more in line with data-privacy laws'
// preference for retaining only what you actually need rather than erasing records
// that might still matter for a dispute or handover). A manager can only deactivate
// their own staff; a partner can also deactivate managers (but not other partners).
app.post('/api/users/:id/deactivate', auth, managerOrAbove, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'partner') return res.status(400).json({ error: 'Cannot deactivate a partner account' });
  if (req.user.role === 'manager' && user.role !== 'employee') return res.status(400).json({ error: 'Managers can only deactivate their own staff' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  user.active = false;
  user.deactivatedAt = new Date().toISOString();
  saveDB(db);
  res.json({ ok: true, active: false });
});

// Reverse a deactivation, e.g. someone was let go by mistake or has rejoined.
app.post('/api/users/:id/reactivate', auth, managerOrAbove, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  user.active = true;
  user.deactivatedAt = null;
  saveDB(db);
  res.json({ ok: true, active: true });
});

// Permanent removal — wipes the account entirely, including the option to ever see
// their historical entries again. Deactivate is almost always the right first step;
// use this only when you specifically need the record gone (e.g. a data-erasure
// request), since it can't be undone the way deactivation can.
app.delete('/api/users/:id', auth, managerOrAbove, (req, res) => {
  const db  = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const target = db.users[idx];
  if (target.role === 'partner') return res.status(400).json({ error: 'Cannot delete a partner account' });
  if (req.user.role === 'manager' && target.role !== 'employee') return res.status(400).json({ error: 'Managers can only remove their own staff' });
  if (!canManage(req.user, target)) return res.status(403).json({ error: 'Not allowed' });
  db.users.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
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
  const db = loadDB();
  const { from, to } = resolveRange(req);
  let list = db.entries.filter(e => tsInRange(e.startTime, from, to));
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db, req.user);
    ids.add(req.user.id);
    list = list.filter(e => ids.has(e.userId));
  } else if (req.user.role !== 'partner') {
    list = list.filter(e => e.userId === req.user.id);
  }
  res.json(list.sort((a,b) => new Date(b.startTime) - new Date(a.startTime)));
});

// Every entry visible to the requester, with no date filter — a partner gets the
// whole org, a manager gets their own team (mirrors the scoping in /api/entries).
app.get('/api/entries/all', auth, managerOrAbove, (req, res) => {
  const db = loadDB();
  let list = db.entries;
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db, req.user);
    ids.add(req.user.id);
    list = list.filter(e => ids.has(e.userId));
  }
  res.json(list.sort((a,b) => new Date(b.startTime) - new Date(a.startTime)));
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
    const db  = loadDB();
    const ids = req.user.role === 'manager' ? visibleEmployeeIds(db, req.user) : null;
    if (ids) ids.add(req.user.id);
    const files = fs.readdirSync(SHOTS_DIR).filter(f => f.endsWith('.jpg'))
      .map(f => {
        const parts     = f.replace('.jpg','').split('_');
        const userId    = parts[0];
        const screenNum = parseInt((parts[2]||'screen1').replace('screen','')) || 1;
        return { filename:f, userId, ts: fs.statSync(path.join(SHOTS_DIR,f)).mtimeMs,
                 userName: db.users.find(u=>u.id===userId)?.name || 'Unknown',
                 screenNum, screenLabel: `Screen ${screenNum}` };
      })
      .filter(f => req.user.role === 'partner' || (ids ? ids.has(f.userId) : f.userId === req.user.id))
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
    const db = loadDB();
    ensureRules(db) && saveDB(db);
    const category = classify(db, appName, title);
    activity.apps.push({ userId, userName, appName, title, category, ts: now });
    saveActivity(activity);
    return res.json({ ok: true, category });
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

// GET /api/activity/status — latest status per employee (manager sees own team, partner sees everyone)
app.get('/api/activity/status', auth, managerOrAbove, (req, res) => {
  const activity = loadActivity();
  const db       = loadDB();
  ensureRules(db);

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

  const employees = visibleEmployees(db, req.user);
  res.json(employees.map(u => {
    const hb  = latest[u.id];
    const ap  = latestApp[u.id];
    const online = hb && (Date.now() - new Date(hb.ts)) < 90 * 1000;
    return {
      userId: u.id, userName: u.name, email: u.email,
      online: !!online, lastSeen: hb?.ts || null,
      activityScore: hb?.activityScore ?? null, isIdle: hb?.isIdle ?? null, idleSecs: hb?.idleSecs ?? null,
      activeApp: ap?.appName || null, activeTitle: ap?.title || null, appTs: ap?.ts || null,
      flag: ap ? classify(db, ap.appName, ap.title) : null,
    };
  }));
});

// ── Monitoring rules (manager only) ───────────────────────────────────────────
app.get('/api/settings/rules', auth, managerOrAbove, (req, res) => {
  const db = loadDB();
  const changed = ensureRules(db);
  if (changed) saveDB(db);
  res.json(db.rules);
});

app.put('/api/settings/rules', auth, managerOrAbove, (req, res) => {
  const { rules } = req.body;
  if (!Array.isArray(rules)) return res.status(400).json({ error: 'rules array required' });
  const db = loadDB();
  db.rules = rules
    .filter(r => r && r.pattern && (r.category === 'work' || r.category === 'redflag'))
    .map(r => ({ id: r.id || crypto.randomUUID(), pattern: r.pattern.trim(), category: r.category }));
  saveDB(db);
  res.json(db.rules);
});

// Merge in the suggested starter list without wiping custom rules already added
app.post('/api/settings/rules/suggested', auth, managerOrAbove, (req, res) => {
  const db = loadDB();
  ensureRules(db);
  const existing = new Set(db.rules.map(r => r.pattern.toLowerCase()));
  for (const s of SUGGESTED_RULES) {
    if (!existing.has(s.pattern.toLowerCase())) {
      db.rules.push({ id: crypto.randomUUID(), ...s });
      existing.add(s.pattern.toLowerCase());
    }
  }
  saveDB(db);
  res.json(db.rules);
});

// GET /api/activity/logs?date=YYYY-MM-DD (or from=&to=)&userId=xxx — heartbeat timeline.
// Supports both a single day (?date=) and a day/week/month/custom range (?from=&to=).
app.get('/api/activity/logs', auth, managerOrAbove, (req, res) => {
  const db  = loadDB();
  const { from, to } = resolveRange(req);
  const activity = loadActivity();
  let hbs = activity.heartbeats.filter(h => tsInRange(h.ts, from, to));
  if (req.query.userId) {
    const target = db.users.find(u => u.id === req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    hbs = hbs.filter(h => h.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db, req.user);
    hbs = hbs.filter(h => ids.has(h.userId));
  }
  res.json(hbs.sort((a, b) => new Date(a.ts) - new Date(b.ts)));
});

// GET /api/activity/appusage?date=YYYY-MM-DD (or from=&to=)&userId=xxx — top apps
app.get('/api/activity/appusage', auth, managerOrAbove, (req, res) => {
  const activity = loadActivity();
  const db       = loadDB();
  ensureRules(db);
  const { from, to } = resolveRange(req);
  let apps = activity.apps.filter(a => tsInRange(a.ts, from, to));
  if (req.query.userId) {
    const target = db.users.find(u => u.id === req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    apps = apps.filter(a => a.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db, req.user);
    apps = apps.filter(a => ids.has(a.userId));
  }
  const counts = {};
  for (const a of apps) {
    const key = `${a.userId}|||${a.appName}`;
    if (!counts[key]) counts[key] = { count: 0, redflag: 0, work: 0 };
    counts[key].count++;
    const cat = classify(db, a.appName, a.title);
    if (cat === 'redflag') counts[key].redflag++;
    else if (cat === 'work') counts[key].work++;
  }
  res.json(Object.entries(counts)
    .map(([key, v]) => {
      const [uid, appName] = key.split('|||');
      const category = v.redflag > 0 ? 'redflag' : (v.work > 0 ? 'work' : 'neutral');
      return { userId: uid, appName, count: v.count, category };
    })
    .sort((a, b) => b.count - a.count));
});

// GET /api/activity/screenshots?date=YYYY-MM-DD (or from=&to=)&userId=xxx — screenshot list
app.get('/api/activity/screenshots', auth, managerOrAbove, (req, res) => {
  const db  = loadDB();
  const { from, to } = resolveRange(req);
  const activity = loadActivity();
  let shots = activity.screenshots.filter(s => tsInRange(s.ts, from, to));
  if (req.query.userId) {
    const target = db.users.find(u => u.id === req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    shots = shots.filter(s => s.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db, req.user);
    shots = shots.filter(s => ids.has(s.userId));
  }
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
