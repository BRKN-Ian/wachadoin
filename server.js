const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const archiver = require('archiver');
const PDFDocument = require('pdfkit');
const helmet   = require('helmet');
const dbLib    = require('./db');
const { issueToken, hashToken, verifyToken, rateLimited } = require('./lib/tokens');
const { ALERT_DEFAULTS, resolveAlertSettings, weekendAdjustedElapsedMs, isDigestDueNow } = require('./lib/alerts');
const mailer   = require('./lib/mailer');

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', true);

process.on('uncaughtException',  err => console.error('[uncaughtException]',  err));
process.on('unhandledRejection', err => console.error('[unhandledRejection]', err));

// ── Storage ────────────────────────────────────────────────────
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

const SHOTS_DIR = path.join(DATA_DIR, 'screenshots');
if (!fs.existsSync(SHOTS_DIR)) fs.mkdirSync(SHOTS_DIR, { recursive: true });

const LEGACY_DB_FILE       = path.join(DATA_DIR, 'timetrack.json');
const LEGACY_ACTIVITY_FILE = path.join(DATA_DIR, 'activity.json');

const db = dbLib.open(DATA_DIR);
const genAgentToken = dbLib.genAgentToken;

// Two retention windows, not one. Activity/timeline data (heartbeats, app usage) is a
// per-firm record clients rely on for at least a year; screenshots are a much more
// sensitive, short-lived evidence artifact that only sticks around longer if the
// organization is specifically paying for permanent storage.
const ACTIVITY_RETENTION_MS   = 365 * 24 * 60 * 60 * 1000; // 12 months
const SCREENSHOT_RETENTION_MS = 7   * 24 * 60 * 60 * 1000; // 7 days, unless org.permanentScreenshots

const PLATFORM_ORG_ID = 'platform';

// ── App/website rules (unchanged defaults, now seeded per-organization) ──────
const SUGGESTED_RULES = [
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
  { pattern: 'youtube',          category: 'redflag' },
  { pattern: 'facebook',         category: 'redflag' },
  { pattern: 'instagram',        category: 'redflag' },
  { pattern: 'tiktok',           category: 'redflag' },
  { pattern: 'twitter',          category: 'redflag' },
  { pattern: 'reddit',           category: 'redflag' },
  { pattern: 'netflix',          category: 'redflag' },
  { pattern: 'twitch',           category: 'redflag' },
  { pattern: 'linkedin jobs',    category: 'redflag' },
  { pattern: 'indeed.com',       category: 'redflag' },
  { pattern: 'glassdoor',        category: 'redflag' },
  { pattern: 'ziprecruiter',     category: 'redflag' },
  // 'sensitive' rules never affect the work/redflag productivity flag (see
  // classify(), which only matches work/redflag rows) — they exist purely to
  // tell the desktop Agent which apps/sites should never be screenshotted.
  // Deliberately NOT seeded with the firm's own accounting/tax software
  // (Pastel, Xero, SARS eFiling, etc.) — for an accounting firm monitoring
  // its own staff, screenshots of *those* systems are the whole point (it's
  // how you'd catch someone doing unauthorized side-work on client software
  // during paid hours). This category is for things genuinely outside the
  // engagement — personal banking, personal email/medical portals — that a
  // firm may still want to exclude if an employee happens to have them open.
  // Left empty by default; each firm adds their own if they want any at all.
];

function ensureRules(orgId) {
  const existing = db.listRules(orgId);
  if (existing.length > 0) return existing;
  const seeded = SUGGESTED_RULES.map(r => ({ id: crypto.randomUUID(), organizationId: orgId, ...r }));
  db.replaceRules(orgId, seeded);
  return seeded;
}

function classify(orgId, appName, title) {
  const hay = `${appName || ''} ${title || ''}`.toLowerCase();
  for (const r of ensureRules(orgId)) {
    // 'sensitive' rows are a separate concern (see isSensitiveApp) — skip them
    // here so they never show up as this employee's work/redflag flag.
    if ((r.category === 'work' || r.category === 'redflag') && hay.includes(r.pattern.toLowerCase())) return r.category;
  }
  return 'neutral';
}

// Screenshot-exclusion check: does this app/window match one of the org's
// 'sensitive' rules? Used both by the dashboard (to show which rules exist)
// and indirectly by the Agent, which fetches the raw pattern list itself via
// GET /api/agent/config and does the same match locally before capturing.
function isSensitiveApp(orgId, appName, title) {
  const hay = `${appName || ''} ${title || ''}`.toLowerCase();
  return ensureRules(orgId).some(r => r.category === 'sensitive' && hay.includes(r.pattern.toLowerCase()));
}

// ── One-time migration: old flat-JSON single-organization installs ─────────
// Existing Acute production data (timetrack.json + activity.json) predates
// organizations entirely. On first boot against the new SQLite store, if that
// legacy data exists and hasn't been imported yet, fold it into a single
// "legacy-internal" organization so nothing Acute already has goes dark.
function importLegacyJsonIfPresent() {
  if (db.listOrgs().some(o => o.id !== PLATFORM_ORG_ID)) return; // already migrated / already has real orgs
  if (!fs.existsSync(LEGACY_DB_FILE)) return;

  let legacy;
  try { legacy = JSON.parse(fs.readFileSync(LEGACY_DB_FILE, 'utf8')); } catch { return; }
  if (!legacy.users || legacy.users.length === 0) return;

  console.log('[migration] Importing legacy single-organization data into SQLite...');
  const org = db.createOrg({ name: 'Acute Accountants Inc', plan: 'legacy-internal', seatLimit: null, permanentScreenshots: false, status: 'internal' });

  const idMap = {}; // legacy id -> same id (kept identical; only organizationId is new)
  for (const u of legacy.users) {
    idMap[u.id] = u.id;
    db.insertUser({
      id: u.id, organizationId: org.id, name: u.name, email: u.email,
      passwordHash: u.passwordHash || null, role: u.role, managerId: u.managerId || null,
      agentToken: u.agentToken || genAgentToken(), active: u.active !== false,
      deactivatedAt: u.deactivatedAt || null, popiaAcknowledgedAt: u.popiaAcknowledgedAt || null,
      createdAt: u.createdAt || new Date().toISOString(),
    });
  }
  for (const e of (legacy.entries || [])) {
    db.insertEntry({
      id: e.id, organizationId: org.id, userId: e.userId, userName: e.userName || null,
      project: e.project || null, task: e.task || null, startTime: e.startTime || null,
      endTime: e.endTime || null, durationMs: e.durationMs ?? null, activityScore: e.activityScore ?? null,
      activeMs: e.activeMs ?? null, idleMs: e.idleMs ?? null, screenshotCount: e.screenshotCount || 0,
      status: e.status || 'completed',
    });
  }
  if (legacy.rules && legacy.rules.length) {
    db.replaceRules(org.id, legacy.rules.map(r => ({ id: r.id || crypto.randomUUID(), organizationId: org.id, pattern: r.pattern, category: r.category })));
  }

  if (fs.existsSync(LEGACY_ACTIVITY_FILE)) {
    let activity;
    try { activity = JSON.parse(fs.readFileSync(LEGACY_ACTIVITY_FILE, 'utf8')); } catch { activity = null; }
    if (activity) {
      for (const hb of (activity.heartbeats || []))
        db.insertHeartbeat({ organizationId: org.id, userId: hb.userId, userName: hb.userName || null, activityScore: hb.activityScore ?? null, idleSecs: hb.idleSecs ?? null, isIdle: !!hb.isIdle, ts: hb.ts });
      for (const a of (activity.apps || []))
        db.insertAppEvent({ organizationId: org.id, userId: a.userId, userName: a.userName || null, appName: a.appName || null, title: a.title || null, category: a.category || 'neutral', ts: a.ts });
      for (const s of (activity.screenshots || [])) {
        try {
          db.insertScreenshotRecord({ filename: s.filename, organizationId: org.id, userId: s.userId, userName: s.userName || null, screenIndex: s.screenIndex || 1, screenName: s.screenName || 'Screen 1', ts: s.ts });
        } catch { /* duplicate filename — skip */ }
      }
    }
  }

  console.log(`[migration] Done. Legacy data now lives under organization "${org.name}" (${org.id}).`);
}

// Reserved platform organization that superadmin accounts belong to. Not a real
// customer — exists purely so superadmin users have somewhere to hang off of without
// ever being mistaken for a client organization in the /api/admin/orgs list.
function ensurePlatformOrg() {
  if (!db.getOrg(PLATFORM_ORG_ID)) {
    db.createOrg({ id: PLATFORM_ORG_ID, name: 'Wachadoin (platform)', plan: 'platform', seatLimit: null, permanentScreenshots: false, status: 'internal' });
  }
}

// ── Trial length & no-pro-rata cancellation ─────────────────────────────────
// Free trials run exactly 7 days from signup (trialEndsAt is set once, at
// signup, and never recomputed). Nothing in the app blocks a trialing org once
// that date passes — it's surfaced as a dashboard banner only, so a firm that
// forgets to convert doesn't lose access before Acute has had a chance to
// reach out.
const TRIAL_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

// Cancellation, by contrast, IS enforced: there's no payment gateway to stop
// charging pro-rata, so the policy is simply that an org keeps (and is
// expected to pay for) its full current term — monthly subscribers keep
// access to the end of the current month, annual subscribers to the end of
// the current year. computeAccessUntil finds the next term boundary after
// `fromDate`, counting in fixed-length periods from the org's signup date
// (the only anchor we have without real billing/renewal tracking).
function computeAccessUntil(org, fromDate) {
  const periodMs = (org.billingCycle === 'annual' ? 365 : 30) * 24 * 60 * 60 * 1000;
  let periodEnd = new Date(org.createdAt).getTime();
  const from = fromDate.getTime();
  while (periodEnd <= from) periodEnd += periodMs;
  return new Date(periodEnd).toISOString();
}

// True once a canceled org's paid-through date has actually passed — this is
// the one place cancellation turns into a real access cutoff (see auth() and
// the login route below).
function orgAccessExpired(org) {
  return !!(org && org.status === 'canceled' && org.accessUntil && new Date(org.accessUntil) <= new Date());
}

// The subset of org fields the dashboard (not the superadmin console, which
// gets the full picture from /api/admin/orgs) needs to show trial/cancellation
// banners. Returns null for the platform org itself (superadmin has no
// "subscription" of its own).
function orgSummaryFor(organizationId) {
  const org = organizationId && db.getOrg(organizationId);
  if (!org || org.id === PLATFORM_ORG_ID) return null;
  return {
    id: org.id, status: org.status, billingCycle: org.billingCycle,
    trialEndsAt: org.trialEndsAt, cancelRequestedAt: org.cancelRequestedAt, accessUntil: org.accessUntil,
  };
}

// Bootstraps the very first superadmin (Acute's own back-office login) and, on
// pre-multi-tenant installs, the first Partner/Director — mirroring the old
// migrateHierarchy() bootstrap so nothing regresses for an install that already
// went through that migration once.
function bootstrapAccounts() {
  ensurePlatformOrg();
  importLegacyJsonIfPresent();

  if (!db.listAllUsers().some(u => u.role === 'superadmin')) {
    const email    = process.env.SUPERADMIN_EMAIL    || 'admin@wachadoin.com';
    const password = process.env.SUPERADMIN_PASSWORD || crypto.randomBytes(6).toString('hex');
    const passwordHash = bcrypt.hashSync(password, 10);
    db.insertUser({ organizationId: PLATFORM_ORG_ID, name: 'Wachadoin Admin', email, passwordHash, role: 'superadmin', agentToken: genAgentToken() });
    // Never log the real password — Render's logs are retained and viewable by
    // anyone with dashboard access. If SUPERADMIN_PASSWORD wasn't set to control
    // it directly, use the normal "forgot password" flow on this email to set one.
    console.log(`[Wachadoin] Bootstrapped a superadmin account — email: ${email}. Set SUPERADMIN_PASSWORD in the environment to control the password directly, or use "Forgot password" on this email to set one now.`);
  }

  // Legacy-internal org: backfill managerId on any employee that predates the
  // hierarchy, and make sure it has at least one partner.
  for (const org of db.listOrgs()) {
    if (org.id === PLATFORM_ORG_ID) continue;
    const users = db.listUsersByOrg(org.id);
    if (users.length === 0) continue;
    const firstManager = users.find(u => u.role === 'manager');
    if (firstManager) {
      for (const u of users) {
        if (u.role === 'employee' && !u.managerId) db.updateUser({ ...u, managerId: firstManager.id });
      }
    }
    if (!users.some(u => u.role === 'partner')) {
      const email    = process.env.PARTNER_EMAIL    || 'director@timetrack.com';
      const password = process.env.PARTNER_PASSWORD || crypto.randomBytes(6).toString('hex');
      const passwordHash = bcrypt.hashSync(password, 10);
      db.insertUser({ organizationId: org.id, name: 'Director', email, passwordHash, role: 'partner', agentToken: genAgentToken() });
      console.log(`[Wachadoin] Bootstrapped a Partner/Director account for org "${org.name}" — email: ${email}. Set PARTNER_PASSWORD in the environment to control the password directly, or use "Forgot password" on this email to set one now.`);
    }
  }
}
bootstrapAccounts();

// Demo data for local dev/testing only — never runs against a real deployment
// unless explicitly opted into with SEED_DEMO=true, even on a totally fresh
// database, since it creates guessable admin123/director123 accounts.
// Real customer organizations always come from /api/auth/signup.
function maybeSeedDemoOrg() {
  if (process.env.SEED_DEMO !== 'true') return;
  const realOrgs = db.listOrgs().filter(o => o.id !== PLATFORM_ORG_ID);
  if (realOrgs.length > 0) return;

  const org = db.createOrg({ name: 'Demo Firm', plan: 'growth', seatLimit: null, permanentScreenshots: false, status: 'trialing' });
  const partnerHash = bcrypt.hashSync('director123', 10);
  const manHash     = bcrypt.hashSync('admin123', 10);
  const today       = new Date().toISOString().split('T')[0];

  const partner = db.insertUser({ organizationId: org.id, name: 'Director', email: 'director@timetrack.com', passwordHash: partnerHash, role: 'partner' });
  const manager = db.insertUser({ organizationId: org.id, name: 'Admin Manager', email: 'admin@timetrack.com', passwordHash: manHash, role: 'manager' });
  const emps = [
    { name: 'Sarah Johnson', email: 'sarah@timetrack.com' },
    { name: 'Marcus Chen',   email: 'marcus@timetrack.com' },
    { name: 'Tom Walker',    email: 'tom@timetrack.com' },
  ].map(e => db.insertUser({ organizationId: org.id, name: e.name, email: e.email, role: 'employee', managerId: manager.id }));

  const mk = (userId, userName, project, task, startTime, endTime, activityScore, screenshotCount) =>
    db.insertEntry({ id: crypto.randomUUID(), organizationId: org.id, userId, userName, project, task, startTime, endTime,
      durationMs: new Date(endTime) - new Date(startTime), activityScore, activeMs: null, idleMs: null, screenshotCount, status: 'completed' });

  mk(emps[0].id, emps[0].name, 'Acme Corp – Website Redesign', 'Frontend Development', `${today}T08:02:00.000Z`, `${today}T10:45:00.000Z`, 91, 18);
  mk(emps[1].id, emps[1].name, 'Beta Ltd – Mobile App',        'iOS Development',      `${today}T08:15:00.000Z`, `${today}T12:00:00.000Z`, 95, 22);
  mk(emps[2].id, emps[2].name, 'Gamma Inc – Data Migration',   'ETL Development',      `${today}T07:55:00.000Z`, `${today}T11:30:00.000Z`, 82, 20);

  console.log('[Wachadoin] Demo data ready. Manager login: admin@timetrack.com / admin123. Director (partner) login: director@timetrack.com / director123');
}
maybeSeedDemoOrg();

// ── Retention sweep ────────────────────────────────────────────────────────
function sweepRetention() {
  const activityCutoffIso = new Date(Date.now() - ACTIVITY_RETENTION_MS).toISOString();
  for (const org of db.listOrgs()) {
    if (org.id === PLATFORM_ORG_ID) continue;
    db.pruneHeartbeats(org.id, activityCutoffIso);
    db.pruneAppEvents(org.id, activityCutoffIso);

    if (org.permanentScreenshots) continue; // this org has paid to keep screenshots forever
    const shotCutoffIso = new Date(Date.now() - SCREENSHOT_RETENTION_MS).toISOString();
    for (const filename of db.expiredScreenshotFilenames(org.id, shotCutoffIso)) {
      db.deleteScreenshotRecord(filename);
      try { fs.unlinkSync(path.join(SHOTS_DIR, filename)); } catch {}
    }
    db.pruneScreenshotSkips(org.id, shotCutoffIso);
  }
}
// Belt-and-braces sweep of orphaned screenshot files on disk (e.g. a DB row lost to a
// crash mid-write) — only safe to delete by file age, capped at the shortest retention
// any org could have (7 days); a permanent-storage org's files are never this old in
// practice since their rows are never pruned, but if a file truly has no matching row
// at all it's orphaned regardless of org and safe to remove once past the default window.
function sweepOrphanedScreenshotFiles() {
  try {
    const cutoff = Date.now() - SCREENSHOT_RETENTION_MS;
    for (const f of fs.readdirSync(SHOTS_DIR)) {
      const fp = path.join(SHOTS_DIR, f);
      try {
        if (fs.statSync(fp).mtimeMs < cutoff && !db.raw.prepare('SELECT 1 FROM screenshots WHERE filename = ?').get(f)) {
          fs.unlinkSync(fp);
        }
      } catch {}
    }
  } catch {}
}
sweepRetention();
sweepOrphanedScreenshotFiles();
setInterval(() => { sweepRetention(); sweepOrphanedScreenshotFiles(); }, 24 * 60 * 60 * 1000);

// No hardcoded fallback: a shipped-in-source secret would let anyone who's
// read the code forge a valid login for any user, including superadmin.
// Refuse to start rather than silently sign tokens with a guessable secret.
if (!process.env.JWT_SECRET) {
  console.error('[Wachadoin] FATAL: JWT_SECRET is not set. Refusing to start — set a strong random JWT_SECRET in the environment and redeploy.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// ── Middleware ─────────────────────────────────────────────────
// contentSecurityPolicy is off for now: login.html's dashboard is one large
// inline <script> plus ~36 inline onclick= handlers, and a default CSP would
// block all of it. Everything else helmet sets by default (HSTS, X-Frame-
// Options/frameguard, X-Content-Type-Options, disabling X-Powered-By, etc.)
// is a real improvement with zero risk to the current frontend. A real CSP
// is worth doing later, but it means moving those inline handlers to
// addEventListener first — a frontend refactor of its own.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  if (token.startsWith('wag_')) {
    const user = db.findUserByAgentToken(token);
    if (!user) return res.status(401).json({ error: 'Invalid agent token' });
    if (user.active === false) return res.status(401).json({ error: 'Account deactivated' });
    if (orgAccessExpired(db.getOrg(user.organizationId)))
      return res.status(403).json({ error: "This organization's subscription has ended." });
    req.user = { id: user.id, name: user.name, email: user.email, role: user.role, organizationId: user.organizationId, viaAgent: true };
    return next();
  }

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }

  if (payload.role === 'employee') return res.status(403).json({ error: 'Staff accounts do not have dashboard access' });

  const u = db.findUserById(payload.id);
  if (!u) return res.status(401).json({ error: 'Invalid or expired token' });
  if (u.active === false) return res.status(401).json({ error: 'Account deactivated' });
  // Cancellation isn't pro-rata — an org keeps access through the end of its current
  // paid term (see computeAccessUntil above) and only actually gets cut off once that
  // date passes. Superadmin's own org is never 'canceled', so this never affects it.
  if (orgAccessExpired(db.getOrg(u.organizationId)))
    return res.status(403).json({ error: "This organization's subscription has ended. Contact Acute to reactivate." });
  // Always trust the freshly-loaded organizationId/role over the (possibly days-old) JWT
  // payload, defensively — there's no role-change endpoint today, but this costs nothing.
  req.user = { id: u.id, name: u.name, email: u.email, role: u.role, organizationId: u.organizationId };
  next();
}

function managerOrAbove(req, res, next) {
  if (!['manager', 'partner'].includes(req.user?.role)) return res.status(403).json({ error: 'Manager access required' });
  next();
}
function partnerOnly(req, res, next) {
  if (req.user?.role !== 'partner') return res.status(403).json({ error: 'Partner access required' });
  next();
}
// Acute's own back-office role. Deliberately cannot see into any organization's
// activity data — only organization/subscription metadata — so "Acute can manage
// billing" never quietly becomes "Acute can read a client's staff activity."
function superAdminOnly(req, res, next) {
  if (req.user?.role !== 'superadmin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Org hierarchy, scoped to the caller's own organization only. `users` must already be
// the org-scoped list (db.listUsersByOrg(actor.organizationId)) — every call site below
// fetches that first, so no cross-tenant leakage can happen here.
function visibleEmployees(users, actor) {
  const employees = users.filter(u => u.role === 'employee');
  if (actor.role === 'partner') return employees;
  return employees.filter(e => e.managerId === actor.id);
}
function visibleEmployeeIds(users, actor) {
  return new Set(visibleEmployees(users, actor).map(e => e.id));
}
// Can `actor` (manager/partner) view or act on `target`? Cross-tenant actions are always
// rejected first — a partner at Firm A must never be able to manage a user at Firm B,
// even by guessing/enumerating a valid user id.
function canManage(actor, target) {
  if (!target || target.organizationId !== actor.organizationId) return false;
  if (actor.id === target.id) return true;
  if (actor.role === 'partner') return target.role !== 'partner';
  if (actor.role === 'manager') return target.role === 'employee' && target.managerId === actor.id;
  return false;
}

// ── Alerts: who should be told what, and how often ──────────────────────────
// All the raw signals (idle seconds, last heartbeat, red-flag classification)
// already exist for Live Status above — this reuses them rather than adding
// any new tracking, and needs no change to the desktop Agent at all.
//
// Cooldowns are deliberately simple (a fixed "don't repeat within N hours"
// window per recipient+employee+type) rather than exact edge-detection on
// when a condition started/cleared — good enough for a periodic sweep, and
// every fired alert is logged (db.insertAlertLog) so it can be reasoned about
// or shown back to a manager later.
const ALERT_SWEEP_INTERVAL_MS   = 5  * 60 * 1000;  // how often the real-time check runs
const ALERT_IDLE_COOLDOWN_MS    = 2  * 60 * 60 * 1000; // 2h — don't re-alert the same idle stretch every 5 minutes
const ALERT_OFFLINE_COOLDOWN_MS = 12 * 60 * 60 * 1000; // 12h
const ALERT_REDFLAG_COOLDOWN_MS = 1  * 60 * 60 * 1000; // 1h per employee, regardless of which flagged site
const DIGEST_SWEEP_INTERVAL_MS  = 60 * 60 * 1000;  // hourly check for whose digest is due right now

// Who gets alerted about a given employee: their direct manager (if any) plus
// every partner/director in the org — partners already see every employee on
// Live Status, so the same visibility rule applies here. Each recipient still
// only gets an email if THEIR OWN thresholds are crossed and THEIR OWN
// toggles allow it (see resolveAlertSettings) — this only decides who's in
// the running, not what fires.
function alertRecipientsFor(orgUsers, employee) {
  const recipients = orgUsers.filter(u => u.role === 'partner');
  const mgr = orgUsers.find(u => u.id === employee.managerId && u.role === 'manager');
  if (mgr) recipients.push(mgr);
  return [...new Map(recipients.map(r => [r.id, r])).values()];
}

function withinAlertCooldown(recipientId, employeeId, alertType, cooldownMs) {
  const last = db.lastAlertFiredAt(recipientId, employeeId, alertType);
  return !!last && (Date.now() - new Date(last).getTime()) < cooldownMs;
}
function logAlert(organizationId, recipientId, employeeId, alertType, detail) {
  db.insertAlertLog({ organizationId, recipientId, employeeId, alertType, detail: detail || null, firedAt: new Date().toISOString() });
}
function sendRealtimeAlert(recipient, employee, type, message) {
  const subject = {
    redflag: `Wachadoin alert: ${employee.name} visited a flagged site`,
    idle:    `Wachadoin alert: ${employee.name} has been idle`,
    offline: `Wachadoin alert: ${employee.name} appears offline`,
  }[type] || `Wachadoin alert: ${employee.name}`;
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222">
    <p><strong>${employee.name}</strong> ${message}.</p>
    <p style="color:#666;font-size:12px">You're getting this because you manage ${employee.name}, or are a partner/director at your firm. Change your thresholds or turn this off any time in Wachadoin under <strong>Alert Settings</strong>.</p>
  </div>`;
  mailer.sendMail({ to: recipient.email, subject, html }).catch(err => console.error('[alerts] send failed:', err.message));
}

function runAlertSweep() {
  for (const org of db.listOrgs()) {
    if (org.id === PLATFORM_ORG_ID) continue;
    const orgUsers = db.listUsersByOrg(org.id);
    const employees = orgUsers.filter(u => u.role === 'employee' && u.active !== false);
    if (!employees.length) continue;

    const latestHb = {};  for (const hb of db.latestHeartbeatsByOrg(org.id)) latestHb[hb.userId] = hb;
    const latestApp = {}; for (const a of db.latestAppEventsByOrg(org.id)) latestApp[a.userId] = a;
    const nowIso = new Date().toISOString();

    for (const emp of employees) {
      const recipients = alertRecipientsFor(orgUsers, emp);
      if (!recipients.length) continue;
      const hb = latestHb[emp.id];
      const ap = latestApp[emp.id];
      const flag = ap ? classify(org.id, ap.appName, ap.title) : null;

      for (const recipient of recipients) {
        const settings = resolveAlertSettings(recipient);

        if (flag === 'redflag' && settings.redFlagEnabled && ap &&
            !withinAlertCooldown(recipient.id, emp.id, 'redflag', ALERT_REDFLAG_COOLDOWN_MS)) {
          logAlert(org.id, recipient.id, emp.id, 'redflag', `${ap.appName || 'Unknown app'}${ap.title ? ` — "${ap.title}"` : ''}`);
          sendRealtimeAlert(recipient, emp, 'redflag', `visited a flagged site/app: ${ap.appName || 'unknown'}${ap.title ? ` — "${ap.title}"` : ''}`);
        }

        if (hb && hb.idleSecs != null && hb.idleSecs >= settings.idleMins * 60 &&
            !withinAlertCooldown(recipient.id, emp.id, 'idle', ALERT_IDLE_COOLDOWN_MS)) {
          logAlert(org.id, recipient.id, emp.id, 'idle', `idle for ${Math.round(hb.idleSecs / 60)} min`);
          sendRealtimeAlert(recipient, emp, 'idle', `has been idle for ${Math.round(hb.idleSecs / 60)} minutes`);
        }

        // No heartbeat at all yet just means the Agent hasn't started, not "offline" — only
        // ever alert once there's at least one heartbeat on record to measure a gap from.
        if (hb) {
          const elapsedMs = weekendAdjustedElapsedMs(hb.ts, nowIso);
          if (elapsedMs >= settings.offlineMins * 60 * 1000 &&
              !withinAlertCooldown(recipient.id, emp.id, 'offline', ALERT_OFFLINE_COOLDOWN_MS)) {
            logAlert(org.id, recipient.id, emp.id, 'offline', `no activity since ${hb.ts}`);
            sendRealtimeAlert(recipient, emp, 'offline', `has had no activity since ${new Date(hb.ts).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' })} (weekend time excluded)`);
          }
        }
      }
    }
  }
}

// Weekly per-recipient summary: tracked hours, average activity score, and
// how many of each alert type fired for each employee they can see, over the
// last 7 days. Runs hourly and relies on isDigestDueNow() to only actually
// send once per recipient per matching SAST day/hour.
function sendDigestEmail(org, orgUsers, recipient, now) {
  const employees = visibleEmployees(orgUsers, recipient);
  if (!employees.length) return;
  const sinceIso = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const entries = db.listEntriesByOrg(org.id, { from: sinceIso.slice(0, 10), to: now.toISOString().slice(0, 10) });
  const alertCounts = db.alertCountsForRecipientSince(recipient.id, sinceIso);

  const rows = employees.map(emp => {
    const empEntries = entries.filter(e => e.userId === emp.id);
    const totalMs = empEntries.reduce((s, e) => s + (e.durationMs || 0), 0);
    const scored = empEntries.filter(e => e.activityScore != null);
    const avgScore = scored.length ? Math.round(scored.reduce((s, e) => s + e.activityScore, 0) / scored.length) : null;
    const counts = { idle: 0, offline: 0, redflag: 0 };
    for (const c of alertCounts) if (c.employeeId === emp.id && counts[c.alertType] !== undefined) counts[c.alertType] = c.c;
    return { name: emp.name, hours: (totalMs / 3600000).toFixed(1), avgScore, ...counts };
  });
  if (!rows.length) return;

  const tableRows = rows.map(r => `<tr>
      <td style="padding:6px 10px;border-bottom:1px solid #eee">${r.name}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">${r.hours}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">${r.avgScore ?? '—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right;color:${r.redflag ? '#c0392b' : '#666'}">${r.redflag}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">${r.idle}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">${r.offline}</td>
    </tr>`).join('');
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222">
    <p>Here's the past 7 days for your team on Wachadoin:</p>
    <table style="border-collapse:collapse;width:100%;max-width:640px">
      <thead><tr style="text-align:left;font-size:12px;color:#666">
        <th style="padding:6px 10px">Employee</th><th style="padding:6px 10px;text-align:right">Hours logged</th>
        <th style="padding:6px 10px;text-align:right">Avg activity</th><th style="padding:6px 10px;text-align:right">Red flags</th>
        <th style="padding:6px 10px;text-align:right">Idle alerts</th><th style="padding:6px 10px;text-align:right">Offline alerts</th>
      </tr></thead>
      <tbody>${tableRows}</tbody>
    </table>
    <p style="color:#666;font-size:12px;margin-top:16px">Change how often you get this, or turn it off, any time in Wachadoin under <strong>Alert Settings</strong>.</p>
  </div>`;
  mailer.sendMail({ to: recipient.email, subject: `Wachadoin weekly summary — ${rows.length} team member${rows.length === 1 ? '' : 's'}`, html })
    .catch(err => console.error('[alerts] digest send failed:', err.message));
}

function runDigestSweep() {
  const now = new Date();
  for (const org of db.listOrgs()) {
    if (org.id === PLATFORM_ORG_ID) continue;
    const orgUsers = db.listUsersByOrg(org.id);
    for (const recipient of orgUsers.filter(u => u.role === 'manager' || u.role === 'partner')) {
      const settings = resolveAlertSettings(recipient);
      if (!isDigestDueNow(settings, now, recipient.alertLastDigestSentAt)) continue;
      sendDigestEmail(org, orgUsers, recipient, now);
      db.updateUser({ ...recipient, alertLastDigestSentAt: now.toISOString() });
    }
  }
}

setInterval(runAlertSweep, ALERT_SWEEP_INTERVAL_MS);
setInterval(runDigestSweep, DIGEST_SWEEP_INTERVAL_MS);

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

// ── Auth ───────────────────────────────────────────────────────
// Creates a person inside the caller's own organization. Staff (role 'employee')
// never get a password; they're only ever identified by their Agent Key.
app.post('/api/auth/register', auth, managerOrAbove, async (req, res) => {
  const { name, email, password, role, managerId } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  if (db.findUserByEmail(email)) return res.status(400).json({ error: 'Email already registered' });

  const orgUsers = db.listUsersByOrg(req.user.organizationId);
  // Staff (employees) never get an invite/login — only Managers and Partners/
  // Directors do, since they're the only roles that ever sign in to the dashboard.
  const wantsManager = role === 'manager' && req.user.role === 'partner';
  const wantsPartner = role === 'partner' && req.user.role === 'partner';
  if ((role === 'manager' || role === 'partner') && req.user.role !== 'partner')
    return res.status(403).json({ error: 'Only a partner/director can add a manager or another partner/director' });

  let user, inviteLink;
  if (wantsManager || wantsPartner) {
    // Invite-based, not partner-sets-the-password: the Partner no longer types
    // (and therefore doesn't end up knowing) the new person's password. The
    // account is created with no passwordHash and inviteStatus: 'pending';
    // they set their own password via the link, same token mechanism
    // as /api/auth/forgot-password (see lib/tokens.js).
    const { raw, hash } = issueToken();
    const resetTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    user = db.insertUser({
      organizationId: req.user.organizationId, name: name.trim(), email: email.toLowerCase().trim(),
      role: wantsPartner ? 'partner' : 'manager', inviteStatus: 'pending', resetTokenHash: hash, resetTokenExpiresAt,
    });
    inviteLink = `${req.protocol}://${req.get('host')}/login?invite=${raw}`;
  } else {
    let assignedManagerId = req.user.role === 'manager' ? req.user.id : managerId;
    const mgr = orgUsers.find(u => u.id === assignedManagerId && u.role === 'manager');
    if (!mgr) return res.status(400).json({ error: 'A valid manager must be chosen for this employee' });
    user = db.insertUser({ organizationId: req.user.organizationId, name: name.trim(), email: email.toLowerCase().trim(), role: 'employee', managerId: mgr.id });
  }
  res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role, managerId: user.managerId || null, inviteStatus: user.inviteStatus || null }, inviteLink });
});

// Regenerates a manager's or partner's invite link if the original was lost —
// same token mechanism, just a fresh one issued (the old one, if still unused,
// stops working the moment this overwrites its hash). Deliberately doesn't use
// canManage() here: that helper blocks a partner from acting on another
// partner's *active* account (deactivate/delete/agent-token), which is the
// right protection for those actions but not for this one — reissuing a still-
// pending invite doesn't touch anyone's existing access, so any partner in the
// same org can do it for any pending manager OR partner invite.
app.post('/api/users/:id/reissue-invite', auth, partnerOnly, (req, res) => {
  const user = db.findUserById(req.params.id);
  if (!user || user.organizationId !== req.user.organizationId) return res.status(404).json({ error: 'User not found' });
  if (user.inviteStatus !== 'pending') return res.status(400).json({ error: 'This account has already been activated' });
  if (rateLimited(`reissue:${user.id}`)) return res.status(429).json({ error: 'Too many attempts — try again in a few minutes.' });
  const { raw, hash } = issueToken();
  const resetTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.updateUser({ ...user, resetTokenHash: hash, resetTokenExpiresAt });
  res.json({ inviteLink: `${req.protocol}://${req.get('host')}/login?invite=${raw}` });
});

// Completes a manager invite: sets their own password and activates the
// account. Public (no auth token yet — the invite token itself is the proof).
app.post('/api/auth/accept-invite', async (req, res) => {
  const { token: raw, password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const hash = hashToken(String(raw || ''));
  const user = db.findUserByResetToken(hash);
  if (!user || !verifyToken(raw, user.resetTokenHash, user.resetTokenExpiresAt)) {
    return res.status(400).json({ error: 'This invite link is invalid or has expired — ask your partner to resend it.' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  db.updateUser({ ...user, passwordHash, resetTokenHash: null, resetTokenExpiresAt: null, inviteStatus: null });
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role, organizationId: user.organizationId }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role }, organization: orgSummaryFor(user.organizationId) });
});

// Public self-serve signup: creates a brand-new organization plus its first Partner
// account in one step. This is the only way a new organization comes into being —
// every other account is created by an existing partner/manager inside their org.
// No payment is collected here (that's Phase 2); new organizations start trialing.
const PUBLIC_PLANS = new Set(['starter', 'growth', 'firm']);
app.post('/api/auth/signup', async (req, res) => {
  const { orgName, name, email, password } = req.body;
  let { plan, billingCycle } = req.body;
  if (!orgName || !name || !email || !password) return res.status(400).json({ error: 'Firm name, your name, email and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.findUserByEmail(email)) return res.status(400).json({ error: 'Email already registered' });
  if (!PUBLIC_PLANS.has(plan)) plan = 'starter';
  // Annual billing is prepaid for the year at a 10% discount off the monthly rate.
  // No payment gateway exists yet (that's Phase 2), so this is just the customer's
  // stated preference for now — Acute's back office (see /api/admin/orgs below)
  // uses it to know how to invoice once real billing is wired up.
  billingCycle = billingCycle === 'annual' ? 'annual' : 'monthly';

  // Free trial is 7 days from right now — set once and never recomputed. Signup
  // already requires a name, email, and password, so "requires signup" (i.e. we
  // have that person's details before the trial clock even starts) is satisfied
  // by the checks above; this just stamps when the 7 days runs out.
  const trialEndsAt = new Date(Date.now() + TRIAL_DAYS_MS).toISOString();
  const org = db.createOrg({ name: orgName.trim(), plan, seatLimit: null, permanentScreenshots: false, status: 'trialing', billingCycle, trialEndsAt });
  const passwordHash = await bcrypt.hash(password, 10);
  const partner = db.insertUser({ organizationId: org.id, name: name.trim(), email: email.toLowerCase().trim(), passwordHash, role: 'partner' });

  const token = jwt.sign({ id: partner.id, name: partner.name, email: partner.email, role: partner.role, organizationId: org.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: partner.id, name: partner.name, email: partner.email, role: partner.role }, organization: { id: org.id, name: org.name, plan: org.plan, status: org.status, billingCycle: org.billingCycle, trialEndsAt: org.trialEndsAt } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  // Unlimited password guessing against a known email was previously possible —
  // cap attempts per email, same rateLimited() helper already used for
  // forgot-password/reissue-invite (see lib/tokens.js).
  if (rateLimited(`login:${(email || '').toString().toLowerCase()}`, { max: 10, windowMs: 15 * 60 * 1000 })) {
    return res.status(429).json({ error: 'Too many login attempts — try again in a few minutes.' });
  }
  const user = db.findUserByEmail(email);
  if (user && user.role === 'employee')
    return res.status(403).json({ error: "Staff accounts don't have a dashboard login — ask your manager for your Agent Key instead." });
  if (user && !user.passwordHash && user.inviteStatus === 'pending')
    return res.status(403).json({ error: "This account hasn't been activated yet — check your invite link, or ask your partner to resend it." });
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Invalid email or password' });
  if (user.active === false)
    return res.status(403).json({ error: 'This account has been deactivated. Contact your manager.' });
  // Same no-pro-rata cutoff as auth() below, checked here too so a cut-off org gets a
  // clear message at login instead of a token that then 403s on its first real request.
  if (user.role !== 'superadmin' && orgAccessExpired(db.getOrg(user.organizationId)))
    return res.status(403).json({ error: "This organization's subscription has ended. Contact Acute to reactivate." });
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role, organizationId: user.organizationId }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, popiaAcknowledgedAt: user.popiaAcknowledgedAt || null }, organization: orgSummaryFor(user.organizationId) });
});

// Self-service password reset. There's no transactional email provider wired
// up yet, so the reset link is handed back directly in the response instead
// of being emailed — a deliberate, temporary stopgap (see resetLink below).
// Swapping in real email later is a one-line change: stop returning resetLink
// and call a sendEmail() with it instead. The token itself is unaffected.
app.post('/api/auth/forgot-password', async (req, res) => {
  const email = (req.body?.email || '').toString();
  if (rateLimited(`forgot:${email.toLowerCase()}`)) {
    return res.status(429).json({ error: 'Too many attempts — try again in a few minutes.' });
  }
  const user = db.findUserByEmail(email);
  // Always return 200 with the same shape whether or not the account exists,
  // so this endpoint can't be used to enumerate registered emails.
  const response = { ok: true };
  if (user && user.role !== 'employee' && user.active !== false) {
    const { raw, hash } = issueToken();
    const resetTokenExpiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    db.updateUser({ ...user, resetTokenHash: hash, resetTokenExpiresAt });
    const resetLink = `${req.protocol}://${req.get('host')}/login?reset=${raw}`;
    // Resend is live now — email the link to the account owner instead of
    // handing it back in the API response (that let anyone who merely knew a
    // victim's email address reset their password with no inbox access at all).
    await mailer.sendMail({
      to: user.email,
      subject: 'Reset your Wachadoin password',
      html: `<p>Someone (hopefully you) asked to reset the password on your Wachadoin account.</p>
             <p><a href="${resetLink}">Click here to choose a new password</a>. This link expires in 30 minutes.</p>
             <p>If you didn't request this, you can safely ignore this email — your password hasn't been changed.</p>`,
    });
  }
  res.json(response);
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token: raw, password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const hash = hashToken(String(raw || ''));
  const user = db.findUserByResetToken(hash);
  if (!user || !verifyToken(raw, user.resetTokenHash, user.resetTokenExpiresAt)) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired — request a new one.' });
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  // Also clears inviteStatus: this token column is shared with the manager-invite
  // flow (POST /api/auth/accept-invite), so a still-pending invite that gets
  // completed through this endpoint instead shouldn't stay stuck as "pending".
  db.updateUser({ ...user, passwordHash, resetTokenHash: null, resetTokenExpiresAt: null, inviteStatus: null });
  res.json({ ok: true });
});

app.post('/api/auth/popia-ack', auth, (req, res) => {
  const user = db.findUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const popiaAcknowledgedAt = new Date().toISOString();
  db.updateUser({ ...user, popiaAcknowledgedAt });
  res.json({ ok: true, popiaAcknowledgedAt });
});

// Lightweight "is my token still valid, and who am I" check the frontend can call
// for ANY authenticated dashboard role (manager, partner, or superadmin) — unlike
// /api/users, which 403s for superadmin since superadmin isn't scoped to an
// organization at all.
app.get('/api/auth/session', auth, (req, res) => {
  res.json({ user: { id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role }, organization: orgSummaryFor(req.user.organizationId) });
});

// ── Users ──────────────────────────────────────────────────────
app.get('/api/users', auth, managerOrAbove, (req, res) => {
  const orgUsers = db.listUsersByOrg(req.user.organizationId);
  const managers = orgUsers.filter(u => u.role === 'manager');
  const mgrName  = id => managers.find(m => m.id === id)?.name || null;

  let visible;
  if (req.user.role === 'partner') {
    // Now that a partner can invite peer partners/directors, they need to see
    // them here too (previously this list dropped every partner but yourself,
    // from back when an org only ever had one).
    visible = orgUsers;
  } else {
    visible = [req.user, ...visibleEmployees(orgUsers, req.user)].map(u => orgUsers.find(x => x.id === u.id) || u);
  }
  res.json(visible.map(u => ({
    id: u.id, name: u.name, email: u.email, role: u.role, active: u.active !== false,
    managerId: u.managerId || null, managerName: u.role === 'employee' ? mgrName(u.managerId) : null,
    inviteStatus: u.inviteStatus || null,
    consentRecordedAt: u.consentRecordedAt || null, consentRecordedBy: u.consentRecordedBy || null, consentNote: u.consentNote || null,
  })));
});

app.get('/api/users/:id/agent-token', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  const agentToken = user.agentToken || genAgentToken();
  if (!user.agentToken) db.updateUser({ ...user, agentToken });
  res.json({ agentToken, serverUrl: `${req.protocol}://${req.get('host')}` });
});

app.post('/api/users/:id/agent-token/regenerate', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  const agentToken = genAgentToken();
  db.updateUser({ ...user, agentToken });
  res.json({ agentToken, serverUrl: `${req.protocol}://${req.get('host')}` });
});

// Polled periodically by the desktop Agent (plain `auth` so an agent token
// works here same as it does for POST /api/activity) so it knows which
// apps/windows count as 'sensitive' for this org and should never be
// screenshotted. Kept deliberately tiny — just the pattern strings, nothing
// that requires a new Agent release to change when a firm edits their list.
app.get('/api/agent/config', auth, (req, res) => {
  const sensitivePatterns = ensureRules(req.user.organizationId)
    .filter(r => r.category === 'sensitive')
    .map(r => r.pattern);
  res.json({ sensitivePatterns });
});

app.post('/api/users/:id/deactivate', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.params.id);
  // Org-ownership check runs first, before any role-specific message — the
  // old order let a manager/partner learn whether a foreign-org id existed at
  // all, and roughly what role it had, purely from which error came back.
  // A 404 now covers both "doesn't exist" and "not yours to see" up front;
  // canManage() below still enforces the finer-grained same-org rules.
  if (!user || user.organizationId !== req.user.organizationId) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'partner') return res.status(400).json({ error: 'Cannot deactivate a partner account' });
  if (req.user.role === 'manager' && user.role !== 'employee') return res.status(400).json({ error: 'Managers can only deactivate their own staff' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  db.updateUser({ ...user, active: false, deactivatedAt: new Date().toISOString() });
  res.json({ ok: true, active: false });
});

app.post('/api/users/:id/reactivate', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  db.updateUser({ ...user, active: true, deactivatedAt: null });
  res.json({ ok: true, active: true });
});

// Records that a subordinate (who may never log in themselves, e.g. an
// employee) was given written notice about monitoring and consented outside
// the app — a signed form, an email, whatever the firm actually did. This is
// deliberately separate from /api/auth/popia-ack, which only ever records
// the logged-in dashboard user clicking through the notice for themselves.
app.post('/api/users/:id/consent', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.user, user)) return res.status(403).json({ error: 'Not allowed' });
  const note = (req.body?.note || '').toString().slice(0, 500);
  const consentRecordedAt = new Date().toISOString();
  db.updateUser({ ...user, consentRecordedAt, consentRecordedBy: req.user.name, consentNote: note });
  res.json({ ok: true, consentRecordedAt, consentRecordedBy: req.user.name, consentNote: note });
});

app.delete('/api/users/:id', auth, managerOrAbove, (req, res) => {
  const target = db.findUserById(req.params.id);
  // Same reordering as /deactivate above — org check first, so a foreign-org
  // id can't be distinguished from a nonexistent one before canManage() runs.
  if (!target || target.organizationId !== req.user.organizationId) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'partner') return res.status(400).json({ error: 'Cannot delete a partner account' });
  if (req.user.role === 'manager' && target.role !== 'employee') return res.status(400).json({ error: 'Managers can only remove their own staff' });
  if (!canManage(req.user, target)) return res.status(403).json({ error: 'Not allowed' });
  db.deleteUser(target.id);
  res.json({ ok: true });
});

// ── Alert settings ─────────────────────────────────────────────
// Deliberately self-service and personal, not something a partner sets for a
// manager: each manager/partner configures their OWN thresholds for what
// they want to be told about, per Ian's ask. There's no endpoint for setting
// someone else's — /api/users/me only.
function alertSettingsResponse(user) {
  return { ...resolveAlertSettings(user), defaults: ALERT_DEFAULTS };
}
app.get('/api/users/me/alert-settings', auth, managerOrAbove, (req, res) => {
  res.json(alertSettingsResponse(db.findUserById(req.user.id)));
});
app.put('/api/users/me/alert-settings', auth, managerOrAbove, (req, res) => {
  const user = db.findUserById(req.user.id);
  const { idleMins, offlineMins, redFlagEnabled, digestEnabled, digestDay, digestHour } = req.body || {};
  const clampInt = (v, lo, hi, current) => {
    if (v === undefined) return current;
    const n = Math.round(Number(v));
    return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : current;
  };
  const updated = db.updateUser({
    ...user,
    alertIdleMins:    clampInt(idleMins, 1, 1440, user.alertIdleMins),
    alertOfflineMins: clampInt(offlineMins, 15, 20160, user.alertOfflineMins),
    alertRedFlagEnabled: redFlagEnabled !== undefined ? (redFlagEnabled ? 1 : 0) : user.alertRedFlagEnabled,
    alertDigestEnabled:  digestEnabled  !== undefined ? (digestEnabled  ? 1 : 0) : user.alertDigestEnabled,
    alertDigestDay:  clampInt(digestDay, 0, 6, user.alertDigestDay),
    alertDigestHour: clampInt(digestHour, 0, 23, user.alertDigestHour),
  });
  res.json(alertSettingsResponse(updated));
});

// ── Entries ────────────────────────────────────────────────────
app.post('/api/entries', auth, (req, res) => {
  const { project, task } = req.body;
  if (!project || !task) return res.status(400).json({ error: 'Project and task required' });
  for (const running of db.findRunningEntries(req.user.id)) {
    running.endTime    = new Date().toISOString();
    running.durationMs = new Date(running.endTime) - new Date(running.startTime);
    running.status     = 'completed';
    db.updateEntry(running);
  }
  const entry = { id: crypto.randomUUID(), organizationId: req.user.organizationId, userId: req.user.id, userName: req.user.name,
    project, task, startTime: new Date().toISOString(), endTime: null,
    durationMs: null, activityScore: null, activeMs: null, idleMs: null, screenshotCount: 0, status: 'running' };
  db.insertEntry(entry);
  res.json(entry);
});

app.put('/api/entries/:id', auth, (req, res) => {
  const { activityScore, activeMs, idleMs } = req.body;
  const e = db.findEntryById(req.params.id);
  if (!e || e.userId !== req.user.id) return res.status(404).json({ error: 'Entry not found' });
  e.endTime       = new Date().toISOString();
  e.durationMs    = new Date(e.endTime) - new Date(e.startTime);
  e.activityScore = Math.round(activityScore ?? 0);
  e.activeMs      = activeMs ?? null;
  e.idleMs        = idleMs   ?? null;
  e.status        = 'completed';
  db.updateEntry(e);
  res.json(e);
});

app.delete('/api/entries/:id', auth, (req, res) => {
  const e = db.findEntryById(req.params.id);
  if (!e || e.userId !== req.user.id) return res.status(404).json({ error: 'Not found' });
  db.deleteEntry(e.id, req.user.organizationId);
  res.json({ ok: true });
});

app.get('/api/entries', auth, (req, res) => {
  const { from, to } = resolveRange(req);
  let list = db.listEntriesByOrg(req.user.organizationId, { from, to });
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    ids.add(req.user.id);
    list = list.filter(e => ids.has(e.userId));
  } else if (req.user.role !== 'partner') {
    list = list.filter(e => e.userId === req.user.id);
  }
  res.json(list);
});

app.get('/api/entries/all', auth, managerOrAbove, (req, res) => {
  let list = db.listEntriesByOrg(req.user.organizationId);
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    ids.add(req.user.id);
    list = list.filter(e => ids.has(e.userId));
  }
  res.json(list);
});

// ── Screenshots ────────────────────────────────────────────────
// screenIndex arrives from the client as free-form input; despite the name,
// splicing it unsanitized into a filename let a "../../.." value escape
// SHOTS_DIR entirely via path.join. Clamp it to a small positive integer.
function safeScreenIndex(v) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n) || n < 1) return 1;
  return Math.min(n, 20);
}

app.post('/api/screenshots', auth, (req, res) => {
  const { entryId, base64, screenIndex } = req.body;
  if (!base64) return res.status(400).json({ error: 'No image data' });
  const idx = safeScreenIndex(screenIndex);
  const filename = `${req.user.id}_${Date.now()}_screen${idx}.jpg`;
  try {
    fs.writeFileSync(path.join(SHOTS_DIR, filename), Buffer.from(base64, 'base64'));
    db.insertScreenshotRecord({ filename, organizationId: req.user.organizationId, userId: req.user.id, userName: req.user.name, screenIndex: idx, screenName: `Screen ${idx}`, ts: new Date().toISOString() });
    // Only bump a screenshot count on an entry that's actually this requester's
    // own, in their own org — entryId was previously trusted as-is, letting any
    // authenticated caller (including an employee's agent token) tamper with
    // another organization's entry counters via a guessed/leaked id.
    if (entryId) {
      const entry = db.findEntryById(entryId);
      if (entry && entry.organizationId === req.user.organizationId && entry.userId === req.user.id) {
        db.bumpScreenshotCount(entryId);
      }
    }
    res.json({ filename });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save screenshot' });
  }
});

app.get('/api/screenshots', auth, (req, res) => {
  const ids = req.user.role === 'manager' ? visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user) : null;
  if (ids) ids.add(req.user.id);
  let shots = db.listRecentScreenshotsByOrg(req.user.organizationId, 50);
  shots = shots.filter(s => req.user.role === 'partner' || (ids ? ids.has(s.userId) : s.userId === req.user.id));
  res.json(shots.map(s => ({ filename: s.filename, userId: s.userId, userName: s.userName, ts: new Date(s.ts).getTime(), screenNum: s.screenIndex, screenLabel: s.screenName })));
});

// NOTE: this must stay registered before the /:filename route below, otherwise Express
// would match "export" itself as a :filename and this would never be reached.
app.get('/api/screenshots/export', auth, managerOrAbove, (req, res) => {
  const { from, to } = resolveRange(req);
  let shots = db.listScreenshotsByOrgRange(req.user.organizationId, from, to);
  if (req.query.userId) {
    const target = db.findUserById(req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    shots = shots.filter(s => s.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    shots = shots.filter(s => ids.has(s.userId));
  }

  const rangeLabel = from === to ? from : `${from}_to_${to}`;
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="wachadoin-screenshots-${rangeLabel}.zip"`);
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);

  const manifest = ['filename,employee,timestamp,screen'];
  for (const s of shots) {
    const fp = path.join(SHOTS_DIR, s.filename);
    if (fs.existsSync(fp)) archive.file(fp, { name: s.filename });
    manifest.push([s.filename, s.userName, s.ts, s.screenName].map(csvEscape).join(','));
  }
  archive.append(manifest.join('\r\n'), { name: 'manifest.csv' });
  archive.finalize();
});

app.get('/api/screenshots/:filename', auth, (req, res) => {
  const filename = path.basename(req.params.filename);
  const record = db.raw.prepare('SELECT * FROM screenshots WHERE filename = ?').get(filename);
  if (!record || record.organizationId !== req.user.organizationId) return res.status(404).end();
  // Org match alone wasn't enough — it let one manager fetch another manager's
  // employees' screenshots (and an employee's own agent token fetch anyone's)
  // just by knowing/guessing a filename. Apply the same visibility scoping
  // used by GET /api/screenshots above.
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    ids.add(req.user.id);
    if (!ids.has(record.userId)) return res.status(404).end();
  } else if (req.user.role !== 'partner' && record.userId !== req.user.id) {
    return res.status(404).end();
  }
  const fp = path.join(SHOTS_DIR, filename);
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.sendFile(fp);
});

// ── Activity API ────────────────────────────────────────────────────────────
app.post('/api/activity', auth, (req, res) => {
  const { type, ts } = req.body;
  if (!type) return res.status(400).json({ error: 'type required' });

  const organizationId = req.user.organizationId;
  const userId   = req.user.id;
  const userName = req.user.name;
  const now      = ts || new Date().toISOString();

  if (type === 'heartbeat') {
    const { activityScore, idleSecs, isIdle } = req.body;
    db.insertHeartbeat({ organizationId, userId, userName, activityScore, idleSecs, isIdle: !!isIdle, ts: now });
    return res.json({ ok: true });
  }

  if (type === 'app') {
    const { appName, title } = req.body;
    const category = classify(organizationId, appName, title);
    db.insertAppEvent({ organizationId, userId, userName, appName, title, category, ts: now });
    return res.json({ ok: true, category });
  }

  if (type === 'screenshot') {
    const { base64, screenIndex, screenName } = req.body;
    if (!base64) return res.status(400).json({ error: 'No image data' });
    const idx      = safeScreenIndex(screenIndex);
    const filename = `${userId}_${Date.now()}_screen${idx}.jpg`;
    try {
      fs.writeFileSync(path.join(SHOTS_DIR, filename), Buffer.from(base64, 'base64'));
      db.insertScreenshotRecord({ filename, organizationId, userId, userName, screenIndex: idx, screenName: screenName || `Screen ${idx}`, ts: now });
      return res.json({ ok: true, filename });
    } catch (e) {
      return res.status(500).json({ error: 'Failed to save screenshot' });
    }
  }

  // The Agent sends this instead of 'screenshot' when the focused app/window
  // matched a 'sensitive' rule at capture time — no image ever left the
  // employee's machine. Recorded so the gap in the gallery reads as a
  // deliberate policy rather than a missing screenshot (see GET
  // /api/activity/screenshots, which merges these in alongside real shots).
  if (type === 'screenshot_skipped') {
    const { appName, title } = req.body;
    db.insertScreenshotSkip({ organizationId, userId, userName, appName: appName || null, title: title || null, ts: now });
    return res.json({ ok: true });
  }

  res.status(400).json({ error: 'Unknown type' });
});

app.get('/api/activity/status', auth, managerOrAbove, (req, res) => {
  const orgUsers = db.listUsersByOrg(req.user.organizationId);
  const latestHb  = {}; for (const hb of db.latestHeartbeatsByOrg(req.user.organizationId)) latestHb[hb.userId] = hb;
  const latestApp = {}; for (const a  of db.latestAppEventsByOrg(req.user.organizationId)) latestApp[a.userId] = a;

  const employees = visibleEmployees(orgUsers, req.user);
  res.json(employees.map(u => {
    const hb = latestHb[u.id];
    const ap = latestApp[u.id];
    const online = hb && (Date.now() - new Date(hb.ts)) < 90 * 1000;
    return {
      userId: u.id, userName: u.name, email: u.email,
      online: !!online, lastSeen: hb?.ts || null,
      activityScore: hb?.activityScore ?? null, isIdle: hb?.isIdle ?? null, idleSecs: hb?.idleSecs ?? null,
      activeApp: ap?.appName || null, activeTitle: ap?.title || null, appTs: ap?.ts || null,
      flag: ap ? classify(req.user.organizationId, ap.appName, ap.title) : null,
    };
  }));
});

// ── Monitoring rules ───────────────────────────────────────────────────────
app.get('/api/settings/rules', auth, managerOrAbove, (req, res) => {
  res.json(ensureRules(req.user.organizationId));
});

app.put('/api/settings/rules', auth, managerOrAbove, (req, res) => {
  const { rules } = req.body;
  if (!Array.isArray(rules)) return res.status(400).json({ error: 'rules array required' });
  const clean = rules
    .filter(r => r && r.pattern && (r.category === 'work' || r.category === 'redflag' || r.category === 'sensitive'))
    .map(r => ({ id: r.id || crypto.randomUUID(), organizationId: req.user.organizationId, pattern: r.pattern.trim(), category: r.category }));
  db.replaceRules(req.user.organizationId, clean);
  res.json(clean);
});

app.post('/api/settings/rules/suggested', auth, managerOrAbove, (req, res) => {
  const existingRules = ensureRules(req.user.organizationId);
  const existing = new Set(existingRules.map(r => r.pattern.toLowerCase()));
  const merged = [...existingRules];
  for (const s of SUGGESTED_RULES) {
    if (!existing.has(s.pattern.toLowerCase())) {
      merged.push({ id: crypto.randomUUID(), organizationId: req.user.organizationId, ...s });
      existing.add(s.pattern.toLowerCase());
    }
  }
  db.replaceRules(req.user.organizationId, merged);
  res.json(merged);
});

app.get('/api/activity/logs', auth, managerOrAbove, (req, res) => {
  const { from, to } = resolveRange(req);
  let hbs = db.listHeartbeatsByOrgRange(req.user.organizationId, from, to);
  if (req.query.userId) {
    const target = db.findUserById(req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    hbs = hbs.filter(h => h.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    hbs = hbs.filter(h => ids.has(h.userId));
  }
  res.json(hbs);
});

app.get('/api/activity/appusage', auth, managerOrAbove, (req, res) => {
  const { from, to } = resolveRange(req);
  let apps = db.listAppEventsByOrgRange(req.user.organizationId, from, to);
  if (req.query.userId) {
    const target = db.findUserById(req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    apps = apps.filter(a => a.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    apps = apps.filter(a => ids.has(a.userId));
  }
  const counts = {};
  for (const a of apps) {
    const key = `${a.userId}|||${a.appName}`;
    if (!counts[key]) counts[key] = { count: 0, redflag: 0, work: 0 };
    counts[key].count++;
    if (a.category === 'redflag') counts[key].redflag++;
    else if (a.category === 'work') counts[key].work++;
  }
  res.json(Object.entries(counts)
    .map(([key, v]) => {
      const [uid, appName] = key.split('|||');
      const category = v.redflag > 0 ? 'redflag' : (v.work > 0 ? 'work' : 'neutral');
      return { userId: uid, appName, count: v.count, category };
    })
    .sort((a, b) => b.count - a.count));
});

app.get('/api/activity/screenshots', auth, managerOrAbove, (req, res) => {
  const { from, to } = resolveRange(req);
  let shots = db.listScreenshotsByOrgRange(req.user.organizationId, from, to);
  let skips = db.listScreenshotSkipsByOrgRange(req.user.organizationId, from, to);
  if (req.query.userId) {
    const target = db.findUserById(req.query.userId);
    if (!target || (!canManage(req.user, target) && target.id !== req.user.id))
      return res.status(403).json({ error: 'Not allowed to view this user' });
    shots = shots.filter(s => s.userId === req.query.userId);
    skips = skips.filter(s => s.userId === req.query.userId);
  } else if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    shots = shots.filter(s => ids.has(s.userId));
    skips = skips.filter(s => ids.has(s.userId));
  }
  // Merge skip placeholders in alongside real screenshots, newest first, so a
  // gap in the gallery reads as "screenshot deliberately skipped" rather than
  // just... missing. Marked with skipped:true; no filename (there's no image).
  const merged = [
    ...shots.map(s => ({ ...s, skipped: false })),
    ...skips.map(s => ({ ...s, skipped: true, filename: null, screenName: null })),
  ].sort((a, b) => new Date(b.ts) - new Date(a.ts));
  res.json(merged);
});

// ── Evidence export ─────────────────────────────────────────────────────────
// Downloadable reports/screenshots "for evidence if needed" — reuses the exact same
// range + visibility scoping as the on-screen views above, just rendered to a file.
function csvEscape(v) {
  if (v === null || v === undefined) return '';
  let s = String(v);
  // Neutralize formula injection: a value starting with =, +, -, or @ is
  // interpreted as a live formula by Excel/Sheets when the CSV is opened,
  // and project/task names are free text any employee can set. Prefixing
  // with an apostrophe forces it to be read as plain text.
  if (/^[=+\-@]/.test(s)) s = `'${s}`;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

app.get('/api/reports/export', auth, managerOrAbove, (req, res) => {
  const { from, to } = resolveRange(req);
  let entries = db.listEntriesByOrg(req.user.organizationId, { from, to });
  if (req.user.role === 'manager') {
    const ids = visibleEmployeeIds(db.listUsersByOrg(req.user.organizationId), req.user);
    ids.add(req.user.id);
    entries = entries.filter(e => ids.has(e.userId));
  }
  entries = entries.slice().sort((a, b) => new Date(a.startTime) - new Date(b.startTime));

  const format = req.query.format === 'pdf' ? 'pdf' : 'csv';
  const rangeLabel = from === to ? from : `${from}_to_${to}`;

  // Consent is a per-person attribute, not a per-entry one — look each
  // employee up once rather than re-fetching per row.
  const usersById = new Map(db.listUsersByOrg(req.user.organizationId).map(u => [u.id, u]));
  const consentFor = userId => usersById.get(userId) || {};

  if (format === 'csv') {
    const header = ['Employee', 'Project', 'Task', 'Start', 'End', 'Duration (min)', 'Activity Score', 'Screenshots', 'Status', 'Consent Recorded', 'Consent Recorded By', 'Consent Note'];
    const rows = entries.map(e => {
      const c = consentFor(e.userId);
      return [
        e.userName, e.project, e.task, e.startTime, e.endTime || '',
        e.durationMs ? Math.round(e.durationMs / 60000) : '', e.activityScore ?? '', e.screenshotCount || 0, e.status,
        c.consentRecordedAt || '', c.consentRecordedBy || '', c.consentNote || '',
      ];
    });
    const csv = [header, ...rows].map(r => r.map(csvEscape).join(',')).join('\r\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="wachadoin-report-${rangeLabel}.csv"`);
    return res.send(csv);
  }

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="wachadoin-report-${rangeLabel}.pdf"`);
  const doc = new PDFDocument({ margin: 40, size: 'A4' });
  doc.pipe(res);
  doc.fontSize(18).text('Wachadoin Activity Report', { align: 'left' });
  doc.fontSize(10).fillColor('#555').text(`Range: ${from} to ${to}  ·  Generated: ${new Date().toISOString()}`);
  doc.moveDown();

  // Consent status per employee, once — not per row, since it's a per-person
  // fact and the entry table below can have many rows per employee.
  const employeeIds = [...new Set(entries.map(e => e.userId))];
  if (employeeIds.length) {
    doc.fillColor('#000').fontSize(11).font('Helvetica-Bold').text('Monitoring consent on file');
    doc.font('Helvetica').fontSize(9);
    for (const id of employeeIds) {
      const c = consentFor(id);
      const name = c.name || entries.find(e => e.userId === id)?.userName || id;
      const status = c.consentRecordedAt
        ? `Recorded ${c.consentRecordedAt.slice(0, 10)} by ${c.consentRecordedBy || 'unknown'}${c.consentNote ? ` — "${c.consentNote}"` : ''}`
        : 'Not yet recorded';
      doc.fillColor(c.consentRecordedAt ? '#000' : '#a33').text(`${name}: ${status}`);
    }
    doc.fillColor('#000');
    doc.moveDown();
  }

  const colX = [40, 160, 260, 350, 420, 470, 520];
  const headers = ['Employee', 'Project', 'Task', 'Start', 'Mins', 'Score', 'Shots'];
  doc.fontSize(9).font('Helvetica-Bold');
  headers.forEach((h, i) => doc.text(h, colX[i], doc.y, { continued: i < headers.length - 1, width: 100 }));
  doc.moveDown(0.5);
  doc.font('Helvetica');
  for (const e of entries) {
    const y = doc.y;
    doc.text(String(e.userName || '').slice(0, 18), colX[0], y, { width: 115 });
    doc.text(String(e.project || '').slice(0, 18), colX[1], y, { width: 95 });
    doc.text(String(e.task || '').slice(0, 14), colX[2], y, { width: 65 });
    doc.text((e.startTime || '').replace('T', ' ').slice(0, 16), colX[3], y, { width: 65 });
    doc.text(e.durationMs ? String(Math.round(e.durationMs / 60000)) : '-', colX[4], y, { width: 45 });
    doc.text(e.activityScore ?? '-', colX[5], y, { width: 45 });
    doc.text(String(e.screenshotCount || 0), colX[6], y, { width: 40 });
    doc.moveDown(0.3);
    if (doc.y > 760) doc.addPage();
  }
  if (entries.length === 0) doc.fontSize(10).fillColor('#777').text('No entries in this range.');
  doc.end();
});

// ── Superadmin: manage client organizations & subscriptions ────────────────
// Deliberately metadata-only (plan, seats, status) — never touches an org's users,
// entries, or activity data. Real billing automation is Phase 2; for now plan/status
// changes here are the manual lever until a payment gateway is wired up.
app.get('/api/admin/orgs', auth, superAdminOnly, (req, res) => {
  const orgs = db.listOrgs().filter(o => o.id !== PLATFORM_ORG_ID);
  res.json(orgs.map(o => {
    const users = db.listUsersByOrg(o.id);
    return {
      id: o.id, name: o.name, plan: o.plan, status: o.status, seatLimit: o.seatLimit,
      permanentScreenshots: o.permanentScreenshots, billingCycle: o.billingCycle, createdAt: o.createdAt,
      trialEndsAt: o.trialEndsAt, cancelRequestedAt: o.cancelRequestedAt, accessUntil: o.accessUntil,
      managerCount: users.filter(u => u.role === 'manager' || u.role === 'partner').length,
      employeeCount: users.filter(u => u.role === 'employee' && u.active !== false).length,
    };
  }));
});

const ADMIN_PLANS = new Set(['starter', 'growth', 'firm', 'legacy-internal', 'trial']);
const ADMIN_STATUSES = new Set(['trialing', 'active', 'past_due', 'canceled', 'internal']);
const ADMIN_BILLING_CYCLES = new Set(['monthly', 'annual']);
app.patch('/api/admin/orgs/:id', auth, superAdminOnly, (req, res) => {
  const org = db.getOrg(req.params.id);
  if (!org || org.id === PLATFORM_ORG_ID) return res.status(404).json({ error: 'Organization not found' });
  const { plan, seatLimit, permanentScreenshots, status, billingCycle } = req.body;
  if (plan !== undefined && !ADMIN_PLANS.has(plan)) return res.status(400).json({ error: 'Invalid plan' });
  if (status !== undefined && !ADMIN_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid status' });
  if (billingCycle !== undefined && !ADMIN_BILLING_CYCLES.has(billingCycle)) return res.status(400).json({ error: 'Invalid billing cycle' });
  const nextStatus = status ?? org.status;
  const nextBillingCycle = billingCycle ?? org.billingCycle;
  // No pro-rata refunds: cancelling doesn't cut an org off immediately, it just locks in
  // the date their current term (month or year, from whichever billing cycle is in
  // effect right now) runs out — access continues until then (enforced in auth() and
  // the login route above). Only stamp this the moment status actually *becomes*
  // 'canceled'; re-saving an already-canceled org must not push accessUntil forward.
  // Reactivating (status moving away from 'canceled') clears both fields again.
  let cancelRequestedAt = org.cancelRequestedAt;
  let accessUntil = org.accessUntil;
  if (nextStatus === 'canceled' && org.status !== 'canceled') {
    cancelRequestedAt = new Date().toISOString();
    accessUntil = computeAccessUntil({ ...org, billingCycle: nextBillingCycle }, new Date());
  } else if (nextStatus !== 'canceled' && org.status === 'canceled') {
    cancelRequestedAt = null;
    accessUntil = null;
  }
  const updated = db.updateOrg({
    id: org.id, name: org.name,
    plan: plan ?? org.plan,
    seatLimit: seatLimit !== undefined ? seatLimit : org.seatLimit,
    permanentScreenshots: permanentScreenshots !== undefined ? !!permanentScreenshots : org.permanentScreenshots,
    status: nextStatus,
    billingCycle: nextBillingCycle,
    trialEndsAt: org.trialEndsAt,
    cancelRequestedAt, accessUntil,
  });
  res.json(updated);
});

// ── Start ──────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Wachadoin.com running on port ${PORT}`);
});

server.on('error', err => {
  console.error('[server error]', err);
  process.exit(1);
});
