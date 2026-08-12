// ── SQLite storage layer ──────────────────────────────────────────────────
// Replaces the old "read the whole JSON file, mutate it in memory, write the
// whole file back" pattern (timetrack.json / activity.json). That was fine
// for one organization's data; it stops being fine once there are many paying
// client organizations retaining 12 months of activity history — every
// request would otherwise deserialize and re-serialize *everyone's* data.
//
// This module keeps the same shape of data the rest of the app already
// works with (plain camelCase JS objects/arrays) so server.js's existing
// filter/map/visibility logic barely changes — it just calls a scoped loader
// (e.g. listUsersByOrg(orgId)) instead of loadDB().users, and SQLite does the
// per-organization + per-date-range filtering via indexed columns instead of
// scanning one giant in-memory array on every request.
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

function genAgentToken() {
  return 'wag_' + crypto.randomBytes(24).toString('hex');
}

function open(dataDir) {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'wachadoin.db'));
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'trial',
      seatLimit INTEGER,
      permanentScreenshots INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'trialing',
      createdAt TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      organizationId TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      passwordHash TEXT,
      role TEXT NOT NULL,
      managerId TEXT,
      agentToken TEXT UNIQUE,
      active INTEGER NOT NULL DEFAULT 1,
      deactivatedAt TEXT,
      popiaAcknowledgedAt TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_users_org ON users(organizationId);
    CREATE INDEX IF NOT EXISTS idx_users_agentToken ON users(agentToken);

    CREATE TABLE IF NOT EXISTS entries (
      id TEXT PRIMARY KEY,
      organizationId TEXT NOT NULL,
      userId TEXT NOT NULL,
      userName TEXT,
      project TEXT,
      task TEXT,
      startTime TEXT,
      endTime TEXT,
      durationMs INTEGER,
      activityScore INTEGER,
      activeMs INTEGER,
      idleMs INTEGER,
      screenshotCount INTEGER DEFAULT 0,
      status TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_entries_org_start ON entries(organizationId, startTime);
    CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(userId);

    CREATE TABLE IF NOT EXISTS heartbeats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizationId TEXT NOT NULL,
      userId TEXT NOT NULL,
      userName TEXT,
      activityScore INTEGER,
      idleSecs INTEGER,
      isIdle INTEGER,
      ts TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_hb_org_ts ON heartbeats(organizationId, ts);
    CREATE INDEX IF NOT EXISTS idx_hb_user_ts ON heartbeats(userId, ts);

    CREATE TABLE IF NOT EXISTS app_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizationId TEXT NOT NULL,
      userId TEXT NOT NULL,
      userName TEXT,
      appName TEXT,
      title TEXT,
      category TEXT,
      ts TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_app_org_ts ON app_events(organizationId, ts);
    CREATE INDEX IF NOT EXISTS idx_app_user_ts ON app_events(userId, ts);

    CREATE TABLE IF NOT EXISTS screenshots (
      filename TEXT PRIMARY KEY,
      organizationId TEXT NOT NULL,
      userId TEXT NOT NULL,
      userName TEXT,
      screenIndex INTEGER,
      screenName TEXT,
      ts TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_shots_org_ts ON screenshots(organizationId, ts);
    CREATE INDEX IF NOT EXISTS idx_shots_user_ts ON screenshots(userId, ts);

    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      organizationId TEXT NOT NULL,
      pattern TEXT NOT NULL,
      category TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rules_org ON rules(organizationId);

    -- One row per screenshot the Agent deliberately skipped because a
    -- 'sensitive' rule matched the focused app/window — no image ever
    -- existed for these. Kept separate from 'screenshots' (rather than a
    -- nullable-filename row there) so the two stay simple: 'screenshots' is
    -- always a real, existing file on disk.
    CREATE TABLE IF NOT EXISTS screenshot_skips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizationId TEXT NOT NULL,
      userId TEXT NOT NULL,
      userName TEXT,
      appName TEXT,
      title TEXT,
      ts TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_shot_skips_org_ts ON screenshot_skips(organizationId, ts);
    CREATE INDEX IF NOT EXISTS idx_shot_skips_user_ts ON screenshot_skips(userId, ts);

    CREATE TABLE IF NOT EXISTS alert_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizationId TEXT NOT NULL,
      recipientId TEXT NOT NULL,
      employeeId TEXT NOT NULL,
      alertType TEXT NOT NULL,
      detail TEXT,
      firedAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_alert_log_lookup ON alert_log(recipientId, employeeId, alertType, firedAt);
  `);

  // ── Migrations (additive-only ALTER TABLEs against existing installs) ─────
  // CREATE TABLE IF NOT EXISTS above never touches a table that already exists,
  // so new columns on a pre-existing `users` table (i.e. any production install
  // that predates a given feature) need to be added explicitly here. Every one
  // of these is nullable, so old rows just load with NULLs — nothing backfills.
  function ensureColumn(table, col, type) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
    if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
  }
  // Shared by password reset and manager invites (single-use token hash + expiry).
  ensureColumn('users', 'resetTokenHash', 'TEXT');
  ensureColumn('users', 'resetTokenExpiresAt', 'TEXT');
  // 'pending' while an invited manager hasn't set a password yet, else NULL.
  ensureColumn('users', 'inviteStatus', 'TEXT');
  // Offline consent tracking — a Partner/Manager attesting that a *subordinate*
  // (who may never log in) was told about monitoring and consented outside the
  // app. Deliberately separate from popiaAcknowledgedAt, which only ever records
  // the logged-in dashboard user acknowledging the notice for themselves.
  ensureColumn('users', 'consentRecordedAt', 'TEXT');
  ensureColumn('users', 'consentRecordedBy', 'TEXT');
  ensureColumn('users', 'consentNote', 'TEXT');
  // 'monthly' (default) or 'annual' — annual is prepaid for the year at a 10%
  // discount off the monthly rate. Metadata only, same as plan/status/seatLimit
  // above: no payment gateway exists yet, so this doesn't itself charge anyone
  // anything — it's what Acute's back office (and, later, real billing) goes by.
  ensureColumn('organizations', 'billingCycle', 'TEXT');
  // Free trials run 7 days from signup — set once, never recomputed. Purely
  // informational (the dashboard shows a banner once it passes); nothing in
  // the app blocks access when a trial expires, per Ian's call.
  ensureColumn('organizations', 'trialEndsAt', 'TEXT');
  // Cancellation is metadata-only like everything else here (no payment
  // gateway to actually stop charging), but it IS enforced in-app: there's no
  // pro-rata refund, so an org keeps (and is expected to pay for) its full
  // current term. cancelRequestedAt records when a superadmin cancelled it;
  // accessUntil is the computed end of that term, after which auth() below
  // actually cuts the org off. Both are null while status isn't 'canceled'.
  ensureColumn('organizations', 'cancelRequestedAt', 'TEXT');
  ensureColumn('organizations', 'accessUntil', 'TEXT');
  // Per-recipient alert preferences (manager/partner configuring their OWN
  // thresholds, not something set org-wide) — every column is nullable and
  // NULL means "use the platform default", resolved in lib/alerts.js's
  // resolveAlertSettings() rather than backfilled here.
  ensureColumn('users', 'alertIdleMins', 'INTEGER');
  ensureColumn('users', 'alertOfflineMins', 'INTEGER');
  ensureColumn('users', 'alertRedFlagEnabled', 'INTEGER');
  ensureColumn('users', 'alertDigestEnabled', 'INTEGER');
  ensureColumn('users', 'alertDigestDay', 'INTEGER');   // 0=Sun..6=Sat, SAST
  ensureColumn('users', 'alertDigestHour', 'INTEGER');  // 0-23, SAST
  ensureColumn('users', 'alertLastDigestSentAt', 'TEXT');

  // ── Organizations ────────────────────────────────────────────────────────
  const stmtInsertOrg = db.prepare(`INSERT INTO organizations
    (id, name, plan, seatLimit, permanentScreenshots, status, billingCycle, trialEndsAt, cancelRequestedAt, accessUntil, createdAt)
    VALUES (@id, @name, @plan, @seatLimit, @permanentScreenshots, @status, @billingCycle, @trialEndsAt, @cancelRequestedAt, @accessUntil, @createdAt)`);
  const stmtGetOrg = db.prepare(`SELECT * FROM organizations WHERE id = ?`);
  const stmtListOrgs = db.prepare(`SELECT * FROM organizations ORDER BY createdAt ASC`);
  const stmtUpdateOrg = db.prepare(`UPDATE organizations SET
    name=@name, plan=@plan, seatLimit=@seatLimit, permanentScreenshots=@permanentScreenshots, status=@status, billingCycle=@billingCycle,
    trialEndsAt=@trialEndsAt, cancelRequestedAt=@cancelRequestedAt, accessUntil=@accessUntil
    WHERE id=@id`);

  function rowToOrg(r) {
    if (!r) return null;
    return {
      ...r, permanentScreenshots: !!r.permanentScreenshots, billingCycle: r.billingCycle || 'monthly',
      trialEndsAt: r.trialEndsAt || null, cancelRequestedAt: r.cancelRequestedAt || null, accessUntil: r.accessUntil || null,
    };
  }

  function createOrg({ id, name, plan, seatLimit, permanentScreenshots, status, billingCycle, trialEndsAt }) {
    const row = {
      id: id || crypto.randomUUID(), name, plan: plan || 'trial',
      seatLimit: seatLimit ?? null, permanentScreenshots: permanentScreenshots ? 1 : 0,
      status: status || 'trialing', billingCycle: billingCycle === 'annual' ? 'annual' : 'monthly',
      trialEndsAt: trialEndsAt || null, cancelRequestedAt: null, accessUntil: null,
      createdAt: new Date().toISOString(),
    };
    stmtInsertOrg.run(row);
    return rowToOrg(row);
  }
  function getOrg(id) { return rowToOrg(stmtGetOrg.get(id)); }
  function listOrgs() { return stmtListOrgs.all().map(rowToOrg); }
  function updateOrg(org) {
    stmtUpdateOrg.run({
      ...org, permanentScreenshots: org.permanentScreenshots ? 1 : 0, billingCycle: org.billingCycle === 'annual' ? 'annual' : 'monthly',
      trialEndsAt: org.trialEndsAt || null, cancelRequestedAt: org.cancelRequestedAt || null, accessUntil: org.accessUntil || null,
    });
    return getOrg(org.id);
  }

  // ── Users ────────────────────────────────────────────────────────────────
  const stmtInsertUser = db.prepare(`INSERT INTO users
    (id, organizationId, name, email, passwordHash, role, managerId, agentToken, active, deactivatedAt, popiaAcknowledgedAt, createdAt,
     resetTokenHash, resetTokenExpiresAt, inviteStatus, consentRecordedAt, consentRecordedBy, consentNote,
     alertIdleMins, alertOfflineMins, alertRedFlagEnabled, alertDigestEnabled, alertDigestDay, alertDigestHour, alertLastDigestSentAt)
    VALUES (@id, @organizationId, @name, @email, @passwordHash, @role, @managerId, @agentToken, @active, @deactivatedAt, @popiaAcknowledgedAt, @createdAt,
     @resetTokenHash, @resetTokenExpiresAt, @inviteStatus, @consentRecordedAt, @consentRecordedBy, @consentNote,
     @alertIdleMins, @alertOfflineMins, @alertRedFlagEnabled, @alertDigestEnabled, @alertDigestDay, @alertDigestHour, @alertLastDigestSentAt)`);
  const stmtGetUserById = db.prepare(`SELECT * FROM users WHERE id = ?`);
  const stmtGetUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`);
  const stmtGetUserByAgentToken = db.prepare(`SELECT * FROM users WHERE agentToken = ?`);
  const stmtGetUserByResetToken = db.prepare(`SELECT * FROM users WHERE resetTokenHash = ?`);
  const stmtListUsersByOrg = db.prepare(`SELECT * FROM users WHERE organizationId = ?`);
  const stmtListAllUsers = db.prepare(`SELECT * FROM users`);
  const stmtUpdateUser = db.prepare(`UPDATE users SET
    name=@name, email=@email, passwordHash=@passwordHash, role=@role, managerId=@managerId,
    agentToken=@agentToken, active=@active, deactivatedAt=@deactivatedAt, popiaAcknowledgedAt=@popiaAcknowledgedAt,
    resetTokenHash=@resetTokenHash, resetTokenExpiresAt=@resetTokenExpiresAt, inviteStatus=@inviteStatus,
    consentRecordedAt=@consentRecordedAt, consentRecordedBy=@consentRecordedBy, consentNote=@consentNote,
    alertIdleMins=@alertIdleMins, alertOfflineMins=@alertOfflineMins, alertRedFlagEnabled=@alertRedFlagEnabled,
    alertDigestEnabled=@alertDigestEnabled, alertDigestDay=@alertDigestDay, alertDigestHour=@alertDigestHour,
    alertLastDigestSentAt=@alertLastDigestSentAt
    WHERE id=@id`);
  const stmtDeleteUser = db.prepare(`DELETE FROM users WHERE id = ?`);
  const stmtCountActiveEmployees = db.prepare(
    `SELECT COUNT(*) AS n FROM users WHERE organizationId = ? AND role = 'employee' AND active = 1`);

  function rowToUser(r) {
    if (!r) return null;
    return { ...r, active: !!r.active };
  }

  function insertUser(user) {
    const row = {
      id: user.id || crypto.randomUUID(),
      organizationId: user.organizationId,
      name: user.name, email: user.email.toLowerCase(),
      passwordHash: user.passwordHash || null,
      role: user.role, managerId: user.managerId || null,
      agentToken: user.agentToken || genAgentToken(),
      active: user.active === false ? 0 : 1,
      deactivatedAt: user.deactivatedAt || null,
      popiaAcknowledgedAt: user.popiaAcknowledgedAt || null,
      createdAt: user.createdAt || new Date().toISOString(),
      resetTokenHash: user.resetTokenHash || null,
      resetTokenExpiresAt: user.resetTokenExpiresAt || null,
      inviteStatus: user.inviteStatus || null,
      consentRecordedAt: user.consentRecordedAt || null,
      consentRecordedBy: user.consentRecordedBy || null,
      consentNote: user.consentNote || null,
      alertIdleMins: user.alertIdleMins ?? null,
      alertOfflineMins: user.alertOfflineMins ?? null,
      alertRedFlagEnabled: user.alertRedFlagEnabled ?? null,
      alertDigestEnabled: user.alertDigestEnabled ?? null,
      alertDigestDay: user.alertDigestDay ?? null,
      alertDigestHour: user.alertDigestHour ?? null,
      alertLastDigestSentAt: user.alertLastDigestSentAt || null,
    };
    stmtInsertUser.run(row);
    return rowToUser(row);
  }
  function findUserById(id) { return rowToUser(stmtGetUserById.get(id)); }
  function findUserByEmail(email) { return rowToUser(stmtGetUserByEmail.get(email)); }
  function findUserByAgentToken(token) { return rowToUser(stmtGetUserByAgentToken.get(token)); }
  function findUserByResetToken(hash) { return rowToUser(stmtGetUserByResetToken.get(hash)); }
  function listUsersByOrg(orgId) { return stmtListUsersByOrg.all(orgId).map(rowToUser); }
  function listAllUsers() { return stmtListAllUsers.all().map(rowToUser); }
  function updateUser(user) {
    stmtUpdateUser.run({
      ...user,
      active: user.active === false ? 0 : 1,
      resetTokenHash: user.resetTokenHash ?? null,
      resetTokenExpiresAt: user.resetTokenExpiresAt ?? null,
      inviteStatus: user.inviteStatus ?? null,
      consentRecordedAt: user.consentRecordedAt ?? null,
      consentRecordedBy: user.consentRecordedBy ?? null,
      consentNote: user.consentNote ?? null,
      alertIdleMins: user.alertIdleMins ?? null,
      alertOfflineMins: user.alertOfflineMins ?? null,
      alertRedFlagEnabled: user.alertRedFlagEnabled ?? null,
      alertDigestEnabled: user.alertDigestEnabled ?? null,
      alertDigestDay: user.alertDigestDay ?? null,
      alertDigestHour: user.alertDigestHour ?? null,
      alertLastDigestSentAt: user.alertLastDigestSentAt ?? null,
    });
    return findUserById(user.id);
  }
  function deleteUser(id) { stmtDeleteUser.run(id); }
  function countActiveEmployees(orgId) { return stmtCountActiveEmployees.get(orgId).n; }

  // ── Entries ──────────────────────────────────────────────────────────────
  const stmtInsertEntry = db.prepare(`INSERT INTO entries
    (id, organizationId, userId, userName, project, task, startTime, endTime, durationMs, activityScore, activeMs, idleMs, screenshotCount, status)
    VALUES (@id, @organizationId, @userId, @userName, @project, @task, @startTime, @endTime, @durationMs, @activityScore, @activeMs, @idleMs, @screenshotCount, @status)`);
  const stmtUpdateEntry = db.prepare(`UPDATE entries SET
    userName=@userName, project=@project, task=@task, startTime=@startTime, endTime=@endTime,
    durationMs=@durationMs, activityScore=@activityScore, activeMs=@activeMs, idleMs=@idleMs,
    screenshotCount=@screenshotCount, status=@status WHERE id=@id`);
  const stmtDeleteEntry = db.prepare(`DELETE FROM entries WHERE id = ? AND organizationId = ?`);
  const stmtFindEntryById = db.prepare(`SELECT * FROM entries WHERE id = ?`);
  const stmtFindRunning = db.prepare(`SELECT * FROM entries WHERE userId = ? AND status = 'running'`);
  const stmtListEntriesOrgRange = db.prepare(
    `SELECT * FROM entries WHERE organizationId = ? AND substr(startTime,1,10) BETWEEN ? AND ? ORDER BY startTime DESC`);
  const stmtListEntriesOrgAll = db.prepare(`SELECT * FROM entries WHERE organizationId = ? ORDER BY startTime DESC`);
  const stmtBumpShotCount = db.prepare(`UPDATE entries SET screenshotCount = screenshotCount + 1 WHERE id = ?`);

  function insertEntry(entry) { stmtInsertEntry.run(entry); return entry; }
  function updateEntry(entry) { stmtUpdateEntry.run(entry); return entry; }
  function deleteEntry(id, organizationId) { const r = stmtDeleteEntry.run(id, organizationId); return r.changes > 0; }
  function findEntryById(id) { return stmtFindEntryById.get(id); }
  function findRunningEntries(userId) { return stmtFindRunning.all(userId); }
  function listEntriesByOrg(orgId, range) {
    if (range && (range.from || range.to)) return stmtListEntriesOrgRange.all(orgId, range.from, range.to);
    return stmtListEntriesOrgAll.all(orgId);
  }
  function bumpScreenshotCount(entryId) { stmtBumpShotCount.run(entryId); }

  // ── Heartbeats ───────────────────────────────────────────────────────────
  const stmtInsertHb = db.prepare(`INSERT INTO heartbeats
    (organizationId, userId, userName, activityScore, idleSecs, isIdle, ts)
    VALUES (@organizationId, @userId, @userName, @activityScore, @idleSecs, @isIdle, @ts)`);
  const stmtListHbOrgRange = db.prepare(
    `SELECT * FROM heartbeats WHERE organizationId = ? AND substr(ts,1,10) BETWEEN ? AND ? ORDER BY ts ASC`);
  const stmtLatestHbPerUser = db.prepare(`
    SELECT h.* FROM heartbeats h
    JOIN (SELECT userId, MAX(ts) AS maxTs FROM heartbeats WHERE organizationId = ? GROUP BY userId) m
      ON h.userId = m.userId AND h.ts = m.maxTs`);
  const stmtPruneHb = db.prepare(`DELETE FROM heartbeats WHERE organizationId = ? AND ts < ?`);

  function insertHeartbeat(row) { stmtInsertHb.run({ ...row, isIdle: row.isIdle ? 1 : 0 }); }
  function listHeartbeatsByOrgRange(orgId, from, to) {
    return stmtListHbOrgRange.all(orgId, from, to).map(r => ({ ...r, isIdle: !!r.isIdle }));
  }
  function latestHeartbeatsByOrg(orgId) {
    return stmtLatestHbPerUser.all(orgId).map(r => ({ ...r, isIdle: !!r.isIdle }));
  }
  function pruneHeartbeats(orgId, cutoffIso) { stmtPruneHb.run(orgId, cutoffIso); }

  // ── App events ───────────────────────────────────────────────────────────
  const stmtInsertApp = db.prepare(`INSERT INTO app_events
    (organizationId, userId, userName, appName, title, category, ts)
    VALUES (@organizationId, @userId, @userName, @appName, @title, @category, @ts)`);
  const stmtListAppOrgRange = db.prepare(
    `SELECT * FROM app_events WHERE organizationId = ? AND substr(ts,1,10) BETWEEN ? AND ? ORDER BY ts ASC`);
  const stmtLatestAppPerUser = db.prepare(`
    SELECT a.* FROM app_events a
    JOIN (SELECT userId, MAX(ts) AS maxTs FROM app_events WHERE organizationId = ? GROUP BY userId) m
      ON a.userId = m.userId AND a.ts = m.maxTs`);
  const stmtPruneApp = db.prepare(`DELETE FROM app_events WHERE organizationId = ? AND ts < ?`);

  function insertAppEvent(row) { stmtInsertApp.run(row); }
  function listAppEventsByOrgRange(orgId, from, to) { return stmtListAppOrgRange.all(orgId, from, to); }
  function latestAppEventsByOrg(orgId) { return stmtLatestAppPerUser.all(orgId); }
  function pruneAppEvents(orgId, cutoffIso) { stmtPruneApp.run(orgId, cutoffIso); }

  // ── Screenshots ──────────────────────────────────────────────────────────
  const stmtInsertShot = db.prepare(`INSERT INTO screenshots
    (filename, organizationId, userId, userName, screenIndex, screenName, ts)
    VALUES (@filename, @organizationId, @userId, @userName, @screenIndex, @screenName, @ts)`);
  const stmtListShotsOrgRange = db.prepare(
    `SELECT * FROM screenshots WHERE organizationId = ? AND substr(ts,1,10) BETWEEN ? AND ? ORDER BY ts DESC`);
  const stmtListShotsOrgRecent = db.prepare(
    `SELECT * FROM screenshots WHERE organizationId = ? ORDER BY ts DESC LIMIT ?`);
  const stmtDeleteShot = db.prepare(`DELETE FROM screenshots WHERE filename = ?`);
  const stmtExpiredShots = db.prepare(`SELECT filename FROM screenshots WHERE organizationId = ? AND ts < ?`);

  function insertScreenshotRecord(row) { stmtInsertShot.run(row); }
  function listScreenshotsByOrgRange(orgId, from, to) { return stmtListShotsOrgRange.all(orgId, from, to); }
  function listRecentScreenshotsByOrg(orgId, limit) { return stmtListShotsOrgRecent.all(orgId, limit || 50); }
  function deleteScreenshotRecord(filename) { stmtDeleteShot.run(filename); }
  function expiredScreenshotFilenames(orgId, cutoffIso) { return stmtExpiredShots.all(orgId, cutoffIso).map(r => r.filename); }

  // ── Screenshot skips ─────────────────────────────────────────────────────
  const stmtInsertShotSkip = db.prepare(`INSERT INTO screenshot_skips
    (organizationId, userId, userName, appName, title, ts)
    VALUES (@organizationId, @userId, @userName, @appName, @title, @ts)`);
  const stmtListShotSkipsOrgRange = db.prepare(
    `SELECT * FROM screenshot_skips WHERE organizationId = ? AND substr(ts,1,10) BETWEEN ? AND ? ORDER BY ts DESC`);
  const stmtPruneShotSkips = db.prepare(`DELETE FROM screenshot_skips WHERE organizationId = ? AND ts < ?`);

  function insertScreenshotSkip(row) { stmtInsertShotSkip.run(row); }
  function listScreenshotSkipsByOrgRange(orgId, from, to) { return stmtListShotSkipsOrgRange.all(orgId, from, to); }
  function pruneScreenshotSkips(orgId, cutoffIso) { stmtPruneShotSkips.run(orgId, cutoffIso); }

  // ── Rules ────────────────────────────────────────────────────────────────
  const stmtInsertRule = db.prepare(`INSERT INTO rules (id, organizationId, pattern, category) VALUES (@id, @organizationId, @pattern, @category)`);
  const stmtListRules = db.prepare(`SELECT * FROM rules WHERE organizationId = ?`);
  const stmtDeleteRulesForOrg = db.prepare(`DELETE FROM rules WHERE organizationId = ?`);

  function insertRule(rule) { stmtInsertRule.run(rule); }
  function listRules(orgId) { return stmtListRules.all(orgId); }
  function replaceRules(orgId, rules) {
    const tx = db.transaction((rows) => {
      stmtDeleteRulesForOrg.run(orgId);
      for (const r of rows) stmtInsertRule.run(r);
    });
    tx(rules);
  }

  // ── Alert log ────────────────────────────────────────────────────────────
  // One row per alert email actually fired (or attempted) — used both to
  // throttle repeat real-time alerts for the same ongoing condition (see
  // lastAlertFiredAt, used as a cooldown gate in server.js) and to build each
  // recipient's weekly digest counts.
  const stmtInsertAlertLog = db.prepare(`INSERT INTO alert_log
    (organizationId, recipientId, employeeId, alertType, detail, firedAt)
    VALUES (@organizationId, @recipientId, @employeeId, @alertType, @detail, @firedAt)`);
  const stmtLastAlertFiredAt = db.prepare(
    `SELECT MAX(firedAt) AS t FROM alert_log WHERE recipientId = ? AND employeeId = ? AND alertType = ?`);
  const stmtAlertCountsSince = db.prepare(
    `SELECT employeeId, alertType, COUNT(*) AS c FROM alert_log
     WHERE recipientId = ? AND firedAt >= ? GROUP BY employeeId, alertType`);

  function insertAlertLog(row) { stmtInsertAlertLog.run(row); }
  function lastAlertFiredAt(recipientId, employeeId, alertType) {
    return stmtLastAlertFiredAt.get(recipientId, employeeId, alertType)?.t || null;
  }
  function alertCountsForRecipientSince(recipientId, sinceIso) {
    return stmtAlertCountsSince.all(recipientId, sinceIso);
  }

  return {
    raw: db,
    createOrg, getOrg, listOrgs, updateOrg,
    insertUser, findUserById, findUserByEmail, findUserByAgentToken, findUserByResetToken, listUsersByOrg, listAllUsers, updateUser, deleteUser, countActiveEmployees,
    insertEntry, updateEntry, deleteEntry, findEntryById, findRunningEntries, listEntriesByOrg, bumpScreenshotCount,
    insertHeartbeat, listHeartbeatsByOrgRange, latestHeartbeatsByOrg, pruneHeartbeats,
    insertAppEvent, listAppEventsByOrgRange, latestAppEventsByOrg, pruneAppEvents,
    insertScreenshotRecord, listScreenshotsByOrgRange, listRecentScreenshotsByOrg, deleteScreenshotRecord, expiredScreenshotFilenames,
    insertScreenshotSkip, listScreenshotSkipsByOrgRange, pruneScreenshotSkips,
    insertRule, listRules, replaceRules,
    insertAlertLog, lastAlertFiredAt, alertCountsForRecipientSince,
  };
}

module.exports = { open, genAgentToken };
