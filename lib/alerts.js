// ── Alert-settings resolution & pure scheduling/calculation helpers ─────────
// Every alert preference lives on the `users` row of the manager/partner who
// receives the alert (see db.js ensureColumn calls) and is nullable — NULL
// means "hasn't customized this, use the platform default" rather than
// backfilling every existing account the moment this feature ships.

const ALERT_DEFAULTS = {
  idleMins: 20,          // alert if idle this many minutes or more
  offlineMins: 1440,     // 24h — Ian's call: default is a full day, weekends don't count against it
  redFlagEnabled: true,
  digestEnabled: true,
  digestDay: 1,          // 0=Sun..6=Sat — Monday
  digestHour: 8,          // 0-23, SAST (see SAST_OFFSET_HOURS below)
};

// South Africa has no daylight saving, so SAST is a fixed UTC+2 offset — used
// below both to align "weekend" day boundaries and to match digest day/hour
// against what a manager configured, since both are meant in local time.
const SAST_OFFSET_HOURS = 2;
const SAST_OFFSET_HOURS_MS = SAST_OFFSET_HOURS * 60 * 60 * 1000;

function resolveAlertSettings(user) {
  const b = (v, fallback) => (v === null || v === undefined ? fallback : !!v);
  return {
    idleMins: user?.alertIdleMins ?? ALERT_DEFAULTS.idleMins,
    offlineMins: user?.alertOfflineMins ?? ALERT_DEFAULTS.offlineMins,
    redFlagEnabled: b(user?.alertRedFlagEnabled, ALERT_DEFAULTS.redFlagEnabled),
    digestEnabled: b(user?.alertDigestEnabled, ALERT_DEFAULTS.digestEnabled),
    digestDay: user?.alertDigestDay ?? ALERT_DEFAULTS.digestDay,
    digestHour: user?.alertDigestHour ?? ALERT_DEFAULTS.digestHour,
  };
}

// Elapsed time between two ISO timestamps, walked in 24h chunks with any
// chunk landing on a Saturday/Sunday (UTC day-of-week) excluded entirely.
// This is a deliberate approximation, not precise business-hour tracking —
// it implements Ian's ask ("24 hours offline, except weekends don't count
// against it") without needing a per-org working-hours configuration. Good
// enough for a threshold check that only runs every few minutes; not meant
// to be exact to the second.
//
// Chunks are aligned to SAST (see SAST_OFFSET_HOURS below) calendar-day
// midnight boundaries, not walked in raw 24h steps from an arbitrary start —
// an earlier version did that and badly overcounted (e.g. a Friday-17:00 to
// Monday-07:00 gap came out as a full 24h "business time" instead of the
// correct ~14h, because the first 24h chunk straddled into Saturday but was
// still classified by its Friday start).
function weekendAdjustedElapsedMs(fromIso, toIso) {
  const SHIFT = SAST_OFFSET_HOURS_MS;
  let cursor = new Date(fromIso).getTime() + SHIFT; // shift into SAST so day boundaries below land on SAST midnight
  const to = new Date(toIso).getTime() + SHIFT;
  if (!(cursor < to)) return 0;
  let elapsed = 0;
  while (cursor < to) {
    const d = new Date(cursor);
    const nextMidnight = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
    const chunkEnd = Math.min(to, nextMidnight);
    const day = d.getUTCDay(); // 0=Sun..6=Sat, of the (shifted) calendar day this chunk falls in
    if (day !== 0 && day !== 6) elapsed += (chunkEnd - cursor);
    cursor = chunkEnd;
  }
  return elapsed;
}

// True at most once per matching SAST calendar day — `lastSentAtIso` (the
// recipient's alertLastDigestSentAt) guards against sending twice if the
// hourly sweep ticks more than once inside the matching hour (e.g. a restart).
function isDigestDueNow(settings, now, lastSentAtIso) {
  if (!settings.digestEnabled) return false;
  const sast = new Date(now.getTime() + SAST_OFFSET_HOURS * 60 * 60 * 1000);
  if (sast.getUTCDay() !== settings.digestDay) return false;
  if (sast.getUTCHours() !== settings.digestHour) return false;
  if (lastSentAtIso) {
    const lastSast = new Date(new Date(lastSentAtIso).getTime() + SAST_OFFSET_HOURS * 60 * 60 * 1000);
    if (lastSast.toISOString().slice(0, 10) === sast.toISOString().slice(0, 10)) return false;
  }
  return true;
}

module.exports = { ALERT_DEFAULTS, resolveAlertSettings, weekendAdjustedElapsedMs, isDigestDueNow, SAST_OFFSET_HOURS };
