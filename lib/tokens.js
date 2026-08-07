// ── Single-use, short-expiry tokens ───────────────────────────────────────
// Shared by password reset and manager invites. Deliberately NOT a JWT: we
// need to revoke a token the instant it's used (a JWT stays "valid" until it
// expires, with no built-in single-use tracking), so instead we store a hash
// of a random value on the user's row and null it out on successful use.
//
// The raw token already has 256 bits of entropy from crypto.randomBytes, so a
// plain SHA-256 hash (not bcrypt) is the right tool here — there's no
// low-entropy-secret brute-force risk to slow down against, we just don't
// want the raw value sitting in the database in plaintext.
const crypto = require('crypto');

function issueToken() {
    const raw = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, hash };
}

function hashToken(raw) {
    return crypto.createHash('sha256').update(raw).digest('hex');
}

// Verifies a raw token against a stored hash + ISO expiry string. Returns
// true/false — callers are responsible for nulling out the stored
// hash/expiry on the user row once they've honored a successful verification,
// so the token can't be replayed.
function verifyToken(raw, storedHash, expiresAtIso) {
    if (!raw || !storedHash || !expiresAtIso) return false;
    if (new Date(expiresAtIso).getTime() < Date.now()) return false;
    const incomingHash = Buffer.from(hashToken(raw), 'hex');
    const stored = Buffer.from(storedHash, 'hex');
    if (incomingHash.length !== stored.length) return false;
    return crypto.timingSafeEqual(incomingHash, stored);
}

// ── Minimal in-memory rate limiter ────────────────────────────────────────
// The app has no rate limiting anywhere today. These two endpoints are the
// first to hand back something sensitive (a working reset/invite link) in
// the response body, so a basic per-key cap is worth having even before a
// real dependency like express-rate-limit is worth pulling in. Resets on
// server restart — acceptable for what this is guarding.
const attempts = new Map(); // key -> array of timestamps (ms)

function rateLimited(key, { max = 5, windowMs = 15 * 60 * 1000 } = {}) {
    const now = Date.now();
    const list = (attempts.get(key) || []).filter(t => now - t < windowMs);
    list.push(now);
    attempts.set(key, list);
    return list.length > max;
}

module.exports = { issueToken, hashToken, verifyToken, rateLimited };
