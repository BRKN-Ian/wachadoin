'use strict';
/*
 * "Never screenshot a sensitive app" policy — kept as plain, dependency-free
 * logic (no 'electron' require) so it can be unit-tested with plain Node.
 * main.js (which does require 'electron', and so can only run inside an
 * Electron process) just requires this and wires it into the screenshot
 * timer.
 *
 * The actual list of sensitive app/window patterns lives server-side, per
 * organization (see GET /api/agent/config in server.js, backed by the same
 * 'rules' table the dashboard's Monitoring Rules screen edits). Only this
 * matching *mechanism* needs a new Agent build to exist at all — once it
 * ships, a firm can add or remove sensitive apps from their dashboard at any
 * time with no Agent update required.
 */

const CONFIG_REFRESH_MS = 30 * 60 * 1000; // re-fetch the org's list at most this often

let cache = { patterns: [], fetchedAt: 0 };

// Case-insensitive substring match against "<appName> <title>" — the same
// convention the server's own classify()/isSensitiveApp() use, so what the
// Agent skips matches what the dashboard calls "sensitive" for this org.
function matchesSensitivePattern(patterns, appName, title) {
  const hay = `${appName || ''} ${title || ''}`.toLowerCase();
  return (patterns || []).some(p => p && hay.includes(String(p).toLowerCase()));
}

// Fetches the org's current sensitive-app patterns, caching for
// CONFIG_REFRESH_MS. On any failure (offline, server error, not configured
// yet) it deliberately fails open — returns the last-known-good list rather
// than throwing, so a transient network blip never blocks the screenshot
// timer entirely. Before the very first successful fetch that list is empty,
// meaning screenshots behave exactly as they did before this feature existed
// until the Agent manages to reach the server at least once.
async function fetchSensitivePatterns(serverUrl, agentToken, { force = false } = {}) {
  const now = Date.now();
  if (!force && cache.fetchedAt !== 0 && (now - cache.fetchedAt) < CONFIG_REFRESH_MS) {
    return cache.patterns;
  }
  try {
    const res = await fetch(`${serverUrl}/api/agent/config`, {
      headers: { Authorization: `Bearer ${agentToken}` },
    });
    if (!res.ok) return cache.patterns;
    const body = await res.json();
    cache = { patterns: Array.isArray(body.sensitivePatterns) ? body.sensitivePatterns : [], fetchedAt: now };
    return cache.patterns;
  } catch (e) {
    return cache.patterns;
  }
}

function _resetCacheForTests() { cache = { patterns: [], fetchedAt: 0 }; }

module.exports = { matchesSensitivePattern, fetchSensitivePatterns, _resetCacheForTests };
