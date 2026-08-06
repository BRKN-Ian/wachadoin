'use strict';
/*
 * Wachadoin Agent — background monitoring agent.
 *
 * Installed once on an employee's Windows or Mac computer. After a one-time setup
 * (paste in the server URL + Agent Key from the manager's dashboard), it:
 *   - launches automatically every time the computer starts, with no UI and no login
 *   - takes a periodic screenshot of the screen(s)
 *   - reports the active window's app name + title (covers browser tabs/site names)
 *   - reports idle time / an activity heartbeat
 * ...to the existing Wachadoin server API, using a long-lived Agent Key instead of a
 * normal user login. It never asks the employee to sign in.
 */

const { app, Tray, Menu, BrowserWindow, ipcMain, powerMonitor, nativeImage } = require('electron');
const fs = require('fs');
const p  = require('path');

const CONFIG_PATH = () => p.join(app.getPath('userData'), 'config.json');

const INTERVALS = {
  heartbeatMs:  30 * 1000,       // idle/activity ping
  activeWinMs:  30 * 1000,       // active app/window title
  screenshotMs: 10 * 60 * 1000,  // screenshot cadence — matches the dashboard's "every ~15 min" framing closely enough
};

const IDLE_THRESHOLD_SECS = 5 * 60; // matches server's existing 5-min idle convention

let tray = null;
let setupWin = null;
let heartbeatTimer = null;
let activeWinTimer = null;
let screenshotTimer = null;
let config = null; // { serverUrl, agentToken, employeeName }

// ── Config ──────────────────────────────────────────────────────────────────
function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH(), 'utf8'));
  } catch {
    return null;
  }
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH(), JSON.stringify(cfg, null, 2));
}

// ── Server calls ────────────────────────────────────────────────────────────
async function postActivity(body) {
  if (!config) return;
  try {
    const res = await fetch(`${config.serverUrl}/api/activity`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.agentToken}` },
      body: JSON.stringify(body),
    });
    if (res.status === 401) {
      // Key was regenerated/revoked server-side — stop and ask for a fresh one.
      stopAllTimers();
      config = null;
      fs.existsSync(CONFIG_PATH()) && fs.unlinkSync(CONFIG_PATH());
      showSetupWindow('Your Agent Key was revoked or is no longer valid. Enter a new one to keep monitoring running.');
    }
  } catch (e) {
    // Offline / server unreachable — just skip this tick, next interval will retry.
    console.error('[wachadoin-agent] post failed:', e.message);
  }
}

async function testConnection(serverUrl, agentToken) {
  try {
    const res = await fetch(`${serverUrl}/api/activity`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ type: 'heartbeat', activityScore: 100, idleSecs: 0, isIdle: false }),
    });
    if (res.ok) return { ok: true };
    const j = await res.json().catch(() => ({}));
    return { ok: false, error: j.error || `Server responded ${res.status}` };
  } catch (e) {
    return { ok: false, error: `Could not reach server: ${e.message}` };
  }
}

// ── Monitoring loops ─────────────────────────────────────────────────────────
function startMonitoring() {
  stopAllTimers();

  heartbeatTimer = setInterval(() => {
    const idleSecs = powerMonitor.getSystemIdleTime();
    const isIdle = idleSecs > IDLE_THRESHOLD_SECS;
    // Simple, defensible activity score: 100 when clearly active, decaying as idle time grows,
    // floored at 0. No keystroke/mouse-content capture — just presence/absence of input.
    const activityScore = isIdle ? 0 : Math.max(0, 100 - Math.round((idleSecs / IDLE_THRESHOLD_SECS) * 100));
    postActivity({ type: 'heartbeat', activityScore, idleSecs, isIdle });
  }, INTERVALS.heartbeatMs);

  activeWinTimer = setInterval(async () => {
    try {
      const getActiveWindow = require('./activeWindow');
      const win = await getActiveWindow();
      if (win) postActivity({ type: 'app', appName: win.appName, title: win.title });
    } catch (e) {
      console.error('[wachadoin-agent] active window lookup failed:', e.message);
    }
  }, INTERVALS.activeWinMs);

  screenshotTimer = setInterval(async () => {
    try {
      const screenshot = require('screenshot-desktop');
      const displays = await screenshot.listDisplays();
      for (let i = 0; i < displays.length; i++) {
        const buf = await screenshot({ screen: displays[i].id, format: 'jpg' });
        postActivity({
          type: 'screenshot',
          base64: buf.toString('base64'),
          screenIndex: i + 1,
          screenName: `Screen ${i + 1}`,
        });
      }
    } catch (e) {
      console.error('[wachadoin-agent] screenshot failed:', e.message);
    }
  }, INTERVALS.screenshotMs);
}

function stopAllTimers() {
  [heartbeatTimer, activeWinTimer, screenshotTimer].forEach(t => t && clearInterval(t));
  heartbeatTimer = activeWinTimer = screenshotTimer = null;
}

// ── Setup window (first run, or re-entry of a new key) ───────────────────────
function showSetupWindow(message) {
  if (setupWin) { setupWin.show(); setupWin.focus(); return; }
  setupWin = new BrowserWindow({
    width: 480, height: 560, resizable: false, minimizable: false, maximizable: false,
    title: 'Wachadoin Agent — Setup',
    webPreferences: { preload: p.join(__dirname, 'preload.js'), contextIsolation: true },
  });
  setupWin.setMenuBarVisibility(false);
  setupWin.loadFile(p.join(__dirname, 'setup.html'));
  setupWin.once('ready-to-show', () => {
    if (message) setupWin.webContents.send('setup:message', message);
  });
  setupWin.on('closed', () => { setupWin = null; });
}

ipcMain.handle('setup:test', async (_e, { serverUrl, agentToken }) => testConnection(serverUrl.replace(/\/+$/, ''), agentToken));

ipcMain.handle('setup:save', async (_e, { serverUrl, agentToken, employeeName }) => {
  serverUrl = serverUrl.replace(/\/+$/, '');
  const result = await testConnection(serverUrl, agentToken);
  if (!result.ok) return result;
  config = { serverUrl, agentToken, employeeName: employeeName || '' };
  saveConfig(config);
  app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true });
  startMonitoring();
  buildTray();
  if (setupWin) { setupWin.close(); }
  return { ok: true };
});

// ── Tray ──────────────────────────────────────────────────────────────────────
function buildTray() {
  if (tray) return;
  const icon = nativeImage.createFromPath(p.join(__dirname, 'build', 'tray.png'));
  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon);
  tray.setToolTip('Wachadoin Agent — running');
  refreshTrayMenu();
}
function refreshTrayMenu() {
  if (!tray) return;
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: config?.employeeName ? `Signed in as ${config.employeeName}` : 'Wachadoin Agent', enabled: false },
    { label: 'Status: reporting to ' + (config?.serverUrl || '—'), enabled: false },
    { type: 'separator' },
    { label: 'Re-enter Agent Key…', click: () => showSetupWindow() },
    { label: 'Quit Wachadoin Agent', click: () => { app.quit(); } },
  ]));
}

// ── Boot ──────────────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  app.dock && app.dock.hide(); // macOS: no dock icon, tray-only
  config = loadConfig();
  if (config && config.serverUrl && config.agentToken) {
    startMonitoring();
    buildTray();
  } else {
    showSetupWindow();
  }
});

app.on('window-all-closed', () => {
  // Keep running in the tray even with no windows open — that's the whole point.
});
