# Wachadoin Agent

The background agent that runs on an employee's Windows or Mac computer so
Wachadoin can track activity without anyone logging in day-to-day. It starts
automatically when the computer turns on, sits quietly in the system
tray/menu bar, and reports to your existing Wachadoin server using a
long-lived **Agent Key** (generated per employee from the "Team Members"
page in the dashboard) instead of a normal user login.

## What it does

- **Screenshots** — every 10 minutes, of every connected screen.
- **Active window** — every 30 seconds, the app name + window title of
  whatever's focused. For a browser this is usually the page/site title
  (e.g. "Xero – Dashboard — Google Chrome"), which is what powers the
  Monitoring Rules (work vs. red-flag) feature on the dashboard.
- **Idle/activity heartbeat** — every 30 seconds, using the OS's own idle-time
  API (no keystroke or mouse-content capture — just presence/absence of
  input).

All three post to the same `/api/activity` endpoint the dashboard already
uses; nothing on the server side changed except adding the Agent Key
authentication path.

## One-time setup (per employee machine)

1. In the dashboard, go to **Team Members** → click **Agent Key** next to
   the employee → copy the **Server URL** and **Agent Key**.
2. Install the agent on their computer (see Installers below) and paste
   those two values into the one-time setup window that appears on first
   launch.
3. Done. It now starts automatically every time the computer boots.

If a laptop is lost or someone leaves, click **Regenerate key** in that same
modal — the old key stops working immediately.

### macOS permissions

The first time it tries to capture a screenshot, macOS will prompt for
**Screen Recording** permission (System Settings → Privacy & Security →
Screen Recording) — this is required by Apple for any app that captures the
screen and only needs to be granted once. Reading the active window's title
also needs **Accessibility** permission granted the same way. Until both are
granted, the agent keeps running and reporting heartbeats — it just won't
have screenshot/window data until permission is given.

## Building the installers

This can't be fully built or tested from this project's Linux sandbox — a
real `.dmg` needs to be built on a Mac, and while a Windows `.exe` can
sometimes be cross-built with Wine, doing it on a real Windows machine is far
more reliable. Two ways to get real installers:

**Option A — GitHub Actions (recommended, no local setup):**
Push this `agent/` folder to a GitHub repo and the included
`.github/workflows/build.yml` builds both automatically on GitHub's own
Windows and Mac runners. Download the finished installers from the run's
Artifacts tab.

**Option B — build locally on each OS:**
```
npm install
npm run dist:win     # on a Windows machine — produces release/WachadoinAgent-Setup-1.0.0.exe
npm run dist:mac      # on a Mac — produces release/WachadoinAgent-1.0.0.dmg
```

### Code signing (not set up yet)

The build config produces **unsigned** installers. That means:
- **Windows**: SmartScreen will show an "Unknown publisher" warning on first
  run (users click "More info" → "Run anyway"). Fine for internal rollout to
  your own staff; a code-signing certificate (~R2,000–R6,000/year from a CA)
  removes this warning.
- **Mac**: Gatekeeper will block the unsigned `.app` unless the employee
  right-clicks → Open the first time. An Apple Developer ID certificate
  ($99/year) plus notarization removes this. Add `CSC_LINK` /
  `CSC_KEY_PASSWORD` (Mac) or `WIN_CSC_LINK` / `WIN_CSC_KEY_PASSWORD`
  (Windows) as GitHub Actions secrets once you have certificates, and
  electron-builder picks them up automatically — no code changes needed.

## Files

- `main.js` — Electron main process: config, tray, timers, posting to the API.
- `activeWindow.js` — cross-platform "what window is focused" helper. Shells
  out to PowerShell (Windows) / AppleScript (Mac) rather than a native Node
  module, specifically so it doesn't need per-Electron-version native
  rebuilding — a common source of breakage that's hard to debug without a
  physical machine of each OS to test on.
- `setup.html` / `preload.js` — the one-time setup window.
- `build/` — app icons (generated from your logo) for the installers and tray.
