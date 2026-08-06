'use strict';
/*
 * Cross-platform "what window is focused right now" helper.
 *
 * Deliberately implemented by shelling out to each OS's own built-in scripting tool
 * (PowerShell on Windows, AppleScript/osascript on macOS) instead of a native Node
 * addon. Native addons have to be rebuilt against Electron's exact ABI for every
 * Electron version and every target OS/arch — a common source of packaging breakage,
 * especially since this can only really be tested by building on a real Windows/Mac
 * machine. Shelling out to tools every OS already ships avoids that failure mode.
 */

const { exec } = require('child_process');

function run(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 5000, windowsHide: true }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.toString().trim());
    });
  });
}

// Returns { appName, title } or null if it can't be determined (e.g. unsupported OS,
// or — on macOS — Accessibility permission hasn't been granted yet).
async function getActiveWindow() {
  if (process.platform === 'win32') return getActiveWindowWindows();
  if (process.platform === 'darwin') return getActiveWindowMac();
  return null; // Linux isn't a supported target for this agent (desktop tracking is Win/Mac only)
}

async function getActiveWindowWindows() {
  // Uses the Win32 API (GetForegroundWindow / GetWindowText) via a tiny inline C# snippet
  // compiled on the fly by PowerShell — no separate binary to ship or maintain.
  const script = `
    Add-Type @"
      using System;
      using System.Runtime.InteropServices;
      using System.Text;
      public class Win32 {
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
        [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
      }
"@
    $hwnd = [Win32]::GetForegroundWindow()
    $sb = New-Object System.Text.StringBuilder 256
    [void][Win32]::GetWindowText($hwnd, $sb, 256)
    $procId = 0
    [void][Win32]::GetWindowThreadProcessId($hwnd, [ref]$procId)
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    $result = @{ title = $sb.ToString(); appName = if ($proc) { $proc.ProcessName } else { "Unknown" } }
    $result | ConvertTo-Json -Compress
  `.replace(/\r?\n/g, ' ');
  const out = await run(`powershell -NoProfile -NonInteractive -Command "${script.replace(/"/g, '\\"')}"`);
  try {
    const parsed = JSON.parse(out);
    return { appName: parsed.appName || 'Unknown', title: parsed.title || '' };
  } catch {
    return null;
  }
}

async function getActiveWindowMac() {
  // First AppleScript call needs macOS Accessibility permission granted to the agent
  // (System Settings > Privacy & Security > Accessibility) — the setup screen explains this.
  const appScript = `osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true'`;
  const appName = await run(appScript).catch(() => 'Unknown');

  const titleScript = `osascript -e '
    tell application "System Events"
      set frontApp to first application process whose frontmost is true
      try
        set winTitle to name of front window of frontApp
      on error
        set winTitle to ""
      end try
    end tell
    return winTitle'`;
  const title = await run(titleScript).catch(() => '');

  return { appName: appName || 'Unknown', title: title || '' };
}

module.exports = getActiveWindow;
