'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wachadoin', {
  test: (serverUrl, agentToken) => ipcRenderer.invoke('setup:test', { serverUrl, agentToken }),
  save: (serverUrl, agentToken, employeeName) => ipcRenderer.invoke('setup:save', { serverUrl, agentToken, employeeName }),
  onMessage: (cb) => ipcRenderer.on('setup:message', (_e, msg) => cb(msg)),
});
