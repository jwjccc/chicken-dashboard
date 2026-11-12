import http from 'node:http';
import https from 'node:https';
import { createGzip, gzip } from 'node:zlib';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, rename, chmod } from 'node:fs/promises';
import { existsSync, createReadStream, readFileSync, readdirSync, writeFileSync, renameSync, chmodSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = existsSync(path.join(__dirname, 'public')) ? __dirname : path.resolve(__dirname, '..');
const dataDir = path.join(rootDir, 'data');
const publicDir = path.join(rootDir, 'public');
const agentProbePath = path.join(rootDir, 'agent', 'probe.sh');
const agentNodeProbePath = path.join(rootDir, 'agent', 'probe-node.cjs');
const configPath = path.join(dataDir, 'config.json');
const statePath = path.join(dataDir, 'state.json');
const connectivityHistoryDbPath = path.join(dataDir, 'connectivity-history.sqlite');
const backgroundCacheDir = path.join(dataDir, 'background-cache');
const MAX_SERVERS = 500;
const MAX_PENDING_INSTALLS = 500;
const MAX_CONNECTIVITY_CHECKS = 200; // compatibility bound for existing reports/configuration
const MAX_CONNECTIVITY_SERVICES = 12;
const flagCodes = new Set(readdirSync(path.join(publicDir, 'icons', 'flags')).filter((name) => /^[a-z]{2}\.svg$/.test(name)).map((name) => name.slice(0, 2).toUpperCase()));
const flagDataCache = new Map();
const serverCountryLookups = new Map();
const countryLookupRetryAt = new Map();
let accessLocationRefreshInFlight = null;
let nextLocationLookupAt = 0;
let connectivityChecksInFlight = null;
let connectivityPrunedAt = 0;

const clients = new Map();
const agentLastReportAt = new Map();
const viewerPresence = new Map();
const adminSessions = new Map();
const loginAttempts = new Map();
const blockedWhitelistRecordAt = new Map();
const connectivityResults = new Map();
const connectivityHistory = new Map();
let config = await loadConfig();
let state = await loadState();
const connectivityDb = openConnectivityHistoryDb();
void migrateConnectivityHistory();
let normalizedWhitelistCache = { source: null, items: [] };
hydrateConnectivityState();
let stateWriteQueue = Promise.resolve();
let configWriteQueue = Promise.resolve();
let stateWriteTimer = null;
let pendingStateWrite = null;
const panelStartedAt = Date.now();
const STATE_WRITE_DEBOUNCE_MS = 5000;
const VIEWER_PRESENCE_TTL_MS = 8000;
const scryptAsync = promisify(scrypt);
const MAX_BODY_BYTES = 1024 * 1024;
const MIN_AGENT_REPORT_INTERVAL_MS = clampInteger(process.env.MIN_AGENT_REPORT_INTERVAL_MS || 750, 250, 60000, 750);
const TRUST_PROXY = /^(1|true|yes)$/i.test(String(process.env.PROBE_TRUST_PROXY || ''));

const port = process.env.PROBE_PORT === '0' ? 0 : Number(config.port || process.env.PROBE_PORT || 8080);
let restartPending = null;
const MAX_SERVER_HISTORY_POINTS = clampInteger(process.env.MAX_SERVER_HISTORY_POINTS || 7200, 500, 200000, 7200);
const MAX_CONNECTIVITY_HISTORY_POINTS = clampInteger(process.env.MAX_CONNECTIVITY_HISTORY_POINTS || 5000, 100, 20000, 5000);
const HISTORY_SAMPLE_INTERVAL_MS = clampInteger(process.env.HISTORY_SAMPLE_INTERVAL_MS || 1000, 500, 3600000, 1000);
const IPAPI_AUTO_CHECK_INTERVAL_MS = 60 * 1000;
let ipApiRefreshInFlight = null;
const ipApiServerRefreshes = new Map();
const ipApiRefreshQueue = [];
let ipApiActiveRefreshes = 0;

const prunedAtStartup = pruneStateHistory();
pruneAccessState();
for (const report of Object.values(state.servers)) {
  // Preserve the last known quality snapshot before any online peer with the
  // same public IP refreshes the shared lookup cache.
  if (!report.ipQualitySnapshot) report.ipQualitySnapshot = cachedServerIpQuality(report);
}
if (prunedAtStartup) saveStateNow().catch((err) => console.error(err));

const requestHandler = async (req, res) => {
  const requestStartedAt = Date.now();
  const requestIp = normalizeClientIp(req.socket?.remoteAddress || 'unknown');
  const requestUrl = String(req.url || '/');
  let responseBytes = 0;
  const originalWrite = res.write.bind(res);
  const originalEnd = res.end.bind(res);
  res.write = (chunk, ...args) => {
    if (chunk) responseBytes += Buffer.byteLength(chunk);
    return originalWrite(chunk, ...args);
  };
  res.end = (chunk, ...args) => {
    if (chunk) responseBytes += Buffer.byteLength(chunk);
    return originalEnd(chunk, ...args);
  };
  res.once('finish', () => {
    if (!requestUrl.startsWith('/api/agent/')) console.log(`[access] ip=${requestIp} method=${req.method} url=${requestUrl} status=${res.statusCode} bytes=${responseBytes} ms=${Date.now() - requestStartedAt}`);
  });
  res.once('close', () => {
    if (!res.writableFinished && !requestUrl.startsWith('/api/agent/')) console.log(`[access-close] ip=${requestIp} method=${req.method} url=${requestUrl} status=${res.statusCode} bytes=${responseBytes} ms=${Date.now() - requestStartedAt}`);
  });
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    const agentPath = url.pathname.startsWith('/api/agent/');
    if (agentPath && !isAgentEndpointRequest(req)) return sendJson(res, {error:'agent_endpoint_changed'}, 410);
    if (req.socket.localPort !== server.address()?.port && !agentPath && url.pathname !== '/healthz') return sendNotFound(res);
    // Security gate: disabled means immediate unconditional pass-through.
    // Keep this synchronous and in-memory; reading config from disk per request
    // can block the event loop and amplify refresh timeouts under load.
    if (!isWhitelistAllowed(req, url)) return sendNotFound(res);

    if (req.method === 'OPTIONS') return handleOptions(res);
    if (req.method === 'GET' && url.pathname.startsWith('/media/background/')) return serveBackgroundProxy(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/backgrounds') {
      return sendJson(res, { backgrounds: publicBackgrounds() });
    }
    if (req.method === 'GET' && url.pathname === '/api/overview') return await sendPublicJson(req, res, buildOverview({compact:url.searchParams.get('compact') === '1'}));
    if (req.method === 'GET' && url.pathname === '/api/flags') return sendJson(res, { flags: publicFlagAssets((url.searchParams.get('codes') || '').split(',').slice(0, 247)) });
    if (req.method === 'GET' && url.pathname.startsWith('/api/servers/')) {
      const id = decodeURIComponent(url.pathname.split('/').pop() || '');
      const detail = await buildServerDetail(id, {
        includeConnectivityHistory: url.searchParams.get('connectivityHistory') === '1',
        connectivityRangeDays: Number(url.searchParams.get('connectivityRangeDays') || 1),
        historySince: Number(url.searchParams.get('historySince') || 0)
      });
      return detail ? await sendPublicJson(req, res, detail) : sendJson(res, { error: 'server_not_found' }, 404);
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/install-options') return handleInstallOptions(req, res);
    if (req.method === 'GET' && url.pathname === '/api/admin/session') return handleAdminSession(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/login') return handleAdminLogin(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/logout') return handleAdminLogout(req, res);
    if (req.method === 'GET' && url.pathname === '/api/admin/servers') return handleAdminListServers(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/servers') return handleAdminAddServer(req, res);
    if (req.method === 'POST' && url.pathname.startsWith('/api/admin/servers/') && url.pathname.endsWith('/delete')) return handleAdminDeleteServer(req, res, url);
    if (req.method === 'POST' && url.pathname.startsWith('/api/admin/servers/') && url.pathname.endsWith('/install-command')) return handleAdminServerInstallCommand(req, res, url);
    if (req.method === 'POST' && url.pathname.startsWith('/api/admin/servers/') && url.pathname.endsWith('/uninstall-command')) return handleAdminServerUninstallCommand(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/admin/settings') return handleAdminSettingsGet(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/admin/viewers') return handleAdminViewersGet(req, res);
    if (req.method === 'GET' && url.pathname === '/api/admin/blocked-whitelist') return handleAdminBlockedWhitelistGet(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/ipapi-refresh') return handleAdminIpApiRefresh(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/settings') return handleAdminSettingsSave(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/restart') return handleAdminRestart(req, res);
    if (req.method === 'GET' && url.pathname === '/api/admin/connectivity') return handleAdminConnectivityGet(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/connectivity') return handleAdminConnectivitySave(req, res);
    if (req.method === 'POST' && url.pathname.startsWith('/api/admin/connectivity/') && url.pathname.endsWith('/delete')) return handleAdminConnectivityDelete(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/connectivity') return handleConnectivityPublic(req, res);
    if (req.method === 'POST' && url.pathname === '/api/viewer-heartbeat') return handleViewerHeartbeat(req, res);
    if (req.method === 'POST' && url.pathname === '/api/viewer-leave') return handleViewerLeave(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/install-command') return handleInstallCommand(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/uninstall-command') return handleUninstallCommand(req, res);
    if (req.method === 'GET' && url.pathname === '/api/agent/probe.sh') return serveAgentProbe(res);
    if (req.method === 'GET' && url.pathname === '/api/agent/probe-node.cjs') return serveAgentNodeProbe(res);
    if (req.method === 'GET' && url.pathname === '/api/agent/install.sh') return serveAgentInstall(res);
    if (req.method === 'GET' && url.pathname === '/api/agent/uninstall.sh') return serveAgentUninstall(res);
    if (req.method === 'GET' && url.pathname === '/api/agent/connectivity') return handleAgentConnectivity(req, res, url);
    if (req.method === 'POST' && url.pathname === '/api/agent/report') return handleAgentReport(req, res);
    if (req.method === 'POST' && url.pathname === '/api/admin/server') return handleServerUpsert(req, res);
    if (req.method === 'GET' && url.pathname === '/api/events') return handleEvents(req, res);
    if (req.method === 'GET' && url.pathname === '/healthz') return sendJson(res, { ok: true, now: Date.now(), panelStartedAt, restart:restartPending });
    if (req.method === 'GET' && url.pathname === '/api/panel-ready.svg') {
      res.writeHead(restartPending ? 503 : 200, securityHeaders({'Content-Type':'image/svg+xml', 'Cache-Control':'no-store'}));
      return res.end(restartPending ? '' : '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>');
    }

    if (req.method === 'GET' && isAdminPagePath(url.pathname)) return serveIndex(req, res, path.join(publicDir, 'index.html'));

    return serveStatic(req, url.pathname, res);
  } catch (err) {
    console.error(err);
    if (err?.code === 'BODY_TOO_LARGE') return sendJson(res, { error: 'request_body_too_large' }, 413);
    if (err?.code === 'INVALID_JSON') return sendJson(res, { error: 'invalid_json' }, 400);
    if (!res.headersSent) sendJson(res, { error: 'internal_error' }, 500);
    else res.destroy();
  }
};
const server = http.createServer(requestHandler);
const configuredAgentPort = agentPortForConfig(config, port);
const agentServer = configuredAgentPort !== port ? http.createServer(requestHandler) : null;
if (agentServer) agentServer.listen(configuredAgentPort);
server.listen(port, () => {
  console.log(`Server Probe Monitor listening on http://0.0.0.0:${port}`);
});

setInterval(() => broadcast({ type: 'refresh', at: Date.now() }), 30000).unref();
setInterval(() => runDueConnectivityChecks(), 1000).unref();
setInterval(() => runDueIpApiRefresh(), IPAPI_AUTO_CHECK_INTERVAL_MS).unref();
setInterval(() => { pruneAccessState(); pruneLoginAttempts(); pruneViewerPresence(); }, 60_000).unref();
let shuttingDown = false;
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  broadcast({type:'restarting', ...restartNotice()});
  revokeAdminSessions();
  agentServer?.close();
  server.close();
  const forceExit = setTimeout(() => process.exit(1), 8000);
  try { await saveStateNow(); connectivityDb.close(); clearTimeout(forceExit); process.exit(0); }
  catch (err) { console.error(err); process.exit(1); }
});
runDueConnectivityChecks().catch((err) => console.error(err));
runDueIpApiRefresh().catch((err) => console.error(err));

async function loadConfig() {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await chmod(dataDir, 0o700);
  if (!existsSync(configPath)) {
    const initial = {
      panelId: `pnl-${randomBytes(16).toString('hex')}`,
      agentIdentityKeys: [],
      port: Number(process.env.PROBE_PORT || 8080) || 8080,
      heartbeatTimeoutSeconds: 45,
      historyRetentionHours: 24,
      dashboardTitle: '服务器监控面板',
      dashboardIcon: '',
      ipapiKey: '',
      ipapiRefreshIntervalHours: 24,
      viewerIpModuleEnabled: false,
      publicHubUrl: process.env.PUBLIC_HUB_URL || '',
      agentToken: 'change-me-before-deploy',
      allowLegacyAgentToken: false,
      adminUsername: 'admin',
      adminPasswordHash: hashAdminPassword('admin'),
      backgrounds: { frontendDesktop: [], frontendMobile: [], adminDesktop: [], adminMobile: [] },
      ipWhitelist: [],
      ipWhitelistEnabled: false,
      connectivityChecks: [],
      pendingInstalls: [],
      servers: []
    };
    await writeJson(configPath, initial);
    return initial;
  }
  await chmod(configPath, 0o600).catch(() => {});
  const loaded = JSON.parse(await readFile(configPath, 'utf8'));
  let changed = false;
  if (!loaded.panelId) { loaded.panelId = `pnl-${randomBytes(16).toString('hex')}`; changed = true; }
  if (!/^pnl-[a-f0-9]{32}$/.test(loaded.panelId)) throw new Error('invalid_panel_identity');
  const identityKeys = rememberedAgentIdentityKeys(loaded);
  if (JSON.stringify(loaded.agentIdentityKeys) !== JSON.stringify(identityKeys)) { loaded.agentIdentityKeys = identityKeys; changed = true; }
  if (!loaded.dashboardTitle) { loaded.dashboardTitle = '服务器监控面板'; changed = true; }
  if (loaded.dashboardIcon == null) { loaded.dashboardIcon = ''; changed = true; }
  if (loaded.ipapiKey == null) { loaded.ipapiKey = ''; changed = true; }
  if (!Number.isInteger(Number(loaded.ipapiRefreshIntervalHours)) || Number(loaded.ipapiRefreshIntervalHours) < 1 || Number(loaded.ipapiRefreshIntervalHours) > 9999) { loaded.ipapiRefreshIntervalHours = 24; changed = true; }
  if (loaded.viewerIpModuleEnabled == null) { loaded.viewerIpModuleEnabled = false; changed = true; }
  if (!Number.isInteger(Number(loaded.port)) || Number(loaded.port) < 1 || Number(loaded.port) > 65535) { loaded.port = 8080; changed = true; }
  if (loaded.publicHubUrl == null) { loaded.publicHubUrl = ''; changed = true; }
  if (!loaded.adminUsername) { loaded.adminUsername = 'admin'; changed = true; }
  if (!loaded.adminPasswordHash) {
    loaded.adminPasswordHash = hashAdminPassword(String(loaded.adminPassword || 'admin'));
    delete loaded.adminPassword;
    changed = true;
  }
  if (Object.hasOwn(loaded, 'adminPassword')) { delete loaded.adminPassword; changed = true; }
  if (loaded.allowLegacyAgentToken !== true) { loaded.allowLegacyAgentToken = false; changed = true; }
  const normalizedBackgrounds = normalizeBackgrounds(loaded.backgrounds);
  if (JSON.stringify(loaded.backgrounds || {}) !== JSON.stringify(normalizedBackgrounds)) { loaded.backgrounds = normalizedBackgrounds; changed = true; }
  if (!Array.isArray(loaded.ipWhitelist)) { loaded.ipWhitelist = []; changed = true; }
  if (loaded.ipWhitelistEnabled !== true) { loaded.ipWhitelistEnabled = false; changed = true; }
  if (!Array.isArray(loaded.connectivityChecks)) { loaded.connectivityChecks = []; changed = true; }
  for (const check of loaded.connectivityChecks) {
    const seconds = Math.max(5,Math.min(720,Math.ceil(Number(check.intervalSeconds || 300)/60)))*60;
    if (check.intervalSeconds !== seconds) {check.intervalSeconds=seconds;changed=true;}
  }
  if (!Array.isArray(loaded.pendingInstalls)) { loaded.pendingInstalls = []; changed = true; }
  if (!Array.isArray(loaded.servers)) { loaded.servers = []; changed = true; }
  if (loaded.connectivityChecks.length > MAX_CONNECTIVITY_CHECKS) { loaded.connectivityChecks = loaded.connectivityChecks.slice(0, MAX_CONNECTIVITY_CHECKS); changed = true; }
  if (loaded.pendingInstalls.length > MAX_PENDING_INSTALLS) { loaded.pendingInstalls = loaded.pendingInstalls.slice(0, MAX_PENDING_INSTALLS); changed = true; }
  if (loaded.servers.length > MAX_SERVERS) { loaded.servers = loaded.servers.slice(0, MAX_SERVERS); changed = true; }
  const pendingBefore = loaded.pendingInstalls.length;
  loaded.pendingInstalls = loaded.pendingInstalls.filter((install) => !install.expiresAt || Number(install.expiresAt) > Date.now());
  if (loaded.pendingInstalls.length !== pendingBefore) changed = true;
  if (changed) await writeJson(configPath, loaded);
  return loaded;
}

async function loadState() {
  const emptyState = () => ({ servers: {}, deletedServerIds: {}, history: {}, trafficCycles: {}, connectivityResults: {}, connectivityHistory: {}, agentConnectivityServed: {}, viewerAccess: [], viewerIpLocations: {}, blockedWhitelistAccess: [], blockedWhitelistIpLocations: {}, serverIpQuality: {}, ipApiLastRefreshAt: 0 });
  if (!existsSync(statePath)) return emptyState();
  await chmod(statePath, 0o600).catch(() => {});
  try {
    const loaded = JSON.parse(await readFile(statePath, 'utf8'));
    return {
      servers: loaded.servers || {},
      deletedServerIds: loaded.deletedServerIds && typeof loaded.deletedServerIds === 'object' ? loaded.deletedServerIds : {},
      history: loaded.history || {},
      trafficCycles: loaded.trafficCycles || {},
      connectivityResults: loaded.connectivityResults || {},
      connectivityHistory: loaded.connectivityHistory || {},
      agentConnectivityServed: loaded.agentConnectivityServed || {},
      viewerAccess: Array.isArray(loaded.viewerAccess) ? loaded.viewerAccess : [],
      viewerIpLocations: loaded.viewerIpLocations && typeof loaded.viewerIpLocations === 'object' ? loaded.viewerIpLocations : {},
      blockedWhitelistAccess: Array.isArray(loaded.blockedWhitelistAccess) ? loaded.blockedWhitelistAccess : [],
      blockedWhitelistIpLocations: loaded.blockedWhitelistIpLocations && typeof loaded.blockedWhitelistIpLocations === 'object' ? loaded.blockedWhitelistIpLocations : {},
      serverIpQuality: loaded.serverIpQuality && typeof loaded.serverIpQuality === 'object' ? loaded.serverIpQuality : {},
      ipApiLastRefreshAt: Number(loaded.ipApiLastRefreshAt || 0)
    };
  } catch (err) {
    const corruptPath = `${statePath}.corrupt-${Date.now()}`;
    await writeFile(corruptPath, await readFile(statePath, 'utf8'));
    console.error(`State file is invalid JSON; moved a copy to ${corruptPath}`);
    return emptyState();
  }
}

function hydrateConnectivityState() {
  for (const [id, result] of Object.entries(state.connectivityResults || {})) connectivityResults.set(id, { ...result, latencyMs: Math.trunc(Number(result.latencyMs) || 0) });
  for (const [id, history] of Object.entries(state.connectivityHistory || {})) {
    if (Array.isArray(history)) connectivityHistory.set(id, aggregateConnectivityHistory(history, 0));
  }
}

function openConnectivityHistoryDb() {
  const database = new DatabaseSync(connectivityHistoryDbPath);
  database.exec(`CREATE TABLE IF NOT EXISTS connectivity_history (
    server_id TEXT NOT NULL, check_id TEXT NOT NULL, checked_at INTEGER NOT NULL,
    latency_ms REAL, ok INTEGER NOT NULL, packet_loss_percent REAL,
    PRIMARY KEY (server_id, check_id, checked_at)
  ); CREATE INDEX IF NOT EXISTS connectivity_history_lookup
    ON connectivity_history (server_id, check_id, checked_at);`);
  return database;
}

function migrateConnectivityHistory() {
  const insert = connectivityDb.prepare(`INSERT OR IGNORE INTO connectivity_history
    (server_id, check_id, checked_at, latency_ms, ok, packet_loss_percent)
    VALUES (?, ?, ?, ?, ?, ?)`);
  for (const [serverId, server] of Object.entries(state.servers || {})) {
    const referenceAt = isReportOnline(server) ? Date.now() : Number(server.lastReportAt || Date.now());
    const cutoff = referenceAt - 15 * 24 * 60 * 60 * 1000;
    for (const item of Array.isArray(server?.connectivity) ? server.connectivity : []) {
      for (const point of Array.isArray(item?.history) ? item.history : []) {
        const t = Number(point?.t || 0);
        if (t >= cutoff && t > 0) insert.run(serverId, String(item.id), t,
          Number.isFinite(Number(point.latencyMs)) ? Number(point.latencyMs) : null,
          point.ok ? 1 : 0, normalizePacketLossPercent(point.packetLossPercent, point.ok ? 0 : 100));
      }
    }
  }
  pruneConnectivityHistory();
}

function readConnectivityHistory(serverId, checkId, cutoff) {
  return connectivityDb.prepare(`SELECT checked_at AS t, latency_ms AS latencyMs,
    ok, packet_loss_percent AS packetLossPercent FROM connectivity_history
    WHERE server_id = ? AND check_id = ? AND checked_at >= ? ORDER BY checked_at ASC`).all(serverId, checkId, cutoff)
    .map((point) => ({ ...point, ok: Boolean(point.ok) }));
}

function appendConnectivityHistory(serverId, checkId, point) {
  connectivityDb.prepare(`INSERT OR IGNORE INTO connectivity_history
    (server_id, check_id, checked_at, latency_ms, ok, packet_loss_percent)
    VALUES (?, ?, ?, ?, ?, ?)`).run(serverId, checkId, point.t, point.latencyMs ?? null,
      point.ok ? 1 : 0, point.packetLossPercent);
  // Replayed agent samples are filtered before reaching SQLite. Retention is
  // maintained hourly, rather than scanning the table on every heartbeat.
  pruneConnectivityHistory();
}

function pruneConnectivityHistory() {
  const now = Date.now();
  if (connectivityPrunedAt && now - connectivityPrunedAt < 3600_000) return;
  connectivityPrunedAt = now;
  const remove = connectivityDb.prepare('DELETE FROM connectivity_history WHERE server_id = ? AND checked_at < ?');
  const ids = new Set(config.servers.map((meta) => meta.id));
  for (const { server_id: id } of connectivityDb.prepare('SELECT DISTINCT server_id FROM connectivity_history').all()) {
    const report = state.servers[id] || {};
    const referenceAt = isReportOnline(report) ? now : Number(report.lastReportAt || now);
    if (!ids.has(id)) connectivityDb.prepare('DELETE FROM connectivity_history WHERE server_id = ?').run(id);
    else remove.run(id, referenceAt - 15 * 86400_000);
  }
}

function pruneStateHistory() {
  let changed = false;
  const now = Date.now();
  const retentionMs = Number(config.historyRetentionHours || 24) * 60 * 60 * 1000;
  const connectivityCutoff = now - 15 * 24 * 60 * 60 * 1000;
  for (const [id, history] of Object.entries(state.history || {})) {
    if (!Array.isArray(history)) {
      delete state.history[id];
      changed = true;
      continue;
    }
    const next = history
      .filter((point) => now - Number(point.t || 0) <= retentionMs)
      .slice(-MAX_SERVER_HISTORY_POINTS);
    if (next.length !== history.length) {
      state.history[id] = next;
      changed = true;
    }
  }
  for (const server of Object.values(state.servers || {})) {
    if (!Array.isArray(server?.connectivity)) continue;
    const serverCutoff = (isReportOnline(server) ? now : Number(server.lastReportAt || now)) - 15 * 86400_000;
    for (const item of server.connectivity) {
      if (!Array.isArray(item?.history)) continue;
      const next = item.history.filter((point) => Number(point?.t || 0) >= serverCutoff).slice(-MAX_CONNECTIVITY_HISTORY_POINTS);
      if (next.length !== item.history.length) { item.history = next; changed = true; }
    }
  }
  for (const [id, history] of Object.entries(state.connectivityHistory || {})) {
    if (!Array.isArray(history)) {
      delete state.connectivityHistory[id];
      connectivityHistory.delete(id);
      changed = true;
      continue;
    }
    const next = history.filter((point) => Number(point?.t || 0) >= connectivityCutoff).slice(-MAX_CONNECTIVITY_HISTORY_POINTS);
    if (next.length !== history.length) {
      state.connectivityHistory[id] = next;
      connectivityHistory.set(id, next);
      changed = true;
    }
  }
  return changed;
}

function persistConnectivityState() {
  state.connectivityResults = Object.fromEntries(connectivityResults.entries());
  state.connectivityHistory = Object.fromEntries(connectivityHistory.entries());
  saveState().catch((err) => console.error(err));
}

function saveStateSoon() {
  if (pendingStateWrite) return pendingStateWrite.promise;
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  pendingStateWrite = { promise, resolve, reject };
    stateWriteTimer = setTimeout(() => {
      stateWriteTimer = null;
      flushStateWrites().catch((err) => console.error(err));
    }, STATE_WRITE_DEBOUNCE_MS);
    stateWriteTimer.unref();
  return promise;
}

async function saveStateNow() {
  if (stateWriteTimer) {
    clearTimeout(stateWriteTimer);
    stateWriteTimer = null;
  }
  await flushStateWrites();
}

async function flushStateWrites() {
  const pending = pendingStateWrite;
  pendingStateWrite = null;
  try {
    stateWriteQueue = stateWriteQueue.catch(() => {}).then(() => writeJsonCompact(statePath, state));
    await stateWriteQueue;
    pending?.resolve();
  } catch (err) {
    pending?.reject(err);
    throw err;
  }
}

const saveState = saveStateSoon;

async function writeJson(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, file);
  await chmod(file, 0o600);
}

async function writeJsonCompact(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, `${JSON.stringify(data)}\n`, { mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, file);
  await chmod(file, 0o600);
}

function buildPublicBootstrapScript() {
  // Include stable visual/runtime metadata in the HTML bootstrap so an admin
  // refresh never waits on a later settings request to restore these fields.
  const basics = {
    dashboardTitle: config.dashboardTitle || '服务器监控面板',
    dashboardIcon: config.dashboardIcon || '',
    viewerIpModuleEnabled: config.viewerIpModuleEnabled !== false,
    panelStartedAt
  };
  const flags = publicFlagAssets(config.servers.map((meta) => serverCountryCode(meta, state.servers[meta.id])));
  const payload = JSON.stringify({ basics, backgrounds: publicBackgrounds(), flags, flagCodes: [...flagCodes] }).replace(/</g, '\\u003c');
  return `<script>window.__SPM_BOOTSTRAP__=${payload};<\/script>`;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error('request_body_too_large'); error.code = 'BODY_TOO_LARGE'; throw error;
    }
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks, size).toString('utf8');
  if (!body) return {};
  try { return JSON.parse(body); } catch { const error = new Error('invalid_json'); error.code = 'INVALID_JSON'; throw error; }
}

async function handleAgentReport(req, res) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
  const rawReport = await readBody(req);
  if (!rawReport.id) return sendJson(res, { error: 'missing_server_id' }, 400);
  if (Array.isArray(rawReport.connectivity) && rawReport.connectivity.some((item) => !item || typeof item !== 'object' || typeof item.ok !== 'boolean')) {
    return sendJson(res, { error: 'invalid_connectivity_schema', message: 'connectivity[].ok must be boolean' }, 400);
  }
  const report = normalizeAgentReport(rawReport);

  const existingMeta = config.servers.find((server) => server.id === report.id);
  const pendingInstall = config.pendingInstalls.find((install) => install.id === report.id);
  // Deletion is permanent until an administrator explicitly creates the ID
  // again; an old agent (including legacy-token agents) cannot resurrect it.
  if (!existingMeta && !pendingInstall && state.deletedServerIds?.[report.id]) {
    return sendJson(res, { error: 'server_deleted', message: '该服务器已被删除，请在后台重新创建后再上报。' }, 410);
  }
  if (!isAgentAuthorized(existingMeta, pendingInstall, token)) return sendJson(res, { error: 'unauthorized' }, 401);

  const now = Date.now();
  const lastReportAt = Number(agentLastReportAt.get(report.id) || 0);
  if (now - lastReportAt < MIN_AGENT_REPORT_INTERVAL_MS) {
    return sendJson(res, { error: 'report_rate_limited', retryAfterMs: MIN_AGENT_REPORT_INTERVAL_MS - (now - lastReportAt) }, 429, { 'Retry-After': '1' });
  }
  agentLastReportAt.set(report.id, now);
  if (!existingMeta) {
    try {
      await transactConfig((draft) => {
        if (draft.servers.some((server) => server.id === report.id)) return;
        if (draft.servers.length >= MAX_SERVERS) throw businessError('server_limit_reached', 'server limit reached');
        const pending = draft.pendingInstalls.find((install) => install.id === report.id);
        draft.servers.push({
          id: report.id,
          name: report.name || report.hostname || report.id,
          location: report.location || '',
          tags: report.tags || [],
          createdAt: now,
          expiresAt: null,
          secret: pending?.secret || token
        });
        if (pending) draft.pendingInstalls = draft.pendingInstalls.filter((install) => install.id !== report.id);
      });
    } catch (err) {
      if (err?.code === 'server_limit_reached') return sendJson(res, { error: err.code }, 409);
      throw err;
    }
  }

  const meta = config.servers.find((server) => server.id === report.id);
  if (isStaleTrafficReport(state.trafficCycles?.[report.id], report)) {
    return sendJson(res, { ok: true, ignored: 'stale_report' });
  }
  // Authentication is tied to the stable ID/secret, never the agent's address.
  // The authenticated connection also supplies a fresh address if discovery
  // services are unavailable or the agent still has a pre-reboot cached IP.
  const observedIp = clientKey(req);
  if (net.isIP(observedIp) && !isPrivateIp(observedIp)) {
    const family = net.isIP(observedIp) === 4 ? '4' : '6';
    report[`publicIpv${family}`] = observedIp;
    report[`ipv${family}`] = observedIp;
    report.publicIp = observedIp;
    report.ip = observedIp;
  }
  updateTrafficCycleState(meta, state.servers[report.id], report, now);
  const mergedReport = mergeAgentReport(state.servers[report.id], report);
  const previousReportAt = Number(state.servers[report.id]?.lastReportAt || 0);
  const connectivityGaps = (state.servers[report.id]?.connectivityGaps || [])
    .filter(gap => Number(gap.end) >= now - 15 * 86400_000);
  if (previousReportAt && !isReportOnline(state.servers[report.id], now)) {
    connectivityGaps.push({ start: previousReportAt, end: now });
    delete state.agentConnectivityServed[report.id];
  }

  state.servers[report.id] = {
    ...state.servers[report.id],
    ...mergedReport,
    firstReportAt: state.servers[report.id]?.firstReportAt || now,
    connectivityGaps: connectivityGaps.slice(-5000),
    connectivity: Array.isArray(report.connectivity) && report.connectivity.length
      ? mergeServerConnectivity(report.id, report.connectivity)
      : (state.servers[report.id]?.connectivity || []),
    lastReportAt: now
  };
  void refreshServerCountryIfNeeded(meta, state.servers[report.id]);
  // First usable IP (including one discovered after startup) starts its own
  // bounded job; it must not wait for a global refresh already in progress.
  if (config.ipapiKey && ipApiRefreshDue(state.servers[report.id])) {
    void refreshServerIpApiQuality(meta).catch((err) => console.error(err));
  }

  // Notify the UI immediately after the in-memory report is committed. Do not
  // wait for history cleanup or state persistence before sending SSE.
  broadcast({ type: 'refresh', id: report.id, at: now });
  maybeAppendHistoryPoint(report.id, compactHistoryPoint(mergedReport, now), now);
  saveStateSoon().catch((err) => console.error(err));
  return sendJson(res, { ok: true, server: report.id });
}

function dueAgentConnectivityChecks(serverId, now = Date.now()) {
  let jobs = state.agentConnectivityServed[serverId];
  if (!jobs || typeof jobs !== 'object') jobs = state.agentConnectivityServed[serverId] = {};
  const active = (config.connectivityChecks || []).filter(check=>check.enabled!==false);
  for (const id of Object.keys(jobs)) if(!active.some(check=>check.id===id)) delete jobs[id];
  const due=[];
  for(const check of active) {
    const intervalMs=Number(check.intervalSeconds || 300)*1000;
    const signature=JSON.stringify([check.target,intervalMs]);
    let job=jobs[check.id];
    if (!job || job.signature!==signature) job=jobs[check.id]={signature,attempts:0,nextAt:0,awaiting:false};
    if(job.awaiting && now-job.dispatchedAt<15000) continue;
    if(!job.awaiting && now<job.nextAt) continue;
    if(job.awaiting && job.attempts>=4) {
      // Do not turn an offline agent into fabricated target failures.
      if(!isReportOnline(state.servers[serverId],now)) continue;
      state.servers[serverId].connectivity=mergeServerConnectivity(serverId,[{id:check.id,checkedAt:now,taskAt:job.slotAt,
        attempts:1,final:true,ok:false,latencyMs:0,packetLossPercent:100,error:'no_response_after_retries'}]);
      broadcast({type:'refresh',id:serverId,at:now});
      continue;
    }
    if(!job.awaiting && !job.retry) {job.attempts=0;job.slotAt=now;}
    job.attempts++;job.dispatchedAt=now;job.awaiting=true;job.retry=false;
    job.nextAt=job.slotAt+intervalMs;
    due.push({check,job});
  }
  return due;
}

function handleAgentConnectivity(req, res, url) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
  const serverId = url.searchParams.get('serverId') || req.headers['x-server-id'] || '';
  const existingMeta = config.servers.find((server) => server.id === serverId);
  const pendingInstall = config.pendingInstalls.find((install) => install.id === serverId);
  if (!serverId || !isAgentAuthorized(existingMeta, pendingInstall, token)) return sendJson(res, { error: 'unauthorized' }, 401);
  const now = Date.now();
  const checks = dueAgentConnectivityChecks(serverId, now);
  const lines = checks.map(({check, job}) => [check.id, check.name, check.target, check.intervalSeconds || 300,
    5-job.attempts, job.slotAt].map(value => String(value ?? '').replace(/[\t\r\n]/g, ' ')).join('\t'));
  void saveStateSoon().catch(err=>console.error(err));
  res.writeHead(200, corsHeaders({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' }));
  res.end(`${lines.join('\n')}\n`);
}

async function handleServerUpsert(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);

  const input = await readBody(req);
  if (!input.id) return sendJson(res, { error: 'missing_server_id' }, 400);
  if (!input.startedAt || !input.expiresAt) return sendJson(res, { error: 'started_at_and_expires_at_required' }, 400);
  if (!isValidIsoDate(String(input.startedAt)) || !isValidIsoDate(String(input.expiresAt))) return sendJson(res, { error: 'invalid_date', message: 'startedAt/expiresAt must be real YYYY-MM-DD dates' }, 400);
  if (Object.prototype.hasOwnProperty.call(input, 'sortOrder') && !isValidServerSortOrder(input.sortOrder)) {
    return sendJson(res, { error: 'invalid_sort_order', message: '服务器ID必须是 1 到 500 的阿拉伯数字' }, 400);
  }
  try {
    const next = await transactConfig((draft) => {
      if (!draft.servers.some((server) => server.id === input.id) && draft.servers.length >= MAX_SERVERS) throw businessError('server_limit_reached', 'server limit reached');
      return upsertServerMeta(draft, input);
    });
    reconcileTrafficCycle(next, state.servers[next.id] || {}, Date.now());
    await saveStateNow();
    broadcast({ type: 'refresh', id: next.id, at: Date.now() });
    return sendJson(res, { ok: true, server: publicServerMeta(next) });
  } catch (err) {
    if (err?.code === 'server_limit_reached') return sendJson(res, { error: err.code }, 409);
    throw err;
  }
}

function upsertServerMeta(draft, input) {
  const current = draft.servers.find((server) => server.id === input.id);
  const has = (key) => Object.prototype.hasOwnProperty.call(input, key);
  const startedAt = has('startedAt') ? input.startedAt || null : current?.startedAt ?? null;
  const expiresAt = has('expiresAt') ? input.expiresAt || null : current?.expiresAt ?? null;
  const remainingInput = has('remainingTrafficBytes') || has('remainingTraffic')
    ? (has('remainingTrafficBytes') ? input.remainingTrafficBytes : input.remainingTraffic)
    : current?.remainingTrafficBytes;
  const priceInput = has('priceAmount') ? input.priceAmount : current?.priceAmount;
  const currencyInput = has('priceCurrency') ? input.priceCurrency : current?.priceCurrency;
  const periodInput = has('pricePeriod') ? input.pricePeriod : current?.pricePeriod;
  const trafficCycleStartInput = has('trafficCycleStartDate') ? input.trafficCycleStartDate : current?.trafficCycleStartDate;
  const trafficCycleUnitInput = has('trafficCycleUnit') ? input.trafficCycleUnit : current?.trafficCycleUnit;
  const sortOrderInput = has('sortOrder') ? input.sortOrder : current?.sortOrder;
  const sortOrder = normalizeServerSortOrder(sortOrderInput);
  if (has('sortOrder') && current && sortOrder) applyServerSortSwap(draft, current.id, sortOrder);
  const next = {
    id: input.id,
    name: input.name || input.displayName || current?.name || input.id,
    location: input.location ?? current?.location ?? '',
    tags: Array.isArray(input.tags) ? input.tags : current?.tags || [],
    startedAt: normalizeNullableDate(startedAt),
    expiresAt: normalizeNullableDate(expiresAt),
    remainingTrafficBytes: normalizeNullableNumber(remainingInput),
    priceAmount: normalizeNullableNumber(priceInput),
    priceCurrency: normalizePriceCurrency(currencyInput),
    pricePeriod: normalizePricePeriod(periodInput),
    trafficCycleStartDate: normalizeTrafficCycleStart(trafficCycleStartInput),
    trafficCycleUnit: normalizeTrafficCycleUnit(trafficCycleUnitInput),
    sortOrder,
    secret: input.secret || current?.secret || generateSecret()
  };

  if (current) Object.assign(current, next);
  else draft.servers.push(next);
  return next;
}

function handleAdminSession(req, res) {
  const session = getAdminSession(req);
  return sendJson(res, { ok: Boolean(session), username: session?.username || null, csrfToken: session?.csrfToken || null });
}

async function handleAdminLogin(req, res) {
  if (restartPending) return sendJson(res, { error: 'panel_restarting' }, 503);
  const loginKey = clientKey(req);
  pruneLoginAttempts();
  const attempt = loginAttempts.get(loginKey);
  if (attempt?.lockedUntil && Date.now() < attempt.lockedUntil) {
    return sendJson(res, { error: 'too_many_attempts' }, 429);
  }
  const input = await readBody(req);
  const username = String(input.username || '').trim().slice(0, 128);
  const password = String(input.password || '').slice(0, 1024);
  if (username !== config.adminUsername || !await verifyAdminPassword(password)) {
    recordFailedLogin(loginKey);
    return sendJson(res, { error: 'invalid_credentials' }, 401);
  }
  if (restartPending) return sendJson(res, { error: 'panel_restarting' }, 503);
  loginAttempts.delete(loginKey);
  const token = randomBytes(32).toString('hex');
  const csrfToken = randomBytes(24).toString('base64url');
  adminSessions.set(token, { username, csrfToken, expiresAt: Date.now() + 12 * 60 * 60 * 1000 });
  return sendJson(res, { ok: true, username, csrfToken }, 200, { 'Set-Cookie': buildAdminCookie(req, token) });
}

function handleAdminLogout(req, res) {
  const token = getBearerToken(req);
  if (token) adminSessions.delete(token);
  const cookieToken = getCookie(req, 'admin_session');
  if (cookieToken) adminSessions.delete(cookieToken);
  return sendJson(res, { ok: true }, 200, { 'Set-Cookie': buildAdminCookie(req, '', 0) });
}

function handleAdminListServers(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const timeoutMs = Number(config.heartbeatTimeoutSeconds || 45) * 1000;
  const servers = orderedServers().map((meta) => adminServerListItem(meta, timeoutMs));
  return sendJson(res, { ok: true, servers });
}

function adminServerListItem(meta, timeoutMs = Number(config.heartbeatTimeoutSeconds || 45) * 1000) {
  const report = state.servers[meta.id] || {};
  const lastReportAt = report.lastReportAt || 0;
  const ips = serverIpFields(report);
  return {
    ...publicServerMeta(meta),
    online: Boolean(lastReportAt && Date.now() - lastReportAt <= timeoutMs),
    lastReportAt,
    hostname: report.hostname || '',
    uptimeSeconds: Number(report.uptimeSeconds || 0),
    ipv4: ips.ipv4,
    ipv6: ips.ipv6,
    remainingTrafficBytes: meta.remainingTrafficBytes ?? null
  };
}

async function handleAdminSettingsGet(req, res, url = null) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const section = String(url?.searchParams?.get('section') || 'all');
  await syncPublicHubUrlFromRequest(req);
  const payload = { ok: true };
  if (section === 'all' || section === 'basic' || section === 'basics') payload.basics = adminPanelBasics();
  if (section === 'all' || section === 'images') payload.backgrounds = normalizeBackgrounds(config.backgrounds);
  if (section === 'all' || section === 'online' || section === 'whitelist') {
    scheduleAccessLocationRefresh();
    payload.onlineViewers = onlineViewerStats();
    payload.viewerAccess = publicViewerAccess();
  }
  if (section === 'all' || section === 'whitelist') {
    scheduleAccessLocationRefresh();
    payload.blockedWhitelistAccess = publicBlockedWhitelistAccess();
    payload.whitelist = adminWhitelistSettings(req);
  }
  return sendJson(res, payload);
}

async function handleAdminViewersGet(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  scheduleAccessLocationRefresh();
  return sendJson(res, {
    ok: true,
    onlineViewers: onlineViewerStats(),
    viewerAccess: publicViewerAccess()
  });
}

async function handleAdminBlockedWhitelistGet(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  scheduleAccessLocationRefresh();
  return sendJson(res, {
    ok: true,
    blockedWhitelistAccess: publicBlockedWhitelistAccess()
  });
}


function agentPortForConfig(settings, fallback = port) {
  if (!settings.publicHubUrl) return fallback;
  const url = new URL(normalizeHubUrl(settings.publicHubUrl));
  return url.protocol === 'http:' ? Number(url.port || 80) : fallback;
}

function isAgentEndpointRequest(req) {
  const endpoint = config.publicHubUrl ? new URL(normalizeHubUrl(config.publicHubUrl)) : null;
  if (endpoint?.protocol === 'https:') {
    const forwarded = TRUST_PROXY && ipLocalLocationLabel(normalizeClientIp(req.socket.remoteAddress)) &&
      String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
    if (!req.socket.encrypted && !forwarded) return false;
    const host = String(forwarded ? (req.headers['x-forwarded-host'] || req.headers.host) : req.headers.host).split(',')[0];
    try { return new URL(`https://${host}`).port === endpoint.port; } catch { return false; }
  }
  const expected = endpoint ? Number(endpoint.port || 80) : (port === 0 ? server.address()?.port : Number(config.port));
  return req.socket.localPort === expected;
}

function restartNotice() {
  return {panelStartedAt, oldPanelPort:server.address()?.port || port, newPanelPort:Number(config.port || port)};
}

function performPanelRestart() {
  const service = String(process.env.PROBE_PANEL_SERVICE || 'server-probe-monitor').replace(/\.service$/, '');
  if (!/^[a-zA-Z0-9_.@:-]+$/.test(service)) throw new Error('invalid_service_name');
  const child = spawn('systemctl', ['--no-block', 'restart', `${service}.service`], {stdio:'ignore'});
  child.on('error', err => console.error('Panel restart failed:',err.message));
  child.unref();
}

function queuePanelRestart(res) {
  if (restartPending) return restartPending;
  restartPending = restartNotice();
  revokeAdminSessions();
  broadcast({type:'restarting', ...restartPending});
  res.once('finish', () => setTimeout(() => performPanelRestart(), 150).unref());
  return restartPending;
}

async function checkNetworkSettings(input) {
  const next = {...config, port: input.panelPort == null ? config.port : normalizePort(input.panelPort),
    publicHubUrl: input.publicHubUrl == null ? config.publicHubUrl : normalizeOptionalHubUrl(input.publicHubUrl)};
  const endpoint = next.publicHubUrl && new URL(next.publicHubUrl);
  if (endpoint?.protocol === 'https:' && (!TRUST_PROXY || Number(endpoint.port || 443) === Number(next.port))) {
    throw businessError('https_proxy_required','当前面板直接提供 HTTP 服务。域名/IP:端口请使用 http://；HTTPS 需要配置 TLS 反向代理并启用 PROBE_TRUST_PROXY。');
  }
  const owned = new Set([server.address()?.port, agentServer?.address()?.port]);
  for (const candidate of new Set([Number(next.port), agentPortForConfig(next, Number(next.port))])) {
    if (owned.has(candidate)) continue;
    for (const host of ['::', '0.0.0.0']) await new Promise((resolve,reject) => {
      const probe=net.createServer();
      probe.once('error',err=>host === '::' && err.code === 'EAFNOSUPPORT' ? resolve() : reject(businessError('port_unavailable',`端口 ${candidate} 已被占用或无法监听，设置未保存。`)));
      probe.listen(candidate,host,()=>probe.close(resolve));
    });
  }
}

function handleAdminRestart(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, {error:'unauthorized'},401);
  const restart=queuePanelRestart(res);
  return sendJson(res,{ok:true,restart,message:'面板正在重启，请重新登录。'});
}

async function handleAdminSettingsSave(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const input = await readBody(req);
  const session = getAdminSession(req);
  try {
    if (input.basics && (input.basics.panelPort != null || input.basics.publicHubUrl != null)) await checkNetworkSettings(input.basics);
    const result = await transactConfig((draft) => {
      const previousPort = Number(draft.port || 8080);
      const previousPublicHubUrl = normalizeOptionalHubUrl(draft.publicHubUrl || '');
      let ipApiKeyChanged = false;
      if (input.backgrounds) draft.backgrounds = normalizeBackgrounds(input.backgrounds);
      if (input.whitelist) {
        const whitelist = normalizeIpWhitelist(input.whitelist.items || input.whitelist.ips || input.whitelist);
        const enabled = Boolean(input.whitelist.enabled && whitelist.length);
        if (enabled && !isIpAllowedByWhitelist(clientKey(req), whitelist)) throw businessError('current_ip_not_whitelisted', `该IP ${clientKey(req)} 为当前访问面板IP，为防止锁定后端，不允许删除。`);
        draft.ipWhitelist = whitelist; draft.ipWhitelistEnabled = enabled;
      }
      if (input.basics) {
        const basics = input.basics;
        if (basics.dashboardTitle != null) draft.dashboardTitle = cleanTextRequired(basics.dashboardTitle || '服务器监控面板', 'dashboardTitle');
        if (basics.dashboardIcon != null) draft.dashboardIcon = String(basics.dashboardIcon || '').trim();
        if (basics.panelPort != null) draft.port = normalizePort(basics.panelPort);
        if (basics.publicHubUrl != null) draft.publicHubUrl = normalizeOptionalHubUrl(basics.publicHubUrl);
        if (basics.ipapiRefreshIntervalHours != null) draft.ipapiRefreshIntervalHours = normalizeIpApiRefreshIntervalHours(basics.ipapiRefreshIntervalHours);
        if (basics.viewerIpModuleEnabled != null) draft.viewerIpModuleEnabled = Boolean(basics.viewerIpModuleEnabled);
        if (basics.ipapiKey != null && String(basics.ipapiKey).trim()) {
          const key = String(basics.ipapiKey).trim(); ipApiKeyChanged = key !== String(draft.ipapiKey || ''); draft.ipapiKey = key;
        }
        delete draft.adminPassword;
      }
      if (input.security) {
        const security = input.security;
        const currentUsername = cleanTextRequired(security.currentUsername || '', 'currentUsername');
        const currentPassword = String(security.currentPassword || '');
        const nextUsername = cleanTextRequired(security.newUsername || '', 'newUsername');
        const nextPassword = String(security.newPassword || '');
        if (currentUsername.length > 128 || nextUsername.length > 128) throw businessError('invalid_username', '用户名长度不能超过 128 个字符。');
        if (nextPassword.length < 8 || nextPassword.length > 1024) throw businessError('invalid_new_password', '新密码长度必须为 8 到 1024 个字符。');
        if (!safeEqual(currentUsername, draft.adminUsername || 'admin') || !verifyAdminPasswordSyncAgainst(currentPassword, draft.adminPasswordHash)) throw businessError('invalid_current_credentials', '原用户名或原密码不正确，已拒绝修改。');
        draft.adminUsername = nextUsername; draft.adminPasswordHash = hashAdminPassword(nextPassword); delete draft.adminPassword;
      }
      return { ipApiKeyChanged, restartRequired: Number(draft.port || 8080) !== previousPort || normalizeOptionalHubUrl(draft.publicHubUrl || '') !== previousPublicHubUrl };
    });
    if (result.ipApiKeyChanged) clearIpApiCache();
    const shouldForceRelogin = Boolean(session && input.security) || result.restartRequired;
    const restart = result.restartRequired ? queuePanelRestart(res) : null;
    if (shouldForceRelogin) revokeAdminSessions();
    scheduleAccessLocationRefresh(); broadcast({ type: 'refresh', at: Date.now() });
    return sendJson(res, { ok: true, forceRelogin: shouldForceRelogin, restartRequired: result.restartRequired, restart, basics: adminPanelBasics(), backgrounds: normalizeBackgrounds(config.backgrounds), onlineViewers: onlineViewerStats(), viewerAccess: publicViewerAccess(), blockedWhitelistAccess: publicBlockedWhitelistAccess(), whitelist: adminWhitelistSettings(req) });
  } catch (err) {
    if (err?.business || /required|unsupported|newlines|must be|between|invalid URL/i.test(err?.message || '')) return sendJson(res, { error: err.code || 'invalid_settings', message: err.message }, 400);
    throw err;
  }
}

function businessError(code, message) { return Object.assign(new Error(message), { business: true, code }); }

async function transactConfig(change) {
  const operation = configWriteQueue.catch(() => {}).then(() => {
    const draft = structuredClone(config);
    // This callback and atomic write are deliberately synchronous. Credential
    // changes are rare and the short event-loop pause prevents any legacy
    // direct config mutation from interleaving and being overwritten.
    const previousIdentityKeys = rememberedAgentIdentityKeys(draft);
    const result = change(draft);
    draft.agentIdentityKeys = rememberedAgentIdentityKeys({...draft, agentIdentityKeys:previousIdentityKeys});
    writeJsonSync(configPath, draft);
    config = draft;
    normalizedWhitelistCache = { source: null, items: [] };
    return result;
  });
  configWriteQueue = operation.then(() => undefined, () => undefined);
  return operation;
}

function writeJsonSync(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
  chmodSync(file, 0o600);
}

function revokeAdminSessions() {
  adminSessions.clear();
}

function clearIpApiCache() {
  // IPAPI results are bound to the credential that produced them. Any key
  // change must invalidate both successful and failed results, otherwise a bad
  // replacement key could keep showing stale data from the previous valid key.
  for (const entry of Object.values(state.serverIpQuality || {})) {
    if (entry && Object.prototype.hasOwnProperty.call(entry, 'ipApi')) delete entry.ipApi;
  }
  state.ipApiLastRefreshAt = 0;
  for (const report of Object.values(state.servers)) {
    report.ipApiRefreshedAt = 0;
    report.ipApiAttemptedAt = 0;
    report.ipApiRefreshIps = '';
  }
  saveState().catch((err) => console.error(err));
}

async function handleAdminIpApiRefresh(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const result = await refreshPanelServerIpApiQuality('manual');
  return sendJson(res, {
    ok: result.failed === 0,
    attempted: result.attempted,
    skipped: result.skipped,
    success: result.success,
    failed: result.failed,
    message: ipApiRefreshResultMessage(result),
    results: result.results.map((item) => ({
      serverName: item.serverName,
      ok: item.ok,
      reason: item.ok ? '更新成功' : item.reason
    }))
  });
}

async function refreshPanelServerIpApiQuality(trigger = 'auto') {
  if (ipApiRefreshInFlight) return ipApiRefreshInFlight;
  ipApiRefreshInFlight = refreshPanelServerIpApiQualityInner(trigger)
    .finally(() => { ipApiRefreshInFlight = null; });
  return ipApiRefreshInFlight;
}

function isReportOnline(report = {}, now = Date.now()) {
  return Boolean(report?.lastReportAt && now - Number(report.lastReportAt) <= Number(config.heartbeatTimeoutSeconds || 45) * 1000);
}

function reportIpSignature(report = {}) {
  const { ipv4, ipv6 } = serverIpFields(report);
  return `${ipv4}|${ipv6}`;
}

function ipApiRefreshDue(report, now = Date.now()) {
  if (!isReportOnline(report, now)) return false;
  const signature = reportIpSignature(report);
  if (signature === '|') return false;
  const interval = normalizeIpApiRefreshIntervalHours(config.ipapiRefreshIntervalHours || 24) * 3600_000;
  const changed = report.ipApiRefreshIps !== reportIpSignature(report);
  const lastSuccess = Number(report.ipApiRefreshedAt || 0);
  const lastAttempt = Number(report.ipApiAttemptedAt || 0);
  return (changed || !lastSuccess || now - lastSuccess >= interval)
    && (report.ipApiAttemptIps !== signature || now - lastAttempt >= 60_000);
}

function refreshServerIpApiQuality(meta, refreshed = new Map()) {
  if (ipApiServerRefreshes.has(meta.id)) return ipApiServerRefreshes.get(meta.id);
  const task = new Promise((resolve, reject) => {
    const job = { meta, refreshed, resolve, reject };
    // New nodes take the next available slot before routine refreshes.
    if (!state.servers[meta.id]?.ipApiRefreshedAt) ipApiRefreshQueue.unshift(job);
    else ipApiRefreshQueue.push(job);
  });
  ipApiServerRefreshes.set(meta.id, task);
  drainIpApiRefreshQueue();
  return task;
}

function drainIpApiRefreshQueue() {
  while (ipApiActiveRefreshes < 4 && ipApiRefreshQueue.length) {
    const job = ipApiRefreshQueue.shift();
    ipApiActiveRefreshes++;
    const finish = () => {
      ipApiServerRefreshes.delete(job.meta.id);
      ipApiActiveRefreshes--;
      drainIpApiRefreshQueue();
    };
    refreshServerIpApiQualityInner(job.meta, job.refreshed).then(
      (result) => { finish(); job.resolve(result); },
      (err) => { finish(); job.reject(err); }
    );
  }
}

async function refreshServerIpApiQualityInner(meta, refreshed) {
  const report = state.servers[meta.id];
  if (!config.servers.some((item) => item.id === meta.id) || !isReportOnline(report) || !config.ipapiKey) return null;
  const signature = reportIpSignature(report);
  if (signature === '|') return { serverName: meta.name || meta.id, ok: false, reason: '等待服务器上报有效 IP' };
  const key = config.ipapiKey;
  report.ipApiAttemptedAt = Date.now();
  report.ipApiAttemptIps = signature;
  report.ipApiRefreshError = '';
  const { ipv4, ipv6 } = serverIpFields(report);
  const failures = [];
  const snapshot = { ipApi: { ipv4: null, ipv6: null }, status: '', message: '' };
  for (const [family, ip] of [['ipv4', ipv4], ['ipv6', ipv6]]) {
    if (!ip) continue;
    if (!isReportOnline(state.servers[meta.id]) || reportIpSignature(state.servers[meta.id]) !== signature || config.ipapiKey !== key) break;
    const lookupKey = `${key}:${ip}`;
    if (!refreshed.has(lookupKey)) {
      refreshed.set(lookupKey, Promise.resolve().then(() => lookupServerIpApiQualityDetailed(ip))
        .catch(() => ({ ok: false, reason: 'IP 质量服务暂时不可用' })));
    }
    const result = await refreshed.get(lookupKey);
    if (result.ok && result.data) snapshot.ipApi[family] = result.data;
    else failures.push(sanitizeIpApiErrorText(result.reason || '更新失败'));
  }
  const current = state.servers[meta.id];
  if (!config.servers.some((item) => item.id === meta.id) || !isReportOnline(current) || reportIpSignature(current) !== signature || config.ipapiKey !== key) return null;
  const previous = current.ipQualitySnapshot?.ipApi || {};
  for (const [family, ip] of [['ipv4', ipv4], ['ipv6', ipv6]]) {
    if (snapshot.ipApi[family]) state.serverIpQuality[ip] = { ipApi: snapshot.ipApi[family], updatedAt: Date.now() };
    else if (current.ipApiRefreshIps === signature) snapshot.ipApi[family] = previous[family] || null;
  }
  if (snapshot.ipApi.ipv4 || snapshot.ipApi.ipv6) current.ipQualitySnapshot = snapshot;
  const ok = failures.length === 0;
  current.ipApiRefreshError = failures.join('；');
  if (ok) {
    current.ipApiRefreshedAt = Date.now();
    current.ipApiRefreshIps = signature;
    state.ipApiLastRefreshAt = Date.now();
  }
  // Publish this node immediately, even if other nodes are still querying.
  broadcast({ type: 'refresh', id: meta.id, at: Date.now() });
  saveStateSoon().catch((err) => console.error(err));
  return { serverName: meta.name || meta.id, ok, reason: failures.join('；') || '更新成功' };
}

async function refreshPanelServerIpApiQualityInner(trigger = 'auto') {
  const now = Date.now();
  const online = orderedServers().filter((meta) => isReportOnline(state.servers[meta.id], now));
  const skipped = config.servers.length - online.length;
  const candidates = trigger === 'auto' ? online.filter((meta) => ipApiRefreshDue(state.servers[meta.id], now)) : online;
  if (!String(config.ipapiKey || '').trim()) {
    const results = candidates.map((meta) => ({ serverName: meta.name || meta.id, ok: false, reason: '后端未填写 IPAPI 密钥' }));
    return { trigger, skipped, attempted: results.length, success: 0, failed: results.length, results };
  }
  const refreshed = new Map();
  const results = (await Promise.all(candidates.map((meta) => refreshServerIpApiQuality(meta, refreshed)))).filter(Boolean);
  const success = results.filter((item) => item.ok).length;
  const failed = results.length - success;
  if (results.length) {
    if (success) state.ipApiLastRefreshAt = Date.now();
    await saveStateNow();
  }
  return { trigger, skipped, attempted: results.length, success, failed, results };
}

async function runDueIpApiRefresh() {
  if (!config.ipapiKey || !Object.values(state.servers).some((report) => ipApiRefreshDue(report))) return;
  await refreshPanelServerIpApiQuality('auto');
}

function ipApiRefreshResultMessage(result = {}) {
  const attempted = Number(result.attempted || 0);
  const failed = Number(result.failed || 0);
  const success = Number(result.success || 0);
  if (!attempted) return result.skipped ? `已跳过 ${result.skipped} 台离线服务器，保留最后一次数据` : '没有可更新的服务器IPAPI数据';
  if (!failed) return `IPAPI数据全部更新成功（${success} 台服务器）`;
  return `IPAPI数据更新完成：成功 ${success} 台服务器，失败 ${failed} 台服务器`;
}

function handleAdminConnectivityGet(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  return sendJson(res, { ok: true, checks: adminConnectivityChecks() });
}

async function handleAdminConnectivitySave(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const input = await readBody(req);
  let check;
  try { check = normalizeConnectivityCheck(input); } catch (err) { return sendJson(res, {error:err.message}, 400); }
  try {
    await transactConfig((draft) => {
      const current = draft.connectivityChecks.find((item) => item.id === check.id);
      if (current) Object.assign(current, check);
      else {
        if (draft.connectivityChecks.length >= MAX_CONNECTIVITY_SERVICES) throw businessError('connectivity_limit_reached', 'connectivity limit reached');
        draft.connectivityChecks.push(check);
      }
    });
  } catch (err) {
    if (err?.code === 'connectivity_limit_reached') return sendJson(res, { error: err.code, message: '达到数量上限' }, 409);
    throw err;
  }
  runConnectivityCheck(check).catch((err) => console.error(err));
  broadcast({ type: 'refresh', at: Date.now() });
  return sendJson(res, { ok: true, check: publicConnectivityCheck(check) });
}

async function handleAdminConnectivityDelete(req, res, url) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const id = decodeURIComponent(url.pathname.split('/').at(-2) || '');
  const deleted = await transactConfig((draft) => {
    const before = draft.connectivityChecks.length;
    draft.connectivityChecks = (draft.connectivityChecks || []).filter((check) => check.id !== id);
    return before !== draft.connectivityChecks.length;
  });
  connectivityDb.prepare('DELETE FROM connectivity_history WHERE check_id = ?').run(id);
  connectivityResults.delete(id);
  connectivityHistory.delete(id);
  delete state.connectivityResults?.[id];
  delete state.connectivityHistory?.[id];
  // Connectivity history is also embedded in every server report. Remove the
  // deleted check there as well so it cannot reappear from persisted state.
  for (const server of Object.values(state.servers || {})) {
    if (Array.isArray(server?.connectivity)) {
      server.connectivity = server.connectivity.filter((item) => item?.id !== id);
    }
  }
  await saveStateNow();
  broadcast({ type: 'refresh', at: Date.now() });
  return sendJson(res, { ok: true, deleted, id });
}

function handleConnectivityPublic(req, res) {
  return sendJson(res, { ok: true, checks: publicConnectivityChecks() });
}

async function handleAdminAddServer(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);

  const input = await readBody(req);
  const hubUrl = installHubUrl(input.hubUrl, req);
  const interval = clampInteger(input.interval, 1, 3600, 2);
  const serverId = cleanRequired(input.serverId || generateServerId(), 'serverId');
  const secret = generateSecret();
  const install = {
    id: serverId,
    secret,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  };
  try {
    await transactConfig((draft) => {
      if (draft.servers.some((server) => server.id === serverId)) throw businessError('server_exists', 'server exists');
      draft.pendingInstalls = [...(draft.pendingInstalls || []), install]
        .filter((item) => Date.now() - Number(item.createdAt || 0) <= 24 * 60 * 60 * 1000)
        .slice(-100);
    });
  } catch (err) {
    if (err?.code === 'server_exists') return sendJson(res, { error: err.code }, 409);
    throw err;
  }
  delete state.deletedServerIds?.[serverId];

  return sendJson(res, {
    ok: true,
    install: { id: install.id, expiresAt: install.expiresAt },
    command: buildInstallCommand({ hubUrl, token: secret, serverId, serverName: serverId, serverLocation: '', interval, reuseExisting:true })
  });
}

async function handleAdminServerInstallCommand(req, res, url) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const id = decodeURIComponent(url.pathname.split('/').at(-2) || '');
  let server = config.servers.find((item) => item.id === id);
  if (!server) return sendJson(res, { error: 'server_not_found' }, 404);
  const input = await readBody(req);
  const hubUrl = installHubUrl(input.hubUrl, req);
  const interval = clampInteger(input.interval, 1, 3600, 2);
  if (!server.secret) {
    server = await transactConfig((draft) => {
      const current = draft.servers.find((item) => item.id === id);
      if (!current) throw businessError('server_not_found', 'server not found');
      if (!current.secret) current.secret = generateSecret();
      return current;
    });
  }
  return sendJson(res, {
    ok: true,
    server: publicServerMeta(server),
    command: buildInstallCommand({
      hubUrl,
      token: server.secret,
      serverId: server.id,
      serverName: server.name || server.id,
      serverLocation: server.location || '',
      interval
    })
  });
}

async function handleAdminServerUninstallCommand(req, res, url) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const id = decodeURIComponent(url.pathname.split('/').at(-2) || '');
  const server = config.servers.find((item) => item.id === id);
  if (!server) return sendJson(res, { error: 'server_not_found' }, 404);
  const input = await readBody(req);
  const hubUrl = installHubUrl(input.hubUrl, req);
  return sendJson(res, {
    ok: true,
    server: publicServerMeta(server),
    command: buildUninstallCommand({ hubUrl })
  });
}

async function handleAdminDeleteServer(req, res, url) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const id = decodeURIComponent(url.pathname.split('/').at(-2) || '');
  const deleted = await transactConfig((draft) => {
    const before = draft.servers.length;
    draft.servers = draft.servers.filter((server) => server.id !== id);
    draft.pendingInstalls = (draft.pendingInstalls || []).filter((install) => install.id !== id);
    return before !== draft.servers.length;
  });
  connectivityDb.prepare('DELETE FROM connectivity_history WHERE server_id = ?').run(id);
  delete state.servers[id];
  delete state.history[id];
  state.deletedServerIds = state.deletedServerIds || {};
  state.deletedServerIds[id] = Date.now();
  delete state.trafficCycles?.[id];
  delete state.agentConnectivityServed?.[id];
  delete state.serverIpQuality?.[id];
  await saveStateNow();
  broadcast({ type: 'refresh', at: Date.now() });
  return sendJson(res, { ok: true, deleted, id });
}

function handleInstallOptions(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const hubUrl = inferHubUrl(req);
  return sendJson(res, {
    hubUrl,
    interval: 2,
    adminConfigured: Boolean(config.adminPasswordHash),
    fields: [
      { name: 'hubUrl', label: '面板地址', required: true, default: hubUrl, env: 'HUB_URL' },
      { name: 'serverId', label: '服务器 ID', required: true, example: 'sg-01', env: 'SERVER_ID' },
      { name: 'serverName', label: '服务器名称', required: true, example: 'Singapore VPS', env: 'SERVER_NAME' },
      { name: 'serverLocation', label: '位置/国家代码', required: false, example: 'SG', env: 'SERVER_LOCATION' },
      { name: 'expiresAt', label: '到期日期', required: false, example: '2027-01-01', configField: 'expiresAt' },
      { name: 'tags', label: '标签', required: false, example: ['prod'], configField: 'tags' },
      { name: 'interval', label: '上报间隔秒数', required: false, default: 2, env: 'INTERVAL' }
    ],
    reportFields: [
      'id', 'name', 'location', 'hostname', 'uptimeSeconds', 'os', 'cpu', 'memory', 'swap', 'disk', 'net', 'connections',
      'city', 'region', 'country', 'latitude', 'longitude', 'timezone', 'org', 'isp', 'asn', 'company', 'route', 'networkType',
      'publicIp', 'publicIpv4', 'publicIpv6', 'ipv4', 'ipv6'
    ]
  });
}

async function handleUninstallCommand(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const input = await readBody(req);
  const hubUrl = installHubUrl(input.hubUrl, req);
  return sendJson(res, { ok: true, command: buildUninstallCommand({ hubUrl }) });
}

async function handleInstallCommand(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);

  const input = await readBody(req);
  const serverId = cleanRequired(input.serverId || input.id, 'serverId');
  const serverName = cleanTextRequired(input.serverName || input.name || serverId, 'serverName');
  const hubUrl = installHubUrl(input.hubUrl, req);
  const serverLocation = String(input.serverLocation || input.location || '').trim();
  const interval = clampInteger(input.interval, 1, 3600, 2);
  const tags = Array.isArray(input.tags) ? input.tags.map((tag) => String(tag).trim()).filter(Boolean) : [];
  const expiresAt = input.expiresAt ? String(input.expiresAt).trim() : null;
  if (expiresAt && !isValidIsoDate(expiresAt)) return sendJson(res, { error: 'invalid_expires_at', message: 'expiresAt must be a real YYYY-MM-DD date' }, 400);

  const secret = config.servers.find((server) => server.id === serverId)?.secret || generateSecret();
  const server = await transactConfig((draft) => upsertServerMeta(draft, { id: serverId, name: serverName, location: serverLocation, tags, expiresAt, secret }));
  broadcast({ type: 'refresh', id: serverId, at: Date.now() });

  return sendJson(res, {
    ok: true,
    server: publicServerMeta(server),
    command: buildInstallCommand({ hubUrl, token: secret, serverId, serverName, serverLocation, interval }),
    env: {
      HUB_URL: hubUrl,
      SERVER_ID: serverId,
      SERVER_NAME: serverName,
      SERVER_LOCATION: serverLocation,
      INTERVAL: String(interval)
    }
  });
}

function agentIdentityKey(serverId, token) {
  return createHash('sha256').update(`${serverId}\n${token}`).digest('hex');
}

function activeAgentIdentityKeys(settings = config) {
  return (settings.servers || []).flatMap(server => {
    const token = server.secret || (settings.allowLegacyAgentToken === true ? settings.agentToken : '');
    return token ? [agentIdentityKey(server.id, token)] : [];
  });
}

function rememberedAgentIdentityKeys(settings) {
  const current = [...activeAgentIdentityKeys(settings),
    ...(settings.pendingInstalls || []).filter(item => item.secret).map(item => agentIdentityKey(item.id, item.secret))];
  const keys = [...(Array.isArray(settings.agentIdentityKeys) ? settings.agentIdentityKeys : []).filter(key => !current.includes(key)), ...current];
  return [...new Set(keys.filter(key => /^[a-f0-9]{64}$/.test(key)))].slice(-4096);
}

function buildInstallCommand({ hubUrl, token, serverId, serverName, serverLocation, interval, reuseExisting = false }) {
  return `curl -fL ${shellQuote(`${hubUrl}/api/agent/install.sh`)} -o agent.sh && chmod +x agent.sh && env PROBE_PANEL_ID=${shellQuote(config.panelId)} PROBE_REUSE_EXISTING=${reuseExisting ? '1' : '0'} PROBE_HUB_URL=${shellQuote(hubUrl)} PROBE_AGENT_TOKEN=${shellQuote(token)} PROBE_SERVER_ID=${shellQuote(serverId)} PROBE_SERVER_NAME=${shellQuote(serverName)} PROBE_SERVER_LOCATION=${shellQuote(serverLocation)} PROBE_INTERVAL=${shellQuote(String(interval))} PROBE_CONNECTIVITY_INTERVAL=60 ./agent.sh`;
}

function buildUninstallCommand({ hubUrl }) {
  return `curl -fL ${shellQuote(`${hubUrl}/api/agent/uninstall.sh`)} -o uninstall-agent.sh && chmod +x uninstall-agent.sh && env PROBE_PANEL_ID=${shellQuote(config.panelId)} ./uninstall-agent.sh`;
}

function buildAgentManager(action) {
  return ['#!/usr/bin/env bash', `PANEL_ID=${shellQuote(config.panelId)}`,
    `MATCH_KEYS=${shellQuote(rememberedAgentIdentityKeys(config).join(' '))}`,
    `ACTIVE_KEYS=${shellQuote(activeAgentIdentityKeys().join(' '))}`,
    `AGENT_ACTION=${shellQuote(action)}`,
    readFileSync(path.join(rootDir, 'agent/manage-agent.sh'), 'utf8')].join('\n');
}

function buildAgentInstaller() { return buildAgentManager('install'); }
function buildAgentUninstaller() { return buildAgentManager('uninstall'); }

function buildOverview({compact = false} = {}) {
  const timeoutMs = Number(config.heartbeatTimeoutSeconds || 45) * 1000;
  const rows = orderedServers().map((meta) => normalizeServer(meta, state.servers[meta.id], timeoutMs));
  const totals = rows.reduce((acc, server) => {
    acc.total += 1;
    if (server.online) acc.online += 1;
    else acc.offline += 1;
    acc.netInTotal += server.net.totalIn || 0;
    acc.netOutTotal += server.net.totalOut || 0;
    acc.tcp += server.connections.tcp || 0;
    acc.udp += server.connections.udp || 0;
    return acc;
  }, { total: 0, online: 0, offline: 0, netInTotal: 0, netOutTotal: 0, tcp: 0, udp: 0 });

  return {
    title: config.dashboardTitle || '服务器监控面板',
    generatedAt: Date.now(),
    panelStartedAt, compact,
    settings: { basics: publicPanelBasics(), backgrounds: publicBackgrounds() },
    onlineViewers: onlineViewerStats(),
    totals,
    servers: rows,
    // The first detail view is already available when its homepage card is
    // visible. Only bounded, recorded samples and cached quality are included;
    // rendering a card must never depend on another network round trip.
    detailSnapshots: Object.fromEntries(rows.map((server) => {
      const report = state.servers[server.id] || {};
      const endAt = server.online ? Date.now() : Number(report.lastReportAt || Date.now());
      const recorded = (compact ? [] : (state.history[server.id] || []).slice(-500))
        .filter((point) => point.t >= endAt - 120_000 && point.t <= endAt);
      const history = recorded.length <= 60 ? recorded : Array.from({ length: 60 }, (_, i) => recorded[Math.round(i * (recorded.length - 1) / 59)]);
      return [server.id, {
        ...(compact ? {} : {history, ipQuality:cachedServerIpQuality(report), connectivityGaps:report.connectivityGaps || []}),
        point: report.lastReportAt ? compactHistoryPoint(report, report.lastReportAt) : null,
        connectivity: publicServerConnectivityChecks(server.id, report.connectivity || [], report.lastReportAt || 0)
      }];
    }))
  };
}

function cachedServerIpQuality(report = {}) {
  if (!isReportOnline(report) && report.ipQualitySnapshot) return report.ipQualitySnapshot;
  if (isReportOnline(report) && report.ipQualitySnapshot?.ipApi && report.ipApiRefreshIps === reportIpSignature(report)) return report.ipQualitySnapshot;
  if (!String(config.ipapiKey || '').trim()) {
    return { ipApi: null, status: 'missing_key', message: '后端未填写 IPAPI 密钥' };
  }
  const ipv4 = normalizeClientIp(report.publicIpv4 || report.ipv4 || (isIpv4(report.publicIp || report.ip) ? report.publicIp || report.ip : ''));
  const ipv6 = normalizeClientIp(report.publicIpv6 || report.ipv6 || (isIpv6(report.publicIp || report.ip) ? report.publicIp || report.ip : ''));
  const cached = state.serverIpQuality || {};
  const value = (ip) => ip && cached[ip]?.ipApi ? { ...cached[ip].ipApi, updatedAt: cached[ip].updatedAt || cached[ip].ipApi.updatedAt || 0 } : null;
  const ipApi = { ipv4: value(ipv4), ipv6: value(ipv6) };
  if (ipApi.ipv4 || ipApi.ipv6) return { ipApi, status: '', message: '' };
  if (!isReportOnline(report)) return { ipApi, status: 'offline', message: '服务器离线，保留已有数据；上线后自动查询。' };
  if (!ipv4 && !ipv6) return { ipApi, status: 'waiting_ip', message: '等待服务器上报有效 IP，收到后立即查询。' };
  if (report.ipApiRefreshError && report.ipApiAttemptIps === reportIpSignature(report)) return { ipApi, status: 'error', message: `${report.ipApiRefreshError}，稍后自动重试。` };
  return { ipApi, status: 'pending', message: '正在查询 IP 质量，完成后自动显示。' };
}

async function buildServerDetail(id, options = {}) {
  const timeoutMs = Number(config.heartbeatTimeoutSeconds || 45) * 1000;
  const meta = config.servers.find((server) => server.id === id);
  if (!meta) return null;
  const report = state.servers[id] || {};
  const server = normalizeServer(meta, report, timeoutMs);
  server.ipQuality = cachedServerIpQuality(report);
  const retainedHistory = Array.isArray(state.history[id]) ? state.history[id].slice(-500) : [];
  const historySince = Number(options.historySince || 0);
  // Only a cursor still present in this server's retained history is valid.
  // A lost/reset/expired cursor receives a complete snapshot for recovery.
  const incremental = historySince > 0 && retainedHistory.some(point => Number(point.t) === historySince);
  return {
    server,
    connectivityGaps: report.connectivityGaps || [],
    connectivity: await publicServerConnectivityChecks(id, report.connectivity || [], report.lastReportAt || 0, options),
    history: incremental ? retainedHistory.filter(point => Number(point.t) > historySince) : retainedHistory,
    historyMode: incremental ? 'incremental' : 'full',
    historyCursor: Number(retainedHistory.at(-1)?.t || 0),
    historyStartAt: Number(retainedHistory[0]?.t || 0),
    point: compactHistoryPoint(report, report.lastReportAt || Date.now())
  };
}

function normalizeServer(meta, report = {}, timeoutMs) {
  const lastReportAt = report.lastReportAt || 0;
  const cycleTraffic = calculateCycleTraffic(meta, report);
  return {
    id: meta.id,
    name: meta.name || report.name || meta.id,
    location: meta.location || report.location || '',
    countryCode: serverCountryCode(meta, report),
    tags: meta.tags || report.tags || [],
    startedAt: meta.startedAt || null,
    expiresAt: meta.expiresAt || report.expiresAt || null,
    remainingTrafficBytes: meta.remainingTrafficBytes ?? null,
    priceAmount: meta.priceAmount ?? null,
    priceCurrency: meta.priceCurrency ?? null,
    pricePeriod: meta.pricePeriod ?? null,
    trafficCycleStartDate: meta.trafficCycleStartDate || '',
    trafficCycleUnit: meta.trafficCycleUnit || 'month',
    sortOrder: normalizeServerSortOrder(meta.sortOrder),
    cycleTraffic,
    trafficResetPaused: isExpiredOffline(meta, report),
    online: Boolean(lastReportAt && Date.now() - lastReportAt <= timeoutMs),
    lastReportAt,
    hostname: report.hostname || '',
    probeVersion: report.probeVersion || '',
    connectivityMeta: report.connectivityMeta || {},
    ipHidden: true,
    city: report.city || '',
    region: report.region || '',
    country: report.country || '',
    continent: report.continent || '',
    latitude: report.latitude || '',
    longitude: report.longitude || '',
    postal: report.postal || '',
    timezone: report.timezone || '',
    callingCode: report.callingCode || '',
    currency: report.currency || '',
    org: report.org || '',
    isp: report.isp || '',
    asn: report.asn || '',
    company: report.company || '',
    route: report.route || '',
    networkType: report.networkType || '',
    uptimeSeconds: Number(report.uptimeSeconds || 0),
    os: report.os || {},
    cpu: report.cpu || { percent: 0, model: '', cores: 0, load: [0, 0, 0] },
    memory: report.memory || { total: 0, used: 0, available: 0, percent: 0 },
    swap: report.swap || { total: 0, used: 0, percent: 0 },
    disk: normalizeDiskReport(report.disk),
    net: report.net || { inBps: 0, outBps: 0, totalIn: 0, totalOut: 0 },
    connections: report.connections || { tcp: 0, udp: 0 }
  };
}

function normalizeDiskReport(disk = {}) {
  const total = Number(disk.total || 0);
  const used = Number(disk.used || 0);
  const available = disk.available == null ? Math.max(0, total - used) : Number(disk.available || 0);
  const percent = disk.percent == null && total > 0 ? Number(((used * 100) / total).toFixed(2)) : Number(disk.percent || 0);
  return { total, used, available, percent };
}

function normalizeAgentReport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw Object.assign(new Error('invalid_report'), { code: 'INVALID_JSON' });
  const text = (value, max = 256) => String(value ?? '').replace(/[\r\n\0]/g, ' ').trim().slice(0, max);
  const number = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    const n = Number(value); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : 0;
  };
  const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const metric = (value, fields) => Object.fromEntries(fields.map(([key, min, max]) => [key, number(object(value)[key], min, max)]));
  let id;
  try { id = cleanRequired(text(input.id, 96), 'id'); } catch { throw Object.assign(new Error('invalid_server_id'), { code: 'INVALID_JSON' }); }
  const report = { id };
  for (const key of ['name','location','hostname','probeVersion','publicIp','ip','publicIpv4','ipv4','publicIpv6','ipv6','ipHostname','city','region','country','continent','latitude','longitude','postal','timezone','callingCode','currency','org','isp','asn','company','route','networkType']) report[key] = text(input[key], key === 'name' ? 128 : 256);
  report.uptimeSeconds = number(input.uptimeSeconds, 0, 3155760000);
  report.bootId = text(input.bootId, 64);
  report.tags = Array.isArray(input.tags) ? input.tags.slice(0, 32).map((v) => text(v, 64)).filter(Boolean) : [];
  report.os = Object.fromEntries(['platform','version','arch','kernel'].map((k) => [k, text(object(input.os)[k], 128)]));
  report.cpu = { ...metric(input.cpu, [['percent',0,100],['cores',0,4096]]), model: text(object(input.cpu).model, 256), load: (Array.isArray(object(input.cpu).load) ? object(input.cpu).load : []).slice(0,3).map((v) => number(v,0,1e6)) };
  report.memory = metric(input.memory, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['available',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  report.swap = metric(input.swap, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  if (!Object.hasOwn(object(input.swap), 'percent')) report.swap.percent = report.swap.total ? Math.min(100, report.swap.used * 100 / report.swap.total) : 0;
  report.disk = metric(input.disk, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['available',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  report.net = metric(input.net, [['inBps',0,Number.MAX_SAFE_INTEGER],['outBps',0,Number.MAX_SAFE_INTEGER],['totalIn',0,Number.MAX_SAFE_INTEGER],['totalOut',0,Number.MAX_SAFE_INTEGER]]);
  // Missing/invalid counters are not a real reset to zero. Keep them absent
  // so accounting and report merging can preserve the last valid baseline.
  for (const key of ['totalIn', 'totalOut']) {
    const raw = input.net?.[key];
    if (raw == null || raw === '' || typeof raw === 'boolean' || !Number.isFinite(Number(raw)) || Number(raw) < 0) delete report.net[key];
  }
  report.connections = metric(input.connections, [['tcp',0,1e7],['udp',0,1e7]]);
  report.connectivity = Array.isArray(input.connectivity) ? input.connectivity.slice(0, MAX_CONNECTIVITY_CHECKS).map((item) => ({ id: text(item?.id,96), name: text(item?.name,128), taskAt:number(item?.taskAt,0,Date.now()+300000), attempts:number(item?.attempts,1,4), final:item?.final===true, ok: item.ok, error: text(item?.error,256), latencyMs: number(item?.latencyMs,0,3600000), packetLossPercent: number(item?.packetLossPercent,0,100), checkedAt: number(item?.checkedAt,0,Date.now()+300000) })).filter((v) => v.id) : [];
  report.connectivityMeta = { count: number(input.connectivityMeta?.count,0,MAX_CONNECTIVITY_CHECKS), error: text(input.connectivityMeta?.error,256) };
  return report;
}

function mergeAgentReport(previous = {}, incoming = {}) {
  const merged = { ...previous, ...incoming };
  merged.net = { ...previous.net, ...incoming.net };
  if (!incoming.bootId) merged.bootId = previous.bootId || '';
  // Startup/DNS failures yield empty metadata, not evidence that a known
  // country or location has disappeared. Preserve successful metadata.
  for (const field of ['location', 'ipHostname', 'city', 'region', 'country', 'continent', 'latitude', 'longitude', 'postal', 'timezone', 'callingCode', 'currency', 'org', 'isp', 'asn', 'company', 'route', 'networkType']) {
    if (!String(incoming[field] || '').trim()) merged[field] = previous[field] || '';
  }
  const country = normalizeCountryCode(incoming.country);
  merged.country = country || previous.country || '';
  const previousIps = serverIpFields(previous);
  const incomingIps = serverIpFields(incoming);
  const ipv4 = incomingIps.ipv4 || previousIps.ipv4;
  const ipv6 = incomingIps.ipv6 || previousIps.ipv6;

  merged.publicIpv4 = ipv4;
  merged.ipv4 = ipv4;
  merged.publicIpv6 = ipv6;
  merged.ipv6 = ipv6;

  const incomingPublicIp = normalizeClientIp(incoming.publicIp || incoming.ip || '');
  const previousPublicIp = normalizeClientIp(previous.publicIp || previous.ip || '');
  const publicIp = (net.isIP(incomingPublicIp) ? incomingPublicIp : '') || ipv4 || ipv6 || (net.isIP(previousPublicIp) ? previousPublicIp : '');
  merged.publicIp = publicIp;
  merged.ip = publicIp;
  return merged;
}

function serverIpFields(report = {}) {
  const candidates = [report.publicIpv4, report.ipv4, report.publicIpv6, report.ipv6, report.publicIp, report.ip]
    .map((value) => normalizeClientIp(value))
    .filter((value) => net.isIP(value));
  return {
    ipv4: candidates.find((value) => net.isIP(value) === 4) || '',
    ipv6: candidates.find((value) => net.isIP(value) === 6) || ''
  };
}

function sanitizeIpQualitySource(source) {
  if (!source) return null;
  const { ip, query, publicIp, publicIpv4, publicIpv6, ipv4, ipv6, ...safe } = source;
  if (!safe.ipType) safe.ipType = inferIpType(safe);
  safe.registeredLocation = uppercaseLeadingCountryCode(safe.registeredLocation);
  safe.usageLocation = uppercaseLeadingCountryCode(safe.usageLocation);
  if (safe.source === 'ping0' && !safe.nativeIp) safe.nativeIp = inferNativeIpLabel(ip || query || publicIp || publicIpv4 || publicIpv6 || ipv4 || ipv6 || '');
  safe.ipHidden = true;
  return safe;
}

function uppercaseLeadingCountryCode(value) {
  const text = String(value || '').trim();
  return text.replace(/^[a-z]{2,3}\b/, (code) => code.toUpperCase());
}

function normalizePing0Quality(input = {}) {
  const ip = normalizeClientIp(input.ping0Ip || '');
  const location = String(input.ping0Location || '').trim();
  const asn = String(input.ping0Asn || '').trim();
  const org = String(input.ping0Org || '').trim();
  if (!ip && !location && !asn && !org) return null;
  const score = scoreIpProfile({ org, asn, source: 'ping0' });
  const riskValue = normalizeRiskValue(input.ping0Risk ?? input.ping0IpRisk ?? input.iprisk);
  const nativeIp = normalizeNativeIpLabel(input.ping0NativeIp ?? input.nativeip, score.datacenter);
  return {
    source: 'ping0',
    location,
    asn,
    org,
    ipType: String(input.ping0IpType || input.iptype || inferPing0IpType({ org, asn, datacenter: score.datacenter })).trim(),
    riskValue: riskValue ?? (score.datacenter ? 35 : score.risk),
    riskLabel: riskLevelText(riskValue ?? (score.datacenter ? 35 : score.risk)),
    nativeIp,
    ipHidden: Boolean(ip),
    ...score,
    updatedAt: Number(input.ping0UpdatedAt || input.lastReportAt || Date.now())
  };
}

async function lookupServerIpApiQualityDetailed(ip) {
  if (!net.isIP(ip)) return { ok: false, reason: '无效 IP 地址', errorData: ip || null };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2200);
  try {
    const url = new URL('https://api.ipapi.is/');
    url.searchParams.set('q', ip);
    if (config.ipapiKey) url.searchParams.set('key', config.ipapiKey);
    const response = await fetch(url, { signal: controller.signal });
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = null; }
    if (!response.ok) {
      return { ok: false, status: response.status, reason: ipApiFailureReason(response.status, data || text), errorData: data || text || response.statusText };
    }
    if (!data) return { ok: false, reason: 'ipapi 返回空数据或非 JSON 数据', errorData: text || null };
    if (data.error) return { ok: false, reason: ipApiFailureReason(response.status, data), errorData: data };
    if (data.is_bogon) return { ok: false, reason: 'ipapi 返回 bogon/private IP，无法生成质量数据', errorData: data };
    const companyType = normalizeIpApiType(data.company?.type);
    const asnType = normalizeIpApiType(data.asn?.type);
    const hosting = Boolean(data.is_datacenter) || companyType === 'hosting' || asnType === 'hosting';
    const proxy = Boolean(data.is_proxy || data.is_vpn || data.is_tor);
    const mobile = Boolean(data.is_mobile);
    const org = data.company?.name || data.asn?.org || data.datacenter?.datacenter || '';
    const asn = data.asn?.asn ? `AS${data.asn.asn} ${data.asn.org || ''}`.trim() : '';
    const location = data.location || {};
    const registered = asnRegisteredLocation(data.asn || {});
    const nativeCategory = inferNativeCategory(registered, location);
    if (![location.country, location.state, location.city, asn, org].some(Boolean)) return { ok: false, reason: 'ipapi 返回数据缺少归属地/ASN/组织信息', errorData: data };
    const score = scoreIpProfile({ proxy, hosting, mobile, org, asn, source: 'ip-api' });
    return { ok: true, data: {
      source: 'ip-api',
      schemaVersion: 2,
      location: [location.country, location.state, location.city].filter(Boolean).join(' '),
      asn,
      org,
      companyType,
      asnType,
      registeredLocation: formatIpApiLocationParts(registered.country, registered.city),
      usageLocation: formatIpApiLocationParts(location.country, location.city),
      nativeCategory,
      ipType: inferIpApiCompositeType(companyType, asnType, hosting),
      proxy,
      hosting,
      mobile,
      ...score,
      updatedAt: Date.now()
    } };
  } catch (err) {
    return { ok: false, reason: err.name === 'AbortError' ? 'ipapi 请求超时' : `ipapi 请求失败：${err.message}`, errorData: err.message };
  } finally {
    clearTimeout(timer);
  }
}

function isIpApiKeyError(status, reason = '', data = null) {
  const text = `${reason || ''} ${typeof data === 'string' ? data : JSON.stringify(data || {})}`;
  return status === 401 || status === 403 || /forbidden|unauthorized|invalid.?key|api.?key|permission|denied/i.test(text);
}

function ipApiFailureReason(status, data) {
  const payload = typeof data === 'string' ? data : JSON.stringify(data || {});
  const message = typeof data === 'object' && data
    ? (data.message || data.error || data.reason || data.detail || '')
    : String(data || '');
  if (status === 401 || status === 403 || /forbidden|unauthorized|invalid.?key|api.?key|permission|denied/i.test(payload)) {
    return `接口拒绝：${message || `HTTP ${status}`}`;
  }
  if (status === 429 || /rate.?limit|quota|too many/i.test(payload)) return `接口拒绝：${message || '请求频率/额度限制'}`;
  if (status >= 400) return `ipapi 返回 HTTP ${status}：${message || payload || '未知错误'}`;
  return message || payload || 'ipapi 返回未知错误';
}

function sanitizeIpApiErrorText(value) {
  return String(value || '')
    .replace(/https?:\/\/\S+/gi, '[接口地址已隐藏]')
    .replace(/([?&]key=)[^&\s]+/gi, '$1[已隐藏]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP已隐藏]')
    .replace(/\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{1,}\b/gi, '[IP已隐藏]')
    .slice(0, 500);
}

function normalizeIpApiType(value) {
  const text = String(value || '').trim().toLowerCase();
  if (!text) return '';
  if (text === 'isp') return 'isp';
  if (text === 'hosting' || text === 'datacenter') return 'hosting';
  return text;
}

function inferIpApiCompositeType(companyType, asnType, hosting = false) {
  const company = normalizeIpApiType(companyType);
  const asn = normalizeIpApiType(asnType);
  if (company === 'isp' && asn === 'isp') return '双ISP / 家宽';
  if (company === 'hosting' && asn === 'hosting') return 'Hosting / 机房';
  if (company === 'isp' || asn === 'isp') return '单ISP / 机房';
  return hosting ? 'Hosting / 机房' : 'ISP / 家宽';
}

function parseRegisteredLocation(address) {
  const text = String(address || '').trim();
  if (!text) return { city: '', country: '' };
  const parts = text.split(',').map((part) => part.trim()).filter(Boolean);
  const country = parts.at(-1) || '';
  const city = parts[0] || '';
  return { city: city.replace(/\b\d{3,}(?:-\d+)?\b/g, '').trim(), country };
}

function asnRegisteredLocation(asn = {}) {
  return {
    city: '',
    country: String(asn.country || '').trim()
  };
}

function formatIpApiLocationParts(country, city) {
  return [uppercaseAsciiWord(country), city].filter(Boolean).join(' ') || '';
}

function uppercaseAsciiWord(value) {
  const text = String(value || '').trim();
  return /^[a-z]{2,3}$/.test(text) ? text.toUpperCase() : text;
}

function inferNativeCategory(registered = {}, location = {}) {
  const regCountry = String(registered.country || '').trim().toLowerCase();
  const useCountry = String(location.country_code || location.country || '').trim().toLowerCase();
  const regCity = String(registered.city || '').trim().toLowerCase();
  const useCity = String(location.city || '').trim().toLowerCase();
  if (!regCountry && !regCity) return '';
  if ((regCountry && useCountry && (regCountry === useCountry || countryNameMatchesCode(regCountry, useCountry))) && (!regCity || !useCity || regCity === useCity)) return '原生IP';
  return '广播IP';
}

function countryNameMatchesCode(name, code) {
  const pairs = { singapore: 'sg', japan: 'jp', 'united states': 'us', usa: 'us', china: 'cn', hongkong: 'hk', 'hong kong': 'hk' };
  return pairs[name] === code || pairs[code] === name;
}

function scoreIpProfile(profile = {}) {
  const org = String(profile.org || '').toLowerCase();
  const datacenter = Boolean(profile.hosting) || /amazon|aws|google|cloudflare|microsoft|azure|oracle|digitalocean|linode|akamai|tencent|alibaba|aliyun|huawei|hetzner|ovh|vultr|leaseweb/.test(org);
  let trust = 86;
  if (profile.proxy) trust = 38;
  else if (datacenter) trust = 68;
  else if (profile.mobile) trust = 78;
  const risk = 100 - trust;
  const level = risk >= 55 ? 'HIGH' : risk >= 35 ? 'MEDIUM' : 'LOW';
  return { trust, risk, confidence: profile.source === 'ip-api' ? 76 : 62, level, datacenter };
}

function inferIpType(profile = {}) {
  if (profile.proxy) return '代理 / VPN';
  if (profile.mobile) return '移动网络';
  if (profile.hosting || profile.datacenter) return 'Hosting / 机房';
  const org = String(profile.org || '').toLowerCase();
  if (/telecom|unicom|mobile|comcast|verizon|at&t|vodafone|telefonica|orange|charter|cox|bt |broadband|isp/.test(org)) return 'ISP / 宽带';
  return '普通网络';
}

function inferPing0IpType(profile = {}) {
  if (profile.proxy) return '代理 IP';
  if (profile.hosting || profile.datacenter) return 'IDC机房 IP';
  const org = String(profile.org || '').toLowerCase();
  if (/telecom|unicom|mobile|comcast|verizon|at&t|vodafone|telefonica|orange|charter|cox|bt |broadband|isp/.test(org)) return '家庭宽带 IP';
  return '家庭宽带 IP';
}

function inferNativeIpLabel(ip) {
  if (!net.isIP(ip)) return '未采集';
  return net.isIP(ip) === 6 ? 'IPv6 出口（已隐藏）' : 'IPv4 出口（已隐藏）';
}

function normalizeRiskValue(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(String(value).replace('%', '').trim());
  if (!Number.isFinite(number)) return null;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function riskLevelText(value) {
  const number = normalizeRiskValue(value);
  if (number === null) return '未采集';
  if (number < 15) return '极度纯净';
  if (number < 25) return '纯净';
  if (number < 40) return '中性';
  if (number < 60) return '轻微风险';
  if (number < 70) return '稍高风险';
  return '极度风险';
}

function normalizeNativeIpLabel(value, datacenter = false) {
  if (value === true || value === 1 || value === '1') return '原生 IP';
  if (value === false || value === 0 || value === '0') return '广播 IP';
  const text = String(value || '').trim();
  if (/原生/i.test(text)) return '原生 IP';
  if (/广播|非原生/i.test(text)) return '广播 IP';
  return datacenter ? '广播 IP' : '原生 IP';
}

function maybeAppendHistoryPoint(serverId, historyPoint, now) {
  const retentionMs = Number(config.historyRetentionHours || 24) * 60 * 60 * 1000;
  const history = Array.isArray(state.history[serverId]) ? state.history[serverId] : [];
  const last = history.at(-1);
  const shouldAppend = !last || now - Number(last.t || 0) >= HISTORY_SAMPLE_INTERVAL_MS;
  if (shouldAppend) history.push(historyPoint);
  else history[history.length - 1] = historyPoint;
  state.history[serverId] = history
    .filter((point) => now - Number(point.t || 0) <= retentionMs)
    .slice(-MAX_SERVER_HISTORY_POINTS);
}

function compactHistoryPoint(report, now) {
  return {
    t: now,
    cpu: Number(report.cpu?.percent || 0),
    mem: Number(report.memory?.percent || 0),
    swap: Number(report.swap?.percent || 0),
    disk: Number(report.disk?.percent || 0),
    inBps: Number(report.net?.inBps || 0),
    outBps: Number(report.net?.outBps || 0),
    totalIn: Number(report.net?.totalIn || 0),
    totalOut: Number(report.net?.totalOut || 0),
    uptimeSeconds: Number(report.uptimeSeconds || 0),
    bootId: report.bootId || '',
    tcp: Number(report.connections?.tcp || 0),
    udp: Number(report.connections?.udp || 0)
  };
}

function calculateCycleTraffic(meta, report = {}) {
  const quotaBytes = normalizeNullableNumber(meta.remainingTrafficBytes) || 0;
  const frozen = isExpiredOffline(meta, report);
  const cycle = currentTrafficCycle(meta, frozen ? Number(report.lastReportAt || Date.now()) : Date.now());
  const stored = state.trafficCycles?.[meta.id];
  const cycleKey = trafficCycleKey(cycle);

  if (stored && (frozen || stored.cycleKey === cycleKey || trafficCyclesOverlap(stored, cycle, report, meta))) {
    const usedIn = Math.max(0, Number(stored.usedIn || 0));
    const usedOut = Math.max(0, Number(stored.usedOut || 0));
    const usedTotal = usedIn + usedOut;
    return {
      startAt: cycle.startAt || Number(stored.startAt || 0) || null,
      endAt: cycle.endAt || Number(stored.endAt || 0) || null,
      unit: cycle.unit,
      quotaBytes,
      usedIn,
      usedOut,
      usedTotal,
      remainingBytes: quotaBytes > 0 ? Math.max(0, quotaBytes - usedTotal) : null
    };
  }

  if (stored) return { startAt: cycle.startAt, endAt: cycle.endAt, unit: cycle.unit, quotaBytes,
    usedIn: 0, usedOut: 0, usedTotal: 0, remainingBytes: quotaBytes > 0 ? quotaBytes : null };
  return calculateCycleTrafficFromHistory(meta, report, cycle, quotaBytes);
}

function trafficCounter(value) {
  if (value == null || value === '' || typeof value === 'boolean') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function trafficBootAt(report, at) {
  const uptime = Number(report?.uptimeSeconds);
  return uptime > 0 && Number.isFinite(uptime) && at > 0 ? at - uptime * 1000 : null;
}

function trafficRebooted(previous, report, now) {
  if (previous.bootId && report.bootId) return previous.bootId !== report.bootId;
  const before = previous.lastBootAt ?? trafficBootAt(previous, previous.lastReportAt || previous.updatedAt);
  const after = trafficBootAt(report, now);
  // Allow sampling/transport jitter. A counter decrease by itself is never
  // sufficient evidence of a reboot (missing samples used to add GB twice).
  const elapsed = now - Number(previous.updatedAt || previous.lastReportAt || 0);
  return before != null && after != null && after > before + 60000
    && Number(report.uptimeSeconds) * 1000 <= elapsed + 5000;
}

function trafficCyclesOverlap(previous, cycle, report = {}, meta = {}) {
  if (!previous) return false;
  const start = Number(previous.startAt || report.firstReportAt || meta.createdAt || previous.updatedAt || 0);
  const end = previous.endAt == null ? Infinity : Number(previous.endAt);
  const nextStart = Number(cycle.startAt || report.firstReportAt || meta.createdAt || 0);
  const nextEnd = cycle.endAt == null ? Infinity : Number(cycle.endAt);
  // Half-open ranges: touching at a reset boundary is not an overlap.
  return Math.max(start, nextStart) < Math.min(end, nextEnd);
}

function reconcileTrafficCycle(meta, report = {}, now = Date.now()) {
  const previous = state.trafficCycles?.[meta.id];
  const cycle = currentTrafficCycle(meta, now);
  const key = trafficCycleKey(cycle);
  if (!previous || (previous.cycleKey === key && previous.endAt === cycle.endAt)) return;
  const retain = trafficCyclesOverlap(previous, cycle, report, meta);
  state.trafficCycles[meta.id] = { ...previous,
    usedIn: retain ? previous.usedIn : 0, usedOut: retain ? previous.usedOut : 0,
    cycleKey: key, startAt: cycle.startAt, endAt: cycle.endAt, unit: cycle.unit,
    countBeforeStart: retain && now < cycle.startAt,
    carryBaseline: retain,
    accountingFrom: retain ? previous.accountingFrom : now
  };
}

function isStaleTrafficReport(previous, report, now = Date.now()) {
  if (!previous) return false;
  if (report.bootId && previous.retiredBootIds?.includes(report.bootId)) return true;
  const bootAt = trafficBootAt(report, now);
  if ((!report.bootId || !previous.bootId) && bootAt != null && previous.lastBootAt != null
      && bootAt < previous.lastBootAt - 60000) return true;
  return Boolean(report.bootId && report.bootId === previous.bootId
    && Number(report.uptimeSeconds) > 0 && Number(previous.uptimeSeconds) > Number(report.uptimeSeconds));
}

function updateTrafficCycleState(meta, previousReport = {}, report = {}, now = Date.now()) {
  if (!meta?.id) return;
  state.trafficCycles = state.trafficCycles || {};
  const cycle = currentTrafficCycle(meta, now);
  const cycleKey = trafficCycleKey(cycle);
  const previous = state.trafficCycles[meta.id];
  if (isStaleTrafficReport(previous, report, now)) return;
  if (previous && now <= Number(previous.updatedAt || 0)) return;
  const sameCycle = previous?.cycleKey === cycleKey && previous?.endAt === cycle.endAt;
  const retain = sameCycle || trafficCyclesOverlap(previous, cycle, previousReport, meta);
  const seed = retain ? previous : previous ? { usedIn: 0, usedOut: 0 } : calculateCycleTrafficFromHistory(meta, previousReport, cycle, 0);
  const next = retain ? previous : {
    usedIn: seed.usedIn, usedOut: seed.usedOut,
    lastTotalIn: trafficCounter(previous?.lastTotalIn ?? previousReport.net?.totalIn),
    lastTotalOut: trafficCounter(previous?.lastTotalOut ?? previousReport.net?.totalOut),
    updatedAt: previousReport.lastReportAt || 0,
    uptimeSeconds: previous?.uptimeSeconds ?? previousReport.uptimeSeconds, bootId: previous?.bootId || previousReport.bootId || '',
    lastBootAt: previous?.lastBootAt, retiredBootIds: previous?.retiredBootIds || []
  };
  if (!sameCycle) next.countBeforeStart = Boolean(retain && now < cycle.startAt);
  const bootReference = { ...previousReport, ...next, lastReportAt: next.updatedAt || previousReport.lastReportAt };
  const rebooted = trafficRebooted(bootReference, report, now);
  const observedBootAt = trafficBootAt(report, now);
  const intervalInCycle = (!next.accountingFrom || Number(next.updatedAt || 0) >= next.accountingFrom)
    && (next.carryBaseline || next.countBeforeStart || (!sameCycle && retain) || !cycle.startAt || Number(next.updatedAt || 0) >= cycle.startAt);
  if (rebooted && next.bootId && report.bootId && next.bootId !== report.bootId) {
    next.retiredBootIds = [...new Set([...(next.retiredBootIds || []), next.bootId])].slice(-16);
  }
  for (const [counter, used, last] of [['totalIn','usedIn','lastTotalIn'], ['totalOut','usedOut','lastTotalOut']]) {
    const current = trafficCounter(report.net?.[counter]);
    const baseline = trafficCounter(next[last]);
    next[used] = Math.max(0, Number(next[used] || 0));
    if (current == null) {
      if (rebooted) next[last] = next.countBeforeStart || !cycle.startAt || observedBootAt >= cycle.startAt ? 0 : null;
      else if (!intervalInCycle) next[last] = null;
      continue;
    }
    if (cycle.startAt && now < cycle.startAt && !next.countBeforeStart) { next[last] = Math.max(baseline ?? 0, current); continue; }
    if (rebooted) {
      // Only the current boot's observed total is known after a real reboot.
      // Never assign pre-boundary bytes to a new cycle after a long outage.
      const bootAt = trafficBootAt(report, now);
      if (next.countBeforeStart || !cycle.startAt || (bootAt != null && bootAt >= cycle.startAt)) next[used] += current;
      next[last] = current;
    } else if (baseline == null || !intervalInCycle) {
      next[last] = current;
    } else if (current >= baseline) {
      next[used] += current - baseline;
      next[last] = current;
    }
    // A lower counter in the same boot retains its high-water baseline. When
    // a temporarily missing interface returns, its entire total is not added.
  }
  Object.assign(next, { version: 2, cycleKey, startAt: cycle.startAt || null,
    endAt: cycle.endAt || null, unit: cycle.unit, updatedAt: now });
  delete next.carryBaseline;
  if (Number(report.uptimeSeconds) > 0) next.uptimeSeconds = report.uptimeSeconds;
  if (observedBootAt != null) next.lastBootAt = observedBootAt;
  if (report.bootId) next.bootId = report.bootId;
  state.trafficCycles[meta.id] = next;
}

function trafficCycleKey(cycle) {
  return `${cycle.startAt || 0}:${cycle.unit}`;
}

function calculateCycleTrafficFromHistory(meta, report = {}, cycle = currentTrafficCycle(meta), quotaBytes = normalizeNullableNumber(meta.remainingTrafficBytes) || 0) {
  const startAt = cycle.startAt || Number(meta.createdAt || report.firstReportAt || report.lastReportAt || 0) || 0;
  const history = [...(state.history?.[meta.id] || [])];
  if (report.lastReportAt) history.push({ ...report.net, t: report.lastReportAt, uptimeSeconds: report.uptimeSeconds, bootId: report.bootId });
  const points = [...new Map(history.filter(p => Number(p.t) >= startAt && (!cycle.endAt || Number(p.t) < cycle.endAt)).map(p => [Number(p.t),p])).values()].sort((a,b)=>a.t-b.t);
  let usedIn = 0, usedOut = 0, previous = null, lastIn = null, lastOut = null;
  for (const point of points) {
    const rebooted = previous && trafficRebooted({ ...previous, lastReportAt: previous.t },point,point.t);
    const incoming = trafficCounter(point.totalIn), outgoing = trafficCounter(point.totalOut);
    if (rebooted) {lastIn=0;lastOut=0;}
    if (incoming != null && (lastIn == null || incoming >= lastIn)) { if(lastIn!=null)usedIn+=incoming-lastIn;lastIn=incoming; }
    if (outgoing != null && (lastOut == null || outgoing >= lastOut)) { if(lastOut!=null)usedOut+=outgoing-lastOut;lastOut=outgoing; }
    previous=point;
  }
  const usedTotal = usedIn + usedOut;
  return { startAt: startAt || null, endAt: cycle.endAt, unit: cycle.unit, quotaBytes, usedIn, usedOut, usedTotal,
    remainingBytes: quotaBytes > 0 ? Math.max(0, quotaBytes - usedTotal) : null };
}

function isExpiredOffline(meta, report = {}) {
  const start = parseLocalDate(meta.startedAt);
  const expiry = parseLocalDate(meta.expiresAt || report.expiresAt);
  if (!start || !expiry || isReportOnline(report)) return false;
  expiry.setHours(23, 59, 59, 999);
  return expiry.getTime() > start.getTime() && Date.now() > expiry.getTime();
}

function currentTrafficCycle(meta, referenceAt = Date.now()) {
  const unit = normalizeTrafficCycleUnit(meta.trafficCycleUnit);
  const anchor = parseLocalDate(meta.trafficCycleStartDate);
  if (!anchor) return { unit, startAt: null, endAt: null };
  let index = 0, start = anchor, next = addTrafficCycle(anchor, unit, 1);
  while (next.getTime() <= referenceAt) {
    start = next;
    next = addTrafficCycle(anchor, unit, ++index + 1);
  }
  return { unit, startAt: start.getTime(), endAt: next.getTime() };
}

function addTrafficCycle(anchor, unit, count = 1) {
  const next = new Date(anchor.getTime());
  if (unit === 'day') next.setDate(next.getDate() + count);
  else if (unit === 'week') next.setDate(next.getDate() + 7 * count);
  else {
    // Always calculate from the original billing day. Jan 31 -> Feb 28 ->
    // Mar 31, rather than overflowing into March and permanently drifting.
    const day = anchor.getDate();
    next.setDate(1);
    if (unit === 'year') next.setFullYear(anchor.getFullYear() + count);
    else next.setMonth(anchor.getMonth() + count);
    const lastDay = new Date(next.getFullYear(),next.getMonth()+1,0).getDate();
    next.setDate(Math.min(day,lastDay));
  }
  return next;
}

function parseLocalDate(value) {
  const text = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return null;
  const date = new Date(`${text}T00:00:00`);
  return Number.isFinite(date.getTime()) ? date : null;
}

function handleEvents(req, res) {
  const viewer = recordViewerAccess(req);
  const ip = clientKey(req);
  const viewerId = normalizeViewerId(new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('viewerId'));
  recordViewerPresence(req, viewerId);
  res.writeHead(200, securityHeaders({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  }));
  clients.set(res, { ip, viewerId, connectedAt: Date.now() });
  res.write(`data: ${JSON.stringify({ type: 'hello', at: Date.now(), panelStartedAt, restart:restartPending, onlineViewers: onlineViewerStats(), viewer })}\n\n`);
  broadcast({ type: 'presence', at: Date.now(), onlineViewers: onlineViewerStats() });
  req.on('close', () => {
    clients.delete(res);
    if (viewerId) viewerPresence.delete(viewerId);
    broadcast({ type: 'presence', at: Date.now(), onlineViewers: onlineViewerStats() });
  });
}

function broadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const client of clients.keys()) {
    if (client.destroyed || client.writableEnded || client.writableNeedDrain || !client.write(data)) {
      // SSE is a notification channel, not a durable queue. A slow or detached
      // browser must reconnect instead of retaining an ever-growing response
      // buffer that eventually stalls other panel requests from the same phone.
      clients.delete(client);
      client.destroy();
    }
  }
}

function sendJson(res, data, status = 200, headers = {}) {
  res.writeHead(status, corsHeaders({ 'Cache-Control':'no-store', 'Content-Type': 'application/json; charset=utf-8', ...headers }));
  res.end(JSON.stringify(data));
}

async function sendPublicJson(req, res, data) {
  let body = Buffer.from(JSON.stringify(data));
  const headers = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', Vary: 'Accept-Encoding' };
  const acceptsGzip = String(req.headers['accept-encoding'] || '').split(',').some(entry => {
    const [coding, ...parameters] = entry.trim().toLowerCase().split(';');
    const quality = parameters.find(parameter => parameter.trim().startsWith('q='));
    return coding === 'gzip' && (quality == null || Number(quality.trim().slice(2)) > 0);
  });
  if (body.length >= 1024 && acceptsGzip) {
    // Only public monitoring payloads are compressed. Low-level asynchronous
    // gzip saves bandwidth without blocking the reporting/event loop.
    try {
      const compressed = await promisify(gzip)(body, { level: 1 });
      if (compressed.length < body.length) { body = compressed; headers['Content-Encoding'] = 'gzip'; }
    } catch { /* Uncompressed JSON remains a valid fallback. */ }
  }
  if (res.destroyed) return;
  headers['Content-Length'] = String(body.length);
  res.writeHead(200, corsHeaders(headers));
  res.end(body);
}

function corsHeaders(headers = {}) {
  const next = securityHeaders({
    ...headers,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-CSRF-Token',
    'Vary': headers.Vary ? `Origin, ${headers.Vary}` : 'Origin'
  });
  return next;
}

function securityHeaders(headers = {}) {
  return {
    ...headers,
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self'",
      "img-src 'self' data: blob: http: https:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join('; '),
    'X-Panel-Instance': String(panelStartedAt),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()'
  };
}

function handleOptions(res) {
  res.writeHead(204, corsHeaders());
  res.end();
}

function getBearerToken(req) {
  return req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const idx = cookie.indexOf('=');
    if (idx < 0) continue;
    const key = cookie.slice(0, idx).trim();
    if (key === name) return decodeURIComponent(cookie.slice(idx + 1));
  }
  return '';
}

function buildAdminCookie(req, token, maxAge = 12 * 60 * 60) {
  const parts = [
    `admin_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAge}`
  ];
  if (isSecureRequest(req)) parts.push('Secure');
  return parts.join('; ');
}

function isSecureRequest(req) {
  return req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function getAdminSession(req) {
  const token = getBearerToken(req) || getCookie(req, 'admin_session');
  const session = token ? adminSessions.get(token) : null;
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    adminSessions.delete(token);
    return null;
  }
  return session;
}

function isAdminAuthorized(req) {
  const session = getAdminSession(req);
  if (!session) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.url !== '/api/admin/login') {
    const csrfToken = req.headers['x-csrf-token'];
    if (!safeEqual(Array.isArray(csrfToken) ? csrfToken[0] : csrfToken, session.csrfToken || '')) return false;
  }
  return true;
}

function isAgentAuthorized(server, pendingInstall, token) {
  if (server?.secret && safeEqual(token, server.secret)) return true;
  if (pendingInstall?.secret && (!pendingInstall.expiresAt || Number(pendingInstall.expiresAt) > Date.now())) return safeEqual(token, pendingInstall.secret);
  return Boolean(config.allowLegacyAgentToken === true && config.agentToken && safeEqual(token, config.agentToken));
}

function hashAdminPassword(password) {
  const salt = randomBytes(16).toString('base64url');
  const digest = scryptSync(String(password || ''), salt, 64).toString('base64url');
  return `scrypt$${salt}$${digest}`;
}

async function hashAdminPasswordAsync(password) {
  const salt = randomBytes(16).toString('base64url');
  const digest = Buffer.from(await scryptAsync(String(password || ''), salt, 64)).toString('base64url');
  return `scrypt$${salt}$${digest}`;
}

async function verifyAdminPassword(password) {
  return verifyAdminPasswordAgainst(password, config.adminPasswordHash);
}

function verifyAdminPasswordSyncAgainst(password, storedHash) {
  const stored = String(storedHash || '');
  const [, salt, digest] = stored.split('$');
  if (!salt || !digest) return false;
  const candidate = scryptSync(String(password || '').slice(0, 1024), salt, 64).toString('base64url');
  return safeEqual(candidate, digest);
}

async function verifyAdminPasswordAgainst(password, passwordHash) {
  const stored = String(passwordHash || '');
  const [, salt, digest] = stored.split('$');
  if (!salt || !digest) return false;
  const candidate = Buffer.from(await scryptAsync(String(password || '').slice(0, 1024), salt, 64)).toString('base64url');
  return safeEqual(candidate, digest);
}

function clientKey(req) {
  const peerIp = normalizeClientIp(req.socket.remoteAddress || 'unknown');
  // Only trust forwarding headers from a local/private reverse proxy. A client
  // connected directly to the panel must not bypass the whitelist by forging
  // X-Forwarded-For with an allowed address.
  const forwarded = (TRUST_PROXY && ipLocalLocationLabel(peerIp) ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '');
  return normalizeClientIp(forwarded || peerIp);
}

function normalizeClientIp(value) {
  let ip = String(value || '').trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function isWhitelistAllowed(req, url) {
  if (isWhitelistExemptPath(url?.pathname || '')) return true;
  // This is deliberately the first policy check: when disabled, do not even
  // resolve the client IP or normalize the list.
  if (config.ipWhitelistEnabled !== true) return true;
  const whitelist = getNormalizedWhitelist();
  if (!whitelist.length) return true;
  const allowed = isIpAllowedByWhitelist(clientKey(req), whitelist);
  if (!allowed) recordBlockedWhitelistAccess(req);
  return allowed;
}

function isWhitelistExemptPath(pathname) {
  return pathname === '/healthz' || pathname.startsWith('/api/agent/');
}

function isAdminPagePath(pathname) {
  return ['/dashboard', '/picture', '/tcping', '/setting'].some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function isIpAllowedByWhitelist(ip, whitelist = config.ipWhitelist || []) {
  const normalizedIp = normalizeClientIp(ip);
  const items = Array.isArray(whitelist) ? whitelist : normalizeIpWhitelist(whitelist);
  return items.includes(normalizedIp);
}

function getNormalizedWhitelist() {
  const source = JSON.stringify(config.ipWhitelist || []);
  if (normalizedWhitelistCache.source !== source) {
    normalizedWhitelistCache = { source, items: normalizeIpWhitelist(config.ipWhitelist || []) };
  }
  return normalizedWhitelistCache.items;
}

function normalizeIpWhitelist(value) {
  const raw = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/);
  return Array.from(new Set(raw.map(normalizeClientIp).filter((ip) => net.isIP(ip)))).slice(0, 500);
}

function adminWhitelistSettings(req) {
  const items = normalizeIpWhitelist(config.ipWhitelist || []);
  return {
    enabled: Boolean(config.ipWhitelistEnabled && items.length),
    items,
    currentIp: clientKey(req)
  };
}

function recordFailedLogin(key, store = loginAttempts, limit = 6, lockMs = 10 * 60 * 1000) {
  const now = Date.now();
  const current = store.get(key) || { count: 0, firstAt: now, lockedUntil: 0 };
  const fresh = now - Number(current.firstAt || 0) > 10 * 60 * 1000 ? { count: 0, firstAt: now, lockedUntil: 0 } : current;
  fresh.count += 1;
  if (fresh.count >= limit) fresh.lockedUntil = now + lockMs;
  store.set(key, fresh);
}

function pruneLoginAttempts() {
  const now = Date.now();
  for (const [key, value] of loginAttempts) if (now - Number(value.firstAt || 0) > 20 * 60 * 1000 && now >= Number(value.lockedUntil || 0)) loginAttempts.delete(key);
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && timingSafeEqual(left, right);
}

function generateSecret() {
  return randomBytes(24).toString('base64url');
}

function generateServerId() {
  return `srv-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
}

function normalizeBackgrounds(value = {}) {
  const normalizeList = (input) => {
    const raw = Array.isArray(input) ? input : String(input || '').split(/\r?\n|,/);
    return Array.from(new Set(raw.map((item) => String(item || '').trim().slice(0, 2048)).filter(Boolean))).slice(0, 100);
  };
  const frontend = normalizeList(value.frontend);
  const admin = normalizeList(value.admin);
  return {
    frontendDesktop: normalizeList(value.frontendDesktop || value.frontendPc || value.frontendDesktopUrls || frontend),
    frontendMobile: normalizeList(value.frontendMobile ?? value.mobileFrontend ?? value.frontendMobileUrls ?? []),
    adminDesktop: normalizeList(value.adminDesktop || value.adminPc || value.adminDesktopUrls || admin),
    adminMobile: normalizeList(value.adminMobile ?? value.mobileAdmin ?? value.adminMobileUrls ?? [])
  };
}

function backgroundProxyId(value) {
  return createHash('sha256').update(String(value || '')).digest('hex').slice(0, 32);
}

function publicBackgrounds() {
  const raw = normalizeBackgrounds(config.backgrounds);
  return Object.fromEntries(Object.entries(raw).map(([key, urls]) => [key, urls.map((url) => `/media/background/${backgroundProxyId(url)}`)]));
}

function findBackgroundUrl(id) {
  for (const urls of Object.values(normalizeBackgrounds(config.backgrounds))) {
    for (const url of urls) if (backgroundProxyId(url) === id) return url;
  }
  return '';
}

async function serveBackgroundProxy(req, res, url) {
  const id = String(url.pathname.split('/').pop() || '');
  if (!/^[a-f0-9]{32}$/.test(id)) return sendNotFound(res);
  const source = findBackgroundUrl(id);
  if (!source || !/^https?:\/\//i.test(source)) return sendNotFound(res);
  const cacheFile = path.join(backgroundCacheDir, `${id}.image`);
  const metaFile = path.join(backgroundCacheDir, `${id}.json`);
  try {
    const cached = await readCachedBackground(cacheFile, metaFile);
    if (cached) return sendCachedBackground(req, res, id, cached);
    const fetched = await fetchBackgroundImage(source);
    await mkdir(backgroundCacheDir, { recursive: true });
    await Promise.all([
      writeFile(cacheFile, fetched.body, { mode: 0o600 }),
      writeFile(metaFile, `${JSON.stringify({ type: fetched.type, source, cachedAt: Date.now() })}\n`, { mode: 0o600 })
    ]);
    return sendCachedBackground(req, res, id, fetched);
  } catch (err) {
    const cached = await readCachedBackground(cacheFile, metaFile).catch(() => null);
    if (cached) return sendCachedBackground(req, res, id, cached);
    if (!res.headersSent) return err?.tooLarge ? sendJson(res, { error: 'image_too_large' }, 413) : sendNotFound(res);
    if (!res.destroyed) res.destroy();
  }
}

async function readCachedBackground(cacheFile, metaFile) {
  try {
    const [body, rawMeta] = await Promise.all([readFile(cacheFile), readFile(metaFile, 'utf8')]);
    const meta = JSON.parse(rawMeta);
    return body.length && String(meta.type || '').startsWith('image/') ? { body, type: meta.type } : null;
  } catch { return null; }
}

function sendCachedBackground(req, res, id, image) {
  const etag = `"bg-${id}"`;
  const headers = securityHeaders({ 'Content-Type': image.type, 'Cache-Control': 'public, max-age=604800, immutable', ETag: etag });
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, headers); return res.end(); }
  res.writeHead(200, { ...headers, 'Content-Length': image.body.length });
  res.end(image.body);
}

async function fetchBackgroundImage(value, redirects = 0) {
  if (redirects > 4) throw new Error('too_many_redirects');
  const target = await resolvePublicHttpUrl(value);
  return new Promise((resolve, reject) => {
    const transport = target.url.protocol === 'https:' ? https : http;
    const upstream = transport.request(target.url, {
      method: 'GET', headers: { Accept: 'image/*', 'User-Agent': 'Mozilla/5.0 ServerProbeMonitor/1.0' },
      lookup: (_hostname, options, callback) => options?.all
        ? callback(null, [{ address: target.address, family: target.family }])
        : callback(null, target.address, target.family),
      servername: target.url.hostname, timeout: 20_000
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        const next = new URL(response.headers.location, target.url).toString();
        return fetchBackgroundImage(next, redirects + 1).then(resolve, reject);
      }
      if (response.statusCode < 200 || response.statusCode >= 300) { response.resume(); return reject(new Error('bad_status')); }
      const type = String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      const declared = Number(response.headers['content-length'] || 0);
      if (!type.startsWith('image/') || declared > 20 * 1024 * 1024) { response.resume(); return reject(Object.assign(new Error('image_too_large'), { tooLarge: declared > 20 * 1024 * 1024 })); }
      const chunks = []; let size = 0;
      response.on('data', (chunk) => { size += chunk.length; if (size > 20 * 1024 * 1024) upstream.destroy(Object.assign(new Error('image_too_large'), { tooLarge: true })); else chunks.push(chunk); });
      response.on('end', () => resolve({ body: Buffer.concat(chunks), type }));
      response.on('error', reject);
    });
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', reject); upstream.end();
  });
}

async function resolvePublicHttpUrl(value) {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('invalid_background_url');
  const addresses = await lookup(parsed.hostname, { all: true, verbatim: true });
  const valid = addresses.filter(({ address }) => !isPrivateIp(address) && address !== '0.0.0.0' && address !== '::');
  if (!addresses.length || valid.length !== addresses.length) throw new Error('private_background_target');
  // Prefer IPv4 on hosts whose panel server has no working IPv6 route. DNS
  // answers commonly list IPv6 first, which previously made image loading fail
  // even though a healthy IPv4 CDN address was available.
  valid.sort((left, right) => Number(right.family === 4) - Number(left.family === 4));
  return { url: parsed, address: valid[0].address, family: valid[0].family };
}

function publicPanelBasics() {
  return {
    dashboardTitle: config.dashboardTitle || '服务器监控面板',
    dashboardIcon: config.dashboardIcon || '',
    panelPort: Number(config.port || 8080),
    runningPort: port,
    publicHubUrl: config.publicHubUrl || '',
    viewerIpModuleEnabled: config.viewerIpModuleEnabled !== false
  };
}

function adminPanelBasics() {
  return { ...publicPanelBasics(), effectiveHubUrl: inferHubUrlFromConfig(), adminUsername: config.adminUsername || 'admin', panelStartedAt, hasIpapiKey: Boolean(config.ipapiKey), ipapiRefreshIntervalHours: normalizeIpApiRefreshIntervalHours(config.ipapiRefreshIntervalHours || 24) };
}

function normalizeIpApiRefreshIntervalHours(value) {
  return clampInteger(value, 1, 9999, 24);
}

function normalizeConnectivityCheck(input) {
  const id = cleanRequired(input.id || `conn-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`, 'id');
  const name = cleanTextRequired(input.name || id, 'name');
  const target = cleanTextRequired(input.target || '', 'target');
  const raw = input.intervalMinutes ?? (input.intervalSeconds != null ? Number(input.intervalSeconds)/60 : 5);
  if (!/^[0-9]+$/.test(String(raw)) || Number(raw)<5 || Number(raw)>720) throw new Error('测试间隔时间只能填写5至720之间的阿拉伯整数');
  const interval = Number(raw)*60;
  return { id, name, target, intervalSeconds: interval, type: 'tcping', enabled: input.enabled !== false };
}

// Keep real observations at their original timestamps for every date range.
// The legacy function name is retained for callers; no averaging or smoothing.
function aggregateConnectivityHistory(history, cutoff) {
  const samples = new Map();
  for (const point of Array.isArray(history) ? history : []) {
    const t = Number(point.lastAt || point.t || 0);
    if (!Number.isFinite(t) || t <= 0 || t < cutoff) continue;
    const latency = Number(point.count ? point.lastLatency : point.latencyMs);
    const ok = Boolean((point.count ? point.lastOk : point.ok) && Number.isFinite(latency) && latency >= 0);
    samples.set(t, { t, latencyMs: ok ? Math.trunc(latency) : 0, ok,
      packetLossPercent: point.packetLossPercent ?? (ok ? 0 : 100) });
  }
  return [...samples.values()].sort((a, b) => a.t - b.t);
}

function publicConnectivityChecks() {
  return (config.connectivityChecks || []).map(publicConnectivityCheck);
}

function adminConnectivityChecks() {
  return (config.connectivityChecks || []).map((check) => ({
    ...check,
    result: connectivityResults.get(check.id) || null
  }));
}

function publicConnectivityCheck(check) {
  const { target: _target, ...safeCheck } = check;
  return { ...safeCheck, result: connectivityResults.get(check.id) || null, history: connectivityHistory.get(check.id) || [] };
}

function publicServerConnectivityChecks(serverId, results, serverLastReportAt = 0, options = {}) {
  const byId = new Map((Array.isArray(results) ? results : []).map((item) => [item.id, item]));
  const includeHistory = Boolean(options.includeConnectivityHistory);
  const rangeDays = clampInteger(options.connectivityRangeDays || 1, 1, 15, 1);
  const historyEndAt = isReportOnline({ lastReportAt: serverLastReportAt }) ? Date.now() : Number(serverLastReportAt || Date.now());
  const cutoff = historyEndAt - rangeDays * 24 * 60 * 60 * 1000;
  return (config.connectivityChecks || []).filter((check) => check.enabled !== false).map((check) => {
    const item = byId.get(check.id) || {};
    const latency = Number(item.latencyMs ?? 0);
    const checkedAt = Number(item.checkedAt || 0);
    const hasServerResult = checkedAt > 0;
    const packetLossPercent = normalizePacketLossPercent(item.packetLossPercent ?? item.packetLoss, item.ok ? 0 : 100);
    const historyPoints = includeHistory ? readConnectivityHistory(serverId, check.id, cutoff) : [];
    const history = includeHistory
      ? aggregateConnectivityHistory(historyPoints, cutoff, rangeDays, check.intervalSeconds, state.servers[serverId]?.connectivityGaps || [])
      : [];
    return {
      id: check.id,
      name: check.name,
      intervalSeconds: check.intervalSeconds,
      type: check.type || 'tcping',
      enabled: check.enabled !== false,
      result: hasServerResult ? {
        ok: Boolean(item.ok),
        error: item.error || '',
        latencyMs: Number.isFinite(latency) ? Math.trunc(latency) : 0,
        packetLossPercent,
        checkedAt
      } : null,
      history,
      hasServerResult,
      historyEndAt,
      paused: !isReportOnline({ lastReportAt: serverLastReportAt }),
      serverLastReportAt: Number(serverLastReportAt || 0)
    };
  });
}

function mergeServerConnectivity(serverId, results) {
  const previous = new Map((state.servers[serverId]?.connectivity || []).map((item) => [item.id, item]));
  const incoming = new Map((results || []).map((item) => [item.id, item]));
  return (config.connectivityChecks || []).filter((check) => check.enabled !== false).flatMap((check) => {
    const item = incoming.get(check.id);
    const prior = previous.get(check.id);
    const checkedAt = Number(item?.checkedAt || 0);
    // Missing targets and repeated/stale reports must never create synthetic
    // timeouts or duplicate historical samples.
    if (!item || !checkedAt || checkedAt <= Number(prior?.checkedAt || 0)) return prior ? [prior] : [];
    const rawLatency = Number(item.latencyMs);
    const ok = Boolean(item.ok && item.latencyMs != null && Number.isFinite(rawLatency) && rawLatency >= 0);
    const latencyMs = ok ? Math.trunc(rawLatency) : 0;
    const job=state.agentConnectivityServed[serverId]?.[check.id];
    if (job && item.taskAt && Number(item.taskAt)!==job.slotAt) return prior ? [prior] : [];
    if (job?.awaiting && !item.taskAt && checkedAt < job.dispatchedAt-5000) return prior ? [prior] : [];
    if (job) {
      if (!ok && !item.final && job.attempts<4) {
        if(checkedAt<=Number(job.failedAt || 0)) return prior ? [prior] : [];
        job.failedAt=checkedAt;job.awaiting=false;job.retry=true;job.nextAt=0;
        return prior ? [prior] : [];
      }
      job.awaiting=false;job.retry=false;
      job.nextAt=Math.max(job.nextAt,job.slotAt+Number(check.intervalSeconds || 300)*1000);
    }
    const packetLossPercent = normalizePacketLossPercent(item.packetLossPercent ?? item.packetLoss, ok ? 0 : 100);
    appendConnectivityHistory(serverId, check.id, { t: checkedAt, latencyMs, ok, packetLossPercent });
    return [{ id: check.id, name: check.name, ok, error: item.error || (ok ? '' : 'no_response'), latencyMs, packetLossPercent, checkedAt, history: [] }];
  });
}

async function runDueConnectivityChecks() {
  if (connectivityChecksInFlight) return connectivityChecksInFlight;
  connectivityChecksInFlight = runDueConnectivityChecksInner().finally(() => { connectivityChecksInFlight = null; });
  return connectivityChecksInFlight;
}

async function runDueConnectivityChecksInner() {
  const now=Date.now();
  await Promise.all((config.connectivityChecks || []).filter(check=>check.enabled!==false).map(async check=>{
    const result=connectivityResults.get(check.id);
    if(!result || now-Number(result.checkedAt || 0)>=Number(check.intervalSeconds || 300)*1000) {
      await runConnectivityCheck(check).catch(err=>console.error(err));
    }
  }));
}

function parseTcpTarget(target) {
  const text = String(target || '').trim();
  const bracket = text.match(/^\[([^\]]+)]:(\d+)$/);
  if (bracket) return { host: bracket[1], port: Number(bracket[2]) };
  const idx = text.lastIndexOf(':');
  if (idx > 0 && !text.slice(0, idx).includes(':')) return { host: text.slice(0, idx), port: Number(text.slice(idx + 1)) };
  return { host: text, port: 80 };
}

async function runConnectivityCheck(check) {
  let result;
  for(let attempt=0;attempt<4;attempt++) {
    result=await runConnectivityCheckAttempt(check);
    if(result.ok && Number.isFinite(result.latencyMs) && result.latencyMs>=0) break;
  }
  setConnectivityResult(check.id,result);
  return connectivityResults.get(check.id);
}

function runConnectivityCheckAttempt(check) {
  const { host, port } = parseTcpTarget(check.target);
  if (!host || !Number.isFinite(port) || port < 1 || port > 65535) return Promise.resolve({ok:false,error:'invalid target',latencyMs:0,checkedAt:Date.now()});
  const started = performance.now();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 5000 });
    let finished = false;
    const done = (ok, error = '') => {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      socket.destroy();
      const result = { ok, error, latencyMs: ok ? Math.max(0, performance.now()-started) : 0, checkedAt: Date.now() };
      resolve(result);
    };
    const deadline=setTimeout(()=>done(false,'timeout'),5000);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false, 'timeout'));
    socket.once('error', (err) => done(false, err.code || err.message));
  });
}

function setConnectivityResult(id, result) {
  result = { ...result, latencyMs: result.ok ? Math.trunc(Number(result.latencyMs) || 0) : 0 };
  connectivityResults.set(id, result);
  const history = connectivityHistory.get(id) || [];
  history.push({ t: result.checkedAt || Date.now(), latencyMs: result.latencyMs, ok: Boolean(result.ok), packetLossPercent: normalizePacketLossPercent(result.packetLossPercent ?? result.packetLoss, result.ok ? 0 : 100) });
  const cutoff = Date.now() - 15 * 24 * 60 * 60 * 1000;
  connectivityHistory.set(id, history.filter((point) => Number(point.t || 0) >= cutoff).slice(-MAX_CONNECTIVITY_HISTORY_POINTS));
  persistConnectivityState();
}


function normalizePacketLossPercent(value, fallback = 0) {
  const n = Number(value);
  if (Number.isFinite(n)) return Math.max(0, Math.min(100, n));
  const f = Number(fallback);
  return Number.isFinite(f) ? Math.max(0, Math.min(100, f)) : 0;
}

function publicServerMeta(server) {
  const { secret: _secret, ...rest } = server;
  rest.sortOrder = normalizeServerSortOrder(rest.sortOrder);
  return rest;
}

function orderedServers() {
  return (config.servers || [])
    .map((server, index) => ({ server, index }))
    .sort((a, b) => {
      const ao = normalizeServerSortOrder(a.server.sortOrder) || a.index + 1;
      const bo = normalizeServerSortOrder(b.server.sortOrder) || b.index + 1;
      return ao - bo || a.index - b.index;
    })
    .map((item) => item.server);
}

function applyServerSortSwap(draft, serverId, targetOrder) {
  const ordered = draft.servers
    .map((server, index) => ({ server, index }))
    .sort((a, b) => {
      const ao = normalizeServerSortOrder(a.server.sortOrder) || a.index + 1;
      const bo = normalizeServerSortOrder(b.server.sortOrder) || b.index + 1;
      return ao - bo || a.index - b.index;
    })
    .map((item) => item.server);
  const currentIndex = ordered.findIndex((server) => server.id === serverId);
  if (currentIndex < 0) return;
  const currentOrder = normalizeServerSortOrder(ordered[currentIndex].sortOrder) || currentIndex + 1;
  const displaced = ordered[targetOrder - 1];
  if (displaced && displaced.id !== serverId) displaced.sortOrder = currentOrder;
}

function inferHubUrl(req) {
  const configured = inferHubUrlFromConfig();
  if (configured) return normalizeHubUrl(configured);
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const host = req.headers['x-forwarded-host'] || req.headers.host || `127.0.0.1:${port}`;
  return normalizeHubUrl(`${String(proto).split(',')[0]}://${String(host).split(',')[0]}`);
}

function inferHubUrlFromConfig() {
  return config.publicHubUrl || '';
}

async function syncPublicHubUrlFromRequest(req) {

  const inferred = inferHubUrlFromRequest(req);
  if (!shouldAutoSyncPublicHubUrl(config.publicHubUrl, inferred)) return false;
  return transactConfig((draft) => {
    if (!shouldAutoSyncPublicHubUrl(draft.publicHubUrl, inferred)) return false;
    draft.publicHubUrl = inferred;
    return true;
  });
}

function inferHubUrlFromRequest(req) {
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const host = req.headers['x-forwarded-host'] || req.headers.host || `127.0.0.1:${port}`;
  return normalizeHubUrl(`${String(proto).split(',')[0]}://${String(host).split(',')[0]}`);
}

function shouldAutoSyncPublicHubUrl(current, inferred) {
  const next = normalizeOptionalHubUrl(inferred);
  if (!next) return false;
  const nextHost = hostnameFromUrl(next);
  if (!net.isIP(nextHost) || isLocalhostName(nextHost)) return false;
  const currentText = String(current || '').trim();
  if (!currentText) return true;
  const currentHost = hostnameFromUrl(currentText);
  if (!net.isIP(currentHost)) return false;
  return normalizeOptionalHubUrl(currentText) !== next;
}

function hostnameFromUrl(value) {
  try { return new URL(normalizeHubUrl(value)).hostname; } catch { return ''; }
}

function isLocalhostName(value) {
  return value === '127.0.0.1' || value === '::1' || value === '0.0.0.0';
}

function installHubUrl(inputHubUrl, req) {
  return inputHubUrl ? normalizeHubUrl(inputHubUrl) : inferHubUrl(req);
}

function normalizeOptionalHubUrl(value) {
  const text = String(value || '').trim();
  return text ? normalizeHubUrl(text) : '';
}

function onlineViewerStats() {
  pruneViewerPresence();
  const uniqueIps = new Set(Array.from(viewerPresence.values()).map((viewer) => viewer.ip).filter(Boolean));
  return { count: uniqueIps.size, connections: viewerPresence.size, updatedAt: Date.now() };
}

function onlineViewerIps() {
  pruneViewerPresence();
  return new Set(Array.from(viewerPresence.values()).map((viewer) => viewer.ip).filter(Boolean));
}

function inferClientDevice(req) {
  const ua = String(req?.headers?.['user-agent'] || '').toLowerCase();
  const isMobile = /mobile|android|iphone|ipad|ipod|windows phone|blackberry|webos|opera mini|iemobile/.test(ua);
  return isMobile ? { type: 'mobile', label: '手机端' } : { type: 'pc', label: 'PC端' };
}

function pruneViewerPresence() {
  const staleBefore = Date.now() - VIEWER_PRESENCE_TTL_MS;
  for (const [id, viewer] of viewerPresence.entries()) {
    if (!viewer?.lastSeenAt || viewer.lastSeenAt < staleBefore) viewerPresence.delete(id);
  }
}

function normalizeViewerId(value) {
  const text = String(value || '').trim();
  return /^[a-zA-Z0-9_.:-]{8,96}$/.test(text) ? text : '';
}

function recordViewerPresence(req, inputViewerId = '') {
  pruneViewerPresence();
  const ip = clientKey(req);
  const client = inferClientDevice(req);
  const viewerId = normalizeViewerId(inputViewerId) || `${ip}:${randomBytes(8).toString('hex')}`;
  viewerPresence.set(viewerId, { ip, clientType: client.type, clientLabel: client.label, lastSeenAt: Date.now() });
  return viewerId;
}

function recordViewerAccess(req, persist = true) {
  const ip = clientKey(req);
  const client = inferClientDevice(req);
  const now = Date.now();
  const current = normalizeViewerAccess(Array.isArray(state.viewerAccess) ? state.viewerAccess : []);
  const existing = current.find((item) => item.ip === ip);
  if (existing) {
    existing.lastAccessAt = now;
    existing.clientType = client.type;
    existing.clientLabel = client.label;
  } else current.push({ ip, clientType: client.type, clientLabel: client.label, firstAccessAt: now, lastAccessAt: now });
  state.viewerAccess = current
    .sort((a, b) => Number(b.lastAccessAt || 0) - Number(a.lastAccessAt || 0))
    .slice(0, 100);
  pruneAccessState();
  if (persist) saveStateSoon().catch((err) => console.error(err));
  return state.viewerAccess.find((item) => item.ip === ip) || { ip, firstAccessAt: now, lastAccessAt: now };
}

function recordBlockedWhitelistAccess(req) {
  const ip = clientKey(req);
  const now = Date.now();
  // A blocked page load can request dozens of assets at once. Record at most
  // once per IP per minute instead of sorting state and scheduling disk writes
  // for every rejected asset/API request.
  if (now - Number(blockedWhitelistRecordAt.get(ip) || 0) < 60_000) return;
  blockedWhitelistRecordAt.set(ip, now);
  while (blockedWhitelistRecordAt.size > 1000) blockedWhitelistRecordAt.delete(blockedWhitelistRecordAt.keys().next().value);
  const client = inferClientDevice(req);
  const current = normalizeViewerAccess(Array.isArray(state.blockedWhitelistAccess) ? state.blockedWhitelistAccess : []);
  const existing = current.find((item) => item.ip === ip);
  if (existing) {
    existing.lastAccessAt = now;
    existing.clientType = client.type;
    existing.clientLabel = client.label;
  } else current.push({ ip, clientType: client.type, clientLabel: client.label, firstAccessAt: now, lastAccessAt: now });
  state.blockedWhitelistAccess = current
    .sort((a, b) => Number(b.lastAccessAt || 0) - Number(a.lastAccessAt || 0))
    .slice(0, 100);
  pruneAccessState();
  saveState().catch((err) => console.error(err));
}

async function handleViewerHeartbeat(req, res) {
  const input = await readBody(req);
  const viewerId = recordViewerPresence(req, input.viewerId);
  // Presence heartbeats are intentionally memory-only. The initial page/SSE
  // connection already records access; rewriting the full state every five
  // seconds caused avoidable CPU, allocation and I/O pressure.
  const viewer = recordViewerAccess(req, false);
  const onlineViewers = onlineViewerStats();
  // Do not fan out a presence event for every five-second heartbeat. That made
  // N viewers generate N² SSE traffic and filled slow mobile response buffers.
  return sendJson(res, { ok: true, viewerId, viewer, onlineViewers });
}

async function handleViewerLeave(req, res) {
  const input = await readBody(req);
  const viewerId = normalizeViewerId(input.viewerId);
  if (viewerId) viewerPresence.delete(viewerId);
  const onlineViewers = onlineViewerStats();
  broadcast({ type: 'presence', at: Date.now(), onlineViewers });
  return sendJson(res, { ok: true, onlineViewers });
}

function publicViewerAccess() {
  const locations = state.viewerIpLocations || {};
  const onlineIps = onlineViewerIps();
  return normalizeViewerAccess(Array.isArray(state.viewerAccess) ? state.viewerAccess : [])
    .slice()
    .sort((a, b) => Number(b.lastAccessAt || 0) - Number(a.lastAccessAt || 0))
    .slice(0, 100)
    .map((item) => {
      const cached = locations[item.ip];
      const local = ipLocalLocationLabel(item.ip);
      const location = local || cached?.label || '';
      return { ...item, location, online: onlineIps.has(item.ip) };
    });
}

function publicBlockedWhitelistAccess() {
  const locations = state.blockedWhitelistIpLocations || {};
  return normalizeViewerAccess(Array.isArray(state.blockedWhitelistAccess) ? state.blockedWhitelistAccess : [])
    .slice()
    .sort((a, b) => Number(b.lastAccessAt || 0) - Number(a.lastAccessAt || 0))
    .slice(0, 100)
    .map((item) => {
      const cached = locations[item.ip];
      const local = ipLocalLocationLabel(item.ip);
      const location = local || cached?.label || '';
      return { ...item, location };
    });
}

function pruneAccessState() {
  for (const [listKey, cacheKey] of [['viewerAccess', 'viewerIpLocations'], ['blockedWhitelistAccess', 'blockedWhitelistIpLocations']]) {
    const list = normalizeViewerAccess(state[listKey] || []).sort((a, b) => b.lastAccessAt - a.lastAccessAt).slice(0, 100);
    state[listKey] = list;
    const retained = new Set(list.map((item) => item.ip));
    for (const ip of Object.keys(state[cacheKey] || {})) if (!retained.has(ip)) delete state[cacheKey][ip];
  }
  const now = Date.now();
  for (const [ip, time] of blockedWhitelistRecordAt) if (now - time >= 60_000) blockedWhitelistRecordAt.delete(ip);
  while (blockedWhitelistRecordAt.size > 1000) blockedWhitelistRecordAt.delete(blockedWhitelistRecordAt.keys().next().value);
  for (const [token, session] of adminSessions) if (now >= session.expiresAt) adminSessions.delete(token);
  const activeIps = new Set(Object.values(state.servers).flatMap((report) => Object.values(serverIpFields(report))));
  for (const ip of Object.keys(state.serverIpQuality || {})) if (!activeIps.has(ip)) delete state.serverIpQuality[ip];
  const ids = new Set(config.servers.map((meta) => meta.id));
  for (const id of countryLookupRetryAt.keys()) if (!ids.has(id)) countryLookupRetryAt.delete(id);
  for (const id of agentLastReportAt.keys()) if (!ids.has(id)) agentLastReportAt.delete(id);
}

function scheduleAccessLocationRefresh() {
  if (accessLocationRefreshInFlight) return accessLocationRefreshInFlight;
  // Return the cached list immediately; only one bounded background sweep may
  // run even if many browsers repeatedly refresh the settings page.
  accessLocationRefreshInFlight = Promise.resolve().then(refreshAccessLocations)
    .catch((err) => console.error('Access location refresh failed:', err.message))
    .finally(() => { accessLocationRefreshInFlight = null; });
  return accessLocationRefreshInFlight;
}

async function refreshAccessLocations() {
  pruneAccessState();
  const sources = [['viewerAccess', 'viewerIpLocations'], ['blockedWhitelistAccess', 'blockedWhitelistIpLocations']];
  const ips = new Set(sources.flatMap(([list]) => state[list].map((item) => item.ip)));
  let changed = false;
  for (const ip of ips) {
    const now = Date.now();
    const cached = sources.map(([, cache]) => state[cache][ip]).filter(Boolean).sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))[0];
    const local = ipLocalLocationLabel(ip);
    let next = cached;
    if (local) next = { label: local, updatedAt: now };
    else if (!(cached?.label && now - Number(cached.updatedAt || 0) < 7 * 86400_000) && now >= Number(cached?.retryAt || 0)) {
      const result = await lookupIpLocationFallback(ip).catch(() => null);
      next = result || { ...cached, retryAt: Date.now() + 10 * 60_000 };
    }
    if (!next || next === cached) continue;
    for (const [list, cache] of sources) {
      if (state[list].some((item) => item.ip === ip)) { state[cache][ip] = next; changed = true; }
    }
  }
  if (changed) saveStateSoon().catch((err) => console.error(err));
}

async function lookupIpLocationFallback(ip) {
  if (!net.isIP(ip) || isPrivateIp(ip)) return null;
  // At most 40 starts/minute, shared with country recovery. The queue is
  // bounded by the retained visitor records and configured servers.
  const startAt = Math.max(Date.now(), nextLocationLookupAt);
  nextLocationLookupAt = startAt + 1500;
  if (startAt > Date.now()) await new Promise((resolve) => setTimeout(resolve, startAt - Date.now()));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1800);
  try {
    const fields = 'status,country,countryCode,regionName,city,as,isp,org,query';
    const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?lang=zh-CN&fields=${fields}`, { signal: controller.signal });
    if (!response.ok) return null;
    const data = await response.json();
    if (!data || data.status !== 'success') return null;
    const parts = [data.country, data.regionName, data.city, data.as, data.isp || data.org]
      .map((value) => String(value || '').trim())
      .filter(Boolean);
    const label = Array.from(new Set(parts)).join(' · ');
    return label ? { label, country: normalizeCountryCode(data.countryCode), source: 'ip-api', updatedAt: Date.now() } : null;
  } finally {
    clearTimeout(timer);
  }
}

function cleanIpLocationLabel(location, asn, org) {
  const parts = [location, asn, org]
    .map((value) => String(value || '').replace(/[\r\n\t]+/g, ' ').trim())
    .filter(Boolean)
    .map((value) => value.slice(0, 80));
  return parts.length ? parts.join(' · ').slice(0, 180) : '';
}

function ipLocalLocationLabel(ip) {
  const text = normalizeClientIp(ip);
  if (!net.isIP(text)) return '';
  if (text === '127.0.0.1' || text === '::1') return '本机';
  if (isPrivateIp(text)) return '内网';
  return '';
}

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a >= 224;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith('::ffff:')) return isPrivateIp(lower.slice(7));
  return lower === '::' || lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || /^fe[89ab]/.test(lower) || lower.startsWith('ff');
}

function normalizeViewerAccess(items) {
  const merged = new Map();
  for (const item of items) {
    const ip = normalizeClientIp(item?.ip || 'unknown');
    const firstAccessAt = Number(item?.firstAccessAt || item?.lastAccessAt || Date.now());
    const lastAccessAt = Number(item?.lastAccessAt || firstAccessAt);
    const clientType = item?.clientType === 'mobile' ? 'mobile' : item?.clientType === 'pc' ? 'pc' : '';
    const clientLabel = clientType === 'mobile' ? '手机端' : clientType === 'pc' ? 'PC端' : '';
    const existing = merged.get(ip);
    if (!existing) merged.set(ip, { ip, clientType, clientLabel, firstAccessAt, lastAccessAt });
    else {
      existing.firstAccessAt = Math.min(Number(existing.firstAccessAt || firstAccessAt), firstAccessAt);
      existing.lastAccessAt = Math.max(Number(existing.lastAccessAt || lastAccessAt), lastAccessAt);
      if (lastAccessAt >= Number(existing.lastAccessAt || 0) && clientType) {
        existing.clientType = clientType;
        existing.clientLabel = clientLabel;
      }
    }
  }
  return Array.from(merged.values());
}

function normalizeHubUrl(value) {
  const text = String(value || '').trim();
  const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`);
  if (parsed.username || parsed.password) throw new Error('hubUrl must not contain credentials');
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('hubUrl must be http or https');
  parsed.hash = '';
  parsed.search = '';
  return parsed.toString().replace(/\/$/, '');
}

function cleanRequired(value, name) {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${name} is required`);
  if (!/^[a-zA-Z0-9._:-]+$/.test(text)) throw new Error(`${name} contains unsupported characters`);
  return text;
}

function cleanTextRequired(value, name) {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${name} is required`);
  if (/\n/.test(text)) throw new Error(`${name} cannot contain newlines`);
  return text;
}

function clampInteger(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function normalizeNullableNumber(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function normalizePort(value) {
  const nextPort = Number.parseInt(value, 10);
  if (!Number.isInteger(nextPort) || nextPort < 1 || nextPort > 65535) throw new Error('panelPort must be between 1 and 65535');
  return nextPort;
}

function normalizePriceCurrency(value) {
  const currency = String(value || '').trim().toUpperCase();
  if (currency === 'USD') return 'USD';
  if (currency === '元' || currency === 'CNY' || currency === 'RMB') return '元';
  return null;
}

function normalizePricePeriod(value) {
  const period = String(value || '').trim();
  const lower = period.toLowerCase();
  if (period === '年' || lower === 'year') return '年';
  if (period === '季' || lower === 'quarter') return '季';
  if (period === '月' || lower === 'month') return '月';
  return null;
}

function normalizeTrafficCycleStart(value) {
  const text = String(value || '').trim();
  return isValidIsoDate(text) ? text : '';
}

function normalizeNullableDate(value) {
  const text = String(value || '').trim();
  return isValidIsoDate(text) ? text : null;
}

function isValidIsoDate(text) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.getUTCFullYear() === Number(match[1]) && date.getUTCMonth() === Number(match[2]) - 1 && date.getUTCDate() === Number(match[3]);
}

function normalizeTrafficCycleUnit(value) {
  const unit = String(value || '').trim().toLowerCase();
  if (['day', 'week', 'month', 'year'].includes(unit)) return unit;
  if (unit === '天') return 'day';
  if (unit === '周') return 'week';
  if (unit === '月') return 'month';
  if (unit === '年') return 'year';
  return 'month';
}

function isValidServerSortOrder(value) {
  const text = String(value ?? '').trim();
  return /^[1-9]\d{0,2}$/.test(text) && Number(text) >= 1 && Number(text) <= 500;
}

function normalizeServerSortOrder(value) {
  const text = String(value ?? '').trim();
  if (!isValidServerSortOrder(text)) return null;
  return Number(text);
}

function isIpv4(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value || ''));
}

function isIpv6(value) {
  return String(value || '').includes(':');
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function systemdEscape(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '');
}

function systemdEnv(name, value) {
  return `"${name}=${systemdEscape(value)}"`;
}

function serveAgentProbe(res) {
  if (!existsSync(agentProbePath)) return sendNotFound(res);
  res.writeHead(200, corsHeaders({
    'Content-Type': 'text/x-shellscript; charset=utf-8',
    'Cache-Control': 'no-cache'
  }));
  createReadStream(agentProbePath).pipe(res);
}

function serveAgentNodeProbe(res) {
  if (!existsSync(agentNodeProbePath)) return sendNotFound(res);
  res.writeHead(200, corsHeaders({
    'Content-Type': 'application/javascript; charset=utf-8',
    'Cache-Control': 'no-cache'
  }));
  createReadStream(agentNodeProbePath).pipe(res);
}

function serveAgentInstall(res) {
  res.writeHead(200, corsHeaders({
    'Content-Type': 'text/x-shellscript; charset=utf-8',
    'Cache-Control': 'no-cache'
  }));
  res.end(buildAgentInstaller());
}

function serveAgentUninstall(res) {
  res.writeHead(200, corsHeaders({
    'Content-Type': 'text/x-shellscript; charset=utf-8',
    'Cache-Control': 'no-cache'
  }));
  res.end(buildAgentUninstaller());
}

function serveStatic(req, requestPath, res) {
  let cleanPath;
  try {
    cleanPath = decodeURIComponent(requestPath === '/' ? '/index.html' : requestPath);
  } catch {
    return sendNotFound(res);
  }
  const filePath = path.resolve(publicDir, `.${cleanPath}`);
  const relative = path.relative(publicDir, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return sendNotFound(res);
  if (!existsSync(filePath)) return sendNotFound(res);
  try {
    if (!statSync(filePath).isFile()) return sendNotFound(res);
  } catch {
    return sendNotFound(res);
  }
  if (isDeniedStaticFile(filePath)) return sendNotFound(res);

  if (cleanPath === '/index.html') return serveIndex(req, res, filePath);

  const ext = path.extname(filePath).toLowerCase();
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml'
  };
  const headers = { 'Content-Type': types[ext] || 'application/octet-stream' };
  // Flags/fonts are versioned with the deployed panel and never change at
  // runtime. Let the browser keep them instead of revalidating every card load.
  if (cleanPath.startsWith('/icons/') || cleanPath.startsWith('/fonts/')) {
    headers['Cache-Control'] = 'public, max-age=2592000, immutable';
  } else if (path.basename(filePath) === 'echarts.min.js') {
    headers['Cache-Control'] = 'public, max-age=86400';
  } else if (['.js', '.css'].includes(ext)) {
    // These URLs carry an explicit release version in index.html. Reusing them
    // avoids repeatedly transferring the whole application over weak mobile
    // routes; a new release version still invalidates the browser cache.
    headers['Cache-Control'] = 'public, max-age=86400, stale-while-revalidate=604800';
  }
  const stream = createReadStream(filePath);
  stream.on('error', () => {
    if (!res.headersSent) sendNotFound(res);
    else res.destroy();
  });
  const acceptsGzip = /(?:^|,)\s*gzip\s*(?:,|$)/i.test(String(req.headers['accept-encoding'] || ''));
  if (acceptsGzip && ['.js', '.css', '.html', '.json', '.svg'].includes(ext)) {
    headers['Content-Encoding'] = 'gzip';
    headers.Vary = 'Accept-Encoding';
    res.writeHead(200, securityHeaders(headers));
    const gzip = createGzip({ level: 6 });
    gzip.on('error', () => res.destroy());
    return stream.pipe(gzip).pipe(res);
  }
  res.writeHead(200, securityHeaders(headers));
  stream.pipe(res);
}

function isDeniedStaticFile(filePath) {
  const name = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();
  return name.startsWith('.') || ['.map', '.env', '.pem', '.key', '.crt', '.bak', '.backup', '.old', '.tmp', '.log', '.sqlite', '.db'].includes(ext);
}

async function serveIndex(req, res, filePath) {
  let html = await readFile(filePath, 'utf8');
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' };
  res.writeHead(200, securityHeaders(headers));
  const requestPath = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  const bootClass = isAdminPagePath(requestPath) ? ' boot-admin' : '';
  const rendered = html
    .replace('<body class="light-mode min-h-screen', `<body class="light-mode min-h-screen${bootClass}`)
    .replace('<!--__PANEL_BOOTSTRAP__-->', buildPublicBootstrapScript());
  res.end(rendered);
}

function escapeHtmlText(input) {
  return String(input ?? '').replace(/[&<>'"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[ch]));
}

function sendNotFound(res) {
  res.writeHead(404, securityHeaders({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, max-age=0',
    'Set-Cookie': 'whitelist_access=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
  }));
  res.end('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>404 Not Found</title><style>html,body{height:100%;margin:0}body{display:grid;place-items:center;font:700 clamp(2.5rem,8vw,6rem)/1.1 Arial,sans-serif;color:#111;background:#fff}</style></head><body>404 Not Found</body></html>');
}


function normalizeCountryCode(value) {
  const aliases = { USA: 'US', UNITEDSTATES: 'US', UK: 'GB', UNITEDKINGDOM: 'GB', BRITAIN: 'GB', SINGAPORE: 'SG', JAPAN: 'JP', TOKYO: 'JP', HONGKONG: 'HK', CHINA: 'CN', GERMANY: 'DE', FRANCE: 'FR', INDIA: 'IN', MUMBAI: 'IN', KOREA: 'KR', TAIWAN: 'TW' };
  const text = String(value || '').trim().replace(/[^a-z]/gi, '').toUpperCase();
  const code = aliases[text] || text;
  return flagCodes.has(code) ? code : '';
}

function serverCountryCode(meta = {}, report = {}) {
  return normalizeCountryCode(report.country) || normalizeCountryCode(meta.location) || normalizeCountryCode(report.location);
}

function publicFlagAssets(codes) {
  const flags = {};
  for (const code of new Set(codes.map(normalizeCountryCode).filter(Boolean))) {
    if (!flagDataCache.has(code)) {
      const svg = readFileSync(path.join(publicDir, 'icons', 'flags', `${code.toLowerCase()}.svg`));
      flagDataCache.set(code, `data:image/svg+xml;base64,${svg.toString('base64')}`);
    }
    flags[code] = flagDataCache.get(code);
  }
  return flags;
}

async function refreshServerCountryIfNeeded(meta, report) {
  const { ipv4, ipv6 } = serverIpFields(report);
  const ip = ipv4 || ipv6;
  if (!ip || !isReportOnline(report) || serverCountryLookups.has(meta.id)) return;
  if (normalizeCountryCode(report.country) && (!report.countryLookupIp || report.countryLookupIp === ip)) {
    report.countryLookupIp = ip;
    return;
  }
  const retry = countryLookupRetryAt.get(meta.id);
  if (retry?.ip === ip && Date.now() < retry.at) return;
  countryLookupRetryAt.set(meta.id, { ip, at: Date.now() + 10 * 60_000 });
  const task = lookupIpLocationFallback(ip).then((result) => {
    const current = state.servers[meta.id];
    const currentIps = serverIpFields(current);
    if (!current || !isReportOnline(current) || (currentIps.ipv4 || currentIps.ipv6) !== ip || !result?.country) return;
    current.country = result.country;
    current.countryLookupIp = ip;
    saveStateSoon().catch((err) => console.error(err));
    broadcast({ type: 'refresh', id: meta.id, at: Date.now() });
  }).catch(() => {}).finally(() => serverCountryLookups.delete(meta.id));
  serverCountryLookups.set(meta.id, task);
  return task;
}
