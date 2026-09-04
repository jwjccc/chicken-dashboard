import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, rename, chmod } from 'node:fs/promises';
import { existsSync, createReadStream, writeFileSync, renameSync, chmodSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const dataDir = path.join(rootDir, 'data');
const publicDir = path.join(rootDir, 'public');
const agentProbePath = path.join(rootDir, 'agent', 'probe.sh');
const agentNodeProbePath = path.join(rootDir, 'agent', 'probe-node.cjs');
const configPath = path.join(dataDir, 'config.json');
const statePath = path.join(dataDir, 'state.json');
const backgroundCacheDir = path.join(dataDir, 'background-cache');
const MAX_SERVERS = 500;
const MAX_PENDING_INSTALLS = 500;
const MAX_CONNECTIVITY_CHECKS = 200;

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
let normalizedWhitelistCache = { source: null, items: [] };
hydrateConnectivityState();
let stateWriteQueue = Promise.resolve();
let configWriteQueue = Promise.resolve();
let stateWriteTimer = null;
let pendingStateWriteResolvers = [];
const panelStartedAt = Date.now();
const STATE_WRITE_DEBOUNCE_MS = 5000;
const VIEWER_PRESENCE_TTL_MS = 8000;
const scryptAsync = promisify(scrypt);
const MAX_BODY_BYTES = 1024 * 1024;
const MIN_AGENT_REPORT_INTERVAL_MS = clampInteger(process.env.MIN_AGENT_REPORT_INTERVAL_MS || 750, 250, 60000, 750);
const TRUST_PROXY = /^(1|true|yes)$/i.test(String(process.env.PROBE_TRUST_PROXY || ''));

const port = Number(process.env.PROBE_PORT || config.port || 8080);
const MAX_SERVER_HISTORY_POINTS = clampInteger(process.env.MAX_SERVER_HISTORY_POINTS || 7200, 500, 200000, 7200);
const MAX_CONNECTIVITY_HISTORY_POINTS = clampInteger(process.env.MAX_CONNECTIVITY_HISTORY_POINTS || 5000, 100, 20000, 5000);
const HISTORY_SAMPLE_INTERVAL_MS = clampInteger(process.env.HISTORY_SAMPLE_INTERVAL_MS || 1000, 500, 3600000, 1000);
const IPAPI_AUTO_CHECK_INTERVAL_MS = 60 * 1000;
let ipApiRefreshInFlight = null;

const prunedAtStartup = pruneStateHistory();
if (prunedAtStartup) saveStateNow().catch((err) => console.error(err));

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (!isWhitelistAllowed(req, url)) return sendNotFound(res);

    if (req.method === 'OPTIONS') return handleOptions(res);
    if (req.method === 'GET' && url.pathname.startsWith('/media/background/')) return serveBackgroundProxy(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/backgrounds') {
      return sendJson(res, { backgrounds: publicBackgrounds() });
    }
    if (req.method === 'GET' && url.pathname === '/api/overview') return sendJson(res, buildOverview());
    if (req.method === 'GET' && url.pathname.startsWith('/api/servers/')) {
      const id = decodeURIComponent(url.pathname.split('/').pop() || '');
      const detail = await buildServerDetail(id, {
        includeConnectivityHistory: url.searchParams.get('connectivityHistory') === '1',
        connectivityRangeDays: Number(url.searchParams.get('connectivityRangeDays') || 1)
      });
      return detail ? sendJson(res, detail) : sendJson(res, { error: 'server_not_found' }, 404);
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
    if (req.method === 'GET' && url.pathname === '/healthz') return sendJson(res, { ok: true, now: Date.now() });

    if (req.method === 'GET' && isAdminPagePath(url.pathname)) return serveIndex(req, res, path.join(publicDir, 'index.html'));

    return serveStatic(req, url.pathname, res);
  } catch (err) {
    console.error(err);
    if (err?.code === 'BODY_TOO_LARGE') return sendJson(res, { error: 'request_body_too_large' }, 413);
    if (err?.code === 'INVALID_JSON') return sendJson(res, { error: 'invalid_json' }, 400);
    if (!res.headersSent) sendJson(res, { error: 'internal_error' }, 500);
    else res.destroy();
  }
});

server.listen(port, () => {
  console.log(`Server Probe Monitor listening on http://0.0.0.0:${port}`);
});

setInterval(() => broadcast({ type: 'refresh', at: Date.now() }), 30000).unref();
setInterval(() => runDueConnectivityChecks(), 1000).unref();
setInterval(() => runDueIpApiRefresh(), IPAPI_AUTO_CHECK_INTERVAL_MS).unref();
runDueConnectivityChecks().catch((err) => console.error(err));
runDueIpApiRefresh().catch((err) => console.error(err));

async function loadConfig() {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await chmod(dataDir, 0o700);
  if (!existsSync(configPath)) {
    const initial = {
      port: 8080,
      heartbeatTimeoutSeconds: 45,
      historyRetentionHours: 24,
      dashboardTitle: '服务器监控面板',
      dashboardIcon: '',
      ipapiKey: '',
      ipapiRefreshIntervalHours: 24,
      viewerIpModuleEnabled: false,
      publicHubUrl: '',
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
  for (const [id, result] of Object.entries(state.connectivityResults || {})) connectivityResults.set(id, result);
  for (const [id, history] of Object.entries(state.connectivityHistory || {})) {
    if (Array.isArray(history)) connectivityHistory.set(id, history);
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
    for (const item of server.connectivity) {
      if (!Array.isArray(item?.history)) continue;
      const next = item.history.filter((point) => Number(point?.t || 0) >= connectivityCutoff).slice(-MAX_CONNECTIVITY_HISTORY_POINTS);
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
  return new Promise((resolve, reject) => {
    pendingStateWriteResolvers.push({ resolve, reject });
    if (stateWriteTimer) return;
    stateWriteTimer = setTimeout(() => {
      stateWriteTimer = null;
      flushStateWrites().catch((err) => console.error(err));
    }, STATE_WRITE_DEBOUNCE_MS);
    stateWriteTimer.unref();
  });
}

async function saveStateNow() {
  if (stateWriteTimer) {
    clearTimeout(stateWriteTimer);
    stateWriteTimer = null;
  }
  await flushStateWrites();
}

async function flushStateWrites() {
  const waiters = pendingStateWriteResolvers.splice(0);
  try {
    stateWriteQueue = stateWriteQueue.catch(() => {}).then(() => writeJsonCompact(statePath, state));
    await stateWriteQueue;
    waiters.forEach(({ resolve }) => resolve());
  } catch (err) {
    waiters.forEach(({ reject }) => reject(err));
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
  const payload = JSON.stringify({ basics, backgrounds: publicBackgrounds() }).replace(/</g, '\\u003c');
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
  updateTrafficCycleState(meta, state.servers[report.id], report, now);
  const mergedReport = mergeAgentReport(state.servers[report.id], report);

  state.servers[report.id] = {
    ...state.servers[report.id],
    ...mergedReport,
    firstReportAt: state.servers[report.id]?.firstReportAt || now,
    connectivity: Array.isArray(report.connectivity) && report.connectivity.length
      ? mergeServerConnectivity(report.id, report.connectivity)
      : (state.servers[report.id]?.connectivity || []),
    lastReportAt: now
  };

  maybeAppendHistoryPoint(report.id, compactHistoryPoint(report, now), now);

  saveStateSoon().catch((err) => console.error(err));
  broadcast({ type: 'refresh', id: report.id, at: now });
  return sendJson(res, { ok: true, server: report.id });
}

function handleAgentConnectivity(req, res, url) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
  const serverId = url.searchParams.get('serverId') || req.headers['x-server-id'] || '';
  const existingMeta = config.servers.find((server) => server.id === serverId);
  const pendingInstall = config.pendingInstalls.find((install) => install.id === serverId);
  if (!serverId || !isAgentAuthorized(existingMeta, pendingInstall, token)) return sendJson(res, { error: 'unauthorized' }, 401);
  const now = Date.now();
  const checks = (config.connectivityChecks || []).filter((check) => check.enabled !== false);
  const dueMs = (checks.length ? Math.max(5, Math.min(...checks.map((check) => Number(check.intervalSeconds || 60)))) : 60) * 1000;
  const lastServed = Number(state.agentConnectivityServed?.[serverId] || 0);
  const shouldServe = checks.length && now - lastServed >= dueMs;
  if (shouldServe) {
    state.agentConnectivityServed = { ...(state.agentConnectivityServed || {}), [serverId]: now };
    saveState().catch((err) => console.error(err));
  }
  const lines = (shouldServe ? checks : [])
    .filter((check) => check.enabled !== false)
    .map((check) => [check.id, check.name, check.target, check.intervalSeconds || 60].map((value) => String(value || '').replace(/[\t\r\n]/g, ' ')).join('\t'));
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
    ? input.remainingTrafficBytes ?? input.remainingTraffic
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
    await ensureViewerAccessLocations();
    payload.onlineViewers = onlineViewerStats();
    payload.viewerAccess = publicViewerAccess();
  }
  if (section === 'all' || section === 'whitelist') {
    await ensureBlockedWhitelistLocations();
    payload.blockedWhitelistAccess = publicBlockedWhitelistAccess();
    payload.whitelist = adminWhitelistSettings(req);
  }
  return sendJson(res, payload);
}

async function handleAdminViewersGet(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  await ensureViewerAccessLocations();
  return sendJson(res, {
    ok: true,
    onlineViewers: onlineViewerStats(),
    viewerAccess: publicViewerAccess()
  });
}

async function handleAdminBlockedWhitelistGet(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  await ensureBlockedWhitelistLocations();
  return sendJson(res, {
    ok: true,
    blockedWhitelistAccess: publicBlockedWhitelistAccess()
  });
}

function handleAdminRestart(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const serviceName = String(process.env.PROBE_PANEL_SERVICE || 'server-probe-monitor').replace(/\.service$/, '');
  if (!/^[a-zA-Z0-9_.@:-]+$/.test(serviceName)) return sendJson(res, { error: 'invalid_service_name' }, 500);
  if (!existsSync('/bin/systemctl') && !existsSync('/usr/bin/systemctl')) {
    return sendJson(res, { error: 'systemctl_not_found', message: '当前环境未发现 systemctl，无法从面板内重启。' }, 500);
  }
  sendJson(res, { ok: true, service: `${serviceName}.service`, message: '面板正在重启，请稍后刷新页面。' });
  setTimeout(() => {
    const child = spawn('systemctl', ['restart', `${serviceName}.service`], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
  }, 300).unref();
}

async function handleAdminSettingsSave(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const input = await readBody(req);
  const session = getAdminSession(req);
  try {
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
    const shouldForceRelogin = Boolean(session && input.security);
    if (shouldForceRelogin) revokeAdminSessions();
    await ensureViewerAccessLocations(); broadcast({ type: 'refresh', at: Date.now() });
    return sendJson(res, { ok: true, forceRelogin: shouldForceRelogin, restartRequired: result.restartRequired, basics: adminPanelBasics(), backgrounds: normalizeBackgrounds(config.backgrounds), onlineViewers: onlineViewerStats(), viewerAccess: publicViewerAccess(), blockedWhitelistAccess: publicBlockedWhitelistAccess(), whitelist: adminWhitelistSettings(req) });
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
    const result = change(draft);
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
  saveState().catch((err) => console.error(err));
}

async function handleAdminIpApiRefresh(req, res) {
  if (!isAdminAuthorized(req)) return sendJson(res, { error: 'unauthorized' }, 401);
  const result = await refreshPanelServerIpApiQuality('manual');
  return sendJson(res, {
    ok: result.failed === 0,
    attempted: result.attempted,
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

async function refreshPanelServerIpApiQualityInner(trigger = 'auto') {
  if (!String(config.ipapiKey || '').trim()) {
    const results = orderedServers().map((meta) => ({ serverName: meta.name || meta.id, ok: false, reason: '后端未填写 IPAPI 密钥' }));
    return { trigger, attempted: results.length, success: 0, failed: results.length, results };
  }
  const servers = [];
  const uniqueIps = new Set();
  for (const meta of orderedServers()) {
    const report = state.servers[meta.id] || {};
    const serverName = meta.name || report.name || meta.id;
    const ips = [
      normalizeClientIp(report.publicIpv4 || report.ipv4 || (isIpv4(report.publicIp || report.ip) ? report.publicIp || report.ip : '')),
      normalizeClientIp(report.publicIpv6 || report.ipv6 || (isIpv6(report.publicIp || report.ip) ? report.publicIp || report.ip : ''))
    ].filter(Boolean);
    servers.push({ serverId: meta.id, serverName, ips });
    ips.forEach((ip) => uniqueIps.add(ip));
  }
  const refreshed = new Map();
  for (const ip of uniqueIps) {
    const result = await lookupServerIpApiQualityDetailed(ip);
    refreshed.set(ip, result);
    if (result.ok && result.data) {
      state.serverIpQuality = state.serverIpQuality || {};
      state.serverIpQuality[ip] = { ...(state.serverIpQuality[ip] || {}), ipApi: result.data, updatedAt: Date.now() };
    }
  }
  const results = servers.map((row) => {
    if (!row.ips.length) return { serverName: row.serverName, ok: false, reason: '未发现该服务器出口IP，无法更新IPAPI数据' };
    const failures = row.ips.map((ip) => refreshed.get(ip) || { ok: false, reason: '未执行查询' }).filter((item) => !item.ok);
    if (!failures.length) return { serverName: row.serverName, ok: true, reason: '更新成功' };
    return {
      serverName: row.serverName,
      ok: false,
      reason: Array.from(new Set(failures.map((item) => sanitizeIpApiErrorText(item.reason || '更新失败')).filter(Boolean))).join('；') || '更新失败'
    };
  });
  const success = results.filter((item) => item.ok).length;
  const failed = results.filter((item) => !item.ok).length;
  // The refresh timestamp represents a completed replacement cycle. Failed
  // queries retain their old snapshot and must not be treated as refreshed.
  if (!failed && success) state.ipApiLastRefreshAt = Date.now();
  await saveStateNow();
  broadcast({ type: 'refresh', at: Date.now() });
  if (failed) {
    const failureText = results
      .filter((item) => !item.ok)
      .map((item) => `${item.serverName || '--'}: ${item.reason || '更新失败'}`)
      .join(' | ');
    console.warn(`IPAPI ${trigger} refresh completed with ${failed}/${results.length} failed: ${failureText}`);
  }
  return { trigger, attempted: results.length, success, failed, results };
}

async function runDueIpApiRefresh() {
  if (!config.ipapiKey) return;
  const intervalHours = normalizeIpApiRefreshIntervalHours(config.ipapiRefreshIntervalHours || 24);
  const intervalMs = intervalHours * 60 * 60 * 1000;
  const last = Number(state.ipApiLastRefreshAt || 0);
  if (last > 0 && Date.now() - last < intervalMs) return;
  await refreshPanelServerIpApiQuality('auto');
}

function ipApiRefreshResultMessage(result = {}) {
  const attempted = Number(result.attempted || 0);
  const failed = Number(result.failed || 0);
  const success = Number(result.success || 0);
  if (!attempted) return '没有可更新的服务器IPAPI数据';
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
  const check = normalizeConnectivityCheck(input);
  try {
    await transactConfig((draft) => {
      const current = draft.connectivityChecks.find((item) => item.id === check.id);
      if (current) Object.assign(current, check);
      else {
        if (draft.connectivityChecks.length >= MAX_CONNECTIVITY_CHECKS) throw businessError('connectivity_limit_reached', 'connectivity limit reached');
        draft.connectivityChecks.push(check);
      }
    });
  } catch (err) {
    if (err?.code === 'connectivity_limit_reached') return sendJson(res, { error: err.code }, 409);
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
    command: buildInstallCommand({ hubUrl, token: secret, serverId, serverName: serverId, serverLocation: '', interval })
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

function buildInstallCommand({ hubUrl, token, serverId, serverName, serverLocation, interval }) {
  return `curl -L ${shellQuote(`${hubUrl}/api/agent/install.sh`)} -o agent.sh && chmod +x agent.sh && env PROBE_HUB_URL=${shellQuote(hubUrl)} PROBE_AGENT_TOKEN=${shellQuote(token)} PROBE_SERVER_ID=${shellQuote(serverId)} PROBE_SERVER_NAME=${shellQuote(serverName)} PROBE_SERVER_LOCATION=${shellQuote(serverLocation)} PROBE_INTERVAL=${shellQuote(String(interval))} PROBE_CONNECTIVITY_INTERVAL=60 ./agent.sh`;
}

function buildUninstallCommand({ hubUrl }) {
  return `curl -L ${shellQuote(`${hubUrl}/api/agent/uninstall.sh`)} -o uninstall-agent.sh && chmod +x uninstall-agent.sh && env PROBE_HUB_URL=${shellQuote(hubUrl)} ./uninstall-agent.sh`;
}

function buildAgentInstaller() {
  return [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    'HUB_URL="${PROBE_HUB_URL:-${HUB_URL:-}}"',
    'AGENT_TOKEN="${PROBE_AGENT_TOKEN:-${AGENT_TOKEN:-}}"',
    'SERVER_ID="${PROBE_SERVER_ID:-${SERVER_ID:-$(hostname)}}"',
    'SERVER_NAME="${PROBE_SERVER_NAME:-${SERVER_NAME:-$(hostname)}}"',
    'SERVER_LOCATION="${PROBE_SERVER_LOCATION:-${SERVER_LOCATION:-}}"',
    'INTERVAL="${PROBE_INTERVAL:-${INTERVAL:-2}}"',
    'CONNECTIVITY_INTERVAL="${PROBE_CONNECTIVITY_INTERVAL:-${CONNECTIVITY_INTERVAL:-60}}"',
    'INSTANCE_ID="$(printf \'%s\' "$HUB_URL" | sha256sum | cut -c1-12)"',
    'INSTALL_DIR="/opt/server-probe-agent-${INSTANCE_ID}"',
    'SERVICE_NAME="server-probe-agent-${INSTANCE_ID}.service"',
    'SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"',
    'ENV_FILE="/etc/${SERVICE_NAME}.env"',
    '',
    'if [[ -z "$HUB_URL" ]]; then',
    '  echo "PROBE_HUB_URL is required" >&2',
    '  exit 1',
    'fi',
    '',
    'if [[ -z "$AGENT_TOKEN" ]]; then',
    '  echo "PROBE_AGENT_TOKEN is required" >&2',
    '  exit 1',
    'fi',
    '',
    '# Migrate the legacy fixed-name agent only when it belongs to this panel.',
    'if [[ -f /etc/server-probe-agent.env ]]; then',
    '  OLD_HUB_URL="$(bash -c \'source /etc/server-probe-agent.env 2>/dev/null; printf %s "${HUB_URL:-}"\' || true)"',
    '  if [[ "$OLD_HUB_URL" == "$HUB_URL" ]]; then',
    '    systemctl disable --now server-probe-agent.service 2>/dev/null || true',
    '    rm -f /etc/systemd/system/server-probe-agent.service /etc/server-probe-agent.env',
    '    rm -rf /opt/server-probe-agent',
    '  fi',
    'fi',
    '',
    'for value in "$HUB_URL" "$AGENT_TOKEN" "$SERVER_ID" "$SERVER_NAME" "$SERVER_LOCATION"; do [[ "$value" != *$\'\n\'* && "$value" != *$\'\r\'* ]] || { echo "Values must not contain newlines" >&2; exit 1; }; done',
    '',
    'if [[ $EUID -ne 0 ]]; then',
    '  if command -v sudo >/dev/null 2>&1; then',
    '    exec sudo -E env \\',
    '      PROBE_HUB_URL="$HUB_URL" \\',
    '      PROBE_AGENT_TOKEN="$AGENT_TOKEN" \\',
    '      PROBE_SERVER_ID="$SERVER_ID" \\',
    '      PROBE_SERVER_NAME="$SERVER_NAME" \\',
    '      PROBE_SERVER_LOCATION="$SERVER_LOCATION" \\',
    '      PROBE_INTERVAL="$INTERVAL" \\',
    '      PROBE_CONNECTIVITY_INTERVAL="$CONNECTIVITY_INTERVAL" \\',
    '      PROBE_INSTALL_DIR="$INSTALL_DIR" \\',
    '      "$0" "$@"',
    '  fi',
    '  echo "Please run as root, or install sudo." >&2',
    '  exit 1',
    'fi',
    '',
    '# Prefer the persistent Node worker. The Shell fallback forks many system',
    '# utilities per sample and can be several seconds slower on tiny VPSes.',
    'if ! command -v node >/dev/null 2>&1; then',
    '  if command -v apt-get >/dev/null 2>&1; then',
    '    export DEBIAN_FRONTEND=noninteractive',
    '    apt-get update && apt-get install -y nodejs',
    '  elif command -v apk >/dev/null 2>&1; then',
    '    apk add --no-cache nodejs',
    '  elif command -v dnf >/dev/null 2>&1; then',
    '    dnf install -y nodejs',
    '  elif command -v yum >/dev/null 2>&1; then',
    '    yum install -y nodejs',
    '  fi',
    'fi',
    '',
    'umask 077',
    'tmp_dir=$(mktemp -d /opt/.server-probe-agent.install.XXXXXX)',
    "trap 'rm -rf -- \"$tmp_dir\"' EXIT",
    'install -d -m 0755 "$INSTALL_DIR"',
    'curl --fail --silent --show-error --connect-timeout 10 --max-time 60 "$HUB_URL/api/agent/probe.sh" -o "$tmp_dir/probe.sh"',
    'curl --fail --silent --show-error --connect-timeout 10 --max-time 60 "$HUB_URL/api/agent/probe-node.cjs" -o "$tmp_dir/probe-node.cjs"',
    'install -m 0755 "$tmp_dir/probe.sh" "$INSTALL_DIR/probe.sh.new" && mv -f "$INSTALL_DIR/probe.sh.new" "$INSTALL_DIR/probe.sh"',
    'install -m 0755 "$tmp_dir/probe-node.cjs" "$INSTALL_DIR/probe-node.cjs.new" && mv -f "$INSTALL_DIR/probe-node.cjs.new" "$INSTALL_DIR/probe-node.cjs"',
    'rm -f "$INSTALL_DIR/probe-node.js"',
    '{ printf "HUB_URL=%q\\nAGENT_TOKEN=%q\\nSERVER_ID=%q\\nSERVER_NAME=%q\\nSERVER_LOCATION=%q\\nINTERVAL=%q\\nCONNECTIVITY_INTERVAL=%q\\n" "$HUB_URL" "$AGENT_TOKEN" "$SERVER_ID" "$SERVER_NAME" "$SERVER_LOCATION" "$INTERVAL" "$CONNECTIVITY_INTERVAL"; } > "$ENV_FILE.new"',
    'chmod 0600 "$ENV_FILE.new" && mv -f "$ENV_FILE.new" "$ENV_FILE"',
    '',
    'cat > "$SERVICE_FILE.new" <<SERVICE',
    '[Unit]',
    'Description=Server Probe Monitor Agent',
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=simple',
    'EnvironmentFile=$ENV_FILE',
    'Environment="CONNECTIONS_TTL_SECONDS=2"',
    'Environment="NODE_OPTIONS=--max-old-space-size=48 --max-semi-space-size=2"',
    'ExecStart=/bin/sh -c \'if command -v node >/dev/null 2>&1 && [ -f "$INSTALL_DIR/probe-node.cjs" ]; then exec node "$INSTALL_DIR/probe-node.cjs"; else exec "$INSTALL_DIR/probe.sh"; fi\'',
    'Restart=always',
    'RestartSec=5',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    'SERVICE',
    'chmod 0644 "$SERVICE_FILE.new" && mv -f "$SERVICE_FILE.new" "$SERVICE_FILE"',
    '',
    '# Stop only this panel instance; agents connected to other panels keep running.',
    'systemctl stop "$SERVICE_NAME" 2>/dev/null || true',
    '# Clean up only this instance before starting exactly one process.',
    'pkill -f "^node $INSTALL_DIR/probe-node\\.(cjs|js)$" 2>/dev/null || true',
    'pkill -f "^(bash|/bin/bash|sh|/bin/sh) $INSTALL_DIR/probe\\.sh$" 2>/dev/null || true',
    'systemctl daemon-reload',
    'systemctl enable "$SERVICE_NAME"',
    'systemctl restart "$SERVICE_NAME"',
    'systemctl status "$SERVICE_NAME" --no-pager',
    ''
  ].join('\n');
}

function buildAgentUninstaller() {
  return [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    'HUB_URL="${PROBE_HUB_URL:-${HUB_URL:-}}"',
    '[[ -n "$HUB_URL" ]] || { echo "PROBE_HUB_URL is required" >&2; exit 1; }',
    "INSTANCE_ID=\"$(printf '%s' \"$HUB_URL\" | sha256sum | cut -c1-12)\"",
    'SERVICE_NAME="server-probe-agent-${INSTANCE_ID}.service"',
    'INSTALL_DIR="/opt/server-probe-agent-${INSTANCE_ID}"',
    'ENV_FILE="/etc/${SERVICE_NAME}.env"',
    'SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"',
    '',
    'if [[ $EUID -ne 0 ]]; then',
    '  if command -v sudo >/dev/null 2>&1; then',
    '    exec sudo -E env PROBE_HUB_URL="$HUB_URL" "$0" "$@"',
    '  fi',
    '  echo "Please run as root, or install sudo." >&2',
    '  exit 1',
    'fi',
    '',
    'if command -v systemctl >/dev/null 2>&1; then',
    '  systemctl stop "$SERVICE_NAME" 2>/dev/null || true',
    '  systemctl disable "$SERVICE_NAME" 2>/dev/null || true',
    'fi',
    'pkill -f "$INSTALL_DIR/probe-node.cjs" 2>/dev/null || true',
    'pkill -f "$INSTALL_DIR/probe.sh" 2>/dev/null || true',
    'rm -f "$SERVICE_FILE" "$ENV_FILE"',
    'rm -rf "$INSTALL_DIR"',
    'if command -v systemctl >/dev/null 2>&1; then',
    '  systemctl daemon-reload',
    '  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true',
    'fi',
    'echo "This panel agent instance has been uninstalled; other panel agents were not changed."',
    ''
  ].join('\n');
}

function buildOverview() {
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
    settings: { basics: publicPanelBasics(), backgrounds: publicBackgrounds() },
    onlineViewers: onlineViewerStats(),
    totals,
    servers: rows
  };
}

function cachedServerIpQuality(report = {}) {
  if (!String(config.ipapiKey || '').trim()) {
    return { ipApi: null, status: 'missing_key', message: '后端未填写 IPAPI 密钥' };
  }
  const ipv4 = normalizeClientIp(report.publicIpv4 || report.ipv4 || (isIpv4(report.publicIp || report.ip) ? report.publicIp || report.ip : ''));
  const ipv6 = normalizeClientIp(report.publicIpv6 || report.ipv6 || (isIpv6(report.publicIp || report.ip) ? report.publicIp || report.ip : ''));
  const cached = state.serverIpQuality || {};
  const value = (ip) => ip && cached[ip]?.ipApi ? { ...cached[ip].ipApi, updatedAt: cached[ip].updatedAt || cached[ip].ipApi.updatedAt || 0 } : null;
  return { ipApi: { ipv4: value(ipv4), ipv6: value(ipv6) }, status: '', message: '' };
}

async function buildServerDetail(id, options = {}) {
  const timeoutMs = Number(config.heartbeatTimeoutSeconds || 45) * 1000;
  const meta = config.servers.find((server) => server.id === id);
  if (!meta) return null;
  const report = state.servers[id] || {};
  const server = normalizeServer(meta, report, timeoutMs);
  server.ipQuality = cachedServerIpQuality(report);
  return {
    server,
    connectivity: publicServerConnectivityChecks(report.connectivity || [], report.lastReportAt || 0, options),
    history: Array.isArray(state.history[id]) ? state.history[id].slice(-500) : [],
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
  report.tags = Array.isArray(input.tags) ? input.tags.slice(0, 32).map((v) => text(v, 64)).filter(Boolean) : [];
  report.os = Object.fromEntries(['platform','version','arch','kernel'].map((k) => [k, text(object(input.os)[k], 128)]));
  report.cpu = { ...metric(input.cpu, [['percent',0,100],['cores',0,4096]]), model: text(object(input.cpu).model, 256), load: (Array.isArray(object(input.cpu).load) ? object(input.cpu).load : []).slice(0,3).map((v) => number(v,0,1e6)) };
  report.memory = metric(input.memory, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['available',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  report.swap = metric(input.swap, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  if (!Object.hasOwn(object(input.swap), 'percent')) report.swap.percent = report.swap.total ? Math.min(100, report.swap.used * 100 / report.swap.total) : 0;
  report.disk = metric(input.disk, [['total',0,Number.MAX_SAFE_INTEGER],['used',0,Number.MAX_SAFE_INTEGER],['available',0,Number.MAX_SAFE_INTEGER],['percent',0,100]]);
  report.net = metric(input.net, [['inBps',0,Number.MAX_SAFE_INTEGER],['outBps',0,Number.MAX_SAFE_INTEGER],['totalIn',0,Number.MAX_SAFE_INTEGER],['totalOut',0,Number.MAX_SAFE_INTEGER]]);
  report.connections = metric(input.connections, [['tcp',0,1e7],['udp',0,1e7]]);
  report.connectivity = Array.isArray(input.connectivity) ? input.connectivity.slice(0, MAX_CONNECTIVITY_CHECKS).map((item) => ({ id: text(item?.id,96), name: text(item?.name,128), ok: item.ok, error: text(item?.error,256), latencyMs: number(item?.latencyMs,0,3600000), packetLossPercent: number(item?.packetLossPercent,0,100), checkedAt: number(item?.checkedAt,0,Date.now()+300000) })).filter((v) => v.id) : [];
  report.connectivityMeta = { count: number(input.connectivityMeta?.count,0,MAX_CONNECTIVITY_CHECKS), error: text(input.connectivityMeta?.error,256) };
  return report;
}

function mergeAgentReport(previous = {}, incoming = {}) {
  const merged = { ...previous, ...incoming };
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
  const publicIp = incomingPublicIp || previousPublicIp || ipv4 || ipv6;
  merged.publicIp = publicIp;
  merged.ip = publicIp;
  return merged;
}

function serverIpFields(report = {}) {
  const candidates = [report.publicIpv4, report.ipv4, report.publicIpv6, report.ipv6, report.publicIp, report.ip]
    .map((value) => normalizeClientIp(value))
    .filter(Boolean);
  return {
    ipv4: candidates.find((value) => isIpv4(value)) || '',
    ipv6: candidates.find((value) => isIpv6(value)) || ''
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
    tcp: Number(report.connections?.tcp || 0),
    udp: Number(report.connections?.udp || 0)
  };
}

function calculateCycleTraffic(meta, report = {}) {
  const quotaBytes = normalizeNullableNumber(meta.remainingTrafficBytes) || 0;
  const cycle = currentTrafficCycle(meta);
  const stored = state.trafficCycles?.[meta.id];
  const cycleKey = trafficCycleKey(cycle);

  if (stored && stored.cycleKey === cycleKey) {
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

  return calculateCycleTrafficFromHistory(meta, report, cycle, quotaBytes);
}

function updateTrafficCycleState(meta, previousReport = {}, report = {}, now = Date.now()) {
  if (!meta?.id) return;
  state.trafficCycles = state.trafficCycles || {};
  const cycle = currentTrafficCycle(meta);
  const cycleKey = trafficCycleKey(cycle);
  const totalIn = Math.max(0, Number(report.net?.totalIn || 0));
  const totalOut = Math.max(0, Number(report.net?.totalOut || 0));
  const previous = state.trafficCycles[meta.id];

  if (!previous || previous.cycleKey !== cycleKey) {
    const seed = calculateCycleTrafficFromHistory(meta, report, cycle, normalizeNullableNumber(meta.remainingTrafficBytes) || 0);
    state.trafficCycles[meta.id] = {
      cycleKey,
      startAt: cycle.startAt || null,
      endAt: cycle.endAt || null,
      unit: cycle.unit,
      usedIn: Math.max(0, Number(seed.usedIn || 0)),
      usedOut: Math.max(0, Number(seed.usedOut || 0)),
      lastTotalIn: totalIn,
      lastTotalOut: totalOut,
      updatedAt: now
    };
    return;
  }

  const deltaIn = trafficCounterDelta(totalIn, previous.lastTotalIn);
  const deltaOut = trafficCounterDelta(totalOut, previous.lastTotalOut);
  previous.startAt = cycle.startAt || previous.startAt || null;
  previous.endAt = cycle.endAt || previous.endAt || null;
  previous.unit = cycle.unit;
  previous.usedIn = Math.max(0, Number(previous.usedIn || 0)) + deltaIn;
  previous.usedOut = Math.max(0, Number(previous.usedOut || 0)) + deltaOut;
  previous.lastTotalIn = totalIn;
  previous.lastTotalOut = totalOut;
  previous.updatedAt = now;
}

function trafficCounterDelta(current, previous) {
  const currentValue = Math.max(0, Number(current || 0));
  const previousValue = Math.max(0, Number(previous || 0));
  if (!Number.isFinite(currentValue)) return 0;
  if (!Number.isFinite(previousValue)) return currentValue;
  if (currentValue >= previousValue) return currentValue - previousValue;
  return currentValue;
}

function trafficCycleKey(cycle) {
  return `${cycle.startAt || 0}:${cycle.unit}`;
}

function calculateCycleTrafficFromHistory(meta, report = {}, cycle = currentTrafficCycle(meta), quotaBytes = normalizeNullableNumber(meta.remainingTrafficBytes) || 0) {
  const totalIn = Number(report.net?.totalIn || 0);
  const totalOut = Number(report.net?.totalOut || 0);
  const history = state.history?.[meta.id] || [];
  const startAt = cycle.startAt || Number(meta.createdAt || report.firstReportAt || report.lastReportAt || 0) || 0;
  let baseline = null;
  let firstInCycle = null;
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const point = history[index];
    if (Number(point.t || 0) <= startAt && (point.totalIn != null || point.totalOut != null)) {
      baseline = point;
      break;
    }
  }
  for (const point of history) {
    if (Number(point.t || 0) >= startAt && (point.totalIn != null || point.totalOut != null)) {
      firstInCycle = point;
      break;
    }
  }
  const base = baseline || firstInCycle;
  const baselineIn = base ? Number(base.totalIn || 0) : totalIn;
  const baselineOut = base ? Number(base.totalOut || 0) : totalOut;
  const usedIn = Math.max(0, totalIn - baselineIn);
  const usedOut = Math.max(0, totalOut - baselineOut);
  const usedTotal = usedIn + usedOut;
  return {
    startAt: startAt || null,
    endAt: cycle.endAt,
    unit: cycle.unit,
    quotaBytes,
    usedIn,
    usedOut,
    usedTotal,
    remainingBytes: quotaBytes > 0 ? Math.max(0, quotaBytes - usedTotal) : null
  };
}

function currentTrafficCycle(meta) {
  const unit = normalizeTrafficCycleUnit(meta.trafficCycleUnit);
  const anchor = parseLocalDate(meta.trafficCycleStartDate);
  if (!anchor) return { unit, startAt: null, endAt: null };
  let start = new Date(anchor.getTime());
  let next = addTrafficCycle(start, unit);
  const now = Date.now();
  while (next.getTime() <= now) {
    start = next;
    next = addTrafficCycle(start, unit);
  }
  return { unit, startAt: start.getTime(), endAt: next.getTime() };
}

function addTrafficCycle(date, unit) {
  const next = new Date(date.getTime());
  if (unit === 'day') next.setDate(next.getDate() + 1);
  else if (unit === 'week') next.setDate(next.getDate() + 7);
  else if (unit === 'year') next.setFullYear(next.getFullYear() + 1);
  else next.setMonth(next.getMonth() + 1);
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
  res.write(`data: ${JSON.stringify({ type: 'hello', at: Date.now(), onlineViewers: onlineViewerStats(), viewer })}\n\n`);
  broadcast({ type: 'presence', at: Date.now(), onlineViewers: onlineViewerStats() });
  req.on('close', () => {
    clients.delete(res);
    if (viewerId) viewerPresence.delete(viewerId);
    broadcast({ type: 'presence', at: Date.now(), onlineViewers: onlineViewerStats() });
  });
}

function broadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const client of clients.keys()) client.write(data);
}

function sendJson(res, data, status = 200, headers = {}) {
  res.writeHead(status, corsHeaders({ 'Content-Type': 'application/json; charset=utf-8', ...headers }));
  res.end(JSON.stringify(data));
}

function corsHeaders(headers = {}) {
  const next = securityHeaders({
    ...headers,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-CSRF-Token',
    'Vary': 'Origin'
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
  const whitelist = getNormalizedWhitelist();
  if (!config.ipWhitelistEnabled || !whitelist.length) return true;
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
    frontendMobile: normalizeList(value.frontendMobile || value.mobileFrontend || value.frontendMobileUrls || frontend),
    adminDesktop: normalizeList(value.adminDesktop || value.adminPc || value.adminDesktopUrls || admin),
    adminMobile: normalizeList(value.adminMobile || value.mobileAdmin || value.adminMobileUrls || admin)
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
      lookup: (_hostname, _options, callback) => callback(null, target.address, target.family),
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
  const interval = clampInteger(input.intervalSeconds || input.interval || 60, 5, 86400, 60);
  return { id, name, target, intervalSeconds: interval, type: 'tcping', enabled: input.enabled !== false };
}

function aggregateConnectivityHistory(history, cutoff, rangeDays, intervalSeconds = 60) {
  // Keep payload and browser work nearly constant for 1/7/15 day views. Nezha
  // serves period-shaped series rather than shipping every raw probe sample.
  const bucketMs = rangeDays <= 1 ? 3 * 60_000 : rangeDays <= 7 ? 15 * 60_000 : 30 * 60_000;
  const useAverage = rangeDays > 1 || Number(intervalSeconds || 60) < 180;
  const buckets = new Map();
  for (const point of history) {
    const t = Number(point?.t || 0);
    if (!Number.isFinite(t) || t < cutoff) continue;
    const key = Math.floor(t / bucketMs) * bucketMs;
    const bucket = buckets.get(key) || { t: key, latestAt: 0, latestLatency: null, latestOk: false, latestLoss: null, latencyTotal: 0, latencyCount: 0, lossTotal: 0, lossCount: 0 };
    const latency = Number(point?.latencyMs);
    if (point?.ok && Number.isFinite(latency) && latency > 0) {
      bucket.latencyTotal += latency;
      bucket.latencyCount += 1;
    }
    const loss = Number(point?.packetLossPercent);
    if (Number.isFinite(loss)) {
      bucket.lossTotal += loss;
      bucket.lossCount += 1;
    }
    if (t >= bucket.latestAt) {
      bucket.latestAt = t;
      bucket.latestLatency = point?.ok && Number.isFinite(latency) && latency > 0 ? latency : null;
      bucket.latestOk = Boolean(point?.ok && bucket.latestLatency != null);
      bucket.latestLoss = Number.isFinite(loss) ? loss : (bucket.latestOk ? 0 : 100);
    }
    buckets.set(key, bucket);
  }
  return [...buckets.values()].sort((a, b) => a.t - b.t).map((bucket) => ({
    t: bucket.t,
    latencyMs: useAverage ? (bucket.latencyCount ? bucket.latencyTotal / bucket.latencyCount : null) : bucket.latestLatency,
    ok: useAverage ? bucket.latencyCount > 0 : bucket.latestOk,
    packetLossPercent: useAverage
      ? (bucket.lossCount ? bucket.lossTotal / bucket.lossCount : (bucket.latencyCount ? 0 : 100))
      : bucket.latestLoss
  }));
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

function publicServerConnectivityChecks(results, serverLastReportAt = 0, options = {}) {
  const byId = new Map((Array.isArray(results) ? results : []).map((item) => [item.id, item]));
  const includeHistory = Boolean(options.includeConnectivityHistory);
  const rangeDays = clampInteger(options.connectivityRangeDays || 1, 1, 15, 1);
  const cutoff = Date.now() - rangeDays * 24 * 60 * 60 * 1000;
  return (config.connectivityChecks || []).filter((check) => check.enabled !== false).map((check) => {
    const item = byId.get(check.id) || {};
    const latency = Number(item.latencyMs ?? 0);
    const checkedAt = Number(item.checkedAt || 0);
    const hasServerResult = checkedAt > 0;
    const packetLossPercent = normalizePacketLossPercent(item.packetLossPercent ?? item.packetLoss, item.ok ? 0 : 100);
    const history = includeHistory && Array.isArray(item.history)
      ? aggregateConnectivityHistory(item.history, cutoff, rangeDays, check.intervalSeconds)
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
        latencyMs: Number.isFinite(latency) ? latency : 0,
        packetLossPercent,
        checkedAt
      } : null,
      history,
      hasServerResult,
      serverLastReportAt: Number(serverLastReportAt || 0)
    };
  });
}

function mergeServerConnectivity(serverId, results) {
  const previous = new Map(Array.isArray(state.servers?.[serverId]?.connectivity) ? state.servers[serverId].connectivity.map((item) => [item.id, item]) : []);
  const incoming = new Map((Array.isArray(results) ? results : []).map((item) => [item.id, item]));
  const now = Date.now();
  const batchTimes = (Array.isArray(results) ? results : [])
    .map((item) => Number(item.checkedAt || 0))
    .filter((value) => Number.isFinite(value) && value > 0);
  const batchCheckedAt = batchTimes.length ? Math.max(...batchTimes) : now;
  return (config.connectivityChecks || []).filter((check) => check.enabled !== false).map((check) => {
    const item = incoming.get(check.id) || {};
    const prior = previous.get(check.id) || {};
    const checkedAt = batchCheckedAt;
    const hasLatency = item.latencyMs !== undefined && item.latencyMs !== null && Number.isFinite(Number(item.latencyMs));
    const latencyMs = hasLatency ? Math.max(0, Number(item.latencyMs)) : 0;
    const ok = Boolean(item.ok && latencyMs > 0);
    const packetLossPercent = normalizePacketLossPercent(item.packetLossPercent ?? item.packetLoss, ok ? 0 : 100);
    const point = { t: checkedAt, latencyMs, ok, packetLossPercent };
    const history = [...(Array.isArray(prior.history) ? prior.history : []), point]
      .filter((entry) => Number(entry.t || 0) >= now - 15 * 24 * 60 * 60 * 1000)
      .slice(-MAX_CONNECTIVITY_HISTORY_POINTS);
    return {
      id: check.id,
      name: check.name,
      ok,
      error: item.error || (ok ? '' : 'no_response'),
      latencyMs,
      packetLossPercent,
      checkedAt,
      history
    };
  });
}

async function runDueConnectivityChecks() {
  const now = Date.now();
  for (const check of config.connectivityChecks || []) {
    if (!check.enabled) continue;
    const result = connectivityResults.get(check.id);
    const dueMs = Number(check.intervalSeconds || 60) * 1000;
    if (!result || now - Number(result.checkedAt || 0) >= dueMs) {
      await runConnectivityCheck(check).catch((err) => {
        setConnectivityResult(check.id, { ok: false, error: err.message, latencyMs: null, checkedAt: Date.now() });
      });
    }
  }
}

function parseTcpTarget(target) {
  const text = String(target || '').trim();
  const bracket = text.match(/^\[([^\]]+)]:(\d+)$/);
  if (bracket) return { host: bracket[1], port: Number(bracket[2]) };
  const idx = text.lastIndexOf(':');
  if (idx > 0 && !text.slice(0, idx).includes(':')) return { host: text.slice(0, idx), port: Number(text.slice(idx + 1)) };
  return { host: text, port: 80 };
}

function runConnectivityCheck(check) {
  const { host, port } = parseTcpTarget(check.target);
  if (!host || !Number.isFinite(port) || port < 1 || port > 65535) throw new Error('invalid target');
  const started = Date.now();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 5000 });
    const done = (ok, error = '') => {
      socket.destroy();
      const result = { ok, error, latencyMs: ok ? Date.now() - started : null, checkedAt: Date.now() };
      setConnectivityResult(check.id, result);
      resolve(result);
    };
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false, 'timeout'));
    socket.once('error', (err) => done(false, err.code || err.message));
  });
}

function setConnectivityResult(id, result) {
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
  return process.env.PUBLIC_HUB_URL || config.publicHubUrl || '';
}

async function syncPublicHubUrlFromRequest(req) {
  if (process.env.PUBLIC_HUB_URL) return false;
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

function recordViewerAccess(req) {
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
  saveState().catch((err) => console.error(err));
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
  saveState().catch((err) => console.error(err));
}

async function handleViewerHeartbeat(req, res) {
  const input = await readBody(req);
  const viewerId = recordViewerPresence(req, input.viewerId);
  const viewer = recordViewerAccess(req);
  const onlineViewers = onlineViewerStats();
  broadcast({ type: 'presence', at: Date.now(), onlineViewers });
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

async function ensureViewerAccessLocations() {
  const items = normalizeViewerAccess(Array.isArray(state.viewerAccess) ? state.viewerAccess : []).slice(0, 100);
  state.viewerIpLocations = state.viewerIpLocations || {};
  const staleBefore = Date.now() - 7 * 24 * 60 * 60 * 1000;
  let changed = false;
  for (const item of items) {
    const ip = normalizeClientIp(item.ip);
    const localLabel = ipLocalLocationLabel(ip);
    if (localLabel) {
      if (state.viewerIpLocations[ip]?.label !== localLabel) {
        state.viewerIpLocations[ip] = { label: localLabel, updatedAt: Date.now() };
        changed = true;
      }
      continue;
    }
    const cached = state.viewerIpLocations[ip];
    if (cached?.label && (cached.source === 'ping0' || (cached.source === 'ip-api' && Number(cached.updatedAt || 0) >= staleBefore))) continue;
    const fallback = await lookupIpLocationFallback(ip).catch(() => null);
    if (fallback?.label) {
      state.viewerIpLocations[ip] = fallback;
      changed = true;
    }
  }
  if (changed) saveState().catch((err) => console.error(err));
}

async function ensureBlockedWhitelistLocations() {
  const items = normalizeViewerAccess(Array.isArray(state.blockedWhitelistAccess) ? state.blockedWhitelistAccess : []).slice(0, 100);
  state.blockedWhitelistIpLocations = state.blockedWhitelistIpLocations || {};
  const staleBefore = Date.now() - 7 * 24 * 60 * 60 * 1000;
  let changed = false;
  for (const item of items) {
    const ip = normalizeClientIp(item.ip);
    const localLabel = ipLocalLocationLabel(ip);
    if (localLabel) {
      if (state.blockedWhitelistIpLocations[ip]?.label !== localLabel) {
        state.blockedWhitelistIpLocations[ip] = { label: localLabel, updatedAt: Date.now() };
        changed = true;
      }
      continue;
    }
    const cached = state.blockedWhitelistIpLocations[ip];
    if (cached?.label && Number(cached.updatedAt || 0) >= staleBefore) continue;
    const fallback = await lookupIpLocationFallback(ip).catch(() => null);
    if (fallback?.label) {
      state.blockedWhitelistIpLocations[ip] = fallback;
      changed = true;
    }
  }
  if (changed) saveState().catch((err) => console.error(err));
}

async function lookupIpLocationFallback(ip) {
  if (!net.isIP(ip)) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1800);
  try {
    const fields = 'status,country,regionName,city,as,isp,org,query';
    const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?lang=zh-CN&fields=${fields}`, { signal: controller.signal });
    if (!response.ok) return null;
    const data = await response.json();
    if (!data || data.status !== 'success') return null;
    const parts = [data.country, data.regionName, data.city, data.as, data.isp || data.org]
      .map((value) => String(value || '').trim())
      .filter(Boolean);
    const label = Array.from(new Set(parts)).join(' · ');
    return label ? { label, source: 'ip-api', updatedAt: Date.now() } : null;
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
  const parsed = new URL(String(value || '').trim());
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
  } else if (['.js', '.css'].includes(ext)) headers['Cache-Control'] = 'no-cache';
  const stream = createReadStream(filePath);
  stream.on('error', () => {
    if (!res.headersSent) sendNotFound(res);
    else res.destroy();
  });
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
