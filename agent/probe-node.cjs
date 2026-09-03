#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');
const { execFileSync } = require('node:child_process');

const MAX_RESPONSE_BYTES = 1024 * 1024;
const VERSION = '20260903-node-fixed-report-v3';
const HUB_URL = process.env.HUB_URL || 'http://127.0.0.1:8080';
const AGENT_TOKEN = process.env.AGENT_TOKEN || '';
const SERVER_ID = process.env.SERVER_ID || os.hostname();
const SERVER_NAME = process.env.SERVER_NAME || os.hostname();
const SERVER_LOCATION = process.env.SERVER_LOCATION || '';
const INTERVAL = clamp(Number(process.env.INTERVAL || 2), 1, 3600);
const CONNECTIVITY_INTERVAL = clamp(Number(process.env.CONNECTIVITY_INTERVAL || 60), 5, 86400);
const IP_META_TTL = clamp(Number(process.env.IP_META_TTL || 3600), 60, 86400);
const DISK_TTL_MS = clamp(Number(process.env.DISK_TTL_SECONDS || 30), 5, 3600) * 1000;
const CONNECTIONS_TTL_MS = clamp(Number(process.env.CONNECTIONS_TTL_SECONDS || 2), 2, 3600) * 1000;

if (!AGENT_TOKEN) {
  console.error('AGENT_TOKEN is required. Generate a per-server install command from the admin panel.');
  process.exit(1);
}

const hub = new URL(HUB_URL);
// Metrics use their own small connection pool. Like Nezha's independent
// ReportSystemState stream, a delayed response must not serialize sampling.
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 6 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 6 });
const metadataHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: 2 });
let prevNet = null;
let prevCpu = null;
let ipMeta = { data: null, fetchedAt: 0, fetching: false, publicIpv4: '', publicIpv6: '' };
let connectivityRunning = false;
let latestConnectivity = null;
let reportsInFlight = 0;
const MAX_REPORTS_IN_FLIGHT = 6;
let consecutiveFailures = 0;
let lastFailureLogAt = 0;
let diskCache = { data: { total: 0, used: 0, percent: 0 }, at: 0 };
let connectionsCache = { data: { tcp: 0, udp: 0 }, at: 0 };
const staticOs = readOs();
const cpuModel = readCpuModel();
const cpuCores = os.cpus().length;

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function request(method, path, { body, timeoutMs = 5000, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(path, hub);
    const isHttps = target.protocol === 'https:';
    const payload = body == null ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = (isHttps ? https : http).request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method,
      agent: isHttps ? httpsAgent : httpAgent,
      timeout: timeoutMs,
      headers: {
        Authorization: `Bearer ${AGENT_TOKEN}`,
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        ...headers
      }
    }, (res) => {
      const chunks = [];
      let received = 0;
      res.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES) {
          res.destroy(new Error('response body too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
          return;
        }
        resolve(text);
      });
    });
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function readFirstLine(path) {
  try { return fs.readFileSync(path, 'utf8').split('\n')[0]; } catch { return ''; }
}

function readOs() {
  const data = fs.existsSync('/etc/os-release') ? fs.readFileSync('/etc/os-release', 'utf8') : '';
  const values = Object.fromEntries(data.split('\n').map((line) => {
    const index = line.indexOf('=');
    if (index < 0) return null;
    return [line.slice(0, index), line.slice(index + 1).replace(/^"|"$/g, '')];
  }).filter(Boolean));
  return { platform: values.ID || os.platform(), version: values.VERSION_ID || os.release(), arch: os.arch(), kernel: os.release() };
}

function readCpuSnapshot() {
  const parts = readFirstLine('/proc/stat').trim().split(/\s+/).slice(1).map(Number);
  if (!parts.length) return null;
  const idle = (parts[3] || 0) + (parts[4] || 0);
  const total = parts.reduce((sum, value) => sum + (Number(value) || 0), 0);
  return { idle, total };
}

function readCpuPercent() {
  const current = readCpuSnapshot();
  if (!current) return 0;
  const previous = prevCpu || current;
  prevCpu = current;
  const totalDelta = current.total - previous.total;
  const idleDelta = current.idle - previous.idle;
  if (totalDelta <= 0) return 0;
  return Number((((totalDelta - idleDelta) * 100) / totalDelta).toFixed(2));
}

function readCpuModel() {
  const clean = (value) => String(value || '').replace(/\s+/g, ' ').trim();
  const isGeneric = (value) => /common kvm|virtual cpu|qemu virtual|unknown/i.test(value || '');
  let model = '';
  try {
    const line = fs.readFileSync('/proc/cpuinfo', 'utf8').split('\n').find((item) => item.startsWith('model name')) || '';
    model = clean(line.split(':').slice(1).join(':'));
  } catch {
    model = clean(os.cpus()[0]?.model || '');
  }
  if (model && !isGeneric(model)) return model;
  try {
    const out = execFileSync('lscpu', ['-J'], { encoding: 'utf8', timeout: 1500 });
    const rows = JSON.parse(out).lscpu || [];
    const byField = Object.fromEntries(rows.map((row) => [String(row.field || '').replace(/:$/, ''), clean(row.data)]));
    const lscpuModel = byField['Model name'] || byField['BIOS Model name'] || '';
    if (lscpuModel && !isGeneric(lscpuModel)) return lscpuModel;
    const vendor = byField['Vendor ID'] || byField['Hypervisor vendor'] || '';
    if (model && vendor) return `${model} (${vendor})`;
  } catch {}
  return model || clean(os.cpus()[0]?.model || '');
}

function readLoad() {
  const avg = os.loadavg();
  return [Number(avg[0].toFixed(2)), Number(avg[1].toFixed(2)), Number(avg[2].toFixed(2))];
}

function readMem() {
  const data = Object.fromEntries(fs.readFileSync('/proc/meminfo', 'utf8').split('\n').map((line) => {
    const match = line.match(/^([^:]+):\s+(\d+)/);
    return match ? [match[1], Number(match[2]) * 1024] : null;
  }).filter(Boolean));
  const total = data.MemTotal || os.totalmem();
  const available = data.MemAvailable || os.freemem();
  const swapTotal = data.SwapTotal || 0;
  const swapFree = data.SwapFree || 0;
  return { total, used: Math.max(0, total - available), percent: total ? Number((((total - available) * 100) / total).toFixed(2)) : 0, swapTotal, swapUsed: Math.max(0, swapTotal - swapFree) };
}

function readDisk() {
  if (Date.now() - diskCache.at < DISK_TTL_MS) return diskCache.data;
  try {
    const out = execFileSync('df', ['-B1', '/'], { encoding: 'utf8', timeout: 1500 }).trim().split('\n').pop().trim().split(/\s+/);
    const total = Number(out[1] || 0);
    const used = Number(out[2] || 0);
    const available = Number(out[3] || 0);
    diskCache = { data: { total, used, available, percent: total ? Number(((used * 100) / total).toFixed(2)) : 0 }, at: Date.now() };
  } catch { diskCache = { data: diskCache.data, at: Date.now() }; }
  return diskCache.data;
}

function readNetTotals() {
  const lines = fs.readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2);
  let rx = 0;
  let tx = 0;
  for (const line of lines) {
    const [ifaceRaw, rest] = line.split(':');
    if (!rest) continue;
    const iface = ifaceRaw.trim();
    if (!iface || iface === 'lo') continue;
    const parts = rest.trim().split(/\s+/).map(Number);
    rx += parts[0] || 0;
    tx += parts[8] || 0;
  }
  return { rx, tx, at: Date.now() };
}

function readNet() {
  const current = readNetTotals();
  const previous = prevNet || current;
  prevNet = current;
  const elapsed = Math.max(0.001, (current.at - previous.at) / 1000);
  return {
    inBps: Math.max(0, Math.round((current.rx - previous.rx) / elapsed)),
    outBps: Math.max(0, Math.round((current.tx - previous.tx) / elapsed)),
    totalIn: current.rx,
    totalOut: current.tx
  };
}

function countConnections() {
  if (Date.now() - connectionsCache.at < CONNECTIONS_TTL_MS) return connectionsCache.data;
  const parse = (file) => {
    try { return Math.max(0, fs.readFileSync(file, 'utf8').trim().split('\n').length - 1); } catch { return 0; }
  };
  connectionsCache = {
    data: { tcp: parse('/proc/net/tcp') + parse('/proc/net/tcp6'), udp: parse('/proc/net/udp') + parse('/proc/net/udp6') },
    at: Date.now()
  };
  return connectionsCache.data;
}

function uptimeSeconds() {
  const raw = readFirstLine('/proc/uptime').split(/\s+/)[0];
  return Math.floor(Number(raw || 0));
}

async function refreshIpMetaIfDue() {
  if (ipMeta.fetching || Date.now() - ipMeta.fetchedAt < IP_META_TTL * 1000) return;
  ipMeta.fetching = true;
  try {
    const text = await httpsGetText('https://ipinfo.io/json', 5000);
    ipMeta.data = JSON.parse(text);
    const detectedIp = ipMeta.data.ip || '';
    if (detectedIp.includes(':')) ipMeta.publicIpv6 = detectedIp;
    else if (detectedIp) ipMeta.publicIpv4 = detectedIp;
    const [ipv4, ipv6] = await Promise.all([
      httpsGetText('https://api.ipify.org', 3500).catch(() => ''),
      httpsGetText('https://api6.ipify.org', 3500).catch(() => '')
    ]);
    if (ipv4 && !ipv4.includes(':')) ipMeta.publicIpv4 = ipv4.trim();
    if (ipv6 && ipv6.includes(':')) ipMeta.publicIpv6 = ipv6.trim();
    ipMeta.fetchedAt = Date.now();
  } catch {
    ipMeta.fetchedAt = Date.now();
  } finally {
    ipMeta.fetching = false;
  }
}

function httpsGetText(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs, agent: metadataHttpsAgent }, (res) => {
      const chunks = [];
      let received = 0;
      res.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES) {
          res.destroy(new Error('response body too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').trim()));
    });
    req.on('timeout', () => req.destroy(new Error('ip request timeout')));
    req.on('error', reject);
  });
}

function ipFields() {
  const meta = ipMeta.data || {};
  const publicIpv4 = process.env.PUBLIC_IPV4 || ipMeta.publicIpv4 || '';
  const publicIpv6 = process.env.PUBLIC_IPV6 || ipMeta.publicIpv6 || '';
  const publicIp = meta.ip || publicIpv4 || publicIpv6 || '';
  const [latitude = '', longitude = ''] = String(meta.loc || '').split(',');
  const org = meta.org || '';
  const asnMatch = org.match(/^(AS\d+)\s+(.+)$/);
  const asn = asnMatch ? asnMatch[1] : '';
  const isp = asnMatch ? asnMatch[2] : org;
  return {
    publicIp, ip: publicIp,
    publicIpv4,
    ipv4: publicIpv4,
    publicIpv6,
    ipv6: publicIpv6,
    ipHostname: meta.hostname || '', city: meta.city || '', region: meta.region || '', country: meta.country || '', continent: '',
    latitude, longitude, postal: meta.postal || '', timezone: meta.timezone || '', callingCode: '', currency: '', org, isp, asn,
    company: isp, route: '', networkType: 'Data Center'
  };
}

function parseConnectivityLine(line) {
  const [id, name, target, interval] = line.split('\t');
  if (!id || !target) return null;
  let host = target;
  let port = 80;
  const v6 = target.match(/^\[([^\]]+)]:(\d+)$/);
  if (v6) {
    host = v6[1]; port = Number(v6[2]);
  } else if (target.includes(':') && !target.includes('::')) {
    const index = target.lastIndexOf(':');
    host = target.slice(0, index); port = Number(target.slice(index + 1));
  }
  return { id, name, target, interval: Number(interval || CONNECTIVITY_INTERVAL), host, port };
}

function tcpLatency(check) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host: check.host, port: check.port, timeout: 2000 });
    const done = (ok, error = '') => {
      socket.removeAllListeners();
      socket.destroy();
      resolve({ id: check.id, name: check.name, ok, error, latencyMs: ok ? Date.now() - started : 0, packetLossPercent: ok ? 0 : 100, checkedAt: Date.now() });
    };
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false, 'timeout'));
    socket.once('error', () => done(false, 'timeout'));
  });
}

async function runConnectivityChecks() {
  if (connectivityRunning) return;
  connectivityRunning = true;
  try {
    const text = await request('GET', `/api/agent/connectivity?serverId=${encodeURIComponent(SERVER_ID)}`, { timeoutMs: 5000 });
    const checks = text.split('\n').map((line) => line.trim()).filter(Boolean).map(parseConnectivityLine).filter(Boolean);
    // Match Nezha's task model: probes run outside the system-state reporting
    // loop. A slow target only occupies its own promise and cannot delay the
    // next metrics report. Independent targets are probed concurrently.
    const results = await Promise.all(checks.map(tcpLatency));
    latestConnectivity = { connectivity: results, connectivityMeta: { count: checks.length, error: '' } };
  } catch (err) {
    latestConnectivity = { connectivity: [], connectivityMeta: { count: 0, error: err.message || 'fetch_failed' } };
  } finally {
    connectivityRunning = false;
  }
}

function startConnectivityDaemon() {
  runConnectivityChecks().catch(() => {});
  setInterval(() => runConnectivityChecks().catch(() => {}), CONNECTIVITY_INTERVAL * 1000).unref();
}

async function buildPayload() {
  refreshIpMetaIfDue();
  const mem = readMem();
  const disk = readDisk();
  const conn = countConnections();
  return {
    id: SERVER_ID,
    probeVersion: VERSION,
    name: SERVER_NAME,
    location: SERVER_LOCATION,
    hostname: os.hostname(),
    ...ipFields(),
    uptimeSeconds: uptimeSeconds(),
    os: staticOs,
    cpu: { percent: readCpuPercent(), model: cpuModel, cores: cpuCores, load: readLoad() },
    memory: { total: mem.total, used: mem.used, percent: mem.percent },
    swap: { total: mem.swapTotal, used: mem.swapUsed, percent: mem.swapTotal ? Number(((mem.swapUsed * 100) / mem.swapTotal).toFixed(2)) : 0 },
    disk,
    net: readNet(),
    connections: conn,
    ...(latestConnectivity || {})
  };
}

async function sendOnce() {
  if (reportsInFlight >= MAX_REPORTS_IN_FLIGHT) return false;
  reportsInFlight += 1;
  try {
    const payload = await buildPayload();
    await request('POST', '/api/agent/report', { body: payload, timeoutMs: 5000 });
    consecutiveFailures = 0;
    return true;
  } catch (err) {
    consecutiveFailures += 1;
    const now = Date.now();
    if (now - lastFailureLogAt >= 60000 || consecutiveFailures === 1) {
      lastFailureLogAt = now;
      console.error(`[${new Date().toISOString()}] report failed (${consecutiveFailures}x): ${err.message}`);
    }
    return false;
  } finally {
    reportsInFlight -= 1;
  }
}

function nextDelaySeconds(ok) {
  if (ok) return INTERVAL;
  const backoff = Math.min(60, INTERVAL * (2 ** Math.min(consecutiveFailures, 5)));
  return Math.max(INTERVAL, backoff);
}

async function main() {
  await refreshIpMetaIfDue();
  startConnectivityDaemon();
  // Fixed-rate scheduler: do not add HTTP response time to the configured
  // interval. Keep a strict concurrency cap so an unavailable hub cannot
  // create an unbounded queue.
  sendOnce().catch(() => {});
  setInterval(() => sendOnce().catch(() => {}), INTERVAL * 1000);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
