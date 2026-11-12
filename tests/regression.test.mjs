import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, cp, rm, chmod, access, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import http from 'node:http';
import { gunzipSync } from 'node:zlib';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const realFetch = globalThis.fetch;

async function createHub(t, initial = {}) {
  const directory = await mkdtemp(path.join(root, '.test-runtime-'));
  await mkdir(path.join(directory, 'hub'));
  await mkdir(path.join(directory, 'data'));
  await cp(path.join(root, 'public'), path.join(directory, 'public'), { recursive: true });
  await cp(path.join(root, 'agent'), path.join(directory, 'agent'), { recursive: true });
  await writeFile(path.join(directory, 'package.json'), '{"type":"module"}');
  if (initial.config) await writeFile(path.join(directory, 'data/config.json'), JSON.stringify(initial.config));
  if (initial.state) await writeFile(path.join(directory, 'data/state.json'), JSON.stringify(initial.state));
  let source = await readFile(path.join(root, 'hub/server.js'), 'utf8');
  // Export the actual deployed implementation from an isolated fixture. No
  // testing endpoints or test-only credentials are added to the live server.
  source = 'let testClosing = false; const testIntervals = []; const trackedInterval = (...args) => { const timer = setInterval(...args); testIntervals.push(timer); return timer; };\n'
    + source.replace(/\bsetInterval\(/g, 'trackedInterval(');
  source = source.replace('function saveStateSoon() {', 'function saveStateSoon() { if (testClosing) return Promise.resolve();');
  source += `\nexport { server, state, config, connectivityDb, normalizeAgentReport, mergeAgentReport, isReportOnline, buildOverview, buildServerDetail, mergeServerConnectivity, calculateCycleTraffic, currentTrafficCycle, trafficCycleKey, updateTrafficCycleState, cachedServerIpQuality, refreshPanelServerIpApiQuality, runDueIpApiRefresh, reportIpSignature, clearIpApiCache, pruneAccessState, scheduleAccessLocationRefresh, publicFlagAssets, serverCountryCode, saveStateNow, saveStateSoon };
  export const testHooks = {
    getConfig() { return config; },
    resetReportRate(id) { agentLastReportAt.delete(id); },
    refreshServerIpApiQuality,
    aggregateConnectivityHistory,
    normalizeConnectivityCheck, dueAgentConnectivityChecks,
    setLocationLookup(fn) { lookupIpLocationFallback = fn; },
    resetCountryRetry() { countryLookupRetryAt.clear(); },
    setQualityLookup(fn) { lookupServerIpApiQualityDetailed = fn; },
    resetPrune() { connectivityPrunedAt = 0; },
    pruneConnectivityHistory,
    normalizeBackgrounds, normalizeHubUrl, isAgentEndpointRequest,
    buildAgentInstaller, buildAgentUninstaller, buildInstallCommand, buildUninstallCommand, agentIdentityKey, transactConfig,
    reconcileTrafficCycle, trafficCyclesOverlap, isStaleTrafficReport,
    setRestart(fn) { performPanelRestart = fn; },
    async close() { testClosing = true; for (const timer of testIntervals) clearInterval(timer); await saveStateNow(); server.closeAllConnections(); if(agentServer) {agentServer.closeAllConnections(); await new Promise(resolve=>agentServer.close(resolve));} await new Promise(resolve => server.close(resolve)); connectivityDb.close(); }
  };`;
  await writeFile(path.join(directory, 'hub/server.js'), source);
  const previousPort = process.env.PROBE_PORT;
  process.env.PROBE_PORT = initial.runtimePort == null ? '0' : String(initial.runtimePort);
  const signalListeners = new Map(['SIGTERM', 'SIGINT'].map((name) => [name, process.listeners(name)]));
  const hub = await import(pathToFileURL(path.join(directory, 'hub/server.js')));
  if (!hub.server.listening) await once(hub.server, 'listening');
  if (previousPort === undefined) delete process.env.PROBE_PORT; else process.env.PROBE_PORT = previousPort;
  t.after(async () => {
    await hub.testHooks.close();
    for (const [name, before] of signalListeners) for (const listener of process.listeners(name)) if (!before.includes(listener)) process.removeListener(name, listener);
    await rm(directory, { recursive: true, force: true });
  });
  return { ...hub, base: `http://127.0.0.1:${hub.server.address().port}`, directory };
}

test('hub regression: address changes, offline snapshots, bounded settings and storage', async (t) => {
  const hub = await createHub(t);
  const { state, config } = hub;
  const now = Date.now();
  const meta = { id: 'node-a', name: 'Node A', secret: 'test-agent-secret', startedAt: '2020-01-01', expiresAt: '2099-01-01', remainingTrafficBytes: 10000, trafficCycleStartDate: '2026-01-01', trafficCycleUnit: 'month' };
  config.servers.push(meta);
  state.servers[meta.id] = { id: meta.id, country: 'US', publicIpv4: '198.51.100.1', publicIpv6: '2001:db8::1', lastReportAt: now - 100000, net: { totalIn: 100, totalOut: 200 } };
  hub.testHooks.setLocationLookup(async () => ({ label: 'United States', country: 'US', source: 'ip-api', updatedAt: Date.now() }));

  await t.test('same ID and secret reconnect with new IP; preserve country, IPv6 and counters', async () => {
    const result = await realFetch(`${hub.base}/api/agent/report`, { method: 'POST', headers: { Authorization: `Bearer ${meta.secret}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ id: meta.id, publicIpv4: '198.51.100.2', country: '', net: { totalIn: 140, totalOut: 250 }, cpu: { percent: 37 } }) });
    assert.equal(result.status, 200);
    assert.equal(state.servers[meta.id].publicIpv4, '198.51.100.2');
    assert.equal(state.servers[meta.id].publicIpv6, '2001:db8::1');
    assert.equal(state.servers[meta.id].country, 'US');
    assert.equal(state.servers[meta.id].cpu.percent, 37);
    assert.equal(hub.isReportOnline(state.servers[meta.id]), true);
    assert.equal(config.servers.length, 1);
    const unauthorized = await realFetch(`${hub.base}/api/agent/report`, { method: 'POST', headers: { Authorization: 'Bearer wrong', 'Content-Type': 'application/json' }, body: JSON.stringify({ id: meta.id }) });
    assert.equal(unauthorized.status, 401);
  });

  await t.test('expired offline traffic stays in the last recorded cycle', () => {
    const report = state.servers[meta.id];
    report.lastReportAt = new Date('2024-01-20T12:00:00Z').getTime();
    meta.expiresAt = '2024-02-01';
    state.trafficCycles[meta.id] = { cycleKey: 'old-cycle', usedIn: 123, usedOut: 456, startAt: 1, endAt: 2 };
    const result = hub.calculateCycleTraffic(meta, report);
    assert.equal(result.usedTotal, 579);
    assert.equal(result.remainingBytes, 9421);
    assert.equal(hub.buildOverview().servers[0].trafficResetPaused, true);
    report.lastReportAt = Date.now();
    assert.equal(hub.buildOverview().servers[0].trafficResetPaused, false);
    meta.expiresAt = '2099-01-01';
  });

  await t.test('offline IP quality is not queried or overwritten by another node sharing its IP', async () => {
    state.servers[meta.id].lastReportAt = Date.now() - 100000;
    const frozen = { ipApi: { ipv4: { source: 'ip-api', org: 'Original snapshot', updatedAt: 123 } }, status: '', message: '' };
    state.servers[meta.id].ipQualitySnapshot = structuredClone(frozen);
    config.servers.push({ id: 'node-b', name: 'Node B', secret: 'another' });
    state.servers['node-b'] = { publicIpv4: '198.51.100.2', lastReportAt: Date.now() };
    config.ipapiKey = 'test-key';
    let queries = 0;
    hub.testHooks.setQualityLookup(async () => { queries++; return { ok: true, data: { source: 'ip-api', org: 'New snapshot', updatedAt: Date.now() } }; });
    const result = await hub.refreshPanelServerIpApiQuality('manual');
    assert.equal(result.attempted, 1);
    assert.equal(result.skipped, 1);
    assert.equal(queries, 1);
    assert.deepEqual(hub.cachedServerIpQuality(state.servers[meta.id]), frozen);
    state.servers[meta.id].lastReportAt = Date.now();
    await hub.runDueIpApiRefresh();
    assert.equal(queries, 3, 'reconnected dual-stack node is refreshed without waiting for the global interval');
    assert.equal(state.servers[meta.id].ipQualitySnapshot.ipApi.ipv4.org, 'New snapshot');
    config.ipapiKey = '';
  });

  await t.test('quality lookup in flight cannot replace a snapshot after the node goes offline', async () => {
    config.ipapiKey = 'test-key';
    const report = state.servers[meta.id];
    report.lastReportAt = Date.now();
    state.servers['node-b'].lastReportAt = Date.now() - 100000;
    const frozen = structuredClone(report.ipQualitySnapshot);
    let release;
    let queries = 0;
    hub.testHooks.setQualityLookup(() => { queries++; return new Promise(resolve => { release = resolve; }); });
    const pending = hub.refreshPanelServerIpApiQuality('manual');
    await new Promise(resolve => setImmediate(resolve));
    report.lastReportAt = Date.now() - 100000;
    release({ ok: true, data: { org: 'Must not commit' } });
    await pending;
    assert.equal(queries, 1);
    assert.deepEqual(report.ipQualitySnapshot, frozen);
    config.ipapiKey = '';
  });

  await t.test('latency writes only fresh real samples and survives long offline periods', async () => {
    config.connectivityChecks = [{ id: 'check-a', name: 'Tokyo', intervalSeconds: 60, enabled: true }, { id: 'check-b', name: 'Singapore', intervalSeconds: 60, enabled: true }];
    const at = Date.now() - 30 * 86400_000;
    state.servers[meta.id].lastReportAt = at;
    let merged = hub.mergeServerConnectivity(meta.id, [{ id: 'check-a', ok: true, latencyMs: 25, checkedAt: at, packetLossPercent: 0 }]);
    state.servers[meta.id].connectivity = merged;
    assert.equal(merged.length, 1, 'missing targets must not be recorded as synthetic timeouts');
    for (let i = 0; i < 50; i++) state.servers[meta.id].connectivity = hub.mergeServerConnectivity(meta.id, [{ id: 'check-a', ok: true, latencyMs: 99, checkedAt: at }]);
    assert.equal(hub.connectivityDb.prepare('SELECT COUNT(*) AS count FROM connectivity_history').get().count, 1);
    assert.equal(state.servers[meta.id].connectivity[0].latencyMs, 25);
    const first = await hub.buildServerDetail(meta.id, { includeConnectivityHistory: true });
    const second = await hub.buildServerDetail(meta.id, { includeConnectivityHistory: true });
    assert.deepEqual(first.connectivity, second.connectivity);
    assert.equal(first.connectivity[0].history.length, 1);
    hub.testHooks.resetPrune(); hub.testHooks.pruneConnectivityHistory();
    assert.equal(hub.connectivityDb.prepare('SELECT COUNT(*) AS count FROM connectivity_history').get().count, 1);
    state.servers[meta.id].lastReportAt = Date.now();
    state.servers[meta.id].connectivity = hub.mergeServerConnectivity(meta.id, [{ id: 'check-a', ok: true, latencyMs: 30, checkedAt: Date.now() }]);
    assert.equal(state.servers[meta.id].connectivity[0].latencyMs, 30);
    config.connectivityChecks = [];
  });

  await t.test('online and whitelist APIs return immediately while geolocation is stalled', async () => {
    state.viewerAccess = Array.from({ length: 100 }, (_, i) => ({ ip: `203.0.113.${i + 1}`, firstAccessAt: now, lastAccessAt: now + i }));
    state.blockedWhitelistAccess = state.viewerAccess.map(item => ({ ...item }));
    state.viewerIpLocations = {}; state.blockedWhitelistIpLocations = {};
    let release;
    let calls = 0;
    hub.testHooks.setLocationLookup(() => { calls++; return new Promise(resolve => { release = resolve; }); });
    const login = await realFetch(`${hub.base}/api/admin/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const started = performance.now();
    const responses = await Promise.all(Array.from({ length: 12 }, (_, i) => realFetch(`${hub.base}/api/admin/settings?section=${i % 2 ? 'online' : 'whitelist'}`, { headers: { Cookie: cookie } }).then(r => r.json())));
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 1500, `12 concurrent settings reads took ${elapsed}ms`);
    assert.ok(responses.every(data => data.viewerAccess.length === 100));
    assert.equal(calls, 1, 'concurrent readers share one background sweep');
    // Fail the pending request, then make subsequent failures immediate. The
    // next refresh must observe negative caching and avoid repeating them.
    hub.testHooks.setLocationLookup(async () => { calls++; return null; });
    release(null);
    await hub.scheduleAccessLocationRefresh();
    const after = calls;
    await hub.scheduleAccessLocationRefresh();
    assert.equal(calls, after);
    assert.ok(Object.keys(state.viewerIpLocations).length <= 100);
    assert.ok(Object.keys(state.blockedWhitelistIpLocations).length <= 100);
    t.diagnostic(`12 concurrent settings reads: ${Math.round(elapsed)} ms with stalled geolocation`);
  });

  await t.test('long-lived caches and state writes remain bounded', async () => {
    state.viewerAccess = Array.from({ length: 1000 }, (_, i) => ({ ip: `198.18.${Math.floor(i/250)}.${i%250+1}`, lastAccessAt: i + 1 }));
    state.viewerIpLocations = Object.fromEntries(state.viewerAccess.map(item => [item.ip, { label: 'Cached', updatedAt: now }]));
    hub.pruneAccessState();
    assert.equal(state.viewerAccess.length, 100);
    assert.equal(Object.keys(state.viewerIpLocations).length, 100);
    const promise = hub.saveStateSoon();
    for (let i = 0; i < 10000; i++) assert.equal(hub.saveStateSoon(), promise);
    await hub.saveStateNow(); await promise;
  });

  await t.test('valid country flags are embedded; invalid/empty metadata cannot erase the flag', async () => {
    const merged = hub.mergeAgentReport({ country: 'US', publicIpv4: '198.51.100.1' }, { country: '', publicIpv4: '198.51.100.2' });
    assert.equal(merged.country, 'US');
    assert.equal(hub.serverCountryCode({}, { country: 'NotACountry' }), '');
    assert.ok(hub.publicFlagAssets(['US']).US.startsWith('data:image/svg+xml;base64,'));
    const html = await (await realFetch(hub.base)).text();
    assert.ok(html.includes('data:image/svg+xml;base64,'));
    assert.ok(!html.includes(meta.secret));
  });
});

test('hub restart retains the final latency window of an offline server', async (t) => {
  const lastReportAt = Date.now() - 30 * 86400_000;
  const hub = await createHub(t, {
    config: { servers: [{ id: 'offline', name: 'Offline', secret: 'test' }], connectivityChecks: [{ id: 'saved', name: 'Saved', enabled: true, intervalSeconds: 60, target: '127.0.0.1:1' }] },
    state: { servers: { offline: { lastReportAt, country: 'US', connectivity: [{ id: 'saved', ok: true, latencyMs: 42, checkedAt: lastReportAt, history: [{ t: lastReportAt, ok: true, latencyMs: 42, packetLossPercent: 0 }] }] } } }
  });
  const detail = await hub.buildServerDetail('offline', { includeConnectivityHistory: true });
  assert.equal(detail.connectivity[0].paused, true);
  assert.equal(detail.connectivity[0].history.length, 1);
  assert.equal(detail.connectivity[0].history[0].latencyMs, 42);
});

test('new node queries immediately during a running sweep and does not block reports or detail reads', async (t) => {
  const hub = await createHub(t);
  hub.config.ipapiKey = 'fixture-key';
  hub.config.servers.push({ id: 'old', name: 'Old', secret: 'old-secret' });
  hub.state.servers.old = { id: 'old', country: 'US', publicIpv4: '198.51.100.10', lastReportAt: Date.now() };
  hub.config.pendingInstalls.push({ id: 'new', secret: 'new-secret', expiresAt: Date.now() + 60000 });
  const releases = new Map();
  hub.testHooks.setQualityLookup(ip => new Promise(resolve => releases.set(ip, resolve)));
  const sweep = hub.refreshPanelServerIpApiQuality('manual');
  await new Promise(resolve => setImmediate(resolve));
  try {
    const start = performance.now();
    const report = await realFetch(`${hub.base}/api/agent/report`, { method: 'POST', headers: { Authorization: 'Bearer new-secret' }, body: JSON.stringify({ id: 'new', country: 'US', publicIpv4: '198.51.100.11' }) });
    assert.equal(report.status, 200);
    const detail = await realFetch(`${hub.base}/api/servers/new`).then(r => r.json());
    assert.equal(detail.server.ipQuality.status, 'pending');
    assert.ok(performance.now() - start < 1000, 'external queries do not block metrics or details');
    assert.ok(releases.has('198.51.100.11'), 'new IP queried before old sweep finishes');
    releases.get('198.51.100.11')({ ok: true, data: { org: 'Immediate new node', updatedAt: Date.now() } });
    for (let i = 0; i < 50 && !hub.state.servers.new.ipApiRefreshedAt; i++) await new Promise(r => setTimeout(r, 10));
    assert.equal((await hub.buildServerDetail('new')).server.ipQuality.ipApi.ipv4.org, 'Immediate new node');
    assert.equal(hub.state.servers.old.ipApiRefreshedAt, undefined);
  } finally {
    for (const release of releases.values()) release({ ok: true, data: { org: 'Released', updatedAt: Date.now() } });
    await sweep;
  }
});

test('late IP triggers first query; heartbeats deduplicate and failures retry with cooldown', async (t) => {
  const hub = await createHub(t);
  hub.config.ipapiKey = 'fixture-key';
  hub.config.servers.push({ id: 'late', secret: 'test-secret' });
  let queries = 0, release;
  hub.testHooks.setQualityLookup(() => { queries++; return new Promise(resolve => { release = resolve; }); });
  async function report(ip = '') {
    hub.testHooks.resetReportRate('late');
    const r = await realFetch(`${hub.base}/api/agent/report`, { method: 'POST', headers: { Authorization: 'Bearer test-secret' }, body: JSON.stringify({ id: 'late', country: 'US', publicIpv4: ip }) });
    assert.equal(r.status, 200);
  }
  await report();
  assert.equal(queries, 0);
  assert.equal((await hub.buildServerDetail('late')).server.ipQuality.status, 'waiting_ip');
  await report('198.51.100.20');
  assert.equal(queries, 1);
  await report('198.51.100.20');
  assert.equal(queries, 1);
  release({ ok: false, reason: 'Temporary failure' });
  await new Promise(resolve => setImmediate(resolve));
  await report('198.51.100.20');
  assert.equal(queries, 1, 'failed lookup is not retried on every heartbeat');
  assert.equal((await hub.buildServerDetail('late')).server.ipQuality.status, 'error');
  hub.state.servers.late.ipApiAttemptedAt -= 60001;
  await report('198.51.100.20');
  assert.equal(queries, 2);
  release({ ok: true, data: { org: 'Recovered', updatedAt: Date.now() } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((await hub.buildServerDetail('late')).server.ipQuality.ipApi.ipv4.org, 'Recovered');
});

test('IP quality jobs bound concurrency and prioritize a new node over routine work', async (t) => {
  const hub = await createHub(t);
  hub.config.ipapiKey = 'fixture-key';
  for (let i = 0; i < 8; i++) {
    hub.config.servers.push({ id: `q${i}`, secret: 'fixture' });
    hub.state.servers[`q${i}`] = { id: `q${i}`, publicIpv4: `198.51.100.${30+i}`, lastReportAt: Date.now(), ipApiRefreshedAt: 1 };
  }
  const releases = [];
  const calls = [];
  let active = 0, maxActive = 0;
  hub.testHooks.setQualityLookup(ip => {
    calls.push(ip); active++; maxActive = Math.max(maxActive, active);
    return new Promise(resolve => releases.push(() => { active--; resolve({ ok: true, data: { org: 'Test' } }); }));
  });
  const sweep = hub.refreshPanelServerIpApiQuality('manual');
  await new Promise(resolve => setImmediate(resolve));
  const meta = { id: 'priority', secret: 'fixture' };
  hub.config.servers.push(meta);
  hub.state.servers.priority = { id: 'priority', publicIpv4: '198.51.100.99', lastReportAt: Date.now() };
  const first = hub.testHooks.refreshServerIpApiQuality(meta);
  assert.equal(calls.length, 4);
  releases.shift()();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls[4], '198.51.100.99');
  while (releases.length) { releases.shift()(); await new Promise(resolve => setImmediate(resolve)); }
  await Promise.all([sweep, first]);
  assert.equal(maxActive, 4);
  assert.equal(calls.length, 9);
});

test('homepage contains bounded real detail data, including offline history and cached quality', async (t) => {
  const hub = await createHub(t);
  const at = Date.now() - 86400_000;
  hub.config.servers.push({ id: 'instant', name: 'Instant', secret: 'never-expose-this-secret' });
  hub.state.servers.instant = { id: 'instant', lastReportAt: at, cpu: { percent: 27 }, net: { inBps: 123 }, connections: { tcp: 11 }, ipQualitySnapshot: { ipApi: { ipv4: { org: 'Last quality' } } } };
  const samples = Array.from({ length: 1000 }, (_, i) => ({ t: at - (999-i)*1000, cpu: i % 100, tcp: i }));
  hub.state.history.instant = samples;
  const response = await realFetch(hub.base + '/api/overview');
  assert.equal(response.status, 200);
  const payload = await response.json();
  const detail = payload.detailSnapshots.instant;
  assert.equal(detail.history.length, 60);
  assert.equal(detail.history[0].t, at - 120000);
  assert.equal(detail.history.at(-1).t, at);
  for (const sample of detail.history) assert.ok(samples.some(original => original.t === sample.t && original.cpu === sample.cpu));
  assert.equal(detail.point.cpu, 27);
  assert.equal(detail.point.tcp, 11);
  assert.equal(detail.ipQuality.ipApi.ipv4.org, 'Last quality');
  assert.ok(Array.isArray(detail.connectivity));
  assert.ok(!JSON.stringify(payload).includes('never-expose-this-secret'));
  assert.equal(samples.length, 1000, 'building the homepage does not alter stored history');
});

test('12 service limit is atomic; editing and replacing a deleted service remain allowed',async t=>{
  const hub=await createHub(t);
  const login=await realFetch(hub.base+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'admin'})});
  const cookie=login.headers.get('set-cookie').split(';')[0],{csrfToken}=await login.json();
  const headers={'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':csrfToken};
  const save=(id,name=id)=>realFetch(hub.base+'/api/admin/connectivity',{method:'POST',headers,body:JSON.stringify({id,name,target:'127.0.0.1:1',intervalMinutes:5})});
  for(let i=0;i<11;i++) assert.equal((await save('limit-'+i)).status,200);
  const races=await Promise.all([save('twelfth-a'),save('twelfth-b')]);
  assert.deepEqual(races.map(r=>r.status).sort(),[200,409]);
  assert.equal((await races.find(r=>r.status===409).json()).message,'达到数量上限');
  assert.equal(hub.testHooks.getConfig().connectivityChecks.length,12);
  assert.equal((await save('limit-0','Edited at limit')).status,200);
  assert.equal((await save('thirteenth')).status,409);
  assert.equal((await realFetch(hub.base+'/api/admin/connectivity/limit-0/delete',{method:'POST',headers,body:'{}'})).status,200);
  assert.equal((await save('replacement')).status,200);
  assert.equal(hub.testHooks.getConfig().connectivityChecks.length,12);
});

test('raw latency samples, compressed offline time and zero failures across all ranges', async () => {
  const source=await readFile(path.join(root,'public/app.js'),'utf8');
  const select=(a,b)=>source.slice(source.indexOf(`function ${a}(`),source.indexOf(`function ${b}(`));
  const context=vm.createContext({Date,Math,Number,Map,Set,Array,Boolean,activeDetailData:{server:{online:true},connectivityGaps:[]},networkQualityRangeDays:1,networkQualityPeakCut:false});
  vm.runInContext(select('aggregateConnectivityHistory','peakCutSeriesData')+select('peakCutSeriesData','handleNetworkQualityFilterClick')+select('networkQualityTimeline','renderNetworkQualityChartStable')+select('preserveLoadedConnectivityHistory','handleDetailTabClick'),context);
  const base=Date.now()-7200000;
  const history=[10,20,90,0].map((latencyMs,i)=>({t:base+i*300000,latencyMs,ok:latencyMs>0,packetLossPercent:latencyMs?0:100}));
  for(const days of [1,7,15]) {
    context.networkQualityRangeDays=days;
    const raw=context.aggregateConnectivityHistory(history,0,days,300);
    assert.deepEqual(Array.from(raw,p=>p.latencyMs),[10,20,90,0],'all real samples retained without interval averaging');
    assert.equal(context.aggregateConnectivityHistory([...raw,history.at(-1)],0).length,4,'latest report deduplicates');
    const model=context.networkQualitySeriesModel({history:raw,intervalSeconds:300});
    assert.deepEqual(Array.from(model.lineData,p=>p[1]),[10,20,90,0],'no smoothing, blank buckets or interpolation values');
    for(let t=base;t<=history.at(-1).t;t+=30000) assert.ok(context.nearestNetworkQualityObservation(model,t));
  }
  const gap={start:base+900000,end:base+4500000};context.activeDetailData.connectivityGaps=[gap];
  const checks=[{intervalSeconds:300,history:[{t:gap.start,latencyMs:20,ok:true},{t:gap.end-5000,latencyMs:80,ok:true},{t:gap.end+295000,latencyMs:0,ok:false}]}];
  const timeline=context.networkQualityTimeline(checks), model=context.networkQualitySeriesModel(checks[0],timeline);
  assert.equal(model.lineData[1][0]-model.lineData[0][0],300000,'one hour offline is removed, reconnect is the next display step');
  assert.equal(timeline.fromX(model.lineData[1][0]),gap.end-5000,'real reconnect timestamp survives compression');
  assert.equal(context.nearestNetworkQualityObservation(model,model.lineData[1][0]).value,80);
  assert.equal(model.lineData.length,3,'no points fabricated during outage');
  assert.equal(model.lineData.at(-1)[1],0,'failed sample reaches exact chart bottom');
  context.activeDetailData.connectivityGaps=[];
  const slow={intervalSeconds:43200,history:[{t:base,latencyMs:42,ok:true},{t:base+43200000,latencyMs:45,ok:true}]};
  assert.equal(context.networkQualityTimeline([slow]).gaps.length,0,'720-minute interval is not an outage');
  assert.ok(context.nearestNetworkQualityObservation(context.networkQualitySeriesModel(slow),base+21600000),'slow target remains inspectable');
  const cut=context.peakCutSeriesData([20,20,20,2000,0,20]);
  assert.equal(cut[3],null,'MAD spike rejection remains');assert.equal(cut[4],0,'failure zero is never removed');
  assert.equal(cut[0],20);assert.equal(cut[5],20,'filter never invents a replacement value');
  const newer={id:'target',intervalSeconds:300,result:{checkedAt:base+600000,latencyMs:99,ok:true},history:[]};
  const older={...newer,result:{checkedAt:base+300000,latencyMs:40,ok:true},history:[{t:base+300000,latencyMs:40,ok:true}]};
  const merged=context.preserveLoadedConnectivityHistory({server:{online:true},connectivity:[older]},{connectivity:[newer]});
  assert.equal(merged.connectivity[0].result.checkedAt,newer.result.checkedAt);
});

test('minute validation and per-target scheduling with bounded missing/legacy retries',async t=>{
  const hub=await createHub(t);const {config,state,testHooks}=hub;
  for(const value of [4,721,5.5,-5,'1e2','+5','5.0','٥',true,'']) assert.throws(()=>testHooks.normalizeConnectivityCheck({name:'t',target:'localhost:80',intervalMinutes:value}));
  for(const value of [5,720,'15']) assert.equal(testHooks.normalizeConnectivityCheck({target:'localhost:80',intervalMinutes:value}).intervalSeconds,Number(value)*60);
  assert.equal(testHooks.normalizeConnectivityCheck({target:'localhost:80'}).intervalSeconds,300);
  const id='scheduler',now=Date.now();state.servers[id]={lastReportAt:now,connectivity:[]};
  config.connectivityChecks=[{id:'fast',target:'localhost:80',intervalSeconds:300},{id:'slow',target:'localhost:80',intervalSeconds:43200}];
  assert.equal(testHooks.dueAgentConnectivityChecks(id,now).length,2);
  assert.equal(testHooks.dueAgentConnectivityChecks(id,now+1000).length,0,'leases prevent duplicate tasks');
  state.servers[id].connectivity=hub.mergeServerConnectivity(id,[{id:'fast',checkedAt:now+1,ok:false,latencyMs:0},{id:'slow',checkedAt:now+1,ok:true,latencyMs:42}]);
  assert.equal(state.servers[id].connectivity.length,1,'failed first attempt is not prematurely recorded as zero');
  for(let attempt=2;attempt<=4;attempt++){
    const at=now+attempt*1000;
    const due=testHooks.dueAgentConnectivityChecks(id,at);assert.equal(due.length,1);assert.equal(due[0].check.id,'fast');
    state.servers[id].connectivity=hub.mergeServerConnectivity(id,[{id:'fast',checkedAt:at+1,ok:false,latencyMs:0}]);
  }
  assert.equal(hub.connectivityDb.prepare("SELECT COUNT(*) AS n FROM connectivity_history WHERE check_id='fast'").get().n,1);
  assert.equal(state.servers[id].connectivity.find(p=>p.id==='fast').latencyMs,0);
  assert.equal(testHooks.dueAgentConnectivityChecks(id,now+5000).length,0,'three retries is the maximum');
  assert.deepEqual(testHooks.dueAgentConnectivityChecks(id,now+300000).map(x=>x.check.id),['fast'],'each target obeys its own cadence');
  // A task with no response at all also terminates after three retries, but
  // offline nodes never receive fabricated zero history.
  const job=state.agentConnectivityServed[id].fast;
  for(let i=1;i<=3;i++) {state.servers[id].lastReportAt=now+300000+i*16000;testHooks.dueAgentConnectivityChecks(id,now+300000+i*16000);}
  state.servers[id].lastReportAt=now+364000;
  testHooks.dueAgentConnectivityChecks(id,now+364000);
  assert.equal(job.attempts,4);assert.equal(job.awaiting,false);
  assert.equal(hub.connectivityDb.prepare("SELECT COUNT(*) AS n FROM connectivity_history WHERE check_id='fast'").get().n,2);
  const raw=testHooks.aggregateConnectivityHistory([{t:now,latencyMs:10,ok:true},{t:now+1,latencyMs:90,ok:true}],0,15,300);
  assert.deepEqual(raw.map(p=>p.latencyMs),[10,90],'backend never averages');
});

test('agent retries only the failed target and preserves real successful measurements',async()=>{
  let source=await readFile(path.join(root,'agent/probe-node.cjs'),'utf8');source=source.slice(0,source.lastIndexOf('\nmain().catch'));
  const context=vm.createContext({require:createRequire(import.meta.url),Buffer,URL,setTimeout,clearTimeout,setInterval,console,process:{env:{AGENT_TOKEN:'test'},exit(){throw new Error('exit');}}});
  vm.runInContext(source,context);
  try{
    vm.runInContext(`const attemptsById={}; tcpLatency=async check=>{const n=attemptsById[check.id]=(attemptsById[check.id] || 0)+1;return {ok:check.id==='good'||check.id==='recover'&&n===3,latencyMs:check.id==='good'?12.34:check.id==='recover'&&n===3?45.67:0};};`,context);
    const [good,recover,failed]=await Promise.all(['good','recover','failed'].map(id=>context.probeWithRetries({id,maxAttempts:4,taskAt:123})));
    assert.equal(good.attempts,1);assert.equal(good.latencyMs,12);
    assert.equal(recover.attempts,3);assert.equal(recover.latencyMs,45);
    assert.equal(failed.attempts,4);assert.equal(failed.ok,false);assert.equal(failed.latencyMs,0);assert.equal(failed.final,true);
    assert.equal(failed.taskAt,123);
    vm.runInContext('tcpLatency=async()=>({ok:true,latencyMs:0.99})',context);
    const subMs=await context.probeWithRetries({id:'local',maxAttempts:4});
    assert.equal(subMs.latencyMs,0);assert.equal(subMs.ok,true);assert.equal(subMs.attempts,1);
    vm.runInContext('tcpLatency=async()=>{throw new Error("missing result")}',context);
    assert.equal((await context.probeWithRetries({id:'throws',maxAttempts:4})).attempts,4);
  }finally{vm.runInContext('httpAgent.destroy();httpsAgent.destroy();metadataHttpsAgent.destroy()',context);}
});

test('traffic precision truncates and latency persistence keeps successful sub-ms probes distinct from failures', async t => {
  const source=await readFile(path.join(root,'public/app.js'),'utf8');
  const context=vm.createContext({Intl,Math,Number});
  vm.runInContext(source.slice(source.indexOf('function formatBytes('),source.indexOf('function pct(')),context);
  for (const [bytes,expected] of [[3.859*1024**3,'3.85 GB'],[3.999*1024**3,'3.99 GB'],[1023.999*1024,'1023.99 KB'],[0,'0.00 B'],[1024,'1.00 KB']]) {
    assert.equal(context.formatBytes(bytes),expected);
    assert.equal(context.formatBps(bytes),expected+'/s');
  }
  const hub=await createHub(t);
  const now=Date.now();
  hub.config.servers=[{id:'precision',name:'Precision',secret:'fixture'}];
  hub.config.connectivityChecks=[{id:'target',name:'Target',enabled:true,intervalSeconds:300}];
  hub.state.servers.precision={lastReportAt:now,connectivity:[]};
  for (const [i,latencyMs,ok,expected] of [[0,12.99,true,12],[1,0.99,true,0],[2,0,true,0],[3,99.99,false,0]]) {
    const merged=hub.mergeServerConnectivity('precision',[{id:'target',checkedAt:now+i,latencyMs,ok,final:true}]);
    hub.state.servers.precision.connectivity=merged;
    assert.equal(merged[0].latencyMs,expected);assert.equal(merged[0].ok,ok);
  }
  const rows=hub.connectivityDb.prepare('SELECT latency_ms AS latency,ok FROM connectivity_history ORDER BY checked_at').all();
  assert.deepEqual(rows.map(r=>[r.latency,r.ok]),[[12,1],[0,1],[0,1],[0,0]]);
  const old=hub.testHooks.aggregateConnectivityHistory([{t:now,ok:true,latencyMs:45.99},{t:now+1,ok:true,latencyMs:0.99}],0);
  assert.deepEqual(old.map(p=>[p.latencyMs,p.ok]),[[45,true],[0,true]]);
  hub.state.servers.precision.connectivity=[{id:'target',checkedAt:now,latencyMs:45.99,ok:true}];
  assert.equal((await hub.buildServerDetail('precision')).connectivity[0].result.latencyMs,45);
});

test('reconnect records an offline interval without generating intermediate probe rows', async (t) => {
  const hub=await createHub(t);
  const before=Date.now()-1800000;
  hub.config.servers.push({id:'gap-node',secret:'gap-secret'});
  hub.config.connectivityChecks=[{id:'target',name:'Target',enabled:true,intervalSeconds:300}];
  hub.state.servers['gap-node']={lastReportAt:before,country:'US',connectivity:[]};
  hub.state.servers['gap-node'].connectivity=hub.mergeServerConnectivity('gap-node',[{id:'target',checkedAt:before,latencyMs:30,ok:true,packetLossPercent:0}]);
  const current=Date.now();
  const r=await realFetch(hub.base+'/api/agent/report',{method:'POST',headers:{Authorization:'Bearer gap-secret'},body:JSON.stringify({id:'gap-node',country:'US',connectivity:[{id:'target',checkedAt:current,latencyMs:60,ok:true,packetLossPercent:0}]})});
  assert.equal(r.status,200);
  assert.equal(hub.connectivityDb.prepare('SELECT COUNT(*) AS n FROM connectivity_history').get().n,2);
  const detail=await hub.buildServerDetail('gap-node',{includeConnectivityHistory:true});
  assert.equal(detail.connectivityGaps.length,1);
  assert.equal(detail.connectivityGaps[0].start,before);
  assert.equal(detail.connectivity[0].history.length,2);
  assert.deepEqual(detail.connectivity[0].history.map(p=>p.latencyMs),[30,60]);
});

test('frontend rules: expiry, offline chart anchoring and local flags', async () => {
  const source = await readFile(path.join(root, 'public/app.js'), 'utf8');
  const select = (from, to) => source.slice(source.indexOf(`function ${from}(`), source.indexOf(`function ${to}(`));
  const context = vm.createContext({
    Date, Intl, Set, Map, Math, Number, String, Array, JSON,
    fmt: new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 1 }),
    clamp: value => Math.max(0, Math.min(100, value)),
    escapeHtml: value => String(value ?? ''),
    formatBytes: value => `${value} B`,
    supportedFlagCodes: new Set(['US', 'GB', 'SG']), flagAssets: { US: 'data:image/svg+xml;base64,dGVzdA==' },
    activeDetailData: null, networkQualityRangeDays: 1
  });
  vm.runInContext(select('trafficQuotaUsage', 'barMetric') + select('networkQualityReferenceTime', 'networkQualityAxisStepMs') + select('networkQualityAxisStepMs', 'normalizedNetworkQualityHistory') + select('countryCode', 'escapeHtml'), context);
  const server = { online: false, startedAt: '2020-01-01', expiresAt: '2021-01-01', cycleTraffic: { quotaBytes: 1000, usedTotal: 100, remainingBytes: 900, endAt: Date.now() + 86400_000 } };
  assert.equal(context.trafficQuotaUsage(server).resetLabel, '');
  const linked={...server,cycleTraffic:{quotaBytes:1000,usedIn:120,usedOut:80,usedTotal:999,remainingBytes:1}};
  assert.equal(context.trafficQuotaUsage(linked).used,200);
  assert.equal(context.trafficQuotaUsage(linked).remaining,800,'remaining and both cycle directions share one source');
  assert.equal(context.trafficQuotaUsage({...linked,cycleTraffic:{quotaBytes:1000,usedIn:900,usedOut:200}}).remaining,0);
  assert.equal(context.trafficQuotaUsage({...linked,cycleTraffic:{quotaBytes:2000,usedIn:120,usedOut:80}}).used,200,'quota edits never alter cycle usage');
  assert.ok(!context.trafficQuotaBar(context.trafficQuotaUsage(server)).includes('重置'));
  assert.ok(context.trafficQuotaUsage({ ...server, online: true }).resetLabel.includes('天后重置'));
  assert.ok(context.trafficQuotaUsage({ ...server, expiresAt: '2099-01-01' }).resetLabel.includes('天后重置'));
  assert.ok(context.trafficQuotaUsage({ ...server, startedAt: null }).resetLabel.includes('天后重置'));
  context.activeDetailData = { server: { online: false, lastReportAt: 1600000000000 } };
  assert.equal(context.networkQualityReferenceTime(), 1600000000000);
  const axis = context.networkQualityAxisTimes([]);
  assert.ok(axis.at(-1) <= 1600000000000);
  context.activeDetailData.server.online = true;
  assert.ok(context.networkQualityReferenceTime() > 1600000000000);
  assert.ok(context.flagIcon('US').includes('data:image/svg+xml;base64,'));
  assert.equal(context.countryCode('LOCAL'), '--');
  assert.equal(context.countryCode('NotACountry'), '--');
  assert.ok(context.flagIcon('').includes('<svg'));
});

test('agent HTTP failures release resources and metadata never gates reporting', async (t) => {
  let source = await readFile(path.join(root, 'agent/probe-node.cjs'), 'utf8');
  source = source.slice(0, source.lastIndexOf('\nmain().catch'));
  const fixture = http.createServer((req, res) => {
    if (req.url === '/abort') { res.writeHead(200, { 'Content-Length': 1000 }); res.write('partial'); setTimeout(() => res.destroy(), 10); }
    else if (req.url === '/hang') { /* deliberately never respond */ }
    else if (req.url === '/large') res.end('x'.repeat(1024 * 1024 + 1));
    else res.end('ok');
  });
  fixture.listen(0, '127.0.0.1'); await once(fixture, 'listening');
  const base = `http://127.0.0.1:${fixture.address().port}`;
  const context = vm.createContext({ require: createRequire(import.meta.url), Buffer, URL, setTimeout, clearTimeout, setInterval, clearInterval, console: { error() {}, info() {} }, process: { env: { AGENT_TOKEN: 'test', HUB_URL: base }, exit() { throw new Error('unexpected process exit'); } } });
  vm.runInContext(source, context);
  t.after(() => { vm.runInContext('httpAgent.destroy(); httpsAgent.destroy(); metadataHttpsAgent.destroy();', context); fixture.closeAllConnections(); fixture.close(); });
  for (let i = 0; i < 8; i++) {
    await assert.rejects(context.requestText(new URL(`${base}/abort`), { timeoutMs: 200 }));
    await assert.rejects(context.requestText(new URL(`${base}/hang`), { timeoutMs: 60 }));
  }
  await assert.rejects(context.requestText(new URL(`${base}/large`), { timeoutMs: 300 }));
  assert.equal(await context.requestText(new URL(`${base}/ok`), { timeoutMs: 300 }), 'ok');
  vm.runInContext(`
    buildPayload = async () => ({ id: 'test' });
    let attempts = 0;
    request = async () => { if (++attempts <= 10) throw new Error('offline'); return 'ok'; };
  `, context);
  for (let i = 0; i < 10; i++) assert.equal(await context.sendOnce(), false);
  assert.equal(await context.sendOnce(), true);
  assert.equal(vm.runInContext('reportsInFlight', context), 0);
  vm.runInContext(`
    ipMeta = { data: { ip: '198.51.100.1', country: 'US' }, fetchedAt: Date.now(), addressFetchedAt: 0, fetching: false, publicIpv4: '198.51.100.1', publicIpv6: '' };
    httpsGetText = async url => { if (url.includes('api.ipify.org')) return '198.51.100.2'; if (url.includes('api6.ipify.org')) return '2001:db8::2'; throw new Error('geo unavailable'); };
  `, context);
  await context.refreshIpMetaIfDue();
  assert.equal(context.ipFields().publicIpv4, '198.51.100.2');
  assert.equal(context.ipFields().publicIpv6, '2001:db8::2');
  assert.equal(context.ipFields().country, 'US');
  assert.equal(vm.runInContext('ipMeta.fetchedAt', context), 0, 'failed geo lookup remains due for retry');
  vm.runInContext(`
    let startupReports = 0;
    refreshIpMetaIfDue = () => new Promise(() => {});
    startConnectivityDaemon = () => {};
    sendOnce = async () => { startupReports++; return true; };
    setInterval = () => ({ unref() {} });
  `, context);
  await context.main();
  assert.equal(vm.runInContext('startupReports', context), 1, 'startup reports immediately even while metadata never resolves');
});

test('Linux shell retries failed targets independently and returns zero only after exhaustion', {skip:process.platform!=='linux'}, async t=>{
  const directory=await mkdtemp(path.join(root,'.test-runtime-shell-retry-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  let source=await readFile(path.join(root,'agent/probe.sh'),'utf8');
  source=source.slice(0,source.indexOf('if [[ "${1:-}" == "once" ]]'));
  source+=`\nfetch_connectivity_checks() {
    printf 'good\\tGood\\tgood:80\\t300\\t4\\t123\\nrecover\\tRecover\\trecover:80\\t300\\t4\\t123\\nfailed\\tFailed\\tfailed:80\\t300\\t4\\t123\\n' > "$CONNECTIVITY_FILE"
  }
  tcp_latency_ms() {
    local n=0
    [[ ! -f "$STATE_DIR/$1-count" ]] || read -r n < "$STATE_DIR/$1-count"
    n=$((n+1));printf '%s\\n' "$n" > "$STATE_DIR/$1-count"
    if [[ "$1" == good ]] || [[ "$1" == recover && "$n" == 3 ]]; then printf 42;return 0;fi
    return 1
  }
  run_connectivity_checks
  cat "$CONNECTIVITY_RESULT_FILE"
  `;
  const filename=path.join(directory,'probe-fixture.sh');await writeFile(filename,source);
  const {stdout}=await promisify(execFile)('bash',[filename],{env:{...process.env,AGENT_TOKEN:'fixture',STATE_DIR:directory},timeout:10000});
  const results=JSON.parse(stdout).connectivity;
  assert.equal(results.find(p=>p.id==='good').attempts,1);
  assert.equal(results.find(p=>p.id==='recover').attempts,3);
  assert.equal(results.find(p=>p.id==='failed').attempts,4);
  assert.equal(results.find(p=>p.id==='failed').latencyMs,0);
  assert.equal(results.find(p=>p.id==='failed').ok,false);
});

test('Linux panel installer starts fresh installs and reloads active upgrades', { skip: process.platform !== 'linux' }, async (t) => {
  const directory = await mkdtemp(path.join(root, '.test-runtime-installer-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const installDir = path.join(directory, 'panel');
  const units = path.join(directory, 'units');
  const bin = path.join(directory, 'bin');
  await mkdir(units);
  await mkdir(bin);
  const scripts = {
    git: 'if [ "$1" = clone ]; then for last; do :; done; mkdir -p "$last/.git"; fi',
    node: 'printf "22.5.0\\n"',
    sleep: ':',
    curl: 'case " $* " in *" -4 "*) ;; *) exit 1;; esac; case " $* " in *" --noproxy "*) ;; *) exit 1;; esac; case "$*" in *api.ipify.org*) printf "%s" "$INSTALL_TEST_PUBLIC_IP";; *) printf "%s" "$INSTALL_TEST_FALLBACK_IP";; esac',
    ip: 'printf "%s\\n" "$INSTALL_TEST_ROUTE"',
    hostname: 'printf "%s\\n" "$INSTALL_TEST_INTERFACES"',
    systemctl: 'printf "%s\\n" "$*" >> "$INSTALL_TEST_LOG"; if [ "$1" = restart ]; then cp "$INSTALL_TEST_REVISION" "$INSTALL_TEST_LOADED"; fi'
  };
  for (const [name, body] of Object.entries(scripts)) {
    const file = path.join(bin, name);
    await writeFile(file, '#!/bin/sh\n' + body + '\n');
    await chmod(file, 0o755);
  }
  let source = await readFile(path.join(root, 'scripts/install-panel.sh'), 'utf8');
  // Relocate all installation writes; root escalation and systemd are mocked.
  source = source.replace('if [[ $EUID -ne 0 ]]; then', 'if false; then')
    .replaceAll('/opt/server-probe-monitor', installDir)
    .replaceAll('/etc/systemd/system', units);
  const filename = path.join(directory, 'install.sh');
  await writeFile(filename, source);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, PROBE_PANEL_DIR: installDir,
    PROBE_PANEL_SERVICE: 'server-probe-monitor', PROBE_PORT: '8080', INSTALL_TEST_PUBLIC_IP: '203.0.113.42',
    INSTALL_TEST_FALLBACK_IP: '', INSTALL_TEST_ROUTE: '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5',
    INSTALL_TEST_INTERFACES: '2001:db8::5 10.0.0.5 172.17.0.1', INSTALL_TEST_LOG: path.join(directory, 'commands'),
    INSTALL_TEST_REVISION: path.join(directory, 'revision'), INSTALL_TEST_LOADED: path.join(directory, 'loaded') };
  for (const revision of ['first', 'upgrade']) {
    await writeFile(env.INSTALL_TEST_REVISION, revision);
    const { stdout } = await promisify(execFile)('bash', [filename], { env, timeout: 10000 });
    assert.ok(stdout.includes('登录地址: http://203.0.113.42:8080'), 'NAT/IPv6-first hosts must show public IPv4');
    assert.equal(await readFile(env.INSTALL_TEST_LOADED, 'utf8'), revision, 'running service must load the new revision');
    const config = path.join(installDir, 'data/config.json');
    if (revision === 'first') await writeFile(config, 'preserve-existing-data');
    else assert.equal(await readFile(config, 'utf8'), 'preserve-existing-data');
  }
  for (const scenario of [
    { public: '<html>unavailable</html>', fallback: '203.0.113.43\n', expected: 'http://203.0.113.43:8080' },
    { public: '10.0.0.99', fallback: '203.0.113.44', expected: 'http://203.0.113.44:8080' },
    { public: '999.1.2.3', fallback: '2001:db8::1', expected: 'http://10.0.0.5:8080', private: true },
    { public: '', fallback: '', interfaces: '2001:db8::5 203.0.113.45', expected: 'http://203.0.113.45:8080' },
    { public: '', fallback: '', route: '', interfaces: '::1 127.0.0.1 169.254.1.1', expected: null },
    { public: '203.0.113.46', fallback: '', port: '9090', expected: 'http://203.0.113.46:9090' }
  ]) {
    const {stdout} = await promisify(execFile)('bash', [filename], { timeout: 10000, env: {...env,
      INSTALL_TEST_PUBLIC_IP: scenario.public, INSTALL_TEST_FALLBACK_IP: scenario.fallback,
      INSTALL_TEST_ROUTE: scenario.route ?? env.INSTALL_TEST_ROUTE,
      INSTALL_TEST_INTERFACES: scenario.interfaces ?? env.INSTALL_TEST_INTERFACES, PROBE_PORT: scenario.port || '8080'} });
    if (scenario.expected) assert.ok(stdout.includes(`登录地址: ${scenario.expected}`), JSON.stringify(scenario));
    else { assert.ok(stdout.includes('未能自动识别 IPv4')); assert.ok(!stdout.includes('登录地址:')); }
    if (scenario.private) assert.ok(stdout.includes('以上为本机内网地址'));
  }
});

test('Linux shell fallback sends valid metrics without waiting for metadata', { skip: process.platform !== 'linux' }, async (t) => {
  const directory = await mkdtemp(path.join(root, '.test-runtime-shell-'));
  let received;
  const receiver = http.createServer(async (req, res) => {
    if (req.method === 'POST') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      received = JSON.parse(Buffer.concat(chunks).toString());
      res.end('{"ok":true}');
    } else res.end('\n');
  });
  receiver.listen(0, '127.0.0.1'); await once(receiver, 'listening');
  t.after(async () => { receiver.closeAllConnections(); receiver.close(); await rm(directory, { recursive: true, force: true }); });
  await promisify(execFile)('bash', [path.join(root, 'agent/probe.sh'), 'once'], { timeout: 10000, env: { ...process.env, HUB_URL: `http://127.0.0.1:${receiver.address().port}`, AGENT_TOKEN: 'test-secret', SERVER_ID: 'shell-test', STATE_DIR: directory } });
  assert.equal(received.id, 'shell-test');
  assert.equal(received.probeVersion, '20261112-shell-traffic-boot-v5');
  assert.match(received.bootId, /^[a-f0-9-]{36}$/);
  assert.equal(typeof received.cpu.percent, 'number');
  assert.equal(typeof received.memory.total, 'number');
  assert.equal(typeof received.net.totalIn, 'number');
});

test('background scopes remain independent and compact polling keeps real preview points', async t => {
  const hub=await createHub(t);
  const backgrounds=hub.testHooks.normalizeBackgrounds({frontend:['legacy'],frontendDesktop:['desktop'],frontendMobile:[],adminDesktop:['admin'],adminMobile:[]});
  assert.deepEqual(backgrounds.frontendMobile,[]);
  assert.deepEqual(backgrounds.adminMobile,[]);
  assert.deepEqual(backgrounds.frontendDesktop,['desktop']);
  assert.deepEqual(backgrounds.adminDesktop,['admin']);
  assert.equal(hub.testHooks.normalizeHubUrl('monitor.example.com:8080'),'http://monitor.example.com:8080');
  const now=Date.now();
  hub.config.servers.push({id:'compact',name:'Compact',secret:'fixture'});
  hub.state.servers.compact={lastReportAt:now,cpu:{percent:31},memory:{percent:44}};
  hub.state.history.compact=Array.from({length:60},(_,i)=>({t:now-(59-i)*2000,cpu:i,mem:40,swap:0,inBps:20,outBps:30,tcp:5,udp:2}));
  const full=await realFetch(hub.base+'/api/overview').then(r=>r.json());
  const response=await realFetch(hub.base+'/api/overview?compact=1');
  assert.equal(response.headers.get('cache-control'),'no-store');
  assert.ok(response.headers.get('x-panel-instance'));
  const compact=await response.json();
  assert.deepEqual(full.servers,compact.servers);
  assert.equal(compact.detailSnapshots.compact.history,undefined);
  assert.equal(compact.detailSnapshots.compact.point.t,now);
  assert.ok(JSON.stringify(compact).length<JSON.stringify(full).length*0.7);
});

async function unusedPort() {
  const listener=http.createServer();listener.listen(0,'0.0.0.0');await once(listener,'listening');
  const port=listener.address().port;await new Promise(resolve=>listener.close(resolve));return port;
}

test('port saves revoke sessions, reject old agent ports, and persist over stale systemd environment', async t => {
  const agentPort=await unusedPort(),newAgentPort=await unusedPort(),newPanelPort=await unusedPort();
  const hub=await createHub(t,{config:{port:8080,publicHubUrl:`http://127.0.0.1:${agentPort}`,servers:[{id:'ports',name:'Ports',secret:'ports-fixture'}]}});
  let restarts=0;hub.testHooks.setRestart(()=>{restarts++;});
  const agentBase=`http://127.0.0.1:${agentPort}`;
  const report=(base,token='ports-fixture')=>realFetch(base+'/api/agent/report',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({id:'ports',cpu:{percent:55}})});
  assert.equal((await report(hub.base)).status,410);
  assert.equal((await report(agentBase)).status,200);
  assert.equal((await realFetch(agentBase+'/api/overview')).status,404);
  // Whitelist protects viewers, while the active Agent port still requires its token.
  hub.config.ipWhitelistEnabled=true;hub.config.ipWhitelist=['198.51.100.99'];
  assert.equal((await realFetch(hub.base+'/api/overview')).status,404);
  assert.equal((await report(agentBase,'wrong')).status,401);
  hub.testHooks.resetReportRate('ports');assert.equal((await report(agentBase)).status,200);
  hub.config.ipWhitelist=['127.0.0.1'];
  const login=await realFetch(hub.base+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'admin'})});
  const cookie=login.headers.get('set-cookie').split(';')[0],{csrfToken}=await login.json();
  const headers={'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':csrfToken};
  const save=basics=>realFetch(hub.base+'/api/admin/settings',{method:'POST',headers,body:JSON.stringify({basics})});
  const invalid=await save({publicHubUrl:'https://monitor.example.com:8080'});
  assert.equal(invalid.status,400);assert.equal((await invalid.json()).error,'https_proxy_required');
  const occupied=http.createServer();occupied.listen(0,'0.0.0.0');await once(occupied,'listening');
  try {assert.equal((await save({panelPort:occupied.address().port})).status,400);} finally {await new Promise(r=>occupied.close(r));}
  const started=performance.now();
  const result=await save({panelPort:newPanelPort,publicHubUrl:`127.0.0.1:${newAgentPort}`});
  assert.equal(result.status,200);
  const data=await result.json();
  assert.ok(performance.now()-started<1500,'save acknowledges without waiting for overview/geolocation');
  assert.equal(data.restartRequired,true);assert.equal(data.restart.newPanelPort,newPanelPort);
  assert.equal((await realFetch(hub.base+'/api/admin/session',{headers:{Cookie:cookie}}).then(r=>r.json())).ok,false);
  assert.equal((await report(agentBase)).status,410);
  await new Promise(r=>setTimeout(r,220));assert.equal(restarts,1);
  const persisted=JSON.parse(await readFile(path.join(hub.directory,'data/config.json'),'utf8'));
  const restarted=await createHub(t,{config:persisted,runtimePort:new URL(hub.base).port});
  assert.equal(Number(new URL(restarted.base).port),newPanelPort,'saved panel port wins over original PROBE_PORT');
  const newBase=`http://127.0.0.1:${newAgentPort}`;
  assert.equal((await report(newBase)).status,200);
  assert.equal((await report(restarted.base)).status,410);
  assert.equal((await realFetch(restarted.base+'/api/admin/servers',{headers})).status,401);
  // Turning the whitelist on after changing ports cannot block authenticated Agents.
  restarted.config.ipWhitelistEnabled=false;
  restarted.testHooks.resetReportRate('ports');assert.equal((await report(newBase)).status,200);
  restarted.config.ipWhitelistEnabled=true;restarted.config.ipWhitelist=['198.51.100.88'];
  restarted.testHooks.resetReportRate('ports');assert.equal((await report(newBase)).status,200);
  assert.equal((await realFetch(restarted.base+'/api/overview')).status,404);
});

test('manual restart uses the same session invalidation and announcement',async t=>{
  const hub=await createHub(t);let restarts=0;hub.testHooks.setRestart(()=>{restarts++;});
  const login=await realFetch(hub.base+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'admin'})});
  const cookie=login.headers.get('set-cookie').split(';')[0],{csrfToken}=await login.json();
  const result=await realFetch(hub.base+'/api/admin/restart',{method:'POST',headers:{Cookie:cookie,'X-CSRF-Token':csrfToken},body:'{}'});
  assert.equal(result.status,200);assert.ok((await result.json()).restart.panelStartedAt);
  assert.equal((await realFetch(hub.base+'/api/admin/session',{headers:{Cookie:cookie}}).then(r=>r.json())).ok,false);
  assert.ok((await realFetch(hub.base+'/healthz').then(r=>r.json())).restart);
  await new Promise(r=>setTimeout(r,220));assert.equal(restarts,1);
});

test('detail history sends only new real samples and recovers lost cursors; public JSON supports gzip', async t => {
  const hub = await createHub(t);
  const now = Date.now();
  hub.config.servers.push({id:'bandwidth', name:'Bandwidth', secret:'fixture'});
  hub.state.servers.bandwidth = {lastReportAt:now, cpu:{percent:37}, net:{inBps:12345,outBps:54321}};
  const history = Array.from({length:500},(_,i)=>({t:now-(499-i)*2000,cpu:i%100,mem:40,swap:0,inBps:12345+i,outBps:54321-i,tcp:5,udp:2}));
  hub.state.history.bandwidth = history;
  const endpoint = hub.base+'/api/servers/bandwidth?connectivityHistory=0';
  const read = suffix => realFetch(endpoint+suffix).then(r=>r.json());
  const full = await read('');
  assert.equal(full.historyMode,'full');
  assert.deepEqual(full.history,history);
  assert.equal(full.historyCursor,now);
  const newer = await read('&historySince='+history[497].t);
  assert.equal(newer.historyMode,'incremental');
  assert.deepEqual(newer.history,history.slice(-2));
  assert.deepEqual(newer.server.net,full.server.net,'actual network measurements must not be subtracted or hidden');
  assert.ok(JSON.stringify(newer).length < JSON.stringify(full).length*0.15);
  const unchanged = await read('&historySince='+now);
  assert.equal(unchanged.history.length,0);
  assert.equal(unchanged.historyCursor,now);
  for (const cursor of [now+1,history[0].t-2000,-1,'NaN']) {
    const reset=await read('&historySince='+cursor);
    assert.equal(reset.historyMode,'full');assert.equal(reset.history.length,500);
  }
  // Missed updates are delivered together, with no synthetic intermediate samples.
  hub.state.history.bandwidth.push({...history.at(-1),t:now+60000,cpu:83});
  hub.state.servers.bandwidth.lastReportAt=now+60000;
  const resumed = await read('&historySince='+now);
  assert.deepEqual(resumed.history.map(p=>p.t),[now+60000]);
  assert.equal(resumed.historyStartAt,history[1].t);
  const raw = encoding => new Promise((resolve,reject)=>{
    http.get(endpoint,{headers:{'Accept-Encoding':encoding}},response=>{
      const chunks=[];response.on('data',c=>chunks.push(c));response.on('end',()=>resolve({headers:response.headers,body:Buffer.concat(chunks)}));response.on('error',reject);
    }).on('error',reject);
  });
  const compressed=await raw('br, gzip;q=0.8');
  assert.equal(compressed.headers['content-encoding'],'gzip');
  assert.match(compressed.headers.vary,/Origin/);assert.match(compressed.headers.vary,/Accept-Encoding/);
  assert.equal(compressed.headers['cache-control'],'no-store');
  const decoded=JSON.parse(gunzipSync(compressed.body));
  assert.deepEqual(decoded.history,hub.state.history.bandwidth.slice(-500));
  assert.ok(compressed.body.length<Buffer.byteLength(JSON.stringify(decoded))*0.3);
  assert.equal(Number(compressed.headers['content-length']),compressed.body.length);
  for(const encoding of ['gzip;q=0','identity','deflate']) {
    const plain=await raw(encoding);
    assert.equal(plain.headers['content-encoding'],undefined);assert.equal(JSON.parse(plain.body).history.length,500);
  }
  const overview=await realFetch(hub.base+'/api/overview?compact=1',{headers:{'Accept-Encoding':'gzip'}});
  assert.equal(overview.headers.get('content-encoding'),'gzip');
  assert.equal((await overview.json()).servers[0].net.outBps,54321);
});

test('panel identity survives address changes and restarts; legacy fingerprints survive server deletion', async t => {
  const hub=await createHub(t,{config:{servers:[{id:'identity-node',secret:'identity-token'}]}});
  const id=hub.config.panelId;
  assert.match(id,/^pnl-[a-f0-9]{32}$/);
  const key=hub.testHooks.agentIdentityKey('identity-node','identity-token');
  assert.ok(hub.config.agentIdentityKeys.includes(key));
  await hub.testHooks.transactConfig(draft=>{draft.publicHubUrl='http://new-host.example:9080';draft.servers=[];});
  const persisted=JSON.parse(await readFile(path.join(hub.directory,'data/config.json'),'utf8'));
  assert.equal(persisted.panelId,id);assert.ok(persisted.agentIdentityKeys.includes(key));
  const restored=await createHub(t,{config:persisted});
  assert.equal(restored.config.panelId,id);
  const another=await createHub(t);assert.notEqual(another.config.panelId,id);
  const command=hub.testHooks.buildUninstallCommand({hubUrl:'http://new-host.example:9080'});
  assert.ok(command.includes(`PROBE_PANEL_ID='${id}'`));
  assert.ok(!command.includes('PROBE_HUB_URL='),'uninstall identity is independent of the endpoint used to download it');
  const script=hub.testHooks.buildAgentUninstaller();
  assert.ok(script.includes(key));assert.ok(!script.includes('identity-token'));
  const install=hub.testHooks.buildInstallCommand({hubUrl:'http://new-host.example:9080',token:'fixture',serverId:'fixture',serverName:'fixture',serverLocation:'',interval:2,reuseExisting:true});
  assert.ok(install.includes('PROBE_REUSE_EXISTING=1'));assert.ok(install.includes(id));
});

test('Linux Agent lifecycle migrates URL instances, updates one panel, rolls back failures and never removes other panels', {skip:process.platform!=='linux'}, async t => {
  const hub=await createHub(t,{config:{servers:[{id:'owned',secret:'owned-token'}],pendingInstalls:[{id:'pending-new',secret:'pending-token',expiresAt:Date.now()+600000}]}});
  const fixture=await mkdtemp(path.join(root,'.test-runtime-agent-'));
  t.after(()=>rm(fixture,{recursive:true,force:true}));
  const opt=path.join(fixture,'opt'),etc=path.join(fixture,'etc'),run=path.join(fixture,'run'),bin=path.join(fixture,'bin'),mock=path.join(fixture,'mock');
  for(const directory of [opt,etc,run,bin,mock,path.join(etc,'systemd/system')])await mkdir(directory,{recursive:true});
  const quoted=value=>`'${value.replace(/'/g,"'\\''")}'`;
  const stageScript=async(action)=>{
    const source=action==='install'?hub.testHooks.buildAgentInstaller():hub.testHooks.buildAgentUninstaller();
    const file=path.join(fixture,action+'.sh');
    await writeFile(file,source.replace('OPT_ROOT=/opt','OPT_ROOT='+quoted(opt)).replace('ETC_ROOT=/etc','ETC_ROOT='+quoted(etc)).replace('RUN_ROOT=/run','RUN_ROOT='+quoted(run)));
    await promisify(execFile)('bash',['-n',file]);return file;
  };
  const install=await stageScript('install'),uninstall=await stageScript('uninstall');
  const scripts={
    systemctl:`printf '%s\\n' "$*" >> "$MOCK_STATE/commands"
unit="\${@: -1}"
case "$1" in
 is-active) test -f "$MOCK_STATE/$unit.active" ;;
 is-enabled) test -f "$MOCK_STATE/$unit.enabled" ;;
 stop) rm -f "$MOCK_STATE/$unit.active" ;;
 disable) rm -f "$MOCK_STATE/$unit.enabled" ;;
 enable) touch "$MOCK_STATE/$unit.enabled" ;;
 restart) if [ "\${MOCK_FAIL_RESTART:-}" = "$unit" ]; then exit 1; fi; touch "$MOCK_STATE/$unit.active" ;;
esac`,
    pkill:'exit 1',
    curl:`[ "\${MOCK_FAIL_DOWNLOAD:-0}" != 1 ] || exit 22
target=''; url=''
while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; target=$1; elif [[ "$1" == http* ]]; then url=$1; fi; shift; done
if [[ "$url" == */probe-node.cjs ]]; then printf 'setInterval(()=>{},1000);\\n' > "$target"; else printf '#!/usr/bin/env bash\\nexit 0\\n' > "$target"; fi`
  };
  for(const [name,body]of Object.entries(scripts)){const file=path.join(bin,name);await writeFile(file,'#!/usr/bin/env bash\nset -eu\n'+body+'\n');await chmod(file,0o755);}
  const canonical='server-probe-agent-'+hub.config.panelId+'.service';
  const foreignId='pnl-'+'f'.repeat(32),foreign='server-probe-agent-'+foreignId+'.service';
  const ipUnit='server-probe-agent-111111111111.service',domainUnit='server-probe-agent-222222222222.service',unrelated='server-probe-agent-333333333333.service';
  const envPath=unit=>path.join(etc,unit==='server-probe-agent.service'?'server-probe-agent.env':unit+'.env');
  const seed=async(unit,{token='owned-token',id='owned',panel='',url='http://198.51.100.1:8080'}={})=>{
    const directory=path.join(opt,unit.replace(/\.service$/,''));await mkdir(directory,{recursive:true});
    await writeFile(path.join(directory,'probe.sh'),'old-code');
    await writeFile(envPath(unit),`HUB_URL="${url}"\nAGENT_TOKEN="${token}"\nSERVER_ID="${id}"\nSERVER_NAME="$(touch ${fixture}/must-not-execute)"\nPANEL_ID="${panel}"\n`);
    await writeFile(path.join(etc,'systemd/system',unit),'old-unit');
    await writeFile(path.join(mock,unit+'.active'),'');await writeFile(path.join(mock,unit+'.enabled'),'');
  };
  await seed(ipUnit);await seed(domainUnit,{url:'http://panel.example:8080'});
  await seed('server-probe-agent.service');
  await seed(unrelated,{token:'another-token'});
  // Even an identical legacy credential fingerprint cannot override another explicit panel ID.
  await seed(foreign,{panel:foreignId});
  const foreignEnv=await readFile(envPath(foreign),'utf8');
  const env={...process.env,PATH:bin+':'+process.env.PATH,MOCK_STATE:mock,PROBE_HUB_URL:'http://panel.example:9080',PROBE_PANEL_ID:hub.config.panelId,PROBE_SERVER_ID:'pending-new',PROBE_AGENT_TOKEN:'pending-token',PROBE_REUSE_EXISTING:'1'};
  const execute=(script,extra={})=>promisify(execFile)('bash',[script],{env:{...env,...extra},timeout:15000});
  const exists=file=>access(file).then(()=>true,()=>false);
  await assert.rejects(execute(install,{MOCK_FAIL_DOWNLOAD:'1'}));
  assert.ok(await exists(envPath(ipUnit)));assert.ok(await exists(path.join(mock,ipUnit+'.active')));
  await assert.rejects(execute(install,{MOCK_FAIL_RESTART:canonical}));
  assert.ok(await exists(envPath(ipUnit)));assert.ok(await exists(path.join(mock,ipUnit+'.active')));
  assert.equal(await exists(envPath(canonical)),false);
  await execute(install);
  let content=await readFile(envPath(canonical),'utf8');
  assert.ok(content.includes(`PANEL_ID="${hub.config.panelId}"`));
  assert.ok(content.includes('SERVER_ID="owned"'));assert.ok(content.includes('AGENT_TOKEN="owned-token"'));
  assert.ok(content.includes('HUB_URL="http://panel.example:9080"'));
  for(const old of [ipUnit,domainUnit,'server-probe-agent.service'])assert.equal(await exists(envPath(old)),false);
  assert.equal(await exists(path.join(fixture,'must-not-execute')),false,'existing files must not be sourced or evaluated');
  assert.equal(await readFile(envPath(foreign),'utf8'),foreignEnv);
  assert.ok(await exists(envPath(unrelated)));
  await mkdir(path.join(run,canonical.replace(/\.service$/,'')),{recursive:true});
  await writeFile(path.join(run,canonical.replace(/\.service$/,''),'stale-rules'),'old');
  await execute(install,{PROBE_HUB_URL:'http://198.51.100.99:10080'});
  content=await readFile(envPath(canonical),'utf8');
  assert.ok(content.includes('HUB_URL="http://198.51.100.99:10080"'));
  assert.equal(await exists(path.join(run,canonical.replace(/\.service$/,''),'stale-rules')),false);
  assert.equal((await readdir(opt)).filter(name=>name==='server-probe-agent-'+hub.config.panelId).length,1);
  await assert.rejects(execute(uninstall,{PROBE_PANEL_ID:foreignId}));
  assert.ok(await exists(envPath(canonical)));
  // A saved uninstall script remains usable after an address change and without a hub URL.
  await execute(uninstall,{PROBE_HUB_URL:'',HUB_URL:''});
  assert.equal(await exists(envPath(canonical)),false);
  assert.ok(await exists(path.join(mock,foreign+'.active')));assert.ok(await exists(path.join(mock,unrelated+'.active')));
  assert.match((await execute(uninstall)).stdout,/No agent belonging/);
  // Directly uninstall legacy instances too; migration is not a prerequisite.
  await seed(ipUnit);await seed(domainUnit);
  await execute(uninstall);
  assert.equal(await exists(envPath(ipUnit)),false);assert.equal(await exists(envPath(domainUnit)),false);
  assert.equal(await readFile(envPath(foreign),'utf8'),foreignEnv);
});

test('cycle traffic resists missing/reset counters, survives restarts and uses anchored billing dates', async t => {
  const hub=await createHub(t);
  const {state,config}=hub;
  const base=new Date(2026,10,12,12).getTime();
  const meta={id:'cycle',name:'Cycle',trafficCycleStartDate:'2026-11-01',trafficCycleUnit:'month'};
  config.servers=[meta];
  let previous={}, tick=0;
  const send=(net,extra={})=>{
    const now=base+tick++*2000;
    const report=hub.normalizeAgentReport({id:meta.id,net,uptimeSeconds:100000+tick*2,...extra});
    hub.updateTrafficCycleState(meta,previous,report,now);
    previous={...hub.mergeAgentReport(previous,report),lastReportAt:now};
    state.servers[meta.id]=previous;
    return state.trafficCycles[meta.id];
  };
  assert.equal(send({totalIn:10000,totalOut:20000}).usedIn,0,'first report establishes baseline');
  assert.equal(send({totalIn:11000,totalOut:22000}).usedIn,1000);
  assert.equal(send({totalIn:0,totalOut:0}).usedIn,1000,'same boot zero is not a reboot');
  assert.equal(send({totalIn:12000,totalOut:24000}).usedIn,2000,'recovery adds only the real delta');
  assert.equal(send({}).lastTotalIn,12000,'missing counters retain baseline');
  assert.equal(previous.net.totalIn,12000,'display retains last valid counters');
  assert.equal(send({totalIn:null,totalOut:'invalid'}).usedIn,2000);
  assert.equal(send({totalIn:13000,totalOut:26000}).usedIn,3000);
  assert.equal(send({totalIn:7000,totalOut:8000}).usedIn,3000,'old/lower counters do not inflate usage');
  assert.equal(send({totalIn:14000,totalOut:28000}).usedIn,4000);
  assert.equal(send({totalIn:14000,totalOut:28000}).usedIn,4000,'duplicate samples add nothing');
  const reboot=send({totalIn:100,totalOut:200},{uptimeSeconds:5,bootId:'new-boot'});
  assert.equal(reboot.usedIn,4100);assert.equal(reboot.usedOut,8200);
  assert.equal(send({totalIn:200,totalOut:400},{uptimeSeconds:7,bootId:'new-boot'}).usedIn,4200);
  state.trafficCycles=JSON.parse(JSON.stringify(state.trafficCycles));
  assert.equal(send({totalIn:300,totalOut:600},{uptimeSeconds:9,bootId:'new-boot'}).usedIn,4300,'persistent baseline survives panel restart');
  assert.equal(send({totalIn:500,totalOut:700},{uptimeSeconds:10,bootId:'newer-boot'}).usedIn,4800,'boot ID catches reboot even when counter rises');
  const before=state.trafficCycles[meta.id].usedIn;
  meta.trafficCycleStartDate='2026-10-20';
  assert.equal(send({totalIn:600,totalOut:800},{uptimeSeconds:12,bootId:'newer-boot'}).usedIn,before+100,'earlier anchor preserves durable usage');
  const cases=[['2026-01-31','month',new Date(2026,1,28,12),'2026-02-28','2026-03-31'],['2026-01-31','month',new Date(2026,3,30,12),'2026-04-30','2026-05-31'],['2024-02-29','year',new Date(2028,1,29,12),'2028-02-29','2029-02-28']];
  const local=d=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  for(const [date,unit,at,start,end] of cases){const cycle=hub.currentTrafficCycle({trafficCycleStartDate:date,trafficCycleUnit:unit},at.getTime());assert.equal(local(new Date(cycle.startAt)),start);assert.equal(local(new Date(cycle.endAt)),end);}
  const day={id:'boundary',trafficCycleStartDate:'2026-11-01',trafficCycleUnit:'day'};
  const midnight=new Date(2026,10,13).getTime();
  const r1={net:{totalIn:1000,totalOut:2000},uptimeSeconds:10000,lastReportAt:midnight-2000};
  hub.updateTrafficCycleState(day,{},r1,midnight-2000);
  const r2={net:{totalIn:2000,totalOut:4000},uptimeSeconds:20000,lastReportAt:midnight+10000000};
  hub.updateTrafficCycleState(day,r1,r2,r2.lastReportAt);
  assert.equal(state.trafficCycles.boundary.usedIn,0,'long offline delta across boundary is not assigned to new cycle');
  hub.updateTrafficCycleState(day,r2,{net:{totalIn:2100,totalOut:4200},uptimeSeconds:20002},r2.lastReportAt+2000);
  assert.equal(state.trafficCycles.boundary.usedIn,100);
  const nextMidnight=midnight+86400000;
  hub.updateTrafficCycleState(day,r2,{net:{},uptimeSeconds:96400},nextMidnight);
  hub.updateTrafficCycleState(day,{}, {net:{totalIn:9000,totalOut:18000},uptimeSeconds:96402},nextMidnight+2000);
  assert.equal(state.trafficCycles.boundary.usedIn,0,'missing first sample cannot carry old cycle counters across the boundary');
  hub.updateTrafficCycleState(day,{}, {net:{totalIn:9100,totalOut:18200},uptimeSeconds:96404},nextMidnight+4000);
  assert.equal(state.trafficCycles.boundary.usedIn,100);
  const old=hub.normalizeAgentReport({id:'cycle',net:{totalIn:-2,totalOut:Infinity}});
  assert.equal(Object.hasOwn(old.net,'totalIn'),false);assert.equal(Object.hasOwn(old.net,'totalOut'),false);
  meta.remainingTrafficBytes=100000;
  const measured=hub.calculateCycleTraffic(meta,previous);
  assert.equal(measured.remainingBytes,100000-measured.usedIn-measured.usedOut);
  meta.remainingTrafficBytes=200000;
  const changed=hub.calculateCycleTraffic(meta,previous);
  assert.equal(changed.usedTotal,measured.usedTotal);
  assert.equal(changed.remainingBytes,measured.remainingBytes+100000);
});

test('editing unrelated server settings preserves exact quota bytes and explicit clear',async()=>{
  const source=await readFile(path.join(root,'public/app.js'),'utf8');
  const c=vm.createContext({Number,Math});
  vm.runInContext(source.slice(source.indexOf('function remainingTrafficInput('),source.indexOf('async function copyInstallCommand(')),c);
  for(const bytes of [0,563714457600,1234567890123]) {
    const formatted=c.remainingTrafficInput(bytes);
    const input={value:String(formatted.value),dataset:{originalBytes:String(bytes),originalValue:String(formatted.value),originalUnit:formatted.unit}};
    assert.equal(c.trafficQuotaInputBytes(input,formatted.unit),bytes);
    input.value='';assert.equal(c.trafficQuotaInputBytes(input,formatted.unit),null);
  }
});

test('overlapping billing changes retain one total and reset only at the new end', async t => {
  const hub=await createHub(t), {state,testHooks}=hub;
  const date=(m,d,h=0)=>new Date(2026,m-1,d,h).getTime();
  const meta={id:'overlap',trafficCycleStartDate:'2026-01-01',trafficCycleUnit:'month'};
  let previous={}, total=10000;
  const bootAt=date(1,1);
  const send=(at,delta=100)=>{
    total+=delta;
    const report={net:{totalIn:total,totalOut:total*2},uptimeSeconds:(at-bootAt)/1000,bootId:'fixed',lastReportAt:at,firstReportAt:date(1,2)};
    hub.updateTrafficCycleState(meta,previous,report,at);previous=report;state.servers[meta.id]=report;
    return state.trafficCycles[meta.id];
  };
  send(date(1,2));assert.equal(send(date(1,20)).usedIn,100);
  meta.trafficCycleStartDate='2026-01-15';
  testHooks.reconcileTrafficCycle(meta,previous,date(1,20));
  assert.equal(state.trafficCycles.overlap.usedIn,100);
  assert.equal(state.trafficCycles.overlap.endAt,date(2,15));
  assert.equal(send(date(2,1)).usedIn,200,'old reset date must no longer reset');
  assert.equal(send(date(2,14,23)).usedIn,300);
  assert.equal(send(date(2,15)).usedIn,0,'adjacent periods do not overlap');
  assert.equal(send(date(2,15,1)).usedIn,100);
  meta.trafficCycleStartDate='2026-02-20';
  testHooks.reconcileTrafficCycle(meta,previous,date(2,15,1));
  assert.equal(send(date(2,16)).usedIn,200,'future overlapping start continues existing accounting');
  assert.equal(send(date(3,19)).usedIn,300);
  assert.equal(send(date(3,20)).usedIn,0,'resets at new March 20 end');
  send(date(3,20,1));
  meta.trafficCycleStartDate='2026-05-01';
  testHooks.reconcileTrafficCycle(meta,previous,date(3,20,1));
  assert.equal(state.trafficCycles.overlap.usedIn,0,'disjoint change clears immediately');
  assert.equal(send(date(4,25)).usedIn,0);
  assert.equal(send(date(5,1)).usedIn,0,'pre-start interval is not charged');
  assert.equal(send(date(5,1,1)).usedIn,100);
  meta.trafficCycleStartDate='2026-05-15';
  testHooks.reconcileTrafficCycle(meta,previous,date(5,1,1));
  meta.trafficCycleStartDate='2026-06-01';
  testHooks.reconcileTrafficCycle(meta,previous,date(5,1,1));
  assert.equal(state.trafficCycles.overlap.usedIn,100,'repeated changes compare against last saved range even without reports');
  assert.equal(state.trafficCycles.overlap.endAt,date(7,1));
  assert.equal(send(date(6,30)).usedIn,200);
  assert.equal(send(date(7,1)).usedIn,0);
  assert.equal(testHooks.trafficCyclesOverlap({startAt:10,endAt:20},{startAt:20,endAt:30}),false);
  assert.equal(testHooks.trafficCyclesOverlap({startAt:10,endAt:20},{startAt:15,endAt:25}),true);
});

test('late old boots and missing reboot samples never add a full baseline twice',async t=>{
  const hub=await createHub(t), {state}=hub, meta={id:'ordered'};
  const base=Date.now();let previous={};
  const send=(offset,bootId,uptimeSeconds,totalIn,totalOut)=>{
    const report={bootId,uptimeSeconds,net:{totalIn,totalOut},lastReportAt:base+offset};
    hub.updateTrafficCycleState(meta,previous,report,base+offset);previous=report;
    return structuredClone(state.trafficCycles.ordered);
  };
  send(0,'a',10000,100000,200000);
  assert.equal(send(2000,'a',10002,100100,200200).usedIn,100);
  const reset=send(4000,'b',1,undefined,undefined);
  assert.equal(reset.usedIn,100);
  assert.equal(send(6000,'b',3,50,100).usedIn,150,'first valid new boot total is retained');
  const before=structuredClone(state.trafficCycles.ordered);
  send(8000,'a',10008,100200,200400);
  assert.deepEqual(state.trafficCycles.ordered,before,'retired boot cannot restore old high counters');
  assert.equal(send(10000,'b',7,60,120).usedIn,160);
  send(12000,'b',6,55,110);
  assert.equal(state.trafficCycles.ordered.usedIn,160,'out of order same-boot sample ignored');
  const saved=JSON.parse(JSON.stringify(state.trafficCycles));state.trafficCycles=saved;
  send(14000,'a',10014,100300,200600);
  assert.equal(state.trafficCycles.ordered.usedIn,160,'retired boot protection survives persistence');
  assert.equal(send(16000,'b',13,70,140).usedIn,170);
  // Legacy agent delayed delivery must not be mistaken for a reboot.
  previous={};delete state.trafficCycles.ordered;
  send(0,'',10000,100000,200000);
  assert.equal(send(120000,'',10002,100100,200200).usedIn,100);
});

test('admin cycle edits persist offline totals immediately and stale HTTP reports cannot overwrite them',async t=>{
  const hub=await createHub(t), now=Date.now();
  const local=d=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const old=new Date(now);old.setDate(old.getDate()-10);
  const shifted=new Date(now);shifted.setDate(shifted.getDate()-5);
  const meta={id:'saved-cycle',name:'Saved',secret:'saved-token',createdAt:old.getTime(),startedAt:'2020-01-01',expiresAt:'2099-01-01',trafficCycleStartDate:local(old),trafficCycleUnit:'month'};
  hub.config.servers.push(meta);
  const r1={id:meta.id,bootId:'a',uptimeSeconds:10000,net:{totalIn:1000,totalOut:2000},lastReportAt:now-200000};
  const r2={...r1,uptimeSeconds:10002,net:{totalIn:1100,totalOut:2200},lastReportAt:now-198000};
  hub.updateTrafficCycleState(meta,{},r1,r1.lastReportAt);hub.updateTrafficCycleState(meta,r1,r2,r2.lastReportAt);hub.state.servers[meta.id]=r2;
  const login=await realFetch(hub.base+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'admin'})});
  const cookie=login.headers.get('set-cookie').split(';')[0],{csrfToken}=await login.json();
  const headers={'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':csrfToken};
  const save=async date=>{const r=await realFetch(hub.base+'/api/admin/server',{method:'POST',headers,body:JSON.stringify({id:meta.id,startedAt:meta.startedAt,expiresAt:meta.expiresAt,trafficCycleStartDate:date})});assert.equal(r.status,200);};
  await save(local(shifted));
  const disk=JSON.parse(await readFile(path.join(hub.directory,'data/state.json'),'utf8')).trafficCycles[meta.id];
  assert.equal(disk.usedIn,100);assert.equal(disk.usedOut,200);
  assert.equal(disk.startAt,new Date(local(shifted)+'T00:00:00').getTime());
  const report=async payload=>{hub.testHooks.resetReportRate(meta.id);const r=await realFetch(hub.base+'/api/agent/report',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer saved-token'},body:JSON.stringify({id:meta.id,...payload})});assert.equal(r.status,200);return r.json();};
  await report({bootId:'b',uptimeSeconds:1,net:{totalIn:10,totalOut:20}});
  const before=structuredClone(hub.state.trafficCycles[meta.id]);
  assert.equal((await report({bootId:'a',uptimeSeconds:10200,net:{totalIn:5000,totalOut:6000}})).ignored,'stale_report');
  assert.deepEqual(hub.state.trafficCycles[meta.id],before);assert.equal(hub.state.servers[meta.id].net.totalIn,10);
  const future=new Date(now);future.setMonth(future.getMonth()+3);
  await save(local(future));
  const cleared=JSON.parse(await readFile(path.join(hub.directory,'data/state.json'),'utf8')).trafficCycles[meta.id];
  assert.equal(cleared.usedIn,0);assert.equal(cleared.usedOut,0);
});
