package htdocs

// jsHarness são os testes de comportamento do app.mjs, rodados pelo TestAppModule com o node:
// node harness.mjs <caminho do app.mjs> <testdata do store>. Sem crases no texto (string crua do Go).
const jsHarness = `
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const app = await import(pathToFileURL(process.argv[2]).href);
const examples = process.argv[3];
const example = (name) => JSON.parse(readFileSync(join(examples, name), "utf8")).value;

let failures = 0;
let passed = 0;
function check(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failures++;
    console.log("FAIL: " + msg);
  }
}
function eq(got, want, msg) {
  check(JSON.stringify(got) === JSON.stringify(want), msg + ": got " + JSON.stringify(got) + ", want " + JSON.stringify(want));
}

// ---------------------------------------------------------------- resolveAPI e liveURL
eq(app.resolveAPI(""), "https://vps602.tmsoft.com.br:9000", "default API");
eq(app.resolveAPI("?api=http://127.0.0.1:9001"), "http://127.0.0.1:9001", "api http 9001");
eq(app.resolveAPI("?api=https://example.test:9000/x/y"), "https://example.test:9000", "api keeps only the origin");
eq(app.resolveAPI("?api=https://evil.test"), app.DEFAULT_API, "api without port 9000/9001");
eq(app.resolveAPI("?api=https://evil.test:8443"), app.DEFAULT_API, "api on another port");
eq(app.resolveAPI("?api=javascript:alert(1)"), app.DEFAULT_API, "api javascript:");
eq(app.resolveAPI("?api=ftp://h:9000"), app.DEFAULT_API, "api ftp");
eq(app.resolveAPI("?api=https://u:p@h:9000"), app.DEFAULT_API, "api with credentials");
eq(app.resolveAPI("?api=nonsense"), app.DEFAULT_API, "api not a URL");

eq(app.liveURL(app.DEFAULT_API, "ws"), "wss://vps602.tmsoft.com.br:9000/api/v1/ws", "ws URL");
eq(app.liveURL("http://127.0.0.1:9001", "ws", { probe: "abc12345" }), "ws://127.0.0.1:9001/api/v1/ws?probe=abc12345", "ws URL over http");
eq(app.liveURL(app.DEFAULT_API, "sse", { probe: "", kind: "dns.query" }), "https://vps602.tmsoft.com.br:9000/api/v1/stream?kind=dns.query", "sse URL");

// ---------------------------------------------------------------- probe ID e espera
for (let i = 0; i < 200; i++) {
  const id = app.randomProbeID();
  check(/^[a-z0-9]{12}$/.test(id), "probe ID format: " + id);
}
let calls = 0;
const fixed = app.randomProbeID((buf) => {
  calls++;
  buf.fill(calls === 1 ? 255 : 0); // primeiro lote todo descartado (>= 252)
});
eq(fixed, "aaaaaaaaaaaa", "rejection of bytes >= 252");
eq(calls, 2, "a second fill after rejection");
eq([0, 1, 2, 3, 4, 5, 6, 10].map(app.backoffMs), [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000], "backoff");

// ---------------------------------------------------------------- LiveFeed com transportes falsos
function fakeEnv() {
  const env = { timers: [], sockets: [], sources: [] };
  env.setTimeout = (fn, ms) => {
    env.timers.push({ fn, ms, live: true });
    return env.timers.length - 1;
  };
  env.clearTimeout = (id) => {
    if (env.timers[id]) env.timers[id].live = false;
  };
  env.fire = (ms) => {
    const t = env.timers.find((x) => x.live && x.ms === ms);
    if (!t) return false;
    t.live = false;
    t.fn();
    return true;
  };
  env.WebSocket = class {
    constructor(url) {
      this.url = url;
      this.closed = false;
      env.sockets.push(this);
    }
    close() {
      this.closed = true;
    }
  };
  env.EventSource = class {
    constructor(url) {
      this.url = url;
      this.listeners = {};
      this.closed = false;
      env.sources.push(this);
    }
    addEventListener(k, fn) {
      this.listeners[k] = fn;
    }
    close() {
      this.closed = true;
    }
  };
  return env;
}
{
  const env = fakeEnv();
  const events = [];
  const states = [];
  const feed = new app.LiveFeed({
    api: app.DEFAULT_API,
    env,
    onEvent: (e) => events.push(e),
    onState: (s, t, w) => states.push([s, t, w]),
  });
  feed.start();
  eq(env.sockets.length, 1, "starts with WebSocket");
  eq(env.sockets[0].url, "wss://vps602.tmsoft.com.br:9000/api/v1/ws", "WebSocket URL");
  env.sockets[0].onopen();
  eq(states[states.length - 1], ["live", "WebSocket", undefined], "live over WebSocket");
  env.sockets[0].onmessage({ data: '{"kind":"dns.query","ts":"2026-11-09T00:00:00Z","data":{}}' });
  env.sockets[0].onmessage({ data: "not json" });
  env.sockets[0].onmessage({ data: '{"no":"kind"}' });
  eq(events.length, 1, "only valid events are delivered");
  check(!env.fire(3000), "open timer cleared after onopen");
  // queda depois de aberto: reconecta com 1 s, de novo pelo WebSocket
  env.sockets[0].onclose();
  eq(states[states.length - 1], ["reconnecting", "", 1000], "reconnecting in 1 s");
  check(env.fire(1000), "reconnect timer");
  eq(env.sockets.length, 2, "reconnects with WebSocket first");
  // não abriu em 3 s: SSE
  check(env.fire(3000), "WebSocket open timeout");
  check(env.sockets[1].closed, "stalled WebSocket is closed");
  eq(env.sources.length, 1, "falls back to SSE");
  eq(env.sources[0].url, "https://vps602.tmsoft.com.br:9000/api/v1/stream", "SSE URL");
  env.sockets[1].onclose(); // fechamento atrasado do WebSocket abandonado não reconecta
  eq(env.timers.filter((t) => t.live).length, 0, "abandoned WebSocket does not schedule anything");
  env.sources[0].onopen();
  eq(states[states.length - 1], ["live", "SSE", undefined], "live over SSE");
  for (const k of app.LIVE_KINDS) check(typeof env.sources[0].listeners[k] === "function", "SSE listens to " + k);
  env.sources[0].listeners["connection.opened"]({ data: '{"kind":"connection.opened","ts":"x","data":{}}' });
  eq(events.length, 2, "named SSE event delivered");
  // SSE cai duas vezes sem abrir: 1 s, depois 2 s
  env.sources[0].onerror();
  check(env.sources[0].closed, "SSE closed on error");
  eq(states[states.length - 1], ["reconnecting", "", 1000], "attempt reset after a successful open");
  env.fire(1000);
  env.sockets[2].onclose(); // WebSocket recusado na hora (ex.: 503): SSE sem esperar 3 s
  eq(env.sources.length, 2, "immediate WebSocket failure goes to SSE");
  env.sources[1].onerror();
  eq(states[states.length - 1], ["reconnecting", "", 2000], "growing backoff");
  feed.stop();
  check(!env.fire(2000), "stop cancels the retry");
}

// ---------------------------------------------------------------- linhas do feed
{
  const conns = new Map();
  const summary = example("connections-list-example.json")[0];
  app.rememberConn(conns, summary);
  const opened = app.describeEvent({ kind: "connection.opened", ts: summary.started, conn_id: summary.conn_id, data: summary }, conns);
  eq(opened.connID, summary.conn_id, "connection row conn_id");
  eq(opened.dstPort, summary.dst.port, "connection row port");
  eq(opened.srcIP, summary.src.ip, "connection row ip");
  check(opened.what.includes(summary.proto), "connection row proto text");
  const closed = app.describeEvent({ kind: "connection.closed", ts: "x", data: Object.assign({}, summary, { ended: "y" }) }, conns);
  check(closed.closed, "closed connection row");

  const rec = example("connection-example.json");
  app.rememberConn(conns, rec);
  const h1 = app.describeEvent({ kind: "http.request", ts: "x", conn_id: rec.conn_id, data: rec.http[0] }, conns);
  eq(h1.what.startsWith("GET /p/t1a2b3c4/ HTTP/1.1"), true, "h1 request row: " + h1.what);
  eq(h1.dstPort, rec.dst.port, "request row inherits the port from the connection");
  eq(h1.probe, rec.probe_id, "request row inherits the probe");

  const h2fields = [{ name: ":method", value: "GET" }, { name: ":path", value: "/x" }, { name: ":authority", value: "a" }];
  eq(app.describeEvent({ kind: "http.request", ts: "x", data: { stream_id: 1, fields: h2fields, status: 200 } }, conns).what, "GET /x h2 → 200", "h2 row");
  eq(app.describeEvent({ kind: "http.request", ts: "x", data: { stream_id: 0, fields: h2fields, body_len: 0 } }, conns).what, "GET /x h3", "h3 row");

  const q = example("dns-list-example.json")[0];
  const dns = app.describeEvent({ kind: "dns.query", ts: q.ts, data: q }, conns);
  eq(dns.dstPort, 53, "dns row port");
  eq(dns.srcIP, q.resolver.ip, "dns row ip is the resolver");
  check(dns.what.includes(q.qname) && dns.what.includes("ECS 200.1.2.0/24"), "dns row text: " + dns.what);

  const pkt = example("packets-example.json")[0];
  const stray = app.describeEvent({ kind: "packet.stray", ts: pkt.ts, data: pkt }, conns);
  eq([stray.srcIP, stray.dstPort, stray.what], ["192.0.2.10", 7700, pkt.summary], "stray packet row");
  const out = app.describeEvent({ kind: "packet.stray", ts: "x", data: Object.assign({}, pkt, { dir: "out", src: pkt.dst, dst: pkt.src }) }, conns);
  eq([out.srcIP, out.dstPort], ["192.0.2.10", 7700], "outgoing stray packet keeps the client IP");

  const dropped = app.describeEvent({ kind: "stream.dropped", ts: "x", data: { dropped: 7 } }, conns);
  check(dropped.warn && dropped.what.startsWith("7 events"), "dropped row");

  // filtros
  const f = (o) => app.normalizeFilters(o);
  check(app.matchesFilter(h1, f({})), "no filter");
  check(app.matchesFilter(h1, f({ port: String(rec.dst.port) })), "port filter match");
  check(!app.matchesFilter(h1, f({ port: "1" })), "port filter miss");
  check(app.matchesFilter(h1, f({ proto: "HTTP1" })), "proto filter is case-insensitive");
  check(!app.matchesFilter(dns, f({ proto: "h2" })), "proto filter miss");
  check(app.matchesFilter(dns, f({ ip: q.resolver.ip.slice(0, 4) })), "ip filter by prefix");
  check(!app.matchesFilter(stray, f({ probe: "zzzz" })), "probe filter hides rows without probe");
  check(app.matchesFilter(dropped, f({ probe: "zzzz" })), "warnings are always shown");
  for (let i = 0; i < 5000; i++) app.rememberConn(conns, { conn_id: "c" + i });
  check(conns.size <= 4000, "connection map is bounded");
}

// ---------------------------------------------------------------- preferências
{
  const mem = { data: {}, getItem(k) { return this.data[k] || null; }, setItem(k, v) { this.data[k] = v; } };
  app.saveFilters(mem, { port: " 443 ", proto: "h2", ip: "", probe: "abc", extra: "x" });
  eq(app.loadFilters(mem), { port: "443", proto: "h2", ip: "", probe: "" }, "filters round trip (probe is not kept)");
  const broken = { getItem() { throw new Error("denied"); }, setItem() { throw new Error("denied"); } };
  app.saveFilters(broken, { port: "1" });
  eq(app.loadFilters(broken), { port: "", proto: "", ip: "", probe: "" }, "storage failure is tolerated");
  eq(app.loadFilters(null), { port: "", proto: "", ip: "", probe: "" }, "no storage");
  eq(app.loadFilters({ getItem() { return "{bad"; } }), { port: "", proto: "", ip: "", probe: "" }, "corrupt storage");
}

// ---------------------------------------------------------------- detalhe e resumo do probe
{
  const rec = example("connection-example.json");
  const fields = new Map(app.detailFields(rec));
  eq(fields.get("Connection ID"), rec.conn_id, "detail conn_id");
  eq(fields.get("Protocol"), rec.proto, "detail proto");
  check(fields.has("Client") && fields.has("JA4") && fields.has("HTTP/1 first request"), "detail main fields: " + [...fields.keys()].join(", "));
  for (const [k, v] of app.detailFields(rec)) check(typeof v === "string" && v !== "", "detail value is text: " + k);
  eq(app.detailFields({}).length, 0, "empty record");
  const p = example("probe-example.json");
  const lines = app.summarizeProbe(p);
  check(lines[0].startsWith("1 connection and 1 DNS query"), "probe summary: " + lines[0]);
  eq(app.summarizeProbe(null), ["Nothing was recorded for this probe yet."], "probe summary for 404");
}

// ---------------------------------------------------------------- run probe
async function probeRun(pageProtocol, status) {
  const requests = [];
  const sockets = [];
  const fetch = async (url, opts) => {
    requests.push([url, opts]);
    if (url.includes("/api/v1/probes/")) {
      return { status, ok: status === 200, json: async () => ({ probe_id: "x", all_closed: true, connections: [], dns: [] }) };
    }
    return { status: 0, ok: false, type: "opaque" };
  };
  class WS {
    constructor(url) {
      this.url = url;
      this.sent = [];
      sockets.push(this);
      setTimeout(() => this.onopen && this.onopen(), 1);
    }
    send(m) {
      this.sent.push(m);
      setTimeout(() => this.onmessage && this.onmessage({ data: m }), 1);
    }
    close(code) {
      this.code = code;
    }
  }
  const steps = [];
  const res = await app.runProbe("abcdef123456", {
    api: app.DEFAULT_API,
    fetch,
    WebSocket: WS,
    pageProtocol,
    onStep: (label, ok) => steps.push([label, ok]),
    wait: "10s",
  });
  return { requests, sockets, steps, res };
}
{
  const r = await probeRun("https:", 200);
  const urls = r.requests.map((x) => x[0]);
  eq(urls, [
    "https://abcdef123456.dns-monitor.tmsoft.com.br/p/abcdef123456/",
    "https://abcdef123456.dns-monitor.tmsoft.com.br/p/abcdef123456/",
    "https://vps602.tmsoft.com.br:9000/api/v1/probes/abcdef123456?wait=10s",
  ], "probe requests from an https page");
  for (const [url, opts] of r.requests.slice(0, 2)) {
    eq([opts.mode, opts.cache, opts.credentials], ["no-cors", "no-store", "omit"], "probe fetch options " + url);
  }
  eq(r.sockets.map((s) => s.url), ["wss://abcdef123456.dns-monitor.tmsoft.com.br/p/abcdef123456/r?upgrade=ws"], "probe WebSocket");
  eq(r.sockets[0].sent.length, 1, "one WebSocket message");
  eq(r.sockets[0].code, 1000, "WebSocket closed normally");
  check(r.steps.every((s) => s[1]), "all probe steps ok");
  eq(r.res.all_closed, true, "probe result");
  for (const u of urls.concat(r.sockets.map((s) => s.url))) {
    const h = new URL(u).hostname;
    check(h === "vps602.tmsoft.com.br" || h.endsWith(".dns-monitor.tmsoft.com.br"), "allowed host " + h);
  }
}
{
  const r = await probeRun("http:", 404);
  eq(r.requests[2][0], "http://abcdef123456.dns-monitor.tmsoft.com.br/p/abcdef123456/", "plain http only from an http page");
  eq(r.res, null, "404 becomes null");
}
{
  let threw = false;
  try {
    await probeRun("https:", 500);
  } catch {
    threw = true;
  }
  check(threw, "API error is reported");
}

console.log(passed + " checks passed, " + failures + " failed");
process.exit(failures === 0 ? 0 : 1);
`
