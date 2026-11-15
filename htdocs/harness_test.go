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
eq(app.resolveAPI(""), "https://finger-01.badblock.net.br:9000", "default API");
eq(app.resolveAPI("?api=http://127.0.0.1:9001"), "http://127.0.0.1:9001", "api http 9001");
eq(app.resolveAPI("?api=https://example.test:9000/x/y"), "https://example.test:9000", "api keeps only the origin");
eq(app.resolveAPI("?api=https://evil.test"), app.DEFAULT_API, "api without port 9000/9001");
eq(app.resolveAPI("?api=https://evil.test:8443"), app.DEFAULT_API, "api on another port");
eq(app.resolveAPI("?api=javascript:alert(1)"), app.DEFAULT_API, "api javascript:");
eq(app.resolveAPI("?api=ftp://h:9000"), app.DEFAULT_API, "api ftp");
eq(app.resolveAPI("?api=https://u:p@h:9000"), app.DEFAULT_API, "api with credentials");
eq(app.resolveAPI("?api=nonsense"), app.DEFAULT_API, "api not a URL");

eq(app.liveURL(app.DEFAULT_API, "ws"), "wss://finger-01.badblock.net.br:9000/api/v1/ws", "ws URL");
eq(app.liveURL("http://127.0.0.1:9001", "ws", { probe: "abc12345" }), "ws://127.0.0.1:9001/api/v1/ws?probe=abc12345", "ws URL over http");
eq(app.liveURL(app.DEFAULT_API, "sse", { probe: "", kind: "dns.query" }), "https://finger-01.badblock.net.br:9000/api/v1/stream?kind=dns.query", "sse URL");

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
  eq(env.sockets[0].url, "wss://finger-01.badblock.net.br:9000/api/v1/ws", "WebSocket URL");
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
  eq(env.sources[0].url, "https://finger-01.badblock.net.br:9000/api/v1/stream", "SSE URL");
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

// ---------------------------------------------------------------- pausa (tasks 186) e corte do feed (187)
{
  // em pausa, 2000 eventos com payload grande: a fila guarda só linhas resumidas
  const conns = new Map();
  const big = "A".repeat(200000);
  const q = new app.PauseQueue(app.MAX_PENDING);
  const opened = { kind: "connection.opened", ts: "2026-11-14T00:00:00.000Z", conn_id: "c1", data: { conn_id: "c1", proto: "h1", src: { ip: "192.0.2.1", port: 5000 }, dst: { ip: "198.51.100.1", port: 8080 }, probe_id: "pp11pp11" } };
  q.push(app.toRow(opened, conns));
  for (let i = 0; i < app.MAX_PENDING; i++) {
    q.push(app.toRow({ kind: "http.request", ts: "2026-11-14T00:00:01.000Z", conn_id: "c1", data: { request_line: { method: "GET", target: "/" + i, version: "HTTP/1.1" }, raw_head_b64: big, response_sent_b64: big, body: { raw_b64: big } } }, conns));
  }
  eq(q.rows.length, app.MAX_PENDING, "pause queue is bounded");
  eq(q.lost, 1, "the oldest queued row is counted as lost");
  eq(q.count, app.MAX_PENDING + 1, "N new counts queue + lost");
  const json = JSON.stringify(q.rows);
  check(!json.includes("AAAA") && !json.includes("raw_head_b64") && !json.includes("response_sent_b64") && !json.includes('"data"'), "pause queue keeps only summary rows");
  check(json.length < app.MAX_PENDING * 400, "pause queue is small: " + json.length + " bytes");
  check(q.rows.every((r) => typeof r.what === "string"), "queued items are rows");
  // as requisições na pausa herdam porta e probe da conexão, como sem pausa
  eq([q.rows[0].dstPort, q.rows[0].probe, q.rows[0].what === "GET /0 HTTP/1.1"], [8080, "pp11pp11", true], "queued request row");
  const taken = q.take();
  eq([taken.rows.length, taken.lost, q.count, q.rows.length], [app.MAX_PENDING, 1, 0, 0], "take empties the queue");
  eq(taken.rows[app.MAX_PENDING - 1].what.startsWith("GET /1999 "), true, "take keeps the arrival order");

  // mesma sequência com e sem pausa produz as mesmas linhas
  const seq = [
    opened,
    { kind: "http.request", ts: "x", conn_id: "c1", data: { request_line: { method: "GET", target: "/a", version: "HTTP/1.1" } } },
    { kind: "connection.closed", ts: "y", conn_id: "c1", data: Object.assign({}, opened.data, { ended: "y" }) },
    { kind: "dns.query", ts: "z", data: { qtype: "A", qname: "x.example", resolver: { ip: "203.0.113.5", port: 53 }, proto: "udp" } },
  ];
  const live = seq.map((e) => app.toRow(e, new Map(conns)));
  const c2 = new Map();
  const paused = new app.PauseQueue(10);
  for (const e of seq) paused.push(app.toRow(e, c2));
  const c3 = new Map();
  eq(paused.take().rows, seq.map((e) => app.toRow(e, c3)), "paused rows equal live rows");
  check(live.length === 4, "live rows built");

  // texto da linha cortado em MAX_WHAT
  const long = app.describeEvent({ kind: "http.request", ts: "x", data: { request_line: { method: "GET", target: "/" + "b".repeat(5000), version: "HTTP/1.1" } } }, new Map());
  eq(long.what.length, app.MAX_WHAT, "row text is capped");
  check(long.what.endsWith("…"), "capped text ends with an ellipsis");
}
{
  // lista falsa com a mesma interface usada pelo trimFeed (mais nova no topo)
  function fakeList(items) {
    const list = { nodes: [] };
    const node = (it) => ({
      id: it.id,
      hidden: it.hidden,
      get previousElementSibling() {
        const i = list.nodes.indexOf(this);
        return i > 0 ? list.nodes[i - 1] : null;
      },
      remove() {
        const i = list.nodes.indexOf(this);
        if (i >= 0) list.nodes.splice(i, 1);
      },
    });
    list.nodes = items.map(node);
    Object.defineProperty(list, "children", { get: () => list.nodes });
    Object.defineProperty(list, "lastElementChild", { get: () => list.nodes[list.nodes.length - 1] || null });
    return list;
  }
  // com filtro de probe: 10 linhas do probe (visíveis, mais antigas) e 600 de outros probes (ocultas, mais novas)
  const items = [];
  for (let i = 0; i < 600; i++) items.push({ id: "other" + i, hidden: true });
  for (let i = 0; i < 10; i++) items.push({ id: "mine" + i, hidden: false });
  const l1 = fakeList(items);
  const removed = [];
  app.trimFeed(l1, app.MAX_ROWS, (li) => removed.push(li.id));
  eq(l1.children.length, app.MAX_ROWS, "feed never exceeds MAX_ROWS with a filter");
  eq(l1.nodes.filter((n) => !n.hidden).length, 10, "probe rows survive other probes' traffic");
  eq(removed.length, 110, "onRemove called for each removed row");
  check(removed.every((id) => id.startsWith("other")), "only hidden rows removed");
  eq(removed[0], "other599", "the oldest hidden row goes first");
  // sem filtro: saem as mais antigas
  const plain = [];
  for (let i = 0; i < 600; i++) plain.push({ id: "r" + i, hidden: false });
  const l2 = fakeList(plain);
  app.trimFeed(l2, app.MAX_ROWS, () => {});
  eq([l2.children.length, l2.nodes[0].id, l2.nodes[l2.nodes.length - 1].id], [app.MAX_ROWS, "r0", "r499"], "without a filter the oldest rows go");
  // poucas ocultas: saem as ocultas e depois as visíveis mais antigas
  const mixed = [];
  for (let i = 0; i < 503; i++) mixed.push({ id: "v" + i, hidden: i === 10 });
  const l3 = fakeList(mixed);
  const r3 = [];
  app.trimFeed(l3, app.MAX_ROWS, (li) => r3.push(li.id));
  eq(r3, ["v10", "v502", "v501"], "hidden first, then the oldest visible");
  const l4 = fakeList([{ id: "a", hidden: true }]);
  app.trimFeed(l4, app.MAX_ROWS, () => {});
  eq(l4.children.length, 1, "nothing removed under the limit");
  check(typeof app.LiveFeed.prototype.reopen === "undefined", "dead LiveFeed.reopen removed");
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
// status é um código ou uma sequência [código, Retry-After] para as respostas seguidas da API.
async function probeRun(pageProtocol, status, wait = "10s") {
  const requests = [];
  const sockets = [];
  const sleeps = [];
  let clock = 0;
  const answers = Array.isArray(status) ? status.slice() : null;
  const fetch = async (url, opts) => {
    requests.push([url, opts]);
    if (url.includes("/api/v1/probes/")) {
      let code = status;
      let ra = null;
      if (answers) [code, ra] = answers.length > 1 ? answers.shift() : answers[0];
      const headers = { get: (k) => (k.toLowerCase() === "retry-after" ? ra : null) };
      return { status: code, ok: code === 200, headers, json: async () => ({ probe_id: "x", all_closed: true, connections: [], dns: [] }) };
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
    wait,
    now: () => clock,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
  });
  return { requests, sockets, steps, res, sleeps };
}
{
  const r = await probeRun("https:", 200);
  const urls = r.requests.map((x) => x[0]);
  eq(urls, [
    "https://abcdef123456.finger-west-01.badblock.net.br:8443/p/abcdef123456/",
    "https://abcdef123456.finger-west-01.badblock.net.br:8443/p/abcdef123456/",
    "https://finger-01.badblock.net.br:9000/api/v1/probes/abcdef123456?wait=10s",
  ], "probe requests from an https page");
  for (const [url, opts] of r.requests.slice(0, 2)) {
    eq([opts.mode, opts.cache, opts.credentials], ["no-cors", "no-store", "omit"], "probe fetch options " + url);
  }
  eq(r.sockets.map((s) => s.url), ["wss://abcdef123456.finger-west-01.badblock.net.br:8443/p/abcdef123456/r?upgrade=ws"], "probe WebSocket");
  eq(r.sockets[0].sent.length, 1, "one WebSocket message");
  eq(r.sockets[0].code, 1000, "WebSocket closed normally");
  check(r.steps.every((s) => s[1]), "all probe steps ok");
  eq(r.res.all_closed, true, "probe result");
  for (const u of urls.concat(r.sockets.map((s) => s.url))) {
    const h = new URL(u).hostname;
    check(h === "finger-01.badblock.net.br" || h.endsWith(".finger-west-01.badblock.net.br"), "allowed host " + h);
  }
}
{
  const r = await probeRun("http:", 404);
  eq(r.requests[2][0], "http://abcdef123456.finger-west-01.badblock.net.br:8080/p/abcdef123456/", "plain http only from an http page");
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

// ---------------------------------------------------------------- 503 do wait com Retry-After (task 211)
{
  const r = await probeRun("https:", [[503, "1"], [200, null]]);
  eq(r.res.all_closed, true, "503 then 200 succeeds");
  eq(r.sleeps, [1000], "waits Retry-After before retrying");
  eq(r.requests.filter((x) => x[0].includes("/api/v1/probes/")).length, 2, "the wait request is repeated");
}
{
  const r = await probeRun("https:", [[503, "99"], [503, "nope"], [503, null], [200, null]]);
  eq(r.sleeps, [5000, 1000, 1000], "Retry-After capped at 5 s; missing or invalid is 1 s");
  eq(r.res.all_closed, true, "succeeds after several 503");
}
{
  let msg = "";
  try {
    await probeRun("https:", [[503, "2"]], "5s");
  } catch (e) {
    msg = String(e && e.message);
  }
  check(msg.includes("503"), "503 beyond the deadline becomes an error: " + msg);
}
{
  let threw = false;
  try {
    await probeRun("https:", [[500, null]]);
  } catch {
    threw = true;
  }
  check(threw, "other codes are still errors");
}
eq([app.waitMs("10s"), app.waitMs("500ms"), app.waitMs("x")], [10000, 500, 10000], "waitMs");
eq([app.retryAfterMs({}), app.retryAfterMs(null), app.retryAfterMs({ headers: { get: () => " 3 " } })], [1000, 1000, 3000], "retryAfterMs");

console.log(passed + " checks passed, " + failures + " failed");
process.exit(failures === 0 ? 0 : 1);
`
