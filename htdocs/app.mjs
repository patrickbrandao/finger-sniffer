// Página do finger-sniffer (spec 014): feed global ao vivo pela API na 9000, detalhe da conexão e "run probe".
// JS puro, sem build e sem dependências. Tudo que vem da API é de terceiros: entra no DOM só por textContent e
// createElement. As funções exportadas não tocam no DOM e são testadas pelo htdocs_test.go com o node.

export const DEFAULT_API = "https://vps602.tmsoft.com.br:9000";
export const PROBE_ZONE = "dns-monitor.tmsoft.com.br";
export const MAX_ROWS = 500;
export const WS_OPEN_TIMEOUT_MS = 3000;
export const MAX_BACKOFF_MS = 30000;
export const LIVE_KINDS = [
  "connection.opened",
  "connection.updated",
  "connection.closed",
  "http.request",
  "dns.query",
  "packet.stray",
  "stream.dropped",
];
const FILTER_KEYS = ["port", "proto", "ip", "probe"];
const STORAGE_KEY = "finger-sniffer.filters";
const MAX_CONNS = 4000;
const MAX_PENDING = 2000;
const ANNOUNCE_EVERY_MS = 60000;
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

// resolveAPI devolve a origem da API: a constante, ou ?api=<origem> para testes, aceito só com http(s) e porta
// 9000/9001 (spec 014 "Comportamento"). Qualquer outra coisa cai na constante.
export function resolveAPI(search) {
  let v = null;
  try {
    v = new URLSearchParams(search || "").get("api");
  } catch {
    return DEFAULT_API;
  }
  if (!v) return DEFAULT_API;
  let u;
  try {
    u = new URL(v);
  } catch {
    return DEFAULT_API;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return DEFAULT_API;
  if (u.port !== "9000" && u.port !== "9001") return DEFAULT_API;
  if (u.username || u.password) return DEFAULT_API;
  return u.origin;
}

// liveURL monta a URL do /ws (ws/wss conforme a API) ou do /stream, com filtros do servidor opcionais.
export function liveURL(api, transport, filters) {
  const u = new URL(transport === "ws" ? "/api/v1/ws" : "/api/v1/stream", api);
  if (transport === "ws") u.protocol = u.protocol === "http:" ? "ws:" : "wss:";
  for (const [k, v] of Object.entries(filters || {})) {
    if (v) u.searchParams.set(k, String(v));
  }
  return u.href;
}

// randomProbeID gera 12 caracteres [a-z0-9] com crypto.getRandomValues; bytes >= 252 são descartados para
// a distribuição ficar uniforme (252 = 7 × 36).
export function randomProbeID(fill = (a) => globalThis.crypto.getRandomValues(a)) {
  let out = "";
  const buf = new Uint8Array(24);
  while (out.length < 12) {
    fill(buf);
    for (const b of buf) {
      if (b < 252 && out.length < 12) out += ALPHABET[b % 36];
    }
  }
  return out;
}

// backoffMs é a espera antes da tentativa n (0, 1, 2…): 1, 2, 4… até 30 s.
export function backoffMs(attempt) {
  return Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.max(0, attempt));
}

// ------------------------------------------------------------------ conexão ao vivo

// LiveFeed abre o WebSocket; se ele não abrir em 3 s, usa SSE; se cair, reconecta com espera crescente.
// env injeta WebSocket, EventSource e os timers (o teste usa versões falsas).
export class LiveFeed {
  constructor({ api, filters, onEvent, onState, env }) {
    this.api = api;
    this.filters = filters || {};
    this.onEvent = onEvent || (() => {});
    this.onState = onState || (() => {});
    this.env = env;
    this.sock = null;
    this.attempt = 0;
    this.retryTimer = null;
    this.stopped = true;
  }

  start() {
    this.stopped = false;
    this.connect();
  }

  stop() {
    this.stopped = true;
    this.drop();
    if (this.retryTimer !== null) this.env.clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }

  // reopen troca os filtros do servidor (ex.: ?probe=) e reconecta na hora.
  reopen(filters) {
    this.filters = filters || {};
    this.attempt = 0;
    this.stop();
    this.start();
  }

  connect() {
    this.retryTimer = null;
    if (this.stopped) return;
    if (this.env.WebSocket) this.tryWS();
    else this.trySSE();
  }

  // drop solta o transporte atual sem disparar reconexão (os tratadores conferem this.sock).
  drop() {
    const s = this.sock;
    this.sock = null;
    if (!s) return;
    try {
      s.close();
    } catch {
      // nada a fazer: o transporte já estava fechado
    }
  }

  tryWS() {
    const url = liveURL(this.api, "ws", this.filters);
    this.onState("connecting", "WebSocket");
    let ws;
    try {
      ws = new this.env.WebSocket(url);
    } catch {
      this.trySSE();
      return;
    }
    this.sock = ws;
    let opened = false;
    const timer = this.env.setTimeout(() => {
      if (opened || this.sock !== ws) return;
      this.drop();
      this.trySSE();
    }, WS_OPEN_TIMEOUT_MS);
    ws.onopen = () => {
      if (this.sock !== ws) return;
      opened = true;
      this.env.clearTimeout(timer);
      this.attempt = 0;
      this.onState("live", "WebSocket");
    };
    ws.onmessage = (m) => {
      if (this.sock === ws) this.deliver(m.data);
    };
    ws.onclose = () => {
      this.env.clearTimeout(timer);
      if (this.sock !== ws) return;
      this.sock = null;
      if (opened) this.scheduleReconnect();
      else this.trySSE();
    };
  }

  trySSE() {
    if (this.stopped) return;
    if (!this.env.EventSource) {
      this.scheduleReconnect();
      return;
    }
    const url = liveURL(this.api, "sse", this.filters);
    this.onState("connecting", "SSE");
    let es;
    try {
      es = new this.env.EventSource(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.sock = es;
    es.onopen = () => {
      if (this.sock !== es) return;
      this.attempt = 0;
      this.onState("live", "SSE");
    };
    // o SSE manda "event: <kind>"; eventos com nome não passam pelo onmessage
    const handler = (m) => {
      if (this.sock === es) this.deliver(m.data);
    };
    for (const k of LIVE_KINDS) es.addEventListener(k, handler);
    es.onmessage = handler;
    es.onerror = () => {
      if (this.sock !== es) return;
      // o EventSource tentaria sozinho, sem espera crescente nem estado visível: fechamos e cuidamos nós
      this.drop();
      this.scheduleReconnect();
    };
  }

  scheduleReconnect() {
    if (this.stopped || this.retryTimer !== null) return;
    const ms = backoffMs(this.attempt);
    this.attempt++;
    this.onState("reconnecting", "", ms);
    this.retryTimer = this.env.setTimeout(() => this.connect(), ms);
  }

  deliver(text) {
    let ev;
    try {
      ev = JSON.parse(text);
    } catch {
      return;
    }
    if (ev && typeof ev === "object" && typeof ev.kind === "string") this.onEvent(ev);
  }
}

// ------------------------------------------------------------------ modelo das linhas

function str(v) {
  return v === null || v === undefined ? "" : String(v);
}

export function endpoint(e) {
  if (!e || e.ip === undefined) return "?";
  const ip = String(e.ip);
  return ip.includes(":") ? `[${ip}]:${str(e.port)}` : `${ip}:${str(e.port)}`;
}

// rememberConn guarda o resumo da conexão para dar IP, porta e protocolo às linhas de requisição.
export function rememberConn(conns, summary) {
  if (!summary || typeof summary.conn_id !== "string") return;
  conns.delete(summary.conn_id);
  conns.set(summary.conn_id, summary);
  while (conns.size > MAX_CONNS) conns.delete(conns.keys().next().value);
}

function fieldValue(fields, name) {
  if (!Array.isArray(fields)) return "";
  for (const f of fields) {
    if (f && f.name === name) return str(f.value);
  }
  return "";
}

// describeRequest resume HTTP1Request, HTTP2Stream ou HTTP3Request numa linha.
export function describeRequest(d, conn) {
  let text;
  if (d.request_line) {
    const rl = d.request_line;
    text = `${str(rl.method)} ${str(rl.target)} ${str(rl.version)}`.trim();
  } else {
    const proto = str(conn && conn.proto);
    const ver = proto.includes("h3") || proto.startsWith("quic") || "body_len" in d ? "h3" : "h2";
    const method = fieldValue(d.fields, ":method") || "?";
    const path = fieldValue(d.fields, ":path");
    const protocol = fieldValue(d.fields, ":protocol");
    text = `${method} ${path || fieldValue(d.fields, ":authority")} ${ver}${protocol ? ` (${protocol})` : ""}`;
  }
  if (d.status) text += ` → ${d.status}`;
  return text;
}

function connText(d) {
  let text = `${str(d.proto)} ${endpoint(d.src)} → :${str(d.dst && d.dst.port)}`;
  if (d.requests) text += `, ${d.requests} req`;
  if (d.degraded) text += ", degraded";
  return text;
}

const KIND_LABEL = {
  "connection.opened": "conn opened",
  "connection.updated": "conn updated",
  "connection.closed": "conn closed",
  "http.request": "request",
  "dns.query": "dns query",
  "packet.stray": "stray packet",
  "stream.dropped": "dropped",
};

// describeEvent converte um LiveEvent na linha do feed (sem DOM). conns é o mapa conn_id → resumo.
export function describeEvent(ev, conns) {
  const d = ev.data && typeof ev.data === "object" ? ev.data : {};
  const row = {
    kind: str(ev.kind),
    label: KIND_LABEL[ev.kind] || str(ev.kind),
    ts: str(ev.ts),
    connID: ev.conn_id || null,
    probe: ev.probe_id || null,
    proto: "",
    srcIP: "",
    dstPort: null,
    what: "",
    warn: false,
    closed: false,
  };
  const fromConn = (c) => {
    if (!c) return;
    row.proto = str(c.proto);
    row.srcIP = str(c.src && c.src.ip);
    row.dstPort = c.dst && typeof c.dst.port === "number" ? c.dst.port : null;
    row.probe = row.probe || c.probe_id || null;
  };
  switch (ev.kind) {
    case "connection.opened":
    case "connection.updated":
    case "connection.closed":
      row.connID = d.conn_id || row.connID;
      fromConn(d);
      row.closed = ev.kind === "connection.closed" || Boolean(d.ended);
      row.what = connText(d);
      break;
    case "http.request": {
      const c = row.connID ? conns.get(row.connID) : null;
      fromConn(c);
      row.what = describeRequest(d, c);
      break;
    }
    case "dns.query": {
      row.proto = "dns";
      row.srcIP = str(d.resolver && d.resolver.ip);
      row.dstPort = 53;
      row.probe = row.probe || d.probe_id || null;
      row.connID = row.connID || d.conn_id || null;
      let text = `${str(d.qtype)} ${str(d.qname)} from ${endpoint(d.resolver)} over ${str(d.proto)}`;
      if (d.response && d.response.rcode) text += ` → ${d.response.rcode}`;
      if (d.edns && d.edns.ecs && d.edns.ecs.address) {
        text += `, ECS ${d.edns.ecs.address}/${str(d.edns.ecs.source_prefix)}`;
      }
      row.what = text;
      break;
    }
    case "packet.stray": {
      // sentido out: o espelho é a origem; o IP de interesse é sempre o do outro lado
      const client = d.dir === "out" ? d.dst : d.src;
      const mirror = d.dir === "out" ? d.src : d.dst;
      row.proto = str(d.l4);
      row.srcIP = str(client && client.ip);
      row.dstPort = mirror && typeof mirror.port === "number" ? mirror.port : null;
      row.what = d.summary
        ? str(d.summary)
        : `${str(d.l4)} ${d.dir === "out" ? "to" : "from"} ${endpoint(client)} ${str(d.tcp_flags)}`.trim();
      break;
    }
    case "stream.dropped":
      row.warn = true;
      row.what = `${str(d.dropped)} events were not delivered to this page (it could not keep up)`;
      break;
    default:
      row.what = row.kind;
  }
  return row;
}

// ------------------------------------------------------------------ filtros locais

export function normalizeFilters(obj) {
  const out = {};
  for (const k of FILTER_KEYS) {
    const v = obj && typeof obj[k] === "string" ? obj[k].trim().slice(0, 64) : "";
    out[k] = v;
  }
  return out;
}

// matchesFilter diz se a linha aparece: porta exata (porta do espelho), protocolo, IP e probe por trecho.
// Avisos (stream.dropped) aparecem sempre.
export function matchesFilter(row, f) {
  if (row.warn) return true;
  if (f.port && row.dstPort !== Number(f.port)) return false;
  if (f.proto && !row.proto.toLowerCase().includes(f.proto.toLowerCase())) return false;
  if (f.ip && !row.srcIP.toLowerCase().includes(f.ip.toLowerCase())) return false;
  if (f.probe && !str(row.probe).includes(f.probe.toLowerCase())) return false;
  return true;
}

export function loadFilters(storage) {
  try {
    const raw = storage && storage.getItem(STORAGE_KEY);
    return Object.assign(normalizeFilters(raw ? JSON.parse(raw) : {}), { probe: "" });
  } catch {
    return normalizeFilters({});
  }
}

// saveFilters guarda porta, protocolo e IP; o probe não: o ID é efêmero e, guardado, esconderia o feed na volta.
export function saveFilters(storage, f) {
  try {
    if (storage) storage.setItem(STORAGE_KEY, JSON.stringify(Object.assign(normalizeFilters(f), { probe: "" })));
  } catch {
    // modo privado ou armazenamento bloqueado: a preferência só não persiste
  }
}

// ------------------------------------------------------------------ detalhe da conexão

function ms(v) {
  return typeof v === "number" ? `${Math.round(v * 100) / 100} ms` : "";
}

function names(list) {
  if (!Array.isArray(list)) return "";
  return list.map((x) => (x && typeof x === "object" ? str(x.name || x.code) : str(x))).join(", ");
}

function tcpOptions(opts) {
  if (!Array.isArray(opts)) return "";
  return opts.map((o) => (Array.isArray(o) ? o.map(str).join(" ") : "")).join(", ");
}

// detailFields lista os campos principais do registro como pares [rótulo, valor]; valores vazios ficam de fora.
export function detailFields(rec) {
  const out = [];
  const add = (k, v) => {
    const s = str(v);
    if (s !== "") out.push([k, s]);
  };
  const r = rec || {};
  add("Connection ID", r.conn_id);
  add("Probe", r.probe_id);
  add("Protocol", r.proto);
  add("Transport", r.l4 ? `${r.l4} over IPv${str(r.family)}` : "");
  add("Client", r.src ? endpoint(r.src) : "");
  add("Server", r.dst ? endpoint(r.dst) : "");
  add("Started", r.started);
  add("Ended", r.ended || (r.started ? "still open" : ""));
  if (r.close && r.close.how) {
    add("Closed", `by ${str(r.close.by)}, ${str(r.close.how)}${r.close.half_close ? ", half-close" : ""}`);
  }
  add("HTTP requests", r.requests);
  if (r.degraded) add("Degraded", "yes (no pcap or raw bytes: the mirror was under load)");
  const ip = r.ip || {};
  if (ip.ttl !== undefined) {
    add("TTL", `${str(ip.ttl)} (initial ${str(ip.ttl_initial)}, ${str(ip.hops)} hops)${ip.df ? ", DF" : ""}`);
  }
  const tcp = r.tcp || {};
  add("JA4T", tcp.ja4t);
  add("p0f", tcp.p0f);
  add("OS guess", tcp.os_guess);
  add("RTT (handshake)", ms(tcp.rtt_handshake_ms));
  if (tcp.syn) {
    add("SYN window", tcp.syn.window);
    add("SYN options", tcpOptions(tcp.syn.options));
  }
  add("Retransmits in", tcp.retransmits_in);
  const tls = r.tls || {};
  add("TLS SNI", tls.sni);
  add("TLS ALPN offered", Array.isArray(tls.alpn) ? tls.alpn.join(", ") : "");
  add("JA3", tls.ja3_md5);
  add("JA4", tls.ja4);
  if (tls.negotiated) {
    const n = tls.negotiated;
    add("TLS negotiated", `${str(n.version)} ${str(n.cipher)} ${str(n.group)} ${str(n.alpn)}`.trim());
  }
  add("TLS handshake", ms(tls.handshake_ms));
  if (Array.isArray(r.http) && r.http.length > 0) {
    const first = r.http[0];
    add("HTTP/1 first request", describeRequest(first, r));
    const signals = r.http.flatMap((h) => (Array.isArray(h.proxy_signals) ? h.proxy_signals : []));
    add("Proxy signals", signals.map((s) => str(s.kind)).join(", "));
    add("JA4H", first.ja4h);
  }
  const h2 = r.http2 || {};
  add("HTTP/2 mode", h2.mode);
  add("HTTP/2 Akamai", h2.akamai);
  const h3 = r.http3 || {};
  add("QUIC version", h3.version);
  if (h3.client_hello) add("JA4 (QUIC)", h3.client_hello.ja4);
  if (Array.isArray(h3.transport_params)) add("QUIC transport params", h3.transport_params.length);
  if (Array.isArray(h3.requests)) add("HTTP/3 requests", h3.requests.length);
  const ws = r.websocket || {};
  if (ws.over) {
    add("WebSocket", `${str(ws.path)} over ${str(ws.over)}, ${Array.isArray(ws.frames) ? ws.frames.length : 0} frames`);
    add("WebSocket extensions", ws.extensions);
  }
  const raw = r.raw || {};
  add("Raw mode", raw.mode);
  add("PROBE line", raw.probe_line);
  add("Supported groups", names(tls.supported_groups));
  return out;
}

// ------------------------------------------------------------------ run probe

function wsProbe(WS, url, message, timeoutMs) {
  return new Promise((resolve) => {
    let ws;
    let opened = false;
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        ws.close(1000);
      } catch {
        // já fechado
      }
      resolve(ok);
    };
    const timer = setTimeout(() => finish(opened), timeoutMs);
    try {
      ws = new WS(url);
    } catch {
      clearTimeout(timer);
      resolve(false);
      return;
    }
    ws.onopen = () => {
      opened = true;
      ws.send(message);
    };
    ws.onmessage = () => finish(true);
    ws.onerror = () => finish(opened);
    ws.onclose = () => finish(opened);
  });
}

// probeTargets lista as sondagens HTTP do "run probe": duas em https (a segunda deve ir por h3 via Alt-Svc) e
// uma em http só quando a página veio por http (o navegador bloqueia conteúdo misto).
export function probeTargets(id, pageProtocol) {
  const host = `${id}.${PROBE_ZONE}`;
  const path = `/p/${id}/`;
  const out = [
    { label: "HTTPS request", url: `https://${host}${path}` },
    { label: "HTTPS request again (HTTP/3 if the browser took the Alt-Svc)", url: `https://${host}${path}` },
  ];
  if (pageProtocol === "http:") out.push({ label: "plain HTTP request", url: `http://${host}${path}` });
  out.push({ label: "WebSocket with one message", url: `wss://${host}/p/${id}/r?upgrade=ws`, ws: true });
  return out;
}

// runProbe dispara as sondagens em sequência e devolve o GET /api/v1/probes/<id>?wait=… (null se 404).
export async function runProbe(id, { api, fetch, WebSocket, pageProtocol, onStep = () => {}, wait = "10s", wsTimeoutMs = 5000 }) {
  for (const t of probeTargets(id, pageProtocol)) {
    if (t.ws) {
      const ok = WebSocket ? await wsProbe(WebSocket, t.url, `hello from probe ${id}`, wsTimeoutMs) : false;
      onStep(t.label, ok, t.url);
      continue;
    }
    try {
      // no-cors: a resposta é opaca; só importa a conexão chegar ao espelho
      await fetch(t.url, { mode: "no-cors", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
      onStep(t.label, true, t.url);
    } catch (e) {
      onStep(t.label, false, `${t.url}: ${str(e && e.message)}`);
    }
  }
  const res = await fetch(`${api}/api/v1/probes/${encodeURIComponent(id)}?wait=${encodeURIComponent(wait)}`, {
    cache: "no-store",
    credentials: "omit",
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`the API answered ${res.status}`);
  return res.json();
}

// summarizeProbe resume o registro do probe em frases curtas.
export function summarizeProbe(p) {
  if (!p) return ["Nothing was recorded for this probe yet."];
  const lines = [];
  const conns = Array.isArray(p.connections) ? p.connections : [];
  const dns = Array.isArray(p.dns) ? p.dns : [];
  const resolvers = [...new Set(dns.map((q) => str(q.resolver && q.resolver.ip)).filter(Boolean))];
  lines.push(
    `${conns.length} connection${conns.length === 1 ? "" : "s"} and ${dns.length} DNS quer${dns.length === 1 ? "y" : "ies"}` +
      (resolvers.length ? ` (resolvers: ${resolvers.join(", ")})` : "") +
      (p.all_closed ? "; all connections closed." : "; some connections are still open."),
  );
  for (const c of conns) {
    let s = `${str(c.proto)} from ${endpoint(c.src)} to port ${str(c.dst && c.dst.port)}`;
    if (c.requests) s += `, ${c.requests} request${c.requests === 1 ? "" : "s"}`;
    const ja4 = (c.http3 && c.http3.client_hello && c.http3.client_hello.ja4) || (c.tls && c.tls.ja4);
    if (ja4) s += `, JA4 ${ja4}`;
    if (c.tcp && c.tcp.ja4t) s += `, JA4T ${c.tcp.ja4t}`;
    s += c.ended ? `, closed (${str(c.close && c.close.how)})` : ", open";
    lines.push(s);
  }
  const used = new Set(conns.map((c) => str(c.proto)));
  lines.push([...used].some((x) => x.includes("h3")) ? "HTTP/3 was used." : "HTTP/3 was not used (yet).");
  return lines;
}

// ------------------------------------------------------------------ página (DOM)

function boot() {
  const api = resolveAPI(location.search);
  const $ = (id) => document.getElementById(id);
  const ui = {
    state: $("feed-state"),
    pause: $("pause"),
    pending: $("pending"),
    clear: $("clear"),
    run: $("run-probe"),
    form: $("filters"),
    feed: $("feed"),
    empty: $("feed-empty"),
    announce: $("announce"),
    probePanel: $("probe-panel"),
    probeTitle: $("probe-title"),
    probeSteps: $("probe-steps"),
    probeResult: $("probe-result"),
    detail: $("detail"),
    detailTitle: $("detail-title"),
    detailStatus: $("detail-status"),
    detailFields: $("detail-fields"),
    detailPre: $("detail-pre"),
    pcap: $("detail-pcap"),
    rawIn: $("detail-raw-in"),
    rawOut: $("detail-raw-out"),
    json: $("detail-json"),
    refresh: $("detail-refresh"),
    closeDetail: $("detail-close"),
  };
  let storage = null;
  try {
    storage = window.localStorage;
  } catch {
    storage = null;
  }

  const conns = new Map();
  const rowOf = new WeakMap(); // li → linha
  const connRow = new Map(); // conn_id → li da linha da conexão
  let filters = loadFilters(storage);
  let paused = false;
  let pending = [];
  let pendingLost = 0;
  let sinceAnnounce = 0;
  let selected = null;
  let detailID = null;

  for (const k of FILTER_KEYS) ui.form.elements[k].value = filters[k];

  const setText = (el, text) => {
    el.textContent = text;
  };
  const announce = (text) => setText(ui.announce, text);

  function setState(state, transport, waitMs) {
    if (paused && state === "live") state = "paused";
    ui.state.dataset.state = state;
    if (state === "live") setText(ui.state, `live (${transport})`);
    else if (state === "paused") setText(ui.state, "paused");
    else if (state === "reconnecting") setText(ui.state, `reconnecting in ${Math.round(waitMs / 1000)} s`);
    else setText(ui.state, `connecting (${transport})`);
  }
  let lastState = ["connecting", "WebSocket", 0];
  const onState = (s, t, w) => {
    const announceIt = s !== lastState[0] && s !== "connecting";
    lastState = [s, t || lastState[1], w];
    setState(s, lastState[1], w);
    if (announceIt) announce(`Feed ${ui.state.textContent}`);
  };

  function makeRowElement(row) {
    const li = document.createElement("li");
    const el = document.createElement(row.connID ? "button" : "div");
    if (row.connID) {
      el.type = "button";
      el.dataset.conn = row.connID;
    }
    el.className = row.closed ? "row closed" : "row";
    for (const [cls, text] of [
      ["ts", row.ts.slice(11, 23)],
      ["kind", row.label],
      ["proto", row.proto],
      ["what", row.what + (row.probe ? ` [probe ${row.probe}]` : "")],
    ]) {
      const span = document.createElement("span");
      span.className = cls;
      span.textContent = text;
      el.appendChild(span);
    }
    li.appendChild(el);
    if (row.warn) li.className = "warn";
    rowOf.set(li, row);
    li.hidden = !matchesFilter(row, filters);
    return li;
  }

  function trim() {
    while (ui.feed.children.length > MAX_ROWS) {
      const li = ui.feed.lastElementChild;
      const row = rowOf.get(li);
      if (row && row.connID && connRow.get(row.connID) === li) connRow.delete(row.connID);
      li.remove();
    }
    ui.empty.hidden = ui.feed.children.length > 0;
  }

  function apply(ev) {
    if (ev.kind.startsWith("connection.") && ev.data) rememberConn(conns, ev.data);
    const row = describeEvent(ev, conns);
    const isConn = row.kind.startsWith("connection.");
    if (isConn && row.connID && connRow.has(row.connID)) {
      // a conexão já tem linha: atualiza no lugar em vez de repetir
      const old = connRow.get(row.connID);
      const li = makeRowElement(row);
      if (old === selected) {
        li.classList.add("selected");
        selected = li;
      }
      old.replaceWith(li);
      connRow.set(row.connID, li);
      return;
    }
    const li = makeRowElement(row);
    ui.feed.prepend(li);
    if (isConn && row.connID) connRow.set(row.connID, li);
    sinceAnnounce++;
  }

  function updatePending() {
    ui.pending.hidden = !paused || pending.length === 0;
    const n = pending.length + pendingLost;
    setText(ui.pending, `${n} new`);
  }

  function onEvent(ev) {
    if (!LIVE_KINDS.includes(ev.kind)) return;
    if (paused) {
      pending.push(ev);
      if (pending.length > MAX_PENDING) {
        pending.shift();
        pendingLost++;
      }
      updatePending();
      return;
    }
    apply(ev);
    trim();
  }

  function setPaused(p) {
    paused = p;
    ui.pause.setAttribute("aria-pressed", String(p));
    setText(ui.pause, p ? "Resume" : "Pause");
    if (!p) {
      const queued = pending;
      pending = [];
      if (pendingLost > 0) {
        apply({ kind: "stream.dropped", ts: new Date().toISOString(), data: { dropped: pendingLost } });
        pendingLost = 0;
      }
      for (const ev of queued) apply(ev);
      trim();
    }
    updatePending();
    setState(lastState[0], lastState[1], lastState[2]);
    announce(p ? "Feed paused" : "Feed resumed");
  }

  function applyFilters() {
    const f = {};
    for (const k of FILTER_KEYS) f[k] = ui.form.elements[k].value;
    filters = normalizeFilters(f);
    saveFilters(storage, filters);
    for (const li of ui.feed.children) {
      const row = rowOf.get(li);
      if (row) li.hidden = !matchesFilter(row, filters);
    }
  }

  // ---------------------------------------------------------------- detalhe
  async function loadDetail(id) {
    detailID = id;
    const base = `${api}/api/v1/connections/${encodeURIComponent(id)}`;
    ui.detail.hidden = false;
    setText(ui.detailTitle, `Connection ${id}`);
    setText(ui.detailStatus, "Loading…");
    ui.detailFields.replaceChildren();
    setText(ui.detailPre, "");
    ui.pcap.href = `${base}/pcap`;
    ui.pcap.setAttribute("download", `${id}.pcap`);
    ui.rawIn.href = `${base}/raw?dir=in`;
    ui.rawOut.href = `${base}/raw?dir=out`;
    ui.json.href = base;
    ui.detail.focus();
    try {
      const res = await fetch(base, { cache: "no-store", credentials: "omit" });
      if (detailID !== id) return;
      if (res.status === 404) {
        setText(ui.detailStatus, "Not found: the record expired (10 minutes) or does not exist.");
        return;
      }
      if (!res.ok) throw new Error(`the API answered ${res.status}`);
      const rec = await res.json();
      if (detailID !== id) return;
      setText(ui.detailStatus, rec.ended ? "Closed; the record is complete." : "Still open; refresh for the latest state.");
      const frag = document.createDocumentFragment();
      for (const [k, v] of detailFields(rec)) {
        const dt = document.createElement("dt");
        dt.textContent = k;
        const dd = document.createElement("dd");
        dd.textContent = v;
        frag.append(dt, dd);
      }
      ui.detailFields.replaceChildren(frag);
      setText(ui.detailPre, JSON.stringify(rec, null, 2));
    } catch (e) {
      if (detailID === id) setText(ui.detailStatus, `Could not load the record: ${str(e && e.message)}`);
    }
  }

  ui.feed.addEventListener("click", (e) => {
    const btn = e.target instanceof Element ? e.target.closest("button.row") : null;
    if (!btn) return;
    if (selected) selected.classList.remove("selected");
    selected = btn.parentElement;
    selected.classList.add("selected");
    loadDetail(btn.dataset.conn);
  });
  ui.refresh.addEventListener("click", () => {
    if (detailID) loadDetail(detailID);
  });
  ui.closeDetail.addEventListener("click", () => {
    ui.detail.hidden = true;
    detailID = null;
    const btn = selected && selected.isConnected ? selected.querySelector("button.row") : null;
    if (selected) selected.classList.remove("selected");
    selected = null;
    if (btn) btn.focus();
  });

  // ---------------------------------------------------------------- run probe
  ui.run.addEventListener("click", async () => {
    const id = randomProbeID();
    ui.run.disabled = true;
    ui.form.elements.probe.value = id;
    applyFilters();
    ui.probePanel.hidden = false;
    setText(ui.probeTitle, `Probe ${id}`);
    ui.probeSteps.replaceChildren();
    ui.probeResult.replaceChildren();
    announce(`Running probe ${id}; the feed now shows only this probe`);
    const step = (label, ok, detail) => {
      const li = document.createElement("li");
      li.dataset.ok = String(ok);
      li.textContent = `${label}: ${ok ? "sent" : "failed"}`;
      li.title = detail;
      ui.probeSteps.appendChild(li);
    };
    const waiting = document.createElement("p");
    try {
      const resP = runProbe(id, {
        api,
        fetch: window.fetch.bind(window),
        WebSocket: window.WebSocket,
        pageProtocol: location.protocol,
        onStep: (label, ok, detail) => {
          step(label, ok, detail);
          if (label.startsWith("WebSocket")) {
            waiting.textContent = "Waiting for the record (up to 10 s, until the connections close)…";
            ui.probeResult.replaceChildren(waiting);
          }
        },
      });
      const p = await resP;
      const ul = document.createElement("ul");
      for (const line of summarizeProbe(p)) {
        const li = document.createElement("li");
        li.textContent = line;
        ul.appendChild(li);
      }
      const link = document.createElement("a");
      link.href = `${api}/api/v1/probes/${id}`;
      link.textContent = "Full probe record (JSON)";
      ui.probeResult.replaceChildren(ul, link);
      announce(`Probe ${id} finished`);
    } catch (e) {
      const err = document.createElement("p");
      err.textContent = `Probe failed: ${str(e && e.message)}`;
      ui.probeResult.replaceChildren(err);
    } finally {
      ui.run.disabled = false;
    }
  });

  ui.pause.addEventListener("click", () => setPaused(!paused));
  ui.clear.addEventListener("click", () => {
    ui.feed.replaceChildren();
    connRow.clear();
    selected = null;
    trim();
  });
  ui.form.addEventListener("input", applyFilters);
  ui.form.addEventListener("submit", (e) => e.preventDefault());
  ui.form.addEventListener("reset", () => setTimeout(applyFilters, 0));

  // anúncio moderado para leitores de tela: no máximo um resumo por minuto
  setInterval(() => {
    if (!paused && sinceAnnounce > 0) announce(`${sinceAnnounce} new events in the feed`);
    sinceAnnounce = 0;
  }, ANNOUNCE_EVERY_MS);

  const feed = new LiveFeed({
    api,
    onEvent,
    onState,
    env: {
      WebSocket: window.WebSocket,
      EventSource: window.EventSource,
      setTimeout: window.setTimeout.bind(window),
      clearTimeout: window.clearTimeout.bind(window),
    },
  });
  feed.start();
  window.addEventListener("pagehide", () => feed.stop());
  // volta do bfcache: a conexão foi fechada no pagehide
  window.addEventListener("pageshow", (e) => {
    if (e.persisted) feed.start();
  });
}

if (typeof document !== "undefined" && document.getElementById("feed")) boot();
