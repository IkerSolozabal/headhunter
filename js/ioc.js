// Extracción y clasificación de IOC a partir de un mensaje parseado (ver eml.js).

export const CATEGORIES = [
  { id: "ip", label: "Direcciones IP", color: "#22d3ee", icon: "ip" },
  { id: "domain", label: "Dominios", color: "#a855f7", icon: "globe" },
  { id: "hostname", label: "Hostnames", color: "#818cf8", icon: "server" },
  { id: "url", label: "URLs", color: "#f472b6", icon: "link" },
  { id: "email", label: "Emails", color: "#34d399", icon: "mail" },
  { id: "hash", label: "Hashes", color: "#fbbf24", icon: "hash" },
  { id: "file", label: "Ficheros adjuntos", color: "#fb923c", icon: "file" },
  { id: "other", label: "Otros (Message-ID, X-Mailer…)", color: "#94a3b8", icon: "tag" },
];

// ---------------------------------------------------------------- TLDs

const CCTLD = "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw";
const GTLD = "com net org info biz edu gov mil int arpa name pro mobi asia tel travel jobs museum aero coop cat xxx post " +
  "app dev page xyz top online site club shop store tech live life world space website icu vip email link click download win bid loan review men date racing stream trade party science work " +
  "cloud digital agency services solutions support help network systems center company group media news blog today zone one global tools host hosting fun games guru ninja rocks lol wtf " +
  "cyou cfd sbs bond quest rest beauty hair skin makeup monster autos boats homes motorcycles yachts buzz casa uno lat surf fit ink run social sale deals cash money finance financial bank " +
  "insure loans credit capital fund investments market markets exchange trading business consulting management marketing photo photos pics pictures gallery design art studio academy " +
  "education school university college institute training courses health care clinic dental doctor hospital legal law lawyer attorney realestate realty properties property house land " +
  "estate build construction contractors energy solar green eco city country berlin london paris nyc tokyo amsterdam barcelona madrid eus gal moscow wien vegas miami africa " +
  "best bar bet bio black blue red pink cam camp care cards casino center chat cheap city codes coffee community computer cool country coupons cricket dating deal delivery " +
  "direct directory discount domains express fail family farm fashion feedback film fish fitness florist football foundation free fyi gift gifts gold golf graphics gripe guide " +
  "holdings holiday house immo industries international investments jewelry kim kitchen lgbt lighting limited limo live ltd luxury maison marketing mba media memorial moda " +
  "mom movie network ngo ong onl ooo partners parts pet place plus poker porn press productions promo pub recipes rehab rent report rip rocks run sex sexy shoes show singles " +
  "ski soccer software solutions spa store stream style sucks supply supplies surgery systems tax taxi team tech technology tips tires today top tours town toys trade " +
  "university vacations ventures vet viajes video villas vin vision vodka vote voyage wang watch webcam website wiki win wine work works world wtf xin yoga zip mov foo nexus " +
  "google microsoft apple amazon windows office azure aws gmail youtube android chrome play icloud live hotmail outlook yahoo";
const TLDS = new Set((CCTLD + " " + GTLD).split(/\s+/));

// TLDs reales que también son extensiones de fichero/código habituales: en texto libre
// solo los aceptamos si aparecen en un contexto estructurado (URL, email, Received…).
const AMBIGUOUS_TLDS = new Set("zip mov sh md ps pl py rs so one pub tf pm ml cc".split(" "));

// Sufijos públicos de dos o más etiquetas más comunes (eTLD) y plataformas de hosting
// donde cada subdominio pertenece a un cliente distinto.
const MULTI_SUFFIX = new Set((
  "co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk nhs.uk police.uk " +
  "com.au net.au org.au edu.au gov.au asn.au id.au co.nz org.nz net.nz govt.nz ac.nz " +
  "com.br net.br org.br gov.br edu.br co.jp ne.jp or.jp ac.jp go.jp com.mx org.mx gob.mx net.mx edu.mx " +
  "com.ar gob.ar net.ar org.ar com.cn net.cn org.cn gov.cn edu.cn com.tw org.tw com.hk org.hk com.sg com.my " +
  "co.in net.in org.in gov.in ac.in co.za org.za gov.za com.tr gov.tr org.tr co.kr or.kr co.il org.il ac.il " +
  "com.es org.es gob.es nom.es edu.es com.pe gob.pe com.co gov.co com.ve com.ec com.uy com.py com.bo com.pa " +
  "com.do com.gt com.sv com.ni com.cu co.cr co.th or.th co.id or.id ac.id com.ph com.vn com.pk com.ng com.eg " +
  "com.sa com.ua co.ua com.pl net.pl org.pl com.ru msk.ru spb.ru co.at or.at ac.at com.gr co.hu com.pt com.ro " +
  "co.ke co.tz co.ug com.cy com.mt com.lb com.qa com.kw com.bh com.om co.ae " +
  "github.io gitlab.io herokuapp.com azurewebsites.net cloudapp.net web.app firebaseapp.com appspot.com " +
  "blogspot.com workers.dev pages.dev vercel.app netlify.app glitch.me ngrok.io ngrok-free.app r2.dev " +
  "onrender.com repl.co wixsite.com weebly.com 000webhostapp.com duckdns.org s3.amazonaws.com " +
  "cloudfront.net trycloudflare.com myshopify.com sharepoint.com"
).split(/\s+/));

const INTERNAL_TLDS = new Set(["local", "lan", "internal", "localdomain", "corp", "home", "intranet", "private", "localhost"]);

// ---------------------------------------------------------------- utilidades

const HOST_RE_SRC = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})";
const HOST_EXACT = new RegExp(`^${HOST_RE_SRC}$`, "i");
const IPV4_SRC = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}";
const IPV4_EXACT = new RegExp(`^${IPV4_SRC}$`);

/** Revierte el "defang" habitual: hxxp, [.], (.), [at], [:]… */
export function refang(s) {
  return s
    .replace(/\bh(?:xx|\*\*|XX)p(s?)(\[:\]|:)?\/\//gi, "http$1://")
    .replace(/\bfxp:\/\//gi, "ftp://")
    .replace(/\s?[[({]\s?(?:\.|dot)\s?[\])}]\s?/gi, ".")
    .replace(/\s?[[({]\s?(?:@|at)\s?[\])}]\s?/gi, "@")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/");
}

export function defang(value, cat) {
  if (cat === "hash" || cat === "file" || cat === "other") return value;
  let v = value.replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp");
  if (cat === "email") return v.replace(/@/, "[@]").replace(/\.(?=[^.]*$)/, "[.]");
  if (cat === "ip" && v.includes(":")) return v.replace(/:/g, "[:]");
  // Sustituye el último punto del host para que deje de ser clicable.
  if (cat === "url") {
    return v.replace(/^([a-z]+:\/\/)([^/?#]+)/i, (_, p, host) => p + host.replace(/\./g, "[.]"));
  }
  return v.replace(/\./g, "[.]");
}

const ENTITY_MAP = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEntities(s) {
  return s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENTITY_MAP[e.toLowerCase()] ?? m;
  });
}

function tldOf(host) { return host.slice(host.lastIndexOf(".") + 1).toLowerCase(); }

export function isValidHost(host, strict) {
  if (!host || host.length > 253 || !HOST_EXACT.test(host)) return false;
  const tld = tldOf(host);
  if (tld.startsWith("xn--")) return true;
  if (!strict) return /^[a-z]{2,24}$/.test(tld);
  return TLDS.has(tld) && !AMBIGUOUS_TLDS.has(tld);
}

export function registrableDomain(host) {
  host = host.toLowerCase().replace(/\.$/, "");
  const labels = host.split(".");
  if (labels.length < 2) return null;
  if (INTERNAL_TLDS.has(labels[labels.length - 1])) return null;
  for (let n = Math.min(4, labels.length - 1); n >= 2; n--) {
    const suffix = labels.slice(-n).join(".");
    if (MULTI_SUFFIX.has(suffix)) {
      return labels.length > n ? labels.slice(-(n + 1)).join(".") : null;
    }
  }
  return labels.slice(-2).join(".");
}

function ipv4ToInt(ip) { return ip.split(".").reduce((a, o) => (a << 8) + +o, 0) >>> 0; }
const V4_RESERVED = [
  ["0.0.0.0", 8, "Reservada"], ["10.0.0.0", 8, "Privada"], ["100.64.0.0", 10, "CGNAT"],
  ["127.0.0.0", 8, "Loopback"], ["169.254.0.0", 16, "Link-local"], ["172.16.0.0", 12, "Privada"],
  ["192.0.0.0", 24, "Reservada"], ["192.0.2.0", 24, "Documentación"], ["192.168.0.0", 16, "Privada"],
  ["198.18.0.0", 15, "Benchmark"], ["198.51.100.0", 24, "Documentación"], ["203.0.113.0", 24, "Documentación"],
  ["224.0.0.0", 4, "Multicast"], ["240.0.0.0", 4, "Reservada"],
].map(([base, bits, label]) => [ipv4ToInt(base), bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0, label]);

/** Devuelve null si la IP es pública, o una etiqueta (Privada, Loopback…). */
export function ipScope(ip) {
  if (IPV4_EXACT.test(ip)) {
    const n = ipv4ToInt(ip);
    for (const [base, mask, label] of V4_RESERVED) if ((n & mask) >>> 0 === base) return label;
    return null;
  }
  const v = ip.toLowerCase();
  if (v === "::1") return "Loopback";
  if (v === "::") return "Reservada";
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (m) return ipScope(m[1]);
  const first = parseInt(v.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return "Privada (ULA)";
  if ((first & 0xffc0) === 0xfe80) return "Link-local";
  if ((first & 0xff00) === 0xff00) return "Multicast";
  if (v.startsWith("2001:db8:") || v.startsWith("2001:0db8:")) return "Documentación";
  return null;
}

/** Normaliza IPv6 a su forma comprimida canónica, o null si no es válida. */
export function normalizeIPv6(s) {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(":")) return null;
  try {
    const host = new URL(`http://[${s}]/`).hostname;
    return host.slice(1, -1);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- recolector

class Collector {
  constructor() { this.map = new Map(); }

  add(cat, value, source, meta) {
    if (!value) return;
    const key = cat + "|" + (cat === "url" || cat === "other" || cat === "file" ? value : value.toLowerCase());
    let item = this.map.get(key);
    if (!item) {
      item = { cat, value: cat === "url" || cat === "other" || cat === "file" ? value : value.toLowerCase(), sources: new Set(), meta: {} };
      this.map.set(key, item);
    }
    if (source) item.sources.add(source);
    if (meta) Object.assign(item.meta, meta);
    return item;
  }

  addHost(host, source, opts = {}) {
    if (!host) return;
    host = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
    if (IPV4_EXACT.test(host)) return this.addIp(host, source);
    if (host.includes(":")) return this.addIp(host, source);
    if (!host.includes(".")) {
      // Nombre de una sola etiqueta (HELO de un PC, p. ej. WIN-8K2JD7).
      if (opts.allowSingleLabel && /^[a-z0-9][a-z0-9_-]{1,62}$/i.test(host) && !/^(unknown|localhost|localhost\.localdomain)$/i.test(host)) {
        this.add("hostname", host, source, { tags: ["Sin dominio"] });
      }
      return;
    }
    if (!isValidHost(host, !!opts.strict)) return;
    if (host.endsWith(".in-addr.arpa") || host.endsWith(".ip6.arpa")) return;
    const tld = tldOf(host);
    const internal = INTERNAL_TLDS.has(tld);
    const reg = registrableDomain(host);
    if (reg && reg !== host) this.add("hostname", host, source);
    else if (!reg) this.add("hostname", host, source, internal ? { tags: ["Interno"] } : undefined);
    if (reg) this.add("domain", reg, source);
  }

  addIp(ip, source, meta) {
    let v = ip.replace(/^\[|\]$/g, "");
    if (v.toLowerCase().startsWith("ipv6:")) v = v.slice(5);
    if (IPV4_EXACT.test(v)) {
      v = v.split(".").map((o) => String(+o)).join(".");
    } else {
      v = normalizeIPv6(v);
      if (!v) return;
      const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
      if (mapped) v = mapped[1];
    }
    const scope = ipScope(v);
    return this.add("ip", v, source, { version: v.includes(":") ? 6 : 4, scope, ...(meta || {}) });
  }

  addEmail(addr, source) {
    addr = addr.trim().replace(/^mailto:/i, "").replace(/[>.,;]+$/, "");
    const at = addr.lastIndexOf("@");
    if (at < 1) return;
    const local = addr.slice(0, at);
    const host = addr.slice(at + 1).toLowerCase();
    if (!isValidHost(host, false)) return;
    if (local.length > 64) return;
    this.add("email", `${local}@${host}`, source);
    this.addHost(host, source);
  }

  addUrl(raw, source) {
    let url = cleanUrl(raw);
    if (!url) return;
    let parsed;
    try { parsed = new URL(url); } catch { return; }
    if (!/^(https?|ftp|ftps|wss?):$/i.test(parsed.protocol)) return;
    if (!parsed.hostname) return;
    this.add("url", url, source);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    this.addHost(host, source);
  }

  list() { return [...this.map.values()]; }
}

function cleanUrl(u) {
  u = decodeEntities(u.trim());
  u = u.replace(/^[<"'(]+/, "");
  // Recorta puntuación final y paréntesis/corchetes desbalanceados.
  for (;;) {
    const before = u;
    u = u.replace(/[.,;:!?'"*>]+$/, "");
    if (u.endsWith(")") && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) u = u.slice(0, -1);
    if (u.endsWith("]") && (u.match(/\[/g) || []).length < (u.match(/\]/g) || []).length) u = u.slice(0, -1);
    if (u === before) break;
  }
  return u.length > 10 ? u : "";
}

// ---------------------------------------------------------------- extractores de texto

const URL_RE = /\b(?:https?|ftps?|wss?):\/\/[^\s"'<>`{}|\\^ ​]+/gi;
const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9-]{2,59})\b/g;
const IPV4_RE = new RegExp(`(?<![\\d.])${IPV4_SRC}(?![\\d]|\\.\\d)`, "g");
const IPV6_RE = /(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){1,7}(?::|[0-9a-f]{1,4})(?::[0-9a-f]{1,4}){0,6}(?![0-9a-f:])|(?<![0-9a-f:])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![0-9a-f:])/gi;
const HOST_RE = new RegExp(`(?<![a-z0-9@._-])${HOST_RE_SRC}(?![a-z0-9-]|\\.[a-z0-9])`, "gi");

function scanIps(text, c, source) {
  for (const m of text.matchAll(IPV4_RE)) c.addIp(m[0], source);
  for (const m of text.matchAll(IPV6_RE)) {
    const s = m[0];
    // Evita horas (08:14:22), MACs y similares: exige "::" o 8 grupos.
    const groups = s.split(":").length;
    if (!s.includes("::") && groups < 8) continue;
    if (s.replace(/:/g, "").length < 3) continue;
    c.addIp(s, source);
  }
}

/** Extracción genérica sobre texto libre. */
function scanText(text, c, source, { domains = true, html = false } = {}) {
  if (!text) return;
  let t = html ? decodeEntities(text) : text;
  t = refang(t);
  // URLs
  for (const m of t.matchAll(URL_RE)) c.addUrl(m[0], source);
  // mailto: y emails
  for (const m of t.matchAll(EMAIL_RE)) {
    const prev = t.slice(Math.max(0, m.index - 4), m.index);
    if (/cid:$/i.test(prev)) continue;
    c.addEmail(m[0], source);
  }
  scanIps(t, c, source);
  if (domains) {
    // Quitamos URLs y emails ya procesados para reducir ruido.
    const rest = t.replace(URL_RE, " ").replace(EMAIL_RE, " ");
    for (const m of rest.matchAll(HOST_RE)) {
      const host = m[0];
      if (/^\d+(\.\d+)+$/.test(host)) continue;
      c.addHost(host, source, { strict: true });
    }
  }
}

function stripHtmlForText(html) {
  // Conserva atributos (href, src, action…) para que las URLs sigan presentes.
  return html.replace(/<style[\s\S]*?<\/style>/gi, " ");
}

// ---------------------------------------------------------------- cabeceras

const ADDRESS_HEADERS = /^(from|to|cc|bcc|reply-to|sender|return-path|delivered-to|x-original-to|x-original-from|x-envelope-from|x-envelope-to|errors-to|disposition-notification-to|resent-from|resent-to|resent-cc|resent-sender|return-receipt-to|x-forwarded-to|x-forwarded-for|x-sender|x-receiver|x-apparently-to|x-original-sender|envelope-to|x-ms-exchange-organization-originalsender|x-failed-recipients|x-google-original-from)$/i;
const ID_HEADERS = /^(message-id|in-reply-to|references|resent-message-id|x-ms-tnef-correlator|original-message-id|x-microsoft-original-message-id|x-original-message-id)$/i;
const MAILER_HEADERS = /^(x-mailer|user-agent|x-mimeole|x-php-originating-script|x-php-script|x-source|x-source-args|x-source-dir|x-originating-script)$/i;
// Cabeceras muy ruidosas (blobs de antispam de Microsoft, firmas…): sin búsqueda libre de dominios.
const NOISY_HEADERS = /^(x-ms-exchange-|x-microsoft-antispam|x-forefront-|x-ms-office365-|x-ms-publictraffictype|x-ms-traffictypediagnostic|arc-seal|arc-message-signature|dkim-signature|x-google-dkim-signature|x-gm-message-state|x-google-smtp-source|x-received|x-ms-oob-tlc|x-eopattributedmessage|x-eoptenantattributedmessage|x-mailgun-|content-type|content-transfer-encoding|mime-version|thread-index|x-ms-has-attach)/i;

function handleReceived(value, c, label) {
  // from HOST (RDNS [IP])  by HOST  helo=X  envelope-from <x>
  const v = value;
  const from = /\bfrom\s+([^\s;()]+)/i.exec(v);
  if (from) c.addHost(from[1], label, { allowSingleLabel: true });
  const by = /\bby\s+([^\s;()]+)/i.exec(v);
  if (by) c.addHost(by[1], label, { allowSingleLabel: true });
  for (const m of v.matchAll(/\b(?:helo|ehlo)[=\s]+([^\s;()\]]+)/gi)) c.addHost(m[1], label, { allowSingleLabel: true });
  // Nombres dentro de paréntesis: (rdns.example.com [1.2.3.4]) o (HELO x)
  for (const m of v.matchAll(/\(([^()\s[\]]+)\s*\[/g)) c.addHost(m[1], label, { allowSingleLabel: false });
  for (const m of v.matchAll(/<([^<>\s]+@[^<>\s]+)>/g)) c.addEmail(m[1], label);
  for (const m of v.matchAll(/\bfor\s+<?([^\s<>;]+@[^\s<>;]+?)>?[;\s]/gi)) c.addEmail(m[1], label);
  scanIps(v, c, label);
}

function handleAuth(value, c, label) {
  for (const m of value.matchAll(/\b(?:smtp\.mailfrom|envelope-from|header\.from|header\.i|header\.d|smtp\.helo|policy\.d|header\.s)=["']?([^\s;"')]+)/gi)) {
    const v = m[1].replace(/^@/, "");
    if (v.includes("@")) c.addEmail(v, label);
    else c.addHost(v, label);
  }
  for (const m of value.matchAll(/\b(?:d|i)=@?([a-z0-9.-]+\.[a-z]{2,24})\b/gi)) c.addHost(m[1], label);
  for (const m of value.matchAll(/\b(?:client-ip|smtp\.remote-ip|sender IP is|ip)=?\s*([0-9a-f.:]+)/gi)) c.addIp(m[1], label);
  for (const m of value.matchAll(/\bhelo=([^\s;]+)/gi)) c.addHost(m[1], label, { allowSingleLabel: true });
  for (const m of value.matchAll(/\b(?:envelope-from|receiver|mailfrom)=["<]?([^\s;">]+@[^\s;">]+)/gi)) c.addEmail(m[1], label);
  scanIps(value, c, label);
}

function handleHeader(h, c, prefix) {
  const name = h.name.trim();
  const lname = name.toLowerCase();
  const label = prefix + name;
  const value = h.value;
  if (!value) return;

  if (lname === "received" || lname === "x-received") return handleReceived(value, c, label);
  if (/^(authentication-results|arc-authentication-results|received-spf|x-ms-exchange-authentication-results|x-forefront-antispam-report|x-ms-exchange-organization-authas)$/i.test(lname)) {
    handleAuth(value, c, label);
    if (lname !== "x-forefront-antispam-report") return;
  }
  if (lname === "dkim-signature" || lname === "x-google-dkim-signature" || lname === "arc-message-signature") {
    const d = /\bd=([^\s;]+)/i.exec(value);
    if (d) c.addHost(d[1], label);
    const i = /\bi=@?([^\s;]+)/i.exec(value);
    if (i) (i[1].includes("@") ? c.addEmail(i[1], label) : c.addHost(i[1], label));
    return;
  }
  if (ID_HEADERS.test(lname)) {
    for (const m of value.matchAll(/<([^<>\s]+)>/g)) {
      c.add("other", `<${m[1]}>`, label, { kind: name });
      const host = m[1].split("@")[1];
      if (host) c.addHost(host, label);
    }
    if (!/<[^>]+>/.test(value) && value.length < 300) c.add("other", value, label, { kind: name });
    return;
  }
  if (MAILER_HEADERS.test(lname)) {
    c.add("other", value, label, { kind: name });
    scanText(value, c, label, { domains: false });
    return;
  }
  if (/^x-(originating|sender|source|client|remote|real|forwarded)-?(ip|addr|address)?$/i.test(lname) || /-ip$/i.test(lname) || lname === "x-originating-ip") {
    scanIps(value, c, label);
  }
  if (ADDRESS_HEADERS.test(lname)) {
    for (const m of value.matchAll(EMAIL_RE)) c.addEmail(m[0], label);
    // Nombre visible que contiene a su vez otra dirección (spoofing típico).
    scanText(value, c, label, { domains: false });
    return;
  }
  scanText(value, c, label, { domains: !NOISY_HEADERS.test(lname) });
}

// ---------------------------------------------------------------- API

/**
 * @param parsed resultado de parseEml
 * @param extra { fileName, fileHashes: {md5,sha1,sha256}, attachmentHashes: Map(attachment -> {md5,sha1,sha256}) }
 */
export function extractIocs(parsed, extra = {}) {
  const c = new Collector();

  // Cabeceras del mensaje principal (orden original) y de mensajes anidados.
  for (const h of parsed.headers) handleHeader(h, c, "");
  parsed.nested.forEach((n, i) => {
    for (const h of n.headers) handleHeader(h, c, `Adjunto .eml #${i + 1} · `);
  });

  // Saltos Received: numeramos desde el origen (el último Received es el primero en el tiempo).
  const received = parsed.headers.filter((h) => /^received$/i.test(h.name));
  received.forEach((h, idx) => {
    const hop = received.length - idx;
    for (const m of h.value.matchAll(IPV4_RE)) tagHop(c, m[0], hop);
    for (const m of h.value.matchAll(IPV6_RE)) {
      const n = normalizeIPv6(m[0]);
      if (n) tagHop(c, n, hop);
    }
  });

  // Cuerpos.
  for (const t of parsed.texts) {
    const isHtml = /html/.test(t.type);
    const src = t.attachment ? `Adjunto: ${t.attachment}` : isHtml ? "Cuerpo HTML" : "Cuerpo texto";
    scanText(isHtml ? stripHtmlForText(t.content) : t.content, c, src, { html: isHtml });
  }

  // Adjuntos binarios: solo URLs y emails visibles en sus cadenas (p. ej. /URI en PDFs).
  for (const a of parsed.attachments) {
    if (/^text\//.test(a.contentType) || a.contentType === "message/rfc822") continue;
    if (a.size > 15 * 1024 * 1024) continue;
    const ascii = asciiStrings(a.bytes);
    const src = `Adjunto: ${a.filename}`;
    for (const m of ascii.matchAll(URL_RE)) c.addUrl(m[0], src);
    for (const m of ascii.matchAll(EMAIL_RE)) c.addEmail(m[0], src);
  }

  // Ficheros y hashes.
  const hashes = extra.attachmentHashes || new Map();
  for (const a of parsed.attachments) {
    const meta = { size: a.size, contentType: a.contentType, inline: a.inline };
    c.add("file", a.filename, "Adjunto", meta);
    const hs = hashes.get(a);
    if (hs) for (const kind of ["md5", "sha1", "sha256"]) {
      c.add("hash", hs[kind], `Adjunto: ${a.filename}`, { kind: kind.toUpperCase(), file: a.filename });
    }
  }
  if (extra.fileHashes) {
    for (const kind of ["md5", "sha1", "sha256"]) {
      c.add("hash", extra.fileHashes[kind], "Archivo .eml", { kind: kind.toUpperCase(), file: extra.fileName || "mensaje.eml", isEml: true });
    }
  }

  const items = c.list();
  for (const it of items) it.sources = [...it.sources];
  return items;
}

function tagHop(c, ip, hop) {
  const v = ip.includes(":") ? normalizeIPv6(ip) : ip.split(".").map((o) => String(+o)).join(".");
  const it = v && c.map.get("ip|" + v.toLowerCase());
  if (it && !it.meta.hop) it.meta.hop = hop;
}

function asciiStrings(bytes) {
  // Convierte a texto conservando solo caracteres imprimibles (como `strings`).
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, i + CHUNK);
    let s = "";
    for (let j = 0; j < slice.length; j++) {
      const b = slice[j];
      s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "\n";
    }
    out += s;
  }
  return out;
}

/** Datos de resumen para la cabecera de resultados. */
export function summarize(parsed) {
  const get = (n) => parsed.headers.find((h) => h.name.toLowerCase() === n)?.value || "";
  const auth = parsed.headers.filter((h) => /^(authentication-results|arc-authentication-results)$/i.test(h.name)).map((h) => h.value).join(" ");
  const spfHdr = get("received-spf");
  const res = (k) => {
    const m = new RegExp(`\\b${k}=(\\w+)`, "i").exec(auth);
    if (m) return m[1].toLowerCase();
    if (k === "spf" && spfHdr) return spfHdr.split(/\s/)[0].toLowerCase();
    return null;
  };
  return {
    subject: get("subject"),
    from: get("from"),
    to: get("to"),
    cc: get("cc"),
    replyTo: get("reply-to"),
    returnPath: get("return-path"),
    date: get("date"),
    messageId: get("message-id"),
    spf: res("spf"),
    dkim: res("dkim"),
    dmarc: res("dmarc"),
    hops: parsed.headers.filter((h) => /^received$/i.test(h.name)).length,
    attachments: parsed.attachments.length,
  };
}
