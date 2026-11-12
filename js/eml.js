// Parser MIME/EML minimalista y tolerante, sin dependencias.
// Trabaja sobre "cadenas binarias" (1 carácter = 1 byte) para no perder bytes
// de los adjuntos y decodificar cada parte con su charset real.

const MAX_DEPTH = 12;

/** ArrayBuffer | Uint8Array -> cadena binaria (latin1 byte a byte). */
export function bytesToBinary(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function binaryToBytes(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

function normalizeCharset(cs) {
  if (!cs) return "utf-8";
  cs = cs.trim().toLowerCase().replace(/^["']|["']$/g, "");
  if (cs === "ascii" || cs === "us-ascii" || cs === "ansi_x3.4-1968") return "utf-8";
  if (cs === "utf8") return "utf-8";
  if (cs === "latin1" || cs === "latin-1") return "iso-8859-1";
  return cs;
}

/** Decodifica bytes con un charset; si falla, cae a utf-8 y luego a windows-1252. */
export function decodeBytes(bytes, charset) {
  const cs = normalizeCharset(charset);
  try {
    return new TextDecoder(cs, { fatal: cs === "utf-8" }).decode(bytes);
  } catch {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { return new TextDecoder("windows-1252").decode(bytes); }
  }
}

function decodeBinaryText(bin, charset) {
  // Atajo: si es ASCII puro no hace falta decodificar.
  if (!/[\x80-\xff]/.test(bin)) return bin;
  return decodeBytes(binaryToBytes(bin), charset);
}

export function decodeBase64ToBinary(str) {
  const clean = str.replace(/[^A-Za-z0-9+/]/g, "");
  const padded = clean.length % 4 === 1 ? clean.slice(0, -1) : clean;
  try {
    return atob(padded + "===".slice((padded.length + 3) % 4));
  } catch {
    return "";
  }
}

export function decodeQuotedPrintable(str) {
  return str
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** RFC 2047: =?charset?B|Q?texto?= */
export function decodeEncodedWords(value) {
  // Espacios entre dos encoded-words consecutivas se ignoran.
  const joined = value.replace(/(\?=)\s+(=\?)/g, "$1$2");
  return joined.replace(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs, enc, text) => {
    cs = cs.split("*")[0]; // RFC 2231 idioma: charset*lang
    let bin;
    if (enc.toUpperCase() === "B") bin = decodeBase64ToBinary(text);
    else bin = decodeQuotedPrintable(text.replace(/_/g, " "));
    return decodeBytes(binaryToBytes(bin), cs);
  });
}

/** Valor de cabecera en bruto (binario) -> texto legible. */
export function decodeHeaderValue(raw) {
  return decodeEncodedWords(decodeBinaryText(raw, "utf-8")).replace(/\s+/g, " ").trim();
}

function splitHeadBody(raw) {
  const m = /\r?\n\r?\n/.exec(raw);
  if (!m) return { head: raw, body: "" };
  // Si el mensaje empieza directamente con línea en blanco no hay cabeceras.
  return { head: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

/** Devuelve [{name, raw, value}] respetando orden y duplicados. */
export function parseHeaders(head) {
  const lines = head.split(/\r?\n/);
  const out = [];
  let cur = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && cur) {
      cur.raw += "\n" + line;
      continue;
    }
    const idx = line.indexOf(":");
    if (idx > 0 && !/\s/.test(line.slice(0, idx))) {
      cur = { name: line.slice(0, idx), raw: line.slice(idx + 1) };
      out.push(cur);
    } else if (line.startsWith("From ") && out.length === 0) {
      // Línea "From " de formato mbox: se ignora.
      continue;
    }
  }
  for (const h of out) {
    h.raw = h.raw.replace(/\r?\n[ \t]+/g, " ").trim();
    h.value = decodeHeaderValue(h.raw);
  }
  return out;
}

/** Parsea "type/sub; a=b; c="d"" con soporte RFC 2231 (name*=, name*0*=). */
export function parseParams(value) {
  const parts = [];
  let buf = "", inQ = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '"' && value[i - 1] !== "\\") inQ = !inQ;
    if (c === ";" && !inQ) { parts.push(buf); buf = ""; continue; }
    buf += c;
  }
  parts.push(buf);
  const main = parts.shift().trim().toLowerCase();
  const raw = {};
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1).replace(/\\(.)/g, "$1");
    raw[k] = v;
  }
  // Reensamblar continuaciones RFC 2231.
  const params = {};
  const cont = {};
  for (const [k, v] of Object.entries(raw)) {
    const m = /^([^*]+)\*(\d+)?(\*)?$/.exec(k);
    if (!m) { params[k] = v; continue; }
    const [, base, num, star] = m;
    (cont[base] ||= []).push({ n: num ? +num : 0, v, enc: !!star || (!num && k.endsWith("*")) });
  }
  for (const [base, segs] of Object.entries(cont)) {
    segs.sort((a, b) => a.n - b.n);
    let charset = "utf-8";
    let bin = "";
    segs.forEach((s, i) => {
      let v = s.v;
      if (s.enc) {
        if (i === 0) {
          const mm = /^([^']*)'[^']*'(.*)$/.exec(v);
          if (mm) { charset = mm[1] || charset; v = mm[2]; }
        }
        v = v.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      }
      bin += v;
    });
    params[base] = decodeBytes(binaryToBytes(bin), charset);
  }
  for (const k of Object.keys(params)) {
    if (/=\?/.test(params[k])) params[k] = decodeEncodedWords(params[k]);
    else if (/[\x80-\xff]/.test(params[k])) params[k] = decodeBinaryText(params[k], "utf-8");
  }
  return { value: main, params };
}

function getHeader(headers, name) {
  name = name.toLowerCase();
  const h = headers.find((x) => x.name.toLowerCase() === name);
  return h ? h.raw : "";
}

function decodeTransfer(body, cte) {
  cte = (cte || "").trim().toLowerCase();
  if (cte === "base64") return decodeBase64ToBinary(body);
  if (cte === "quoted-printable") return decodeQuotedPrintable(body);
  return body;
}

function splitMultipart(body, boundary) {
  const esc = boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?:^|\\r?\\n)--${esc}(--)?[ \\t]*(?=\\r?\\n|$)`, "g");
  const parts = [];
  let last = -1, m;
  while ((m = re.exec(body))) {
    if (last >= 0) parts.push(body.slice(last, m.index));
    if (m[1]) { last = -1; break; }
    // Saltar el salto de línea tras el delimitador.
    const nl = /^\r?\n/.exec(body.slice(re.lastIndex));
    last = re.lastIndex + (nl ? nl[0].length : 0);
  }
  if (last >= 0) parts.push(body.slice(last)); // mensaje truncado sin cierre
  return parts;
}

/**
 * Parsea un mensaje completo.
 * @returns {{headers, texts:[{type, content, path}], attachments:[{filename, contentType, size, bytes, inline, path}], nested:[]}}
 */
export function parseEml(input) {
  const raw = typeof input === "string" ? input : bytesToBinary(input);
  const result = { headers: [], texts: [], attachments: [], nested: [] };
  const { head } = splitHeadBody(raw);
  result.headers = parseHeaders(head);
  walk(raw, result, "1", 0);
  return result;
}

function walk(raw, result, path, depth) {
  if (depth > MAX_DEPTH) return;
  const { head, body } = splitHeadBody(raw);
  const headers = parseHeaders(head);
  const ct = parseParams(getHeader(headers, "content-type") || "text/plain");
  const cd = parseParams(getHeader(headers, "content-disposition") || "");
  const cte = getHeader(headers, "content-transfer-encoding");
  const type = ct.value || "text/plain";

  if (type.startsWith("multipart/")) {
    const boundary = ct.params.boundary;
    if (!boundary) { result.texts.push({ type: "text/plain", content: decodeBinaryText(body), path }); return; }
    splitMultipart(body, boundary).forEach((p, i) => walk(p, result, `${path}.${i + 1}`, depth + 1));
    return;
  }

  const filename = cd.params.filename || ct.params.name || "";
  const disposition = cd.value;
  const decoded = decodeTransfer(body, cte);

  if (type === "message/rfc822" || type === "message/global") {
    const nested = parseEml(decoded);
    nested.path = path;
    result.nested.push(nested);
    result.attachments.push(makeAttachment(filename || "mensaje-adjunto.eml", type, decoded, disposition, path));
    // Los textos/adjuntos del mensaje anidado también cuentan.
    result.texts.push(...nested.texts);
    result.attachments.push(...nested.attachments);
    return;
  }

  const isText = type.startsWith("text/") || type === "message/delivery-status" || type === "message/rfc822-headers" || type === "text/rfc822-headers";
  const isAttachment = disposition === "attachment" || !!filename || !isText;

  if (isAttachment) {
    result.attachments.push(makeAttachment(filename || `parte-${path}`, type, decoded, disposition, path));
    // Si el adjunto es texto (txt, html, csv, ics...) también lo analizamos.
    if (isText) result.texts.push({ type, content: decodeBinaryText(decoded, ct.params.charset), path, attachment: true });
    return;
  }

  result.texts.push({ type, content: decodeBinaryText(decoded, ct.params.charset), path });
}

function makeAttachment(filename, contentType, bin, disposition, path) {
  return {
    filename,
    contentType,
    disposition: disposition || "",
    inline: disposition === "inline",
    size: bin.length,
    bytes: binaryToBytes(bin),
    path,
  };
}
