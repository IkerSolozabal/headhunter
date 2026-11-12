import { parseEml } from "./eml.js";
import { extractIocs, summarize, CATEGORIES, defang } from "./ioc.js";
import { hashAll } from "./hash.js";
import * as ipinfo from "./ipinfo.js";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ICONS = {
  ip: '<path d="M4 6h16v5H4zM4 13h16v5H4zM8 8.5h.01M8 15.5h.01"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  hash: '<path d="M5 9h14M5 15h14M10 4 8 20M16 4l-2 16"/>',
  file: '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5"/>',
  tag: '<path d="M3 12V4a1 1 0 0 1 1-1h8l9 9-9 9z"/><circle cx="7.5" cy="7.5" r="1.5"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;

const state = {
  items: [],
  selected: new Set(),
  cat: "all",
  query: "",
  publicOnly: true,
  defang: false,
  enrich: new Map(), // ip -> {status: 'loading'|'ok'|'err', data, error}
  rows: new Map(),   // key -> <li>
};
const keyOf = (it) => `${it.cat}|${it.value}`;

// ------------------------------------------------------------------ carga de archivos

const dropzone = $("#dropzone");
const fileInput = $("#fileInput");

fileInput.addEventListener("change", () => fileInput.files[0] && loadFile(fileInput.files[0]));
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
});

let dragDepth = 0;
window.addEventListener("dragenter", (e) => { if (hasFiles(e)) { dragDepth++; dropzone.classList.add("over"); } });
window.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; dropzone.classList.remove("over"); } });
window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener("drop", (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  dropzone.classList.remove("over");
  const f = e.dataTransfer.files[0];
  if (f) loadFile(f);
});
const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes("Files");

window.addEventListener("paste", (e) => {
  if (e.target.closest("input, textarea")) return;
  const f = e.clipboardData?.files?.[0];
  if (f) { e.preventDefault(); return loadFile(f); }
  const text = e.clipboardData?.getData("text/plain");
  if (text && /^[\w-]+:\s/m.test(text) && /\n\s*\n/.test(text)) {
    e.preventDefault();
    analyze(new TextEncoder().encode(text), "pegado.eml");
  }
});

$("#sampleBtn").addEventListener("click", async () => {
  try {
    const res = await fetch("samples/ejemplo-phishing.eml");
    if (!res.ok) throw new Error(res.status);
    analyze(new Uint8Array(await res.arrayBuffer()), "ejemplo-phishing.eml");
  } catch {
    toast("No se pudo cargar el ejemplo", "bad");
  }
});

async function loadFile(file) {
  if (file.size > 60 * 1024 * 1024) return toast("Archivo demasiado grande (máx. 60 MB)", "bad");
  analyze(new Uint8Array(await file.arrayBuffer()), file.name);
}

async function analyze(bytes, fileName) {
  let parsed;
  try {
    parsed = parseEml(bytes);
  } catch (err) {
    console.error(err);
    return toast("No se pudo interpretar el archivo como EML", "bad");
  }
  if (!parsed.headers.length) toast("No se encontraron cabeceras: ¿es un .eml válido?", "bad");

  const attachmentHashes = new Map();
  const [fileHashes] = await Promise.all([
    hashAll(bytes),
    ...parsed.attachments.map(async (a) => attachmentHashes.set(a, await hashAll(a.bytes))),
  ]);

  state.items = extractIocs(parsed, { fileName, fileHashes, attachmentHashes });
  state.selected.clear();
  state.enrich.clear();
  state.cat = "all";
  state.query = "";
  $("#searchInput").value = "";

  renderSummary(summarize(parsed), fileName, bytes.length);
  $("#hero").hidden = true;
  $("#results").hidden = false;
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });

  if (ipinfo.getAuto()) enrichIps();
}

// ------------------------------------------------------------------ resumen

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

function authBadge(name, result) {
  const r = (result || "").toLowerCase();
  const cls = !r ? "none" : r === "pass" ? "pass" : /fail|permerror|temperror/.test(r) && r !== "softfail" ? "fail" : "warn";
  return `<span class="badge ${cls}"><b>${name}</b>${esc(r || "n/d")}</span>`;
}

const domainOf = (addr) => (/@([^>\s]+)/.exec(addr || "")?.[1] || "").toLowerCase();

function renderSummary(s, fileName, size) {
  const counts = Object.fromEntries(CATEGORIES.map((c) => [c.id, state.items.filter((i) => i.cat === c.id).length]));
  const fromD = domainOf(s.from);
  const replyD = domainOf(s.replyTo);
  const rpD = domainOf(s.returnPath);
  const warns = [];
  if (replyD && fromD && replyD !== fromD) warns.push(`Reply-To (${replyD}) ≠ From (${fromD})`);
  if (rpD && fromD && rpD !== fromD && !rpD.endsWith("." + fromD)) warns.push(`Return-Path (${rpD}) ≠ From (${fromD})`);

  const meta = [
    ["De", s.from], ["Para", s.to], ["CC", s.cc], ["Reply-To", s.replyTo],
    ["Return-Path", s.returnPath], ["Fecha", s.date], ["Message-ID", s.messageId],
  ].filter(([, v]) => v);

  $("#summary").innerHTML = `
    <div class="summary-head">
      <div>
        <div class="summary-file">${icon("file")} ${esc(fileName)} · ${fmtSize(size)} · ${s.hops} saltos Received · ${s.attachments} adjuntos</div>
        <h2 class="summary-subject">${esc(s.subject || "(sin asunto)")}</h2>
      </div>
      <button class="ghost-btn" id="newBtn" type="button">Analizar otro</button>
    </div>
    <div class="badges">
      ${authBadge("SPF", s.spf)}${authBadge("DKIM", s.dkim)}${authBadge("DMARC", s.dmarc)}
      ${warns.map((w) => `<span class="badge warn">⚠ ${esc(w)}</span>`).join("")}
    </div>
    <dl class="meta-grid">
      ${meta.map(([k, v]) => `<div class="meta"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join("")}
    </dl>
    <div class="stats">
      ${CATEGORIES.filter((c) => counts[c.id]).map((c) => `<div class="stat" style="--c:${c.color}"><b style="color:${c.color}">${counts[c.id]}</b><span>${esc(c.label.split(" (")[0])}</span></div>`).join("")}
    </div>`;
  $("#newBtn").addEventListener("click", reset);
}

function reset() {
  state.items = [];
  state.selected.clear();
  $("#results").hidden = true;
  $("#hero").hidden = false;
  fileInput.value = "";
  updateSelbar();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ------------------------------------------------------------------ listado

function visibleItems() {
  const q = state.query.toLowerCase();
  return state.items.filter((it) => {
    if (state.publicOnly && it.cat === "ip" && it.meta.scope) return false;
    if (state.cat !== "all" && it.cat !== state.cat) return false;
    if (q) {
      const e = state.enrich.get(it.value)?.data;
      const hay = [it.value, ...it.sources, it.meta.file, it.meta.kind, e?.as_name, e?.asn, e?.country].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderChips() {
  const base = state.items.filter((it) => !(state.publicOnly && it.cat === "ip" && it.meta.scope));
  const chips = [{ id: "all", label: "Todos", n: base.length }]
    .concat(CATEGORIES.map((c) => ({ id: c.id, label: c.label.split(" (")[0], n: base.filter((i) => i.cat === c.id).length })).filter((c) => c.n));
  $("#chips").innerHTML = chips.map((c) =>
    `<button class="chip" role="tab" type="button" data-cat="${c.id}" aria-selected="${state.cat === c.id}">${esc(c.label)} <span class="n">${c.n}</span></button>`).join("");
}

function render() {
  renderChips();
  const vis = visibleItems();
  const groups = $("#groups");
  state.rows.clear();
  if (!vis.length) {
    groups.innerHTML = `<div class="card empty">${state.items.length ? "Nada coincide con el filtro." : "No se encontraron IOC en este archivo."}</div>`;
    updateSelbar();
    return;
  }
  groups.innerHTML = "";
  for (const cat of CATEGORIES) {
    const list = vis.filter((i) => i.cat === cat.id);
    if (!list.length) continue;
    const sec = document.createElement("section");
    sec.className = "group card";
    sec.style.setProperty("--c", cat.color);
    sec.dataset.cat = cat.id;
    sec.innerHTML = `
      <header class="group-head">
        <input type="checkbox" class="check group-check" aria-label="Seleccionar todos: ${esc(cat.label)}">
        <span class="group-icon">${icon(cat.icon)}</span>
        <span class="group-title">${esc(cat.label)}</span>
        <span class="group-count">${list.length}</span>
        <span class="spacer"></span>
        ${cat.id === "ip" ? `<button class="mini-btn" data-act="enrich" type="button">Consultar IPinfo</button>` : ""}
        <button class="mini-btn" data-act="copy-group" type="button">Copiar grupo</button>
      </header>
      <ul class="ioc-list"></ul>`;
    const ul = $(".ioc-list", sec);
    for (const it of list) ul.appendChild(renderRow(it));
    groups.appendChild(sec);
  }
  syncGroupChecks();
  updateSelbar();
}

function renderRow(it) {
  const li = document.createElement("li");
  const k = keyOf(it);
  li.className = "ioc" + (state.selected.has(k) ? " sel" : "");
  li.dataset.key = k;
  li.innerHTML = `
    <input type="checkbox" class="check" ${state.selected.has(k) ? "checked" : ""} aria-label="Seleccionar ${esc(it.value)}">
    <div class="val">${it.cat === "hash" ? `<span class="hash-kind">${esc(it.meta.kind)}</span>` : ""}${esc(it.value)}<small>${esc(subtitle(it))}</small></div>
    <div class="tags">${tagsHtml(it)}</div>`;
  state.rows.set(k, li);
  return li;
}

function subtitle(it) {
  if (it.cat === "hash") return it.meta.isEml ? `Archivo .eml completo · ${it.meta.file}` : it.meta.file;
  if (it.cat === "file") return `${it.meta.contentType} · ${fmtSize(it.meta.size)}${it.meta.inline ? " · inline" : ""}`;
  if (it.cat === "other") return it.meta.kind;
  const src = it.sources.slice(0, 4).join(" · ");
  return it.sources.length > 4 ? `${src} · +${it.sources.length - 4}` : src;
}

const flag = (cc) => (cc && /^[A-Z]{2}$/i.test(cc) ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "");

function tagsHtml(it) {
  const t = [];
  if (it.meta.tags) t.push(...it.meta.tags.map((x) => `<span class="tag">${esc(x)}</span>`));
  if (it.cat === "ip") {
    if (it.meta.hop) t.push(`<span class="tag">Salto #${it.meta.hop}</span>`);
    if (it.meta.version === 6) t.push(`<span class="tag">IPv6</span>`);
    if (it.meta.scope) t.push(`<span class="tag priv">${esc(it.meta.scope)}</span>`);
    const e = state.enrich.get(it.value);
    if (e?.status === "loading") t.push(`<span class="tag loading">IPinfo…</span>`);
    else if (e?.status === "err") t.push(`<span class="tag err" title="${esc(e.error)}">IPinfo: ${esc(e.error)}</span>`);
    else if (e?.status === "ok") {
      const d = e.data || {};
      if (d.asn) t.push(`<span class="tag asn">${esc(d.asn)}</span>`);
      if (d.as_name) t.push(`<span class="tag org" title="${esc(d.as_domain || "")}">${esc(d.as_name)}</span>`);
      if (d.country_code) t.push(`<span class="tag" title="${esc(d.country || "")}">${flag(d.country_code)} ${esc(d.country_code)}</span>`);
      if (d.bogon) t.push(`<span class="tag priv">Bogon</span>`);
    }
  }
  return t.join("");
}

function refreshRow(it) {
  const li = state.rows.get(keyOf(it));
  if (li) $(".tags", li).innerHTML = tagsHtml(it);
}

// ------------------------------------------------------------------ selección

$("#groups").addEventListener("click", (e) => {
  const btn = e.target.closest(".mini-btn");
  if (btn) {
    const cat = btn.closest(".group").dataset.cat;
    if (btn.dataset.act === "enrich") enrichIps(true);
    if (btn.dataset.act === "copy-group") copyItems(visibleItems().filter((i) => i.cat === cat));
    return;
  }
  const gc = e.target.closest(".group-check");
  if (gc) {
    const cat = gc.closest(".group").dataset.cat;
    const list = visibleItems().filter((i) => i.cat === cat);
    for (const it of list) gc.checked ? state.selected.add(keyOf(it)) : state.selected.delete(keyOf(it));
    for (const it of list) paintRow(keyOf(it));
    syncGroupChecks();
    updateSelbar();
    return;
  }
  const li = e.target.closest(".ioc");
  if (!li) return;
  if (window.getSelection()?.toString() && !e.target.matches(".check")) return; // permite seleccionar texto
  const k = li.dataset.key;
  state.selected.has(k) ? state.selected.delete(k) : state.selected.add(k);
  paintRow(k);
  syncGroupChecks();
  updateSelbar();
});

function paintRow(k) {
  const li = state.rows.get(k);
  if (!li) return;
  const on = state.selected.has(k);
  li.classList.toggle("sel", on);
  $(".check", li).checked = on;
}

function syncGroupChecks() {
  const vis = visibleItems();
  for (const sec of document.querySelectorAll(".group")) {
    const list = vis.filter((i) => i.cat === sec.dataset.cat);
    const n = list.filter((i) => state.selected.has(keyOf(i))).length;
    const gc = $(".group-check", sec);
    gc.checked = n > 0 && n === list.length;
    gc.indeterminate = n > 0 && n < list.length;
  }
}

function selectedVisible() {
  return visibleItems().filter((i) => state.selected.has(keyOf(i)));
}

function updateSelbar() {
  const n = selectedVisible().length;
  $("#selCount").textContent = n;
  $("#copyBtn").disabled = n === 0;
  $("#selbar").classList.toggle("show", !$("#results").hidden && state.items.length > 0);
}

$("#selectAllBtn").addEventListener("click", () => {
  for (const it of visibleItems()) state.selected.add(keyOf(it));
  render();
});
$("#selectNoneBtn").addEventListener("click", () => {
  for (const it of visibleItems()) state.selected.delete(keyOf(it));
  render();
});
$("#copyBtn").addEventListener("click", () => copyItems(selectedVisible()));

$("#chips").addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (!chip) return;
  state.cat = chip.dataset.cat;
  render();
});
let searchTimer;
$("#searchInput").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.query = e.target.value.trim(); render(); }, 120);
});
$("#defangToggle").addEventListener("change", (e) => { state.defang = e.target.checked; });
$("#publicOnlyToggle").addEventListener("change", (e) => { state.publicOnly = e.target.checked; render(); });

// ------------------------------------------------------------------ portapapeles

async function copyItems(items) {
  if (!items.length) return toast("No hay nada que copiar", "bad");
  const order = new Map(CATEGORIES.map((c, i) => [c.id, i]));
  const text = [...items]
    .sort((a, b) => order.get(a.cat) - order.get(b.cat))
    .map((it) => (state.defang ? defang(it.value, it.cat) : it.value))
    .join("\n");
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    if (!ok) return toast("El navegador bloqueó el portapapeles", "bad");
  }
  toast(`${items.length} IOC copiados al portapapeles`, "ok");
}

// ------------------------------------------------------------------ IPinfo

async function enrichIps(manual = false) {
  const ips = state.items.filter((i) => i.cat === "ip" && !i.meta.scope);
  if (!ips.length) return manual && toast("No hay IPs públicas que consultar");
  if (!ipinfo.getToken()) {
    $("#settingsBtn").classList.add("attn");
    if (manual) openSettings();
    else toast("Añade tu token de IPinfo (⚙) para ver ASN y organización");
    return;
  }
  const byIp = new Map(ips.map((i) => [i.value, i]));
  for (const ip of byIp.keys()) state.enrich.set(ip, { status: "loading" });
  ips.forEach(refreshRow);
  const fatal = await ipinfo.lookupMany([...byIp.keys()], (ip, data, err) => {
    state.enrich.set(ip, err ? { status: "err", error: err.message } : { status: "ok", data });
    refreshRow(byIp.get(ip));
  });
  if (fatal) {
    toast(fatal.message, "bad");
    if (fatal.code === "auth") $("#settingsBtn").classList.add("attn");
  }
}

// ------------------------------------------------------------------ ajustes

const dlg = $("#settingsDialog");
function openSettings() {
  $("#tokenInput").value = ipinfo.getToken();
  $("#autoEnrichToggle").checked = ipinfo.getAuto();
  dlg.showModal();
}
$("#settingsBtn").addEventListener("click", openSettings);
dlg.addEventListener("close", () => {
  if (dlg.returnValue !== "save") return;
  const had = ipinfo.getToken();
  ipinfo.setToken($("#tokenInput").value);
  ipinfo.setAuto($("#autoEnrichToggle").checked);
  $("#settingsBtn").classList.toggle("attn", !ipinfo.getToken());
  toast("Ajustes guardados", "ok");
  if (ipinfo.getToken() && (ipinfo.getToken() !== had || [...state.enrich.values()].some((e) => e.status === "err"))) {
    if (state.items.length) enrichIps();
  }
});
$("#clearCacheBtn").addEventListener("click", () => {
  ipinfo.clearCache();
  toast("Caché de IPinfo vaciada", "ok");
});
if (!ipinfo.getToken()) $("#settingsBtn").classList.add("attn");

// ------------------------------------------------------------------ toast

let toastTimer;
function toast(msg, kind = "") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}
