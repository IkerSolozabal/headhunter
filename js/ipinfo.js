// Enriquecimiento de IPs con IPinfo Lite (https://ipinfo.io/developers/lite-api).
// El token y la caché viven solo en el localStorage del navegador del usuario.

const TOKEN_KEY = "hh.ipinfo.token";
const AUTO_KEY = "hh.ipinfo.auto";
const CACHE_KEY = "hh.ipinfo.cache.v1";
const TTL = 7 * 24 * 3600 * 1000;
const CONCURRENCY = 4;

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* modo privado */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
};

export const getToken = () => (store.get(TOKEN_KEY) || "").trim();
export const setToken = (t) => (t ? store.set(TOKEN_KEY, t.trim()) : store.del(TOKEN_KEY));
export const getAuto = () => store.get(AUTO_KEY) !== "0";
export const setAuto = (on) => store.set(AUTO_KEY, on ? "1" : "0");

let cache;
function loadCache() {
  if (cache) return cache;
  try { cache = JSON.parse(store.get(CACHE_KEY) || "{}"); } catch { cache = {}; }
  const now = Date.now();
  for (const [ip, e] of Object.entries(cache)) if (!e || now - e.ts > TTL) delete cache[ip];
  return cache;
}
function saveCache() { store.set(CACHE_KEY, JSON.stringify(cache || {})); }
export function clearCache() { cache = {}; store.del(CACHE_KEY); }

export class IpinfoError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}

/** Consulta una IP. Devuelve {ip, asn, as_name, as_domain, country_code, country, ...}. */
export async function lookup(ip, token = getToken()) {
  const c = loadCache();
  if (c[ip]) return c[ip].data;
  if (!token) throw new IpinfoError("Sin token de IPinfo", "no-token");
  let res;
  try {
    res = await fetch(`https://api.ipinfo.io/lite/${encodeURIComponent(ip)}?token=${encodeURIComponent(token)}`, {
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new IpinfoError("No se pudo contactar con IPinfo", "network");
  }
  if (res.status === 401 || res.status === 403) throw new IpinfoError("Token de IPinfo no válido", "auth");
  if (res.status === 429) throw new IpinfoError("Límite de IPinfo alcanzado", "rate");
  if (!res.ok) throw new IpinfoError(`IPinfo respondió ${res.status}`, "http");
  const data = await res.json();
  c[ip] = { ts: Date.now(), data };
  saveCache();
  return data;
}

/**
 * Consulta muchas IPs con concurrencia limitada.
 * onResult(ip, data|null, error|null) se llama según van llegando.
 */
export async function lookupMany(ips, onResult) {
  const queue = [...ips];
  let fatal = null;
  const worker = async () => {
    while (queue.length) {
      const ip = queue.shift();
      if (fatal) { onResult(ip, null, fatal); continue; }
      try {
        onResult(ip, await lookup(ip), null);
      } catch (err) {
        if (err.code === "auth" || err.code === "rate" || err.code === "no-token") fatal = err;
        onResult(ip, null, err);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  return fatal;
}
