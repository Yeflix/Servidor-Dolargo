// ══════════════════════════════════════════════════════════════════════════
//  bcv-mirror.mjs — reemplazo del Cloudflare Worker `dolargo-bcv-mirror`
//
//  Por qué existe: el BCV no envía el certificado intermedio de Sectigo.
//  Cloudflare Workers no puede completar la cadena (→ error 526) y no
//  permite saltarse la validación. Node sí. Se mira la huella SHA-256 del
//  certificado (BCV_PIN_SHA256; las mismas que fija la app): si coincide, la
//  conexión queda «verificada»; si no, se acepta igual y se deja un aviso
//  (modo tolerante, para que una renovación no pare el espejo). Con
//  BCV_STRICT=1 una huella no fijada se rechaza.
//
//  Escribe en Firestore:
//    bcv_mirror/latest → { dolar, euro, updatedAt, source, scrapedBy,
//                          dolarChangedAt, euroChangedAt }
//      *ChangedAt = desde cuándo la tasa tiene ese valor (solo cambia cuando
//      cambia el valor; updatedAt es un latido). La app marca «dato viejo»
//      cuando el dólar lleva más de 4 días sin cambiar.
//    bcv_mirror/status → { lastAttemptAt, ok, error, pinned, certFingerprint,
//                          historyDay, historyResult, dayKey, okToday }
//    bcv_mirror/stats-YYYY-MM-DD (día de Caracas) → { dayKey, runs, ok,
//      firstOkAt, lastOkAt, meetsTarget }  contador de corridas del día
//      (meta: ≥ 5 lecturas buenas). Solo informativo.
//    tasas_historico/YYYY-MM-DD (día de Caracas) → lo CREA si todavía no
//      existe («el primero que llega gana»; nunca pisa uno existente). Usa la
//      tasa del BCV y, si el BCV falla, la última del espejo.
//  La app solo lee `latest` e historial; `status` no la afecta.
//
//  Variables de entorno:
//    FIREBASE_SERVICE_ACCOUNT_JSON  (secret, obligatorio)
//    FIREBASE_PROJECT_ID            (por defecto dolar-go-pro)
//    BCV_PIN_SHA256                 (huellas separadas por coma; si falta se
//                                    usa la fijada en la app)
//    BCV_URL                        (por defecto https://www.bcv.org.ve/)
//  Sin dependencias: solo Node >= 18.
// ══════════════════════════════════════════════════════════════════════════
import https from "node:https";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const MIN_SANE = 1.0;
const MAX_SANE = 1_000_000.0;
const isSane = (v) => v !== null && Number.isFinite(v) && v >= MIN_SANE && v <= MAX_SANE;

// Huellas SHA-256 del certificado del BCV (las mismas que fija la app).
//   1664D332…  capturada 2026-11-14
//   AAD97DF7…  capturada 2026-11-20 (vigente 12-nov-2026 → 30-may-2027)
const DEFAULT_PIN =
  "1664D332CD2A0DF57F59D50A66ADA737F82793D77F8C336BFA7E24E8B2C94F22," +
  "AAD97DF7F4860759A370DA3452AF8FCBA15DC6AE09CC14FE1AE0FD5B25E4D8BF";

// ── Extracción (misma lógica que worker.ts / BcvService de la app) ────────
export function extractBcvRate(html, id) {
  const startRe = new RegExp(`<div\\b[^>]*\\bid=["']${id}["'][^>]*>`, "i");
  const m = startRe.exec(html);
  if (!m) return null;
  let block = html.slice(m.index + m[0].length, m.index + m[0].length + 1500);
  const next = /<div\b[^>]*\bid=["'](?:dolar|euro|yuan|lira|rublo)["']/i.exec(block);
  if (next) block = block.slice(0, next.index);

  const inStrong = /<strong\b[^>]*>([\s\S]*?)<\/strong>/i.exec(block)?.[1];
  const candidates = [];
  if (inStrong) candidates.push(stripTags(inStrong));
  candidates.push(stripTags(block));
  for (const text of candidates) {
    const v = firstNonPercentNumber(text);
    if (isSane(v)) return v;
  }
  return null;
}

const stripTags = (s) => s.replace(/<[^>]+>/g, " ").replace(/&nbsp;/gi, " ");

export function firstNonPercentNumber(text) {
  const re = /(\d{1,3}(?:\.\d{3})*,\d+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const end = m.index + m[0].length;
    let isPct = false;
    for (let i = end; i < text.length && i < end + 3; i++) {
      if (text[i] === "%") { isPct = true; break; }
      if (text[i] !== " ") break;
    }
    if (isPct) continue;
    const num = Number(m[1].replace(/\./g, "").replace(",", "."));
    if (isSane(num)) return num;
  }
  return null;
}

// ── Descarga del BCV ──────────────────────────────────────────────────────
// La cadena TLS del BCV llega incompleta, así que la validación normal falla
// siempre. Se mira la huella del certificado:
//   • huella fijada y vigente → «verificada» (pinned = true);
//   • otra huella → se acepta igual y se avisa (modo tolerante, el de por
//     defecto), para que una renovación del certificado no pare el espejo;
//   • con BCV_STRICT=1 → una huella no fijada se rechaza.
export function fetchBcvHtml(urlStr, pins, strict = false) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    let tlsChecked = false;
    let pinned = false;
    let fingerprint = "";
    const req = https.request(
      {
        host: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: "GET",
        servername: u.hostname,
        agent: false,
        timeout: 25_000,
        rejectUnauthorized: false,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "es-VE,es;q=0.9,en;q=0.8",
          "Accept-Encoding": "identity",
        },
      },
      (res) => {
        if (!tlsChecked) { res.resume(); return reject(new Error("TLS no comprobado")); }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`BCV HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ html: Buffer.concat(chunks).toString("utf8"), pinned, fingerprint })
        );
        res.on("error", reject);
      }
    );
    req.on("socket", (socket) => {
      socket.once("secureConnect", () => {
        const cert = socket.getPeerCertificate();
        if (!cert || !cert.raw) {
          req.destroy(new Error("El BCV no presentó certificado"));
          return;
        }
        fingerprint = crypto.createHash("sha256").update(cert.raw).digest("hex").toUpperCase();
        const now = Date.now();
        const valid = now >= Date.parse(cert.valid_from) && now <= Date.parse(cert.valid_to);
        pinned = valid && pins.includes(fingerprint);
        if (pinned) { tlsChecked = true; return; }
        if (strict) {
          req.destroy(new Error(
            `Certificado del BCV no fijado (huella ${fingerprint}, vigente=${valid}, vence ${cert.valid_to}).`
          ));
          return;
        }
        console.warn(
          `⚠️ Certificado del BCV sin huella fijada (huella ${fingerprint}, vigente=${valid}, ` +
          `vence ${cert.valid_to}). Se acepta en modo tolerante. Para fijarla, agrégala a BCV_PIN_SHA256.`
        );
        tlsChecked = true;
      });
    });
    req.on("timeout", () => req.destroy(new Error("BCV timeout")));
    req.on("error", reject);
    req.end();
  });
}

// ── Firestore REST (service account → JWT → token) ────────────────────────
const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

async function getAccessToken(saJson) {
  const sa = JSON.parse(saJson);
  const now = Math.floor(Date.now() / 1000);
  const aud = sa.token_uri || "https://oauth2.googleapis.com/token";
  const unsigned =
    b64url(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." +
    b64url(JSON.stringify({
      iss: sa.client_email,
      scope: "https://www.googleapis.com/auth/datastore",
      aud, iat: now, exp: now + 3600,
    }));
  const sig = crypto.createSign("RSA-SHA256").update(unsigned).sign(sa.private_key);
  const res = await fetch(aud, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" +
      encodeURIComponent(`${unsigned}.${b64url(sig)}`),
  });
  if (!res.ok) throw new Error(`token HTTP ${res.status}: ${await res.text()}`);
  return (await res.json()).access_token;
}

const FIRESTORE = (projectId) =>
  `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;

/** Valor de Firestore REST. `null` → nullValue. */
const encValue = (v) =>
  v === null ? { nullValue: null } :
  typeof v === "number" ? { doubleValue: v } :
  typeof v === "boolean" ? { booleanValue: v } : { stringValue: String(v) };

const decNumber = (f) => {
  if (!f) return null;
  const v = "doubleValue" in f ? Number(f.doubleValue)
    : "integerValue" in f ? Number(f.integerValue) : null;
  return isSane(v) ? v : null;
};

/** "YYYY-MM-DD" del día en Caracas (UTC-4, sin horario de verano). */
export function caracasDayKey(now = new Date()) {
  return new Date(now.getTime() - 4 * 3600_000).toISOString().slice(0, 10);
}

/** Documento del historial con el mismo formato que guarda la app. */
export function historyFields(dayKey, dolar, euro, source, savedAt) {
  return {
    date: `${dayKey}T12:00:00.000`,
    dayKey,
    dolarPrice: dolar,
    euroPrice: euro,
    usdtPrice: null,
    source,
    savedAt,
  };
}

/** Meta diaria de lecturas buenas del BCV (§14.1). */
export const DAILY_TARGET = 5;

/** Contador del día: suma una corrida (y una buena si `ok`). Función pura. */
export function nextStats(prev, dayKey, ok, nowIso) {
  const runs = (prev?.runs ?? 0) + 1;
  const okCount = (prev?.ok ?? 0) + (ok ? 1 : 0);
  return {
    dayKey,
    runs,
    ok: okCount,
    firstOkAt: prev?.firstOkAt || (ok ? nowIso : ""),
    lastOkAt: ok ? nowIso : (prev?.lastOkAt || ""),
    meetsTarget: okCount >= DAILY_TARGET,
  };
}

/**
 * Desde cuándo vale `value` una tasa. Si el valor no cambió se conserva la
 * marca anterior; si cambió (o no había), es `nowIso`. `fallback` permite
 * sembrar la primera marca desde el historial.
 */
export function nextChangedAt(prevValue, prevChangedAt, value, nowIso, fallback = null) {
  if (value === null) return prevChangedAt || null;
  if (prevValue !== null && Math.abs(prevValue - value) < 1e-9 && prevChangedAt) return prevChangedAt;
  if (prevValue === null || Math.abs(prevValue - value) < 1e-9) return fallback || nowIso;
  return nowIso;
}

/**
 * Primera vez (sin dolarChangedAt): mira los últimos días del historial y
 * devuelve el inicio (00:00 de Caracas, en ISO UTC) del primer día seguido
 * con el mismo `value`. `days` = [{dayKey, value}] del más nuevo al más viejo.
 */
export function changedSinceFromHistory(days, value) {
  let since = null;
  for (const d of days) {
    if (d.value === null || Math.abs(d.value - value) >= 1e-9) break;
    since = d.dayKey;
  }
  return since ? `${since}T04:00:00.000Z` : null;
}

const decString = (f) => (f && "stringValue" in f ? f.stringValue : null);
const decInt = (f) => {
  if (!f) return null;
  const v = "integerValue" in f ? Number(f.integerValue) : "doubleValue" in f ? Number(f.doubleValue) : null;
  return Number.isFinite(v) ? v : null;
};

/** Últimos `n` días del historial (más nuevo primero) para una moneda. */
async function recentHistory(projectId, token, field, n = 10) {
  const url = `${FIRESTORE(projectId)}/tasas_historico?pageSize=${n}&orderBy=__name__%20desc`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`firestore LIST tasas_historico ${res.status}`);
  const docs = (await res.json()).documents ?? [];
  return docs.map((d) => ({ dayKey: d.name.split("/").pop(), value: decNumber(d.fields?.[field]) }));
}

async function getDoc(projectId, token, docPath) {
  const res = await fetch(`${FIRESTORE(projectId)}/${docPath}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`firestore GET ${docPath} ${res.status}: ${await res.text()}`);
  return (await res.json()).fields ?? null;
}

/**
 * Crea `collection/docId` SOLO si no existe (POST con documentId: Firestore
 * responde 409 ALREADY_EXISTS si ya está). Devuelve "created" o "exists".
 */
async function createDocIfMissing(projectId, token, collection, docId, fields) {
  const url = `${FIRESTORE(projectId)}/${collection}?documentId=${encodeURIComponent(docId)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, encValue(v)])) }),
  });
  if (res.status === 409) return "exists";
  if (!res.ok) throw new Error(`firestore CREATE ${collection}/${docId} ${res.status}: ${await res.text()}`);
  return "created";
}

async function patchDoc(projectId, token, docPath, fields) {
  // updateMask: solo se tocan los campos enviados (el resto se conserva).
  const mask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join("&");
  const url = `${FIRESTORE(projectId)}/${docPath}?${mask}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, encValue(v)])) }),
  });
  if (!res.ok) throw new Error(`firestore PATCH ${docPath} ${res.status}: ${await res.text()}`);
}

// ── Main ──────────────────────────────────────────────────────────────────
async function main() {
  const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!saJson) throw new Error("Falta FIREBASE_SERVICE_ACCOUNT_JSON");
  const projectId = process.env.FIREBASE_PROJECT_ID || "dolar-go-pro";
  const pins = (process.env.BCV_PIN_SHA256 || DEFAULT_PIN)
    .split(",").map((s) => s.replace(/[:\s]/g, "").toUpperCase()).filter(Boolean);

  const strict = process.env.BCV_STRICT === "1";
  let dolar = null, euro = null, error = null, pinned = false, fingerprint = "";
  try {
    const res = await fetchBcvHtml(process.env.BCV_URL || "https://www.bcv.org.ve/", pins, strict);
    const html = res.html;
    pinned = res.pinned;
    fingerprint = res.fingerprint;
    dolar = extractBcvRate(html, "dolar");
    euro = extractBcvRate(html, "euro");
    if (dolar === null) error = "no se pudo extraer dolar del HTML";
    else if (euro === null) error = "no se pudo extraer euro del HTML";
  } catch (e) {
    error = e.message;
  }
  console.log(JSON.stringify({ dolar, euro, pinned, error }));

  const token = await getAccessToken(saJson);
  const now = new Date().toISOString();

  // Se lee el espejo ANTES de actualizarlo: sirve para el historial (moneda
  // que faltó) y para saber si la tasa cambió (dolarChangedAt/euroChangedAt).
  let latest = null, latestOk = false;
  try {
    latest = await getDoc(projectId, token, "bcv_mirror/latest");
    latestOk = true;
  } catch (e) {
    console.warn(`⚠️ No se pudo leer el espejo: ${e.message}`);
  }
  const mirrorDolar = decNumber(latest?.dolar);
  const mirrorEuro = decNumber(latest?.euro);

  if (dolar !== null || euro !== null) {
    const fields = { updatedAt: now, source: "bcv.org.ve", scrapedBy: "github-actions-v1" };
    if (dolar !== null) fields.dolar = dolar;
    if (euro !== null) fields.euro = euro;
    // Solo con el espejo leído: si falló la lectura no se puede saber si
    // cambió, y es mejor no tocar la marca que reiniciarla.
    if (latestOk) {
      for (const [cur, field, prevVal] of [["dolar", "dolarPrice", mirrorDolar], ["euro", "euroPrice", mirrorEuro]]) {
        const value = cur === "dolar" ? dolar : euro;
        if (value === null) continue;
        const prevAt = decString(latest?.[`${cur}ChangedAt`]);
        let seed = null;
        if (!prevAt) {
          try {
            seed = changedSinceFromHistory(await recentHistory(projectId, token, field), value);
          } catch (e) {
            console.warn(`⚠️ Historial para ${cur}ChangedAt: ${e.message}`);
          }
        }
        fields[`${cur}ChangedAt`] = nextChangedAt(prevVal, prevAt, value, now, seed);
      }
    }
    await patchDoc(projectId, token, "bcv_mirror/latest", fields);
  }

  // Historial: el documento del día de Caracas, solo si no existe. Con el
  // BCV caído se usa el precio del espejo (a pedido): así el historial no
  // queda con huecos aunque nadie abra la app de admin ese día.
  const dayKey = caracasDayKey();
  const hDolar = dolar ?? mirrorDolar;
  const hEuro = euro ?? mirrorEuro;
  let historyResult;
  if (hDolar === null || hEuro === null) {
    historyResult = "sin datos";
  } else {
    const source = dolar !== null && euro !== null ? "github-actions" : "github-actions-espejo";
    try {
      historyResult = await createDocIfMissing(
        projectId, token, "tasas_historico", dayKey,
        historyFields(dayKey, hDolar, hEuro, source, now),
      );
      if (historyResult === "created") historyResult += ` (${source})`;
    } catch (e) {
      historyResult = `error: ${e.message}`.slice(0, 300);
      console.warn(`⚠️ Historial: ${historyResult}`);
    }
  }
  console.log(`Historial ${dayKey}: ${historyResult}`);

  // Contador del día (§14.1): una corrida más; «buena» = el BCV dio las dos.
  const readOk = dolar !== null && euro !== null;
  let stats = null;
  try {
    const prev = await getDoc(projectId, token, `bcv_mirror/stats-${dayKey}`);
    stats = nextStats(prev ? {
      runs: decInt(prev.runs), ok: decInt(prev.ok),
      firstOkAt: decString(prev.firstOkAt), lastOkAt: decString(prev.lastOkAt),
    } : null, dayKey, readOk, now);
    await patchDoc(projectId, token, `bcv_mirror/stats-${dayKey}`, stats);
    console.log(`Hoy (${dayKey}): ${stats.ok}/${DAILY_TARGET} lecturas buenas en ${stats.runs} corridas`);
  } catch (e) {
    console.warn(`⚠️ Contador del día: ${e.message}`);
  }

  // Latido de diagnóstico: distingue "worker muerto" de "BCV sin cambios".
  await patchDoc(projectId, token, "bcv_mirror/status", {
    lastAttemptAt: now,
    ok: dolar !== null && euro !== null,
    error: error ? error.slice(0, 300) : "",
    pinned,                       // true = huella verificada; false = modo tolerante
    certFingerprint: fingerprint, // huella que presentó el BCV (dato público)
    historyDay: dayKey,
    historyResult,
    dayKey,
    okToday: stats ? stats.ok : -1,
  });

  // Rojo en Actions (y correo de GitHub) si no se obtuvo nada.
  if (dolar === null && euro === null) process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => { console.error("bcv-mirror falló:", e); process.exit(1); });
}
