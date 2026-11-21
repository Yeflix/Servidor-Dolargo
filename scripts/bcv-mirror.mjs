// ══════════════════════════════════════════════════════════════════════════
//  bcv-mirror.mjs — reemplazo del Cloudflare Worker `dolargo-bcv-mirror`
//
//  Por qué existe: el BCV no envía el certificado intermedio de Sectigo.
//  Cloudflare Workers no puede completar la cadena (→ error 526) y no
//  permite saltarse la validación. Node sí, y aquí se hace de forma segura:
//  se acepta el certificado SOLO si su huella SHA-256 está en BCV_PIN_SHA256
//  (la misma huella que fija la app en api_services.dart) y está vigente.
//
//  Escribe en Firestore:
//    bcv_mirror/latest → { dolar, euro, updatedAt, source, scrapedBy }
//    bcv_mirror/status → { lastAttemptAt, ok, error }   (diagnóstico)
//  La app solo lee `latest`; `status` no la afecta.
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

// ── Descarga del BCV con pin de certificado ───────────────────────────────
function fetchBcvHtml(urlStr, pins) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    let pinOk = false;
    const req = https.request(
      {
        host: u.hostname,
        port: 443,
        path: u.pathname + u.search,
        method: "GET",
        servername: u.hostname,
        agent: false,
        timeout: 25_000,
        // La cadena llega incompleta: la validación la hace el pin de abajo.
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
        if (!pinOk) { res.resume(); return reject(new Error("pin no verificado")); }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`BCV HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      }
    );
    req.on("socket", (socket) => {
      socket.once("secureConnect", () => {
        const cert = socket.getPeerCertificate();
        const fp = crypto.createHash("sha256").update(cert.raw).digest("hex").toUpperCase();
        const now = Date.now();
        const valid = now >= Date.parse(cert.valid_from) && now <= Date.parse(cert.valid_to);
        if (valid && pins.includes(fp)) {
          pinOk = true;
        } else {
          req.destroy(new Error(
            `Certificado del BCV no fijado (huella ${fp}, vigente=${valid}, vence ${cert.valid_to}). ` +
            `Verifícala desde una red de confianza y agrégala a BCV_PIN_SHA256.`
          ));
        }
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

async function patchDoc(projectId, token, docPath, fields) {
  // updateMask: solo se tocan los campos enviados (el resto se conserva).
  const mask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join("&");
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${docPath}?${mask}`;
  const enc = (v) =>
    typeof v === "number" ? { doubleValue: v } :
    typeof v === "boolean" ? { booleanValue: v } : { stringValue: String(v) };
  const res = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, enc(v)])) }),
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

  let dolar = null, euro = null, error = null;
  try {
    const html = await fetchBcvHtml(process.env.BCV_URL || "https://www.bcv.org.ve/", pins);
    dolar = extractBcvRate(html, "dolar");
    euro = extractBcvRate(html, "euro");
    if (dolar === null) error = "no se pudo extraer dolar del HTML";
    else if (euro === null) error = "no se pudo extraer euro del HTML";
  } catch (e) {
    error = e.message;
  }
  console.log(JSON.stringify({ dolar, euro, error }));

  const token = await getAccessToken(saJson);
  const now = new Date().toISOString();

  if (dolar !== null || euro !== null) {
    const fields = { updatedAt: now, source: "bcv.org.ve", scrapedBy: "github-actions-v1" };
    if (dolar !== null) fields.dolar = dolar;
    if (euro !== null) fields.euro = euro;
    await patchDoc(projectId, token, "bcv_mirror/latest", fields);
  }
  // Latido de diagnóstico: distingue "worker muerto" de "BCV sin cambios".
  await patchDoc(projectId, token, "bcv_mirror/status", {
    lastAttemptAt: now,
    ok: dolar !== null && euro !== null,
    error: error ? error.slice(0, 300) : "",
  });

  // Rojo en Actions (y correo de GitHub) si no se obtuvo nada.
  if (dolar === null && euro === null) process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => { console.error("bcv-mirror falló:", e); process.exit(1); });
}
