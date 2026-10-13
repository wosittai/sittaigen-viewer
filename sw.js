"use strict";

const MAGIC = "STV1";
let rawKeys = new Map();
let manifestByPath = new Map();
let expiresAt = 0;
let portalClientId = null;
const plaintextCache = new Map();
let cacheBytes = 0;
let sessionRecovery = null;
let finishSessionRecovery = null;
// Large archives are encrypted in independent 1 MiB chunks. This volatile LRU
// keeps nearby map ranges fast without downloading or retaining a whole map.
const MAX_CACHE_BYTES = 48 * 1024 * 1024;

self.addEventListener("install", event => event.waitUntil(self.skipWaiting()));
self.addEventListener("activate", event => event.waitUntil(self.clients.claim()));

self.addEventListener("message", event => {
  const reply = payload => event.ports[0]?.postMessage(payload);
  if (event.data?.type === "unlock") {
    portalClientId = event.source?.id;
    for (const key of rawKeys.values()) key.fill(0);
    rawKeys = new Map();
    manifestByPath = new Map();
    for (const module of event.data.modules || []) {
      rawKeys.set(module.id, new Uint8Array(module.key));
      for (const file of module.manifest.files || []) {
        manifestByPath.set(file.path, { ...file, moduleId: module.id });
      }
    }
    expiresAt = Number(event.data.expiresAt) || 0;
    plaintextCache.clear();
    cacheBytes = 0;
    finishSessionRecovery?.(true);
    reply({ ok: true, files: manifestByPath.size, modules: rawKeys.size });
    return;
  }
  if (event.data?.type === "lock") {
    for (const key of rawKeys.values()) key.fill(0);
    rawKeys.clear();
    manifestByPath.clear();
    expiresAt = 0;
    plaintextCache.clear();
    cacheBytes = 0;
    finishSessionRecovery?.(false);
    reply({ ok: true });
  }
});

function lockedResponse() {
  const body = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Wznawianie sesji</title><style>body{margin:0;background:#0b0d0f;color:#d9d4c9;font:16px system-ui;display:grid;place-items:center;min-height:100vh}main{max-width:520px;padding:40px;text-align:center}a{color:#c9ad78}</style><main><h1>Wznawianie sesji…</h1><p>Jeżeli widok nie wróci automatycznie, przejdź do ekranu projektów.</p><p><a href="../">Wróć do projektów</a></p></main><script>if(parent!==window)parent.postMessage({type:"sittaigen-vault-session-missing"},location.origin)<\/script>`;
  return new Response(body, { status: 401, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function hasActiveSession() {
  return Boolean(rawKeys.size && expiresAt && Date.now() < expiresAt);
}

function clearVaultSession() {
  for (const key of rawKeys.values()) key.fill(0);
  rawKeys.clear();
  manifestByPath.clear();
  plaintextCache.clear();
  cacheBytes = 0;
  expiresAt = 0;
}

function requestSessionFromPortal() {
  if (hasActiveSession()) return Promise.resolve(true);
  if (sessionRecovery) return sessionRecovery;

  clearVaultSession();
  sessionRecovery = new Promise(resolve => {
    const timeout = setTimeout(() => complete(false), 6000);
    const complete = recovered => {
      if (!finishSessionRecovery) return;
      clearTimeout(timeout);
      finishSessionRecovery = null;
      sessionRecovery = null;
      resolve(Boolean(recovered && hasActiveSession()));
    };
    finishSessionRecovery = complete;

    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(clients => {
      if (!clients.length) {
        complete(false);
        return;
      }
      for (const client of clients) client.postMessage({ type: "sittaigen-vault-session-request" });
    }).catch(() => complete(false));
  });
  return sessionRecovery;
}

async function importKey(moduleId) {
  const rawKey = rawKeys.get(moduleId);
  if (!rawKey) throw new Error("Missing module key");
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
}

function remember(cacheKey, bytes) {
  if (bytes.byteLength > MAX_CACHE_BYTES / 2) return;
  while (cacheBytes + bytes.byteLength > MAX_CACHE_BYTES && plaintextCache.size) {
    const [oldestKey, oldest] = plaintextCache.entries().next().value;
    plaintextCache.delete(oldestKey);
    cacheBytes -= oldest.byteLength;
  }
  plaintextCache.set(cacheKey, bytes);
  cacheBytes += bytes.byteLength;
}

async function decryptBlob(blob, aadText, cacheKey, moduleId) {
  if (plaintextCache.has(cacheKey)) {
    const cached = plaintextCache.get(cacheKey);
    plaintextCache.delete(cacheKey);
    plaintextCache.set(cacheKey, cached);
    return cached;
  }
  const response = await fetch(new URL(blob, self.registration.scope), { cache: "no-store" });
  if (!response.ok) throw new Error(`Encrypted object unavailable: ${response.status}`);
  const envelope = new Uint8Array(await response.arrayBuffer());
  if (new TextDecoder().decode(envelope.slice(0, 4)) !== MAGIC) throw new Error("Invalid object envelope");
  const key = await importKey(moduleId);
  const aad = new TextEncoder().encode(aadText);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: envelope.slice(4, 16), additionalData: aad, tagLength: 128 },
    key,
    envelope.slice(16)
  );
  const bytes = new Uint8Array(plaintext);
  remember(cacheKey, bytes);
  return bytes;
}

async function decryptFile(entry) {
  return decryptBlob(entry.blob, `sittaigen-file-v1\0${entry.id}`, `${entry.moduleId}:${entry.id}`, entry.moduleId);
}

async function decryptChunk(entry, index) {
  const chunk = entry.chunks[index];
  return decryptBlob(chunk.blob, `sittaigen-file-v2\0${entry.id}\0${index}`, `${entry.moduleId}:${entry.id}:${index}`, entry.moduleId);
}

function requestedRange(request, size) {
  const range = request.headers.get("Range");
  if (!range) return { start: 0, end: size - 1, partial: false };
  const match = /^bytes=(\d*)-(\d*)$/.exec(range);
  if (!match || (!match[1] && !match[2])) return null;
  let start;
  let end;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) return null;
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Math.min(Number(match[2]), size - 1) : size - 1;
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) return null;
  return { start, end, partial: true };
}

async function readRange(entry, start, end) {
  if (!entry.chunks) {
    const bytes = await decryptFile(entry);
    return bytes.slice(start, end + 1);
  }
  const chunkSize = Number(entry.chunk_size);
  const first = Math.floor(start / chunkSize);
  const last = Math.floor(end / chunkSize);
  const chunks = await Promise.all(Array.from({ length: last - first + 1 }, (_, offset) => decryptChunk(entry, first + offset)));
  const joined = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0));
  let cursor = 0;
  for (const chunk of chunks) {
    joined.set(chunk, cursor);
    cursor += chunk.byteLength;
  }
  const relativeStart = start - first * chunkSize;
  return joined.slice(relativeStart, relativeStart + end - start + 1);
}

async function handleContent(request, encodedPath, event) {
  if (!hasActiveSession() && !(await requestSessionFromPortal())) {
    clearVaultSession();
    return lockedResponse();
  }
  let path;
  try { path = encodedPath.split("/").map(decodeURIComponent).join("/"); }
  catch (_) { return new Response("Invalid path", { status: 400 }); }
  if (!path || path.endsWith("/")) path += "index.html";
  const entry = manifestByPath.get(path);
  if (!entry) return new Response("Not found in encrypted manifest", { status: 404, headers: { "Cache-Control": "no-store" } });

  try {
    const range = requestedRange(request, Number(entry.size));
    if (!range) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${entry.size}` } });
    const bytes = await readRange(entry, range.start, range.end);
    const url = new URL(request.url);
    const headers = new Headers({
      "Content-Type": entry.mime || "application/octet-stream",
      "Content-Length": String(bytes.byteLength),
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      "Accept-Ranges": "bytes"
    });
    if (url.searchParams.get("download") === "1") {
      const filename = path.split("/").pop().replace(/["\\]/g, "_");
      headers.set("Content-Disposition", `attachment; filename="${filename}"`);
    }
    if (range.partial) headers.set("Content-Range", `bytes ${range.start}-${range.end}/${entry.size}`);
    if (request.method === "GET" && !range.partial && (request.mode === "navigate" || url.searchParams.get("download") === "1") && portalClientId) {
      event.waitUntil(self.clients.get(portalClientId).then(client => client?.postMessage({
        type: "sittaigen-audit-view", moduleId: entry.moduleId, path, eventId: crypto.randomUUID()
      })));
    }
    return new Response(request.method === "HEAD" ? null : bytes, { status: range.partial ? 206 : 200, headers });
  } catch (error) {
    return new Response("Decryption or integrity check failed", { status: 500, headers: { "Cache-Control": "no-store" } });
  }
}

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  const scopePath = new URL(self.registration.scope).pathname;
  const contentPrefix = `${scopePath}content/`;
  if (url.origin === self.location.origin && url.pathname.startsWith(contentPrefix)) {
    event.respondWith(handleContent(event.request, url.pathname.slice(contentPrefix.length), event));
  }
});
