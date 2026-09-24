"use strict";

const MAGIC = "STV1";
let rawKey = null;
let manifestByPath = new Map();
const plaintextCache = new Map();
let cacheBytes = 0;
const MAX_CACHE_BYTES = 64 * 1024 * 1024;

self.addEventListener("install", event => event.waitUntil(self.skipWaiting()));
self.addEventListener("activate", event => event.waitUntil(self.clients.claim()));

self.addEventListener("message", event => {
  const reply = payload => event.ports[0]?.postMessage(payload);
  if (event.data?.type === "unlock") {
    rawKey = new Uint8Array(event.data.key);
    manifestByPath = new Map(event.data.manifest.files.map(file => [file.path, file]));
    plaintextCache.clear();
    cacheBytes = 0;
    reply({ ok: true, files: manifestByPath.size });
    return;
  }
  if (event.data?.type === "lock") {
    rawKey = null;
    manifestByPath.clear();
    plaintextCache.clear();
    cacheBytes = 0;
    reply({ ok: true });
  }
});

function lockedResponse() {
  const body = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Repozytorium zablokowane</title><style>body{margin:0;background:#0a0e11;color:#eef2f3;font:16px system-ui;display:grid;place-items:center;min-height:100vh}main{max-width:520px;padding:40px;border:1px solid #3a4850;background:#10161a}a{color:#c6a15b}</style><main><h1>Repozytorium zablokowane</h1><p>Sesja deszyfrująca wygasła albo nie została uruchomiona.</p><p><a href="../">Wróć do strony logowania</a></p></main>`;
  return new Response(body, { status: 401, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

async function importKey() {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
}

async function decryptFile(entry) {
  if (plaintextCache.has(entry.id)) return plaintextCache.get(entry.id);
  const response = await fetch(new URL(entry.blob, self.registration.scope), { cache: "no-store" });
  if (!response.ok) throw new Error(`Encrypted object unavailable: ${response.status}`);
  const envelope = new Uint8Array(await response.arrayBuffer());
  if (new TextDecoder().decode(envelope.slice(0, 4)) !== MAGIC) throw new Error("Invalid object envelope");
  const key = await importKey();
  const aad = new TextEncoder().encode(`sittaigen-file-v1\0${entry.id}`);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: envelope.slice(4, 16), additionalData: aad, tagLength: 128 },
    key,
    envelope.slice(16)
  );
  const bytes = new Uint8Array(plaintext);
  if (bytes.byteLength <= MAX_CACHE_BYTES / 2) {
    while (cacheBytes + bytes.byteLength > MAX_CACHE_BYTES && plaintextCache.size) {
      const [oldestId, oldest] = plaintextCache.entries().next().value;
      plaintextCache.delete(oldestId);
      cacheBytes -= oldest.byteLength;
    }
    plaintextCache.set(entry.id, bytes);
    cacheBytes += bytes.byteLength;
  }
  return bytes;
}

function rangedResponse(bytes, request, headers) {
  const range = request.headers.get("Range");
  if (!range) return new Response(bytes, { status: 200, headers });
  const match = /^bytes=(\d*)-(\d*)$/.exec(range);
  if (!match) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${bytes.byteLength}` } });
  const start = match[1] ? Number(match[1]) : 0;
  const end = match[2] ? Math.min(Number(match[2]), bytes.byteLength - 1) : bytes.byteLength - 1;
  if (start > end || start >= bytes.byteLength) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${bytes.byteLength}` } });
  headers.set("Content-Range", `bytes ${start}-${end}/${bytes.byteLength}`);
  headers.set("Content-Length", String(end - start + 1));
  return new Response(bytes.slice(start, end + 1), { status: 206, headers });
}

async function handleContent(request, encodedPath) {
  if (!rawKey) return lockedResponse();
  let path;
  try { path = encodedPath.split("/").map(decodeURIComponent).join("/"); }
  catch (_) { return new Response("Invalid path", { status: 400 }); }
  if (!path || path.endsWith("/")) path += "index.html";
  const entry = manifestByPath.get(path);
  if (!entry) return new Response("Not found in encrypted manifest", { status: 404, headers: { "Cache-Control": "no-store" } });

  try {
    const bytes = await decryptFile(entry);
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
    return rangedResponse(bytes, request, headers);
  } catch (error) {
    return new Response("Decryption or integrity check failed", { status: 500, headers: { "Cache-Control": "no-store" } });
  }
}

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  const scopePath = new URL(self.registration.scope).pathname;
  const contentPrefix = `${scopePath}content/`;
  if (url.origin === self.location.origin && url.pathname.startsWith(contentPrefix)) {
    event.respondWith(handleContent(event.request, url.pathname.slice(contentPrefix.length)));
  }
});
