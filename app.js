"use strict";

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import {
  browserSessionPersistence,
  getAuth,
  GoogleAuthProvider,
  setPersistence,
  signInWithPopup,
  signOut
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";
import { doc, getDoc, getFirestore } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-firestore.js";

const MANIFEST_AAD = "sittaigen-manifest-v1";
const state = { config: null, manifest: null, user: null, auth: null, db: null };
const elements = {};

function $(id) { return document.getElementById(id); }

function setStatus(message, error = false) {
  elements.technicalStatus.textContent = message;
  elements.technicalStatus.classList.toggle("error", error);
}

function base64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function importKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

async function decryptEnvelope(rawKey, envelope, aadText) {
  const bytes = new Uint8Array(envelope);
  const magic = new TextDecoder().decode(bytes.slice(0, 4));
  if (magic !== "STV1" || bytes.length < 32) throw new Error("Nieprawidłowy format zaszyfrowanego obiektu.");
  const key = await importKey(rawKey);
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytes.slice(4, 16),
      additionalData: new TextEncoder().encode(aadText),
      tagLength: 128
    },
    key,
    bytes.slice(16)
  );
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function registerWorker() {
  if (!("serviceWorker" in navigator)) throw new Error("Ta przeglądarka nie obsługuje bezpiecznego trybu odczytu.");
  const registration = await navigator.serviceWorker.register("sw.js", { scope: "./" });
  await navigator.serviceWorker.ready;
  return registration;
}

async function sendWorkerMessage(registration, payload) {
  const worker = registration.active || registration.waiting || registration.installing;
  if (!worker) throw new Error("Nie można uruchomić warstwy deszyfrującej.");
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timeout = setTimeout(() => reject(new Error("Brak odpowiedzi warstwy deszyfrującej.")), 8000);
    channel.port1.onmessage = event => {
      clearTimeout(timeout);
      event.data?.ok ? resolve(event.data) : reject(new Error(event.data?.error || "Błąd Service Workera"));
    };
    worker.postMessage(payload, [channel.port2]);
  });
}

function contentUrl(path) {
  return `content/${path.split("/").map(encodeURIComponent).join("/")}`;
}

function setPortal(path, activeButton) {
  elements.portalLoading.hidden = false;
  for (const button of [elements.indexButton, elements.simulatorsButton, elements.combinedReportButton]) {
    button.dataset.active = String(button === activeButton);
  }
  elements.portalFrame.src = contentUrl(path);
}

async function unlock(user) {
  if (!user.email || !user.emailVerified) throw new Error("Google nie potwierdził adresu e-mail.");
  setStatus("Sprawdzanie uprawnień i pobieranie klucza…");

  let keySnapshot;
  try {
    keySnapshot = await getDoc(doc(state.db, state.config.keyDocumentPath));
  } catch (error) {
    if (error.code === "permission-denied") throw new Error("To konto nie znajduje się na liście dostępu.");
    throw new Error(`Nie można odczytać klucza: ${error.code || error.message}`);
  }
  if (!keySnapshot.exists()) throw new Error("Administrator nie opublikował klucza repozytorium.");
  const keyDocument = keySnapshot.data();
  const rawKey = base64urlToBytes(keyDocument.key || "");
  if (rawKey.length !== 32 || keyDocument.key_id !== state.config.expectedKeyId) {
    throw new Error("Klucz nie odpowiada opublikowanemu repozytorium.");
  }

  setStatus("Odszyfrowywanie i kontrola integralności manifestu…");
  const manifestResponse = await fetch("vault/manifest.bin", { cache: "no-store" });
  if (!manifestResponse.ok) throw new Error("Nie można pobrać zaszyfrowanego manifestu.");
  const manifestRaw = await decryptEnvelope(rawKey, await manifestResponse.arrayBuffer(), MANIFEST_AAD);
  const manifest = JSON.parse(new TextDecoder().decode(manifestRaw));
  if (manifest.key_id !== keyDocument.key_id || !Array.isArray(manifest.files)) {
    throw new Error("Kontrola integralności manifestu nie powiodła się.");
  }

  const registration = await navigator.serviceWorker.ready;
  await sendWorkerMessage(registration, { type: "unlock", key: rawKey, manifest });

  state.manifest = manifest;
  state.user = user;
  elements.accessPanel.hidden = true;
  elements.archivePanel.hidden = false;
  elements.securityState.dataset.state = "open";
  elements.securityLabel.textContent = "Sesja odszyfrowana";
  elements.identityLine.textContent = `ZWERYFIKOWANO: ${user.email}`;
  setPortal(manifest.main_entry || state.config.mainEntry, elements.indexButton);
}

async function login() {
  try {
    setStatus("Otwieranie bezpiecznego okna logowania Google…");
    const provider = new GoogleAuthProvider();
    provider.setCustomParameters({ prompt: "select_account" });
    const credential = await signInWithPopup(state.auth, provider);
    await unlock(credential.user);
  } catch (error) {
    const cancelled = ["auth/popup-closed-by-user", "auth/cancelled-popup-request"].includes(error.code);
    setStatus(cancelled ? "Logowanie zostało przerwane." : (error.message || "Nie udało się otworzyć repozytorium."), !cancelled);
  }
}

async function logout() {
  try {
    const registration = await navigator.serviceWorker.ready;
    await sendWorkerMessage(registration, { type: "lock" });
  } catch (_) { /* The page is locked even if the worker has already stopped. */ }
  if (state.auth) await signOut(state.auth).catch(() => {});
  state.manifest = null;
  state.user = null;
  elements.portalFrame.src = "about:blank";
  elements.archivePanel.hidden = true;
  elements.accessPanel.hidden = false;
  elements.securityState.dataset.state = "locked";
  elements.securityLabel.textContent = "Repozytorium zablokowane";
  setStatus("Sesja została zamknięta. Klucz usunięto z pamięci przeglądarki.");
}

async function init() {
  Object.assign(elements, {
    accessPanel: $("accessPanel"), archivePanel: $("archivePanel"), loginButton: $("loginButton"),
    logoutButton: $("logoutButton"), technicalStatus: $("technicalStatus"),
    securityState: $("securityState"), securityLabel: $("securityLabel"), identityLine: $("identityLine"),
    indexButton: $("indexButton"), simulatorsButton: $("simulatorsButton"),
    combinedReportButton: $("combinedReportButton"), portalFrame: $("portalFrame"), portalLoading: $("portalLoading")
  });

  try {
    state.config = await fetchJson("config.json");
    await registerWorker();
    const values = Object.values(state.config.firebase || {});
    if (!values.length || values.some(value => !value || String(value).startsWith("CONFIGURE_"))) {
      throw new Error("Administrator nie zakończył jeszcze konfiguracji Firebase.");
    }
    const firebaseApp = initializeApp(state.config.firebase);
    state.auth = getAuth(firebaseApp);
    state.db = getFirestore(firebaseApp);
    await setPersistence(state.auth, browserSessionPersistence);
    elements.loginButton.disabled = false;
    setStatus("Środowisko gotowe. Oczekiwanie na autoryzację.");
  } catch (error) {
    setStatus(error.message || "Nie udało się zainicjalizować repozytorium.", true);
  }

  elements.loginButton.addEventListener("click", login);
  elements.logoutButton.addEventListener("click", logout);
  elements.indexButton.addEventListener("click", () => setPortal(state.manifest.main_entry || state.config.mainEntry, elements.indexButton));
  elements.simulatorsButton.addEventListener("click", () => setPortal("program_badawczy_2025_2026/symulatory/index.html", elements.simulatorsButton));
  elements.combinedReportButton.addEventListener("click", () => setPortal("program_badawczy_2025_2026/SITTAI_program_badawczy_2025-05_2026-09.pdf", elements.combinedReportButton));
  elements.portalFrame.addEventListener("load", () => { elements.portalLoading.hidden = true; });
}

window.addEventListener("DOMContentLoaded", init);
