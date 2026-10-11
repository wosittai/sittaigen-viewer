"use strict";

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import {
  browserLocalPersistence,
  getAuth,
  getIdTokenResult,
  GoogleAuthProvider,
  onAuthStateChanged,
  setPersistence,
  signInWithPopup,
  signOut
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";
import { doc, getDoc, getFirestore } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-firestore.js";

const MANIFEST_AAD = "sittaigen-manifest-v1";
const SESSION_TTL_MS = 6 * 60 * 60 * 1000;
const SESSION_STARTED_KEY = "private-portal-session-started-v1";
const state = {
  auth: null,
  config: null,
  currentProject: null,
  db: null,
  expiryTimer: null,
  manifest: null,
  sessionStartedAt: 0,
  suppressReadyOnce: false,
  unlocking: false,
  user: null
};
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
  const registration = await navigator.serviceWorker.register("sw.js", { scope: "./", updateViaCache: "none" });
  await registration.update();
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

function initials(user) {
  const source = (user.displayName || user.email || "U").trim();
  const parts = source.split(/\s+/).filter(Boolean);
  return parts.slice(0, 2).map(part => part[0]).join("").toUpperCase();
}

function sessionStart(createIfMissing = false) {
  let value = 0;
  try { value = Number(localStorage.getItem(SESSION_STARTED_KEY)) || 0; }
  catch (_) { value = state.sessionStartedAt; }
  if (!value && createIfMissing) {
    value = Date.now();
    try { localStorage.setItem(SESSION_STARTED_KEY, String(value)); }
    catch (_) { /* The in-memory deadline still limits this tab. */ }
  }
  state.sessionStartedAt = value;
  return value;
}

function clearSessionStart() {
  state.sessionStartedAt = 0;
  try { localStorage.removeItem(SESSION_STARTED_KEY); }
  catch (_) { /* Local storage may be disabled. */ }
}

async function verifiedSessionStart(user) {
  try {
    const token = await getIdTokenResult(user);
    const authenticatedAt = Number(token.claims.auth_time) * 1000 || Date.parse(token.authTime);
    if (Number.isFinite(authenticatedAt) && authenticatedAt > 0) {
      state.sessionStartedAt = authenticatedAt;
      try { localStorage.setItem(SESSION_STARTED_KEY, String(authenticatedAt)); }
      catch (_) { /* The signed token still provides the deadline for this tab. */ }
      return authenticatedAt;
    }
  } catch (_) { /* A stored timestamp remains a safe fallback for temporary token errors. */ }
  return sessionStart(true);
}

function sessionRemaining() {
  return state.sessionStartedAt ? state.sessionStartedAt + SESSION_TTL_MS - Date.now() : 0;
}

function formatRemaining(milliseconds) {
  const totalMinutes = Math.max(0, Math.ceil(milliseconds / 60000));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function updateSessionLabel() {
  if (!state.user) return;
  const remaining = sessionRemaining();
  if (remaining <= 0) {
    void logout("Sesja wygasła po 6 godzinach. Zaloguj się ponownie.");
    return;
  }
  elements.securityLabel.textContent = `Sesja aktywna · ${formatRemaining(remaining)}`;
}

function scheduleExpiry() {
  clearInterval(state.expiryTimer);
  updateSessionLabel();
  state.expiryTimer = setInterval(updateSessionLabel, 30000);
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderProjects() {
  elements.projectGrid.replaceChildren();
  const projects = state.manifest?.projects;
  if (!Array.isArray(projects) || !projects.length) throw new Error("Brak projektów w zaszyfrowanym indeksie.");

  projects.forEach((project, index) => {
    const card = createElement("button", "project-card");
    card.type = "button";
    card.dataset.variant = String(index % 4);
    card.setAttribute("aria-label", `Otwórz projekt: ${project.name}`);

    const top = createElement("span", "project-card-top");
    top.append(createElement("span", "project-code", project.code || `PROJEKT ${String(index + 1).padStart(2, "0")}`));
    top.append(createElement("span", "project-arrow", "↗"));

    const visual = createElement("span", "project-visual");
    visual.setAttribute("aria-hidden", "true");
    visual.append(createElement("i"), createElement("i"), createElement("i"));

    const copy = createElement("span", "project-card-copy");
    copy.append(createElement("strong", "project-title", project.name));
    copy.append(createElement("span", "project-summary", project.summary || ""));

    const meta = createElement("span", "project-meta");
    for (const item of project.meta || []) meta.append(createElement("span", "", item));

    card.append(top, visual, copy, meta);
    card.addEventListener("click", () => openProject(project));
    elements.projectGrid.append(card);
  });
}

function showDashboard() {
  state.currentProject = null;
  elements.portalFrame.src = "about:blank";
  elements.projectPanel.hidden = true;
  elements.accessPanel.hidden = true;
  elements.dashboardPanel.hidden = false;
  document.title = "Panel projektowy";
}

function setPortal(view, button) {
  if (!view?.path) return;
  elements.portalLoading.hidden = false;
  for (const item of elements.projectNav.querySelectorAll("button")) item.dataset.active = String(item === button);
  elements.portalFrame.title = `${state.currentProject.name} — ${view.label}`;
  elements.portalFrame.src = contentUrl(view.path);
}

function openProject(project) {
  if (!Array.isArray(project.views) || !project.views.length) return;
  state.currentProject = project;
  elements.dashboardPanel.hidden = true;
  elements.projectPanel.hidden = false;
  elements.projectCode.textContent = project.code || "PROJECT";
  elements.projectName.textContent = project.name;
  elements.projectNav.replaceChildren();

  project.views.forEach((view, index) => {
    const button = createElement("button", "", view.label);
    button.type = "button";
    button.addEventListener("click", () => setPortal(view, button));
    elements.projectNav.append(button);
    if (index === 0) setPortal(view, button);
  });
  document.title = `${project.name} — Panel projektowy`;
}

async function unlock(user) {
  if (state.unlocking || state.user) return;
  state.unlocking = true;
  try {
    if (!user.email || !user.emailVerified) throw new Error("Google nie potwierdził adresu e-mail.");
    setStatus("Sprawdzanie uprawnień…");

    let keySnapshot;
    try {
      keySnapshot = await getDoc(doc(state.db, state.config.keyDocumentPath));
    } catch (error) {
      if (error.code === "permission-denied") throw new Error("To konto nie znajduje się na liście dostępu.");
      throw new Error(`Nie można potwierdzić dostępu: ${error.code || error.message}`);
    }
    if (!keySnapshot.exists()) throw new Error("Przestrzeń nie została jeszcze udostępniona.");
    const keyDocument = keySnapshot.data();
    const rawKey = base64urlToBytes(keyDocument.key || "");
    if (rawKey.length !== 32 || keyDocument.key_id !== state.config.expectedKeyId) {
      throw new Error("Nie można potwierdzić integralności przestrzeni.");
    }

    setStatus("Przygotowywanie prywatnej przestrzeni…");
    const manifestResponse = await fetch("vault/manifest.bin", { cache: "no-store" });
    if (!manifestResponse.ok) throw new Error("Nie można pobrać zaszyfrowanego indeksu.");
    const manifestRaw = await decryptEnvelope(rawKey, await manifestResponse.arrayBuffer(), MANIFEST_AAD);
    const manifest = JSON.parse(new TextDecoder().decode(manifestRaw));
    if (manifest.key_id !== keyDocument.key_id || !Array.isArray(manifest.files)) {
      throw new Error("Kontrola integralności przestrzeni nie powiodła się.");
    }

    const registration = await navigator.serviceWorker.ready;
    await sendWorkerMessage(registration, {
      type: "unlock",
      key: rawKey,
      manifest,
      expiresAt: state.sessionStartedAt + SESSION_TTL_MS
    });

    state.manifest = manifest;
    state.user = user;
    elements.securityState.dataset.state = "open";
    elements.dashboardIdentity.textContent = user.email;
    elements.userAvatar.textContent = initials(user);
    renderProjects();
    showDashboard();
    scheduleExpiry();
  } finally {
    state.unlocking = false;
  }
}

async function login() {
  try {
    setStatus("Otwieranie bezpiecznego okna logowania Google…");
    const provider = new GoogleAuthProvider();
    provider.setCustomParameters({ prompt: "select_account" });
    const credential = await signInWithPopup(state.auth, provider);
    await verifiedSessionStart(credential.user);
    await unlock(credential.user);
  } catch (error) {
    const cancelled = ["auth/popup-closed-by-user", "auth/cancelled-popup-request"].includes(error.code);
    setStatus(cancelled ? "Logowanie zostało przerwane." : (error.message || "Nie udało się otworzyć przestrzeni."), !cancelled);
    if (!cancelled && state.auth?.currentUser) {
      state.suppressReadyOnce = true;
      await signOut(state.auth).catch(() => {});
    }
  }
}

async function lockWorker() {
  try {
    const registration = await navigator.serviceWorker.ready;
    await sendWorkerMessage(registration, { type: "lock" });
  } catch (_) { /* The page is locked even if the worker has already stopped. */ }
}

async function logout(message = "Sesja została bezpiecznie zamknięta.") {
  clearInterval(state.expiryTimer);
  await lockWorker();
  clearSessionStart();
  state.manifest = null;
  state.user = null;
  state.currentProject = null;
  elements.portalFrame.src = "about:blank";
  elements.projectPanel.hidden = true;
  elements.dashboardPanel.hidden = true;
  elements.accessPanel.hidden = false;
  elements.securityState.dataset.state = "locked";
  elements.securityLabel.textContent = "Dostęp zablokowany";
  document.title = "Portal prywatny — dostęp";
  setStatus(message);
  if (state.auth?.currentUser) {
    state.suppressReadyOnce = true;
    await signOut(state.auth).catch(() => {});
  }
}

async function restoreSession(user) {
  if (!user) {
    elements.loginButton.disabled = false;
    if (state.suppressReadyOnce) {
      state.suppressReadyOnce = false;
      return;
    }
    if (state.user) {
      await logout("Sesja autoryzacyjna została zakończona. Zaloguj się ponownie.");
      return;
    }
    if (!state.user) setStatus("Środowisko gotowe. Oczekiwanie na autoryzację.");
    return;
  }

  const startedAt = await verifiedSessionStart(user);
  if (Date.now() - startedAt >= SESSION_TTL_MS) {
    await logout("Poprzednia sesja wygasła. Zaloguj się ponownie.");
    return;
  }

  try {
    setStatus("Przywracanie bezpiecznej sesji…");
    await unlock(user);
  } catch (error) {
    await logout(error.message || "Nie udało się przywrócić sesji.");
    setStatus(error.message || "Nie udało się przywrócić sesji.", true);
  }
}

async function init() {
  Object.assign(elements, {
    accessPanel: $("accessPanel"),
    backButton: $("backButton"),
    dashboardIdentity: $("dashboardIdentity"),
    dashboardLogoutButton: $("dashboardLogoutButton"),
    dashboardPanel: $("dashboardPanel"),
    loginButton: $("loginButton"),
    logoutButton: $("logoutButton"),
    portalFrame: $("portalFrame"),
    portalLoading: $("portalLoading"),
    projectCode: $("projectCode"),
    projectGrid: $("projectGrid"),
    projectName: $("projectName"),
    projectNav: $("projectNav"),
    projectPanel: $("projectPanel"),
    securityLabel: $("securityLabel"),
    securityState: $("securityState"),
    technicalStatus: $("technicalStatus"),
    userAvatar: $("userAvatar")
  });

  elements.loginButton.addEventListener("click", login);
  elements.logoutButton.addEventListener("click", () => logout());
  elements.dashboardLogoutButton.addEventListener("click", () => logout());
  elements.backButton.addEventListener("click", showDashboard);
  elements.portalFrame.addEventListener("load", () => { elements.portalLoading.hidden = true; });
  window.addEventListener("focus", updateSessionLabel);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) updateSessionLabel(); });
  window.addEventListener("storage", event => {
    if (event.key === SESSION_STARTED_KEY && !event.newValue && state.user) void logout();
  });

  try {
    state.config = await fetchJson("config.json");
    await registerWorker();
    const values = Object.values(state.config.firebase || {});
    if (!values.length || values.some(value => !value || String(value).startsWith("CONFIGURE_"))) {
      throw new Error("Administrator nie zakończył jeszcze konfiguracji dostępu.");
    }
    const firebaseApp = initializeApp(state.config.firebase);
    state.auth = getAuth(firebaseApp);
    state.db = getFirestore(firebaseApp);
    await setPersistence(state.auth, browserLocalPersistence);
    onAuthStateChanged(state.auth, user => { void restoreSession(user); });
  } catch (error) {
    setStatus(error.message || "Nie udało się zainicjalizować portalu.", true);
  }
}

window.addEventListener("DOMContentLoaded", init);
