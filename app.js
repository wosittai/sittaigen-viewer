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
import {
  collection,
  doc,
  getDoc,
  getFirestore,
  onSnapshot,
  runTransaction,
  serverTimestamp,
  setDoc,
  Timestamp,
  updateDoc
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-firestore.js";

const MANIFEST_AAD = "sittaigen-manifest-v1";
const SESSION_TTL_MS = 6 * 60 * 60 * 1000;
const SESSION_STARTED_KEY = "private-portal-session-started-v1";
const DEVICE_TRUST_KEY = "private-portal-device-trust-v1";
const DEVICE_TRUST_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const ADMIN_EMAIL = "coinguard2024@gmail.com";
const ACCESS_COLLECTION = "accessUsers";
const LEGACY_EMAILS = new Set(["wosittai@gmail.com", "79elem@gmail.com"]);
const ACCESS_MODULES = [
  { id: "core", label: "SITTAI i mapy lasów" },
  { id: "hawthorn", label: "Mapa głogu" }
];
const ALL_MODULE_IDS = ACCESS_MODULES.map(module => module.id);
const CHALLENGE_WORDS = [
  { id: "word-0", text: "Uroczyście" },
  { id: "word-1", text: "przysięgam," },
  { id: "word-2", text: "że" },
  { id: "word-3", text: "knuję" },
  { id: "word-4", text: "coś" },
  { id: "word-5", text: "niedobrego" }
];
const state = {
  accessExpiryTimer: null,
  accessRecord: null,
  accessUnsubscribe: null,
  adminUsers: [],
  adminUsersUnsubscribe: null,
  auth: null,
  authTime: 0,
  config: null,
  currentProject: null,
  db: null,
  deviceFingerprint: "",
  deviceTrusted: false,
  draggedWordId: null,
  editingEmail: null,
  expiryTimer: null,
  firebaseReady: false,
  manifest: null,
  pendingUser: null,
  recoveryPromise: null,
  sessionStartedAt: 0,
  suppressReadyOnce: false,
  unlocking: false,
  user: null,
  vaultModules: [],
  workerRegistration: null,
  wordBank: [],
  wordSlots: Array(CHALLENGE_WORDS.length).fill(null)
};
const elements = {};

function $(id) { return document.getElementById(id); }
function normalizedEmail(value) { return String(value || "").trim().toLowerCase(); }
function isAdminUser(user = state.user) { return normalizedEmail(user?.email) === ADMIN_EMAIL; }
function normalizedModules(record) {
  if (record?.admin || record?.legacy || !Array.isArray(record?.modules)) return [...ALL_MODULE_IDS];
  return ALL_MODULE_IDS.filter(moduleId => record.modules.includes(moduleId));
}
function moduleLabel(moduleId) {
  return ACCESS_MODULES.find(module => module.id === moduleId)?.label || moduleId;
}

function setStatus(message, error = false) {
  elements.technicalStatus.textContent = message;
  elements.technicalStatus.classList.toggle("error", error);
}

function updateLoginAvailability() {
  if (!elements.loginButton) return;
  elements.loginButton.disabled = !(state.firebaseReady && state.deviceTrusted && !state.unlocking);
}

async function browserFingerprint() {
  const screenLong = Math.max(screen.width || 0, screen.height || 0);
  const screenShort = Math.min(screen.width || 0, screen.height || 0);
  const profile = [
    navigator.userAgentData?.platform || navigator.platform || "",
    (navigator.userAgentData?.brands || []).map(item => item.brand).sort().join(","),
    navigator.language || "",
    Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    navigator.maxTouchPoints || 0,
    screenLong,
    screenShort,
    screen.colorDepth || 0
  ].join("|");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(profile));
  return Array.from(new Uint8Array(digest)).slice(0, 16).map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function shuffledChallengeWords() {
  const words = CHALLENGE_WORDS.map(word => word.id);
  for (let index = words.length - 1; index > 0; index -= 1) {
    const random = new Uint32Array(1);
    crypto.getRandomValues(random);
    const other = random[0] % (index + 1);
    [words[index], words[other]] = [words[other], words[index]];
  }
  if (words.every((word, index) => word === CHALLENGE_WORDS[index].id)) words.push(words.shift());
  return words;
}

function challengeWord(wordId) {
  return CHALLENGE_WORDS.find(word => word.id === wordId);
}

function createWordChip(wordId, location) {
  const word = challengeWord(wordId);
  const chip = createElement("button", "word-chip", word.text);
  chip.type = "button";
  chip.draggable = true;
  chip.dataset.wordId = wordId;
  chip.setAttribute("aria-label", location === "bank" ? `Dodaj słowo: ${word.text}` : `Cofnij słowo: ${word.text}`);
  chip.addEventListener("dragstart", event => {
    state.draggedWordId = wordId;
    chip.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", wordId);
  });
  chip.addEventListener("dragend", () => {
    state.draggedWordId = null;
    chip.classList.remove("dragging");
  });
  chip.addEventListener("click", () => {
    if (location === "bank") {
      const empty = state.wordSlots.indexOf(null);
      if (empty >= 0) moveWordToSlot(wordId, empty);
    } else {
      returnWordToBank(wordId);
    }
  });
  return chip;
}

function moveWordToSlot(wordId, targetIndex) {
  const sourceIndex = state.wordSlots.indexOf(wordId);
  const bankIndex = state.wordBank.indexOf(wordId);
  if (sourceIndex >= 0) state.wordSlots[sourceIndex] = null;
  if (bankIndex >= 0) state.wordBank.splice(bankIndex, 1);

  const displaced = state.wordSlots[targetIndex];
  if (displaced && displaced !== wordId) {
    if (sourceIndex >= 0) state.wordSlots[sourceIndex] = displaced;
    else state.wordBank.push(displaced);
  }
  state.wordSlots[targetIndex] = wordId;
  renderDeviceChallenge();
  checkDeviceChallenge();
}

function returnWordToBank(wordId) {
  const sourceIndex = state.wordSlots.indexOf(wordId);
  if (sourceIndex >= 0) state.wordSlots[sourceIndex] = null;
  if (!state.wordBank.includes(wordId)) state.wordBank.push(wordId);
  renderDeviceChallenge();
}

function renderDeviceChallenge() {
  elements.wordBank.replaceChildren(...state.wordBank.map(wordId => createWordChip(wordId, "bank")));
  elements.sentenceRiver.replaceChildren();
  state.wordSlots.forEach((wordId, index) => {
    const slot = createElement("div", "river-slot");
    slot.dataset.slotIndex = String(index);
    slot.addEventListener("dragover", event => {
      event.preventDefault();
      slot.classList.add("drop-active");
      event.dataTransfer.dropEffect = "move";
    });
    slot.addEventListener("dragleave", () => slot.classList.remove("drop-active"));
    slot.addEventListener("drop", event => {
      event.preventDefault();
      slot.classList.remove("drop-active");
      const dragged = event.dataTransfer.getData("text/plain") || state.draggedWordId;
      if (challengeWord(dragged)) moveWordToSlot(dragged, index);
    });
    if (wordId) slot.append(createWordChip(wordId, "river"));
    elements.sentenceRiver.append(slot);
  });
}

function checkDeviceChallenge() {
  if (state.wordSlots.includes(null)) return;
  const correct = state.wordSlots.every((wordId, index) => wordId === CHALLENGE_WORDS[index].id);
  if (correct) {
    void trustCurrentDevice();
    return;
  }
  elements.challengeStatus.textContent = "Nurt jeszcze się nie układa — przesuń słowa.";
  elements.deviceChallenge.classList.remove("wrong");
  void elements.deviceChallenge.offsetWidth;
  elements.deviceChallenge.classList.add("wrong");
}

async function trustCurrentDevice() {
  if (state.deviceTrusted) return;
  state.deviceTrusted = true;
  try {
    localStorage.setItem(DEVICE_TRUST_KEY, JSON.stringify({
      fingerprint: state.deviceFingerprint,
      expiresAt: Date.now() + DEVICE_TRUST_TTL_MS
    }));
  } catch (_) { /* Trust remains valid for the current tab. */ }

  elements.challengeStatus.textContent = "Nurt otwarty.";
  elements.deviceChallenge.classList.remove("wrong");
  elements.deviceChallenge.classList.add("solved");
  setTimeout(() => {
    elements.deviceChallenge.hidden = true;
    elements.loginButton.hidden = false;
    updateLoginAvailability();
    setStatus(state.firebaseReady ? "Możesz kontynuować." : "Inicjalizacja…");
  }, 650);

  if (state.pendingUser) {
    const pendingUser = state.pendingUser;
    state.pendingUser = null;
    await restoreSession(pendingUser);
  }
}

async function initializeDeviceTrust() {
  state.deviceFingerprint = await browserFingerprint();
  let trusted = false;
  try {
    const saved = JSON.parse(localStorage.getItem(DEVICE_TRUST_KEY) || "null");
    trusted = saved?.fingerprint === state.deviceFingerprint && Number(saved.expiresAt) > Date.now();
    if (!trusted) localStorage.removeItem(DEVICE_TRUST_KEY);
  } catch (_) { trusted = false; }

  state.deviceTrusted = trusted;
  if (trusted) {
    elements.deviceChallenge.hidden = true;
    elements.loginButton.hidden = false;
  } else {
    state.wordBank = shuffledChallengeWords();
    state.wordSlots = Array(CHALLENGE_WORDS.length).fill(null);
    elements.deviceChallenge.hidden = false;
    elements.loginButton.hidden = true;
    elements.wordBank.addEventListener("dragover", event => {
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
    });
    elements.wordBank.addEventListener("drop", event => {
      event.preventDefault();
      const dragged = event.dataTransfer.getData("text/plain") || state.draggedWordId;
      if (challengeWord(dragged)) returnWordToBank(dragged);
    });
    renderDeviceChallenge();
  }
  updateLoginAvailability();
}

function base64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function bytesToBase64url(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function bytesKeyId(value) {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(digest)).slice(0, 12).map(byte => byte.toString(16).padStart(2, "0")).join("");
}

async function deriveModuleKey(masterKey, moduleId) {
  const hmacKey = await crypto.subtle.importKey("raw", masterKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const message = new TextEncoder().encode(`sittaigen-module-key-v1\0${moduleId}`);
  return new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, message));
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

async function primeWorkerSession() {
  const remaining = sessionRemaining();
  if (!state.vaultModules.length || !state.manifest || remaining <= 0) {
    throw new Error("Sesja wygasła po 6 godzinach. Zaloguj się ponownie.");
  }
  const registration = state.workerRegistration || await navigator.serviceWorker.ready;
  state.workerRegistration = registration;
  return sendWorkerMessage(registration, {
    type: "unlock",
    modules: state.vaultModules,
    expiresAt: state.sessionStartedAt + SESSION_TTL_MS
  });
}

async function recoverEmbeddedSession(reloadView = false) {
  if (!state.user || !state.vaultModules.length || !state.manifest) return;
  if (!state.recoveryPromise) {
    state.recoveryPromise = primeWorkerSession().finally(() => {
      state.recoveryPromise = null;
    });
  }
  try {
    await state.recoveryPromise;
    const viewUrl = elements.portalFrame.dataset.contentUrl;
    if (reloadView && viewUrl && !elements.projectPanel.hidden) {
      elements.portalLoading.hidden = false;
      elements.portalFrame.src = viewUrl;
    }
  } catch (error) {
    if (sessionRemaining() <= 0) await logout("Sesja wygasła po 6 godzinach. Zaloguj się ponownie.");
    else setStatus(error.message || "Nie udało się wznowić widoku projektu.", true);
  }
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
    const authTime = Number(token.claims.auth_time);
    const authenticatedAt = authTime * 1000 || Date.parse(token.authTime);
    if (Number.isFinite(authenticatedAt) && authenticatedAt > 0) {
      state.authTime = Number.isInteger(authTime) && authTime > 0 ? authTime : Math.floor(authenticatedAt / 1000);
      state.sessionStartedAt = authenticatedAt;
      try { localStorage.setItem(SESSION_STARTED_KEY, String(authenticatedAt)); }
      catch (_) { /* The signed token still provides the deadline for this tab. */ }
      return authenticatedAt;
    }
  } catch (_) { /* A stored timestamp remains a safe fallback for temporary token errors. */ }
  state.authTime = Math.floor(sessionStart(true) / 1000);
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

function createAdminCard(index) {
  const card = createElement("button", "project-card admin-project-card");
  card.type = "button";
  card.dataset.variant = "admin";
  card.setAttribute("aria-label", "Otwórz panel administracyjny");

  const top = createElement("span", "project-card-top");
  top.append(createElement("span", "project-code", "ADMIN / ACCESS CONTROL"));
  top.append(createElement("span", "project-arrow", "↗"));

  const visual = createElement("span", "project-visual admin-visual");
  visual.setAttribute("aria-hidden", "true");
  visual.append(createElement("i"), createElement("i"), createElement("i"));

  const copy = createElement("span", "project-card-copy");
  copy.append(createElement("strong", "project-title", "ADMIN"));
  copy.append(createElement("span", "project-summary", "Konta, okresy dostępu i limity logowań do prywatnej przestrzeni."));

  const meta = createElement("span", "project-meta");
  meta.append(createElement("span", "", "Tylko administrator"));
  meta.append(createElement("span", "", `${state.adminUsers.filter(item => !item.deleted).length || "—"} kont`));

  card.append(top, visual, copy, meta);
  card.style.setProperty("--project-index", index);
  card.addEventListener("click", showAdminPanel);
  return card;
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

  if (isAdminUser()) elements.projectGrid.append(createAdminCard(projects.length));
}

function showDashboard() {
  state.currentProject = null;
  document.body.classList.remove("login-mode");
  elements.portalFrame.src = "about:blank";
  elements.projectPanel.hidden = true;
  elements.adminPanel.hidden = true;
  elements.accessPanel.hidden = true;
  elements.dashboardPanel.hidden = false;
  document.title = "Panel projektowy";
}

async function setPortal(view, button) {
  if (!view?.path) return;
  elements.portalLoading.hidden = false;
  for (const item of elements.projectNav.querySelectorAll("button")) item.dataset.active = String(item === button);
  elements.portalFrame.title = `${state.currentProject.name} — ${view.label}`;
  const viewUrl = contentUrl(view.path);
  elements.portalFrame.dataset.contentUrl = viewUrl;
  try {
    await primeWorkerSession();
    elements.portalFrame.src = viewUrl;
  } catch (error) {
    elements.portalLoading.textContent = error.message || "Nie udało się wznowić widoku.";
    if (sessionRemaining() <= 0) await logout("Sesja wygasła po 6 godzinach. Zaloguj się ponownie.");
  }
}

function openProject(project) {
  if (!Array.isArray(project.views) || !project.views.length) return;
  state.currentProject = project;
  document.body.classList.remove("login-mode");
  elements.dashboardPanel.hidden = true;
  elements.adminPanel.hidden = true;
  elements.projectPanel.hidden = false;
  elements.projectCode.textContent = project.code || "PROJECT";
  elements.projectName.textContent = project.name;
  elements.projectNav.replaceChildren();

  project.views.forEach((view, index) => {
    const button = createElement("button", "", view.label);
    button.type = "button";
    button.addEventListener("click", () => { void setPortal(view, button); });
    elements.projectNav.append(button);
    if (index === 0) void setPortal(view, button);
  });
  document.title = `${project.name} — Panel projektowy`;
}

function accessDocument(email) {
  return doc(state.db, ACCESS_COLLECTION, normalizedEmail(email));
}

function timestampMillis(value) {
  return value && typeof value.toMillis === "function" ? value.toMillis() : null;
}

function accessFailure(message) {
  const error = new Error(message);
  error.name = "AccessDeniedError";
  return error;
}

function validateAccessRecord(record, countNewLogin) {
  const now = Date.now();
  const startsAt = timestampMillis(record.startsAt);
  const expiresAt = timestampMillis(record.expiresAt);
  const maxLogins = Number(record.maxLogins) || 0;
  const loginCount = Number(record.loginCount) || 0;

  if (record.deleted || record.enabled !== true) throw accessFailure("Dostęp tego konta został wyłączony.");
  if (startsAt && startsAt > now) throw accessFailure(`Dostęp rozpocznie się ${formatDateTime(record.startsAt)}.`);
  if (expiresAt && expiresAt <= now) throw accessFailure("Czas dostępu tego konta już wygasł.");
  if (maxLogins > 0 && loginCount > maxLogins) throw accessFailure("Limit logowań tego konta został przekroczony.");
  if (countNewLogin && maxLogins > 0 && loginCount >= maxLogins) {
    throw accessFailure("Wykorzystano limit logowań tego konta.");
  }
}

async function claimPortalAccess(user) {
  const email = normalizedEmail(user.email);
  if (email === ADMIN_EMAIL) return { admin: true, email };

  try {
    return await runTransaction(state.db, async transaction => {
      const reference = accessDocument(email);
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists()) {
        if (LEGACY_EMAILS.has(email)) return { email, legacy: true };
        throw accessFailure("To konto nie znajduje się na liście dostępu.");
      }

      const record = snapshot.data();
      const countNewLogin = Number(record.lastAuthTime) !== state.authTime;
      validateAccessRecord(record, countNewLogin);
      if (countNewLogin) {
        transaction.update(reference, {
          lastAuthTime: state.authTime,
          lastLoginAt: serverTimestamp(),
          loginCount: (Number(record.loginCount) || 0) + 1
        });
      }
      return {
        ...record,
        email,
        loginCount: (Number(record.loginCount) || 0) + (countNewLogin ? 1 : 0),
        lastAuthTime: state.authTime
      };
    });
  } catch (error) {
    if (LEGACY_EMAILS.has(email) && error.code === "permission-denied") return { email, legacy: true };
    if (error.name === "AccessDeniedError") throw error;
    if (error.code === "permission-denied") throw accessFailure("To konto nie ma aktywnego dostępu.");
    throw error;
  }
}

function stopAccessWatcher() {
  if (state.accessUnsubscribe) state.accessUnsubscribe();
  state.accessUnsubscribe = null;
  clearTimeout(state.accessExpiryTimer);
  state.accessExpiryTimer = null;
}

function scheduleAccessExpiry(record) {
  clearTimeout(state.accessExpiryTimer);
  state.accessExpiryTimer = null;
  const expiresAt = timestampMillis(record?.expiresAt);
  if (!expiresAt) return;
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) {
    void logout("Czas dostępu tego konta wygasł.");
    return;
  }
  state.accessExpiryTimer = setTimeout(
    () => scheduleAccessExpiry(record),
    Math.min(remaining + 250, 2147483647)
  );
}

function startAccessWatcher(user) {
  stopAccessWatcher();
  if (isAdminUser(user)) return;
  const email = normalizedEmail(user.email);
  state.accessUnsubscribe = onSnapshot(accessDocument(email), snapshot => {
    if (!state.user) return;
    if (!snapshot.exists()) {
      if (!LEGACY_EMAILS.has(email)) void logout("Dostęp tego konta został usunięty.");
      return;
    }
    try {
      const record = snapshot.data();
      validateAccessRecord(record, false);
      const previousModules = normalizedModules(state.accessRecord).join(",");
      const nextModules = normalizedModules(record).join(",");
      if (state.accessRecord && previousModules !== nextModules) {
        void logout("Zakres udostępnionych modułów został zmieniony. Zaloguj się ponownie.");
        return;
      }
      state.accessRecord = record;
      scheduleAccessExpiry(record);
    } catch (error) {
      void logout(error.message || "Dostęp tego konta został zakończony.");
    }
  }, error => {
    if (error.code !== "permission-denied" || !LEGACY_EMAILS.has(email)) {
      void logout("Nie można już potwierdzić uprawnień tego konta.");
    }
  });
}

function formatDateTime(value) {
  const milliseconds = timestampMillis(value);
  if (!milliseconds) return "bez terminu";
  return new Intl.DateTimeFormat("pl-PL", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(milliseconds));
}

function toDateTimeInput(value) {
  const milliseconds = timestampMillis(value);
  if (!milliseconds) return "";
  const date = new Date(milliseconds);
  const localDate = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return localDate.toISOString().slice(0, 16);
}

function accessState(record) {
  const now = Date.now();
  const startsAt = timestampMillis(record.startsAt);
  const expiresAt = timestampMillis(record.expiresAt);
  if (record.deleted || record.enabled !== true) return { code: "disabled", label: "Wyłączony" };
  if (startsAt && startsAt > now) return { code: "planned", label: "Zaplanowany" };
  if (expiresAt && expiresAt <= now) return { code: "expired", label: "Wygasł" };
  return { code: "active", label: "Aktywny" };
}

function setAdminStatus(message, error = false) {
  elements.adminStatus.textContent = message;
  elements.adminStatus.classList.toggle("error", error);
}

function createAdminButton(label, action, tone = "") {
  const button = createElement("button", `admin-action ${tone}`.trim(), label);
  button.type = "button";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await action();
    } catch (error) {
      setAdminStatus(error.message || "Nie udało się zapisać zmiany.", true);
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

function editAccessAccount(record) {
  state.editingEmail = record.email;
  elements.accessEmail.value = record.email;
  elements.accessEmail.readOnly = true;
  elements.accessStartsAt.value = toDateTimeInput(record.startsAt);
  elements.accessDuration.value = record.expiresAt ? "custom" : "unlimited";
  elements.accessExpiresAt.value = toDateTimeInput(record.expiresAt);
  elements.accessMaxLogins.value = String(Number(record.maxLogins) || 0);
  elements.accessEnabled.checked = record.enabled === true;
  const modules = normalizedModules(record);
  elements.accessModuleCore.checked = modules.includes("core");
  elements.accessModuleHawthorn.checked = modules.includes("hawthorn");
  elements.accessFormTitle.textContent = "Edytuj dostęp";
  elements.accessSubmitButton.textContent = "Zapisz zmiany";
  elements.accessCancelButton.hidden = false;
  updateDurationControl();
  elements.accessForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

function resetAdminForm() {
  state.editingEmail = null;
  elements.accessForm.reset();
  elements.accessEmail.readOnly = false;
  elements.accessDuration.value = "7d";
  elements.accessMaxLogins.value = "0";
  elements.accessEnabled.checked = true;
  elements.accessModuleCore.checked = true;
  elements.accessModuleHawthorn.checked = true;
  elements.accessFormTitle.textContent = "Dodaj konto";
  elements.accessSubmitButton.textContent = "Dodaj dostęp";
  elements.accessCancelButton.hidden = true;
  updateDurationControl();
}

function updateDurationControl() {
  const custom = elements.accessDuration.value === "custom";
  elements.accessExpiresAt.disabled = !custom;
  elements.accessExpiresAt.required = custom;
  elements.accessExpiryField.dataset.disabled = String(!custom);
}

function renderAdminUsers() {
  const users = state.adminUsers
    .filter(record => !record.deleted)
    .sort((a, b) => a.email.localeCompare(b.email, "pl"));
  elements.adminUserCount.textContent = String(users.length);
  elements.accessUserList.replaceChildren();

  if (!users.length) {
    elements.accessUserList.append(createElement("p", "admin-empty", "Brak dodanych kont. Administrator ma dostęp niezależny od tej listy."));
    return;
  }

  for (const record of users) {
    const card = createElement("article", "access-user");
    const stateInfo = accessState(record);

    const identity = createElement("div", "access-user-identity");
    identity.append(createElement("strong", "", record.email));
    identity.append(createElement("span", `access-badge ${stateInfo.code}`, stateInfo.label));

    const period = createElement("div", "access-user-fact");
    period.append(createElement("span", "", "OKRES DOSTĘPU"));
    const start = record.startsAt ? formatDateTime(record.startsAt) : "od razu";
    const end = record.expiresAt ? formatDateTime(record.expiresAt) : "bezterminowo";
    period.append(createElement("strong", "", `${start} → ${end}`));

    const logins = createElement("div", "access-user-fact");
    logins.append(createElement("span", "", "LOGOWANIA"));
    const used = Number(record.loginCount) || 0;
    const limit = Number(record.maxLogins) || 0;
    logins.append(createElement("strong", "", limit ? `${used} / ${limit}` : `${used} / bez limitu`));
    if (record.lastLoginAt) logins.append(createElement("small", "", `Ostatnie: ${formatDateTime(record.lastLoginAt)}`));

    const modules = createElement("div", "access-user-fact");
    modules.append(createElement("span", "", "MODUŁY"));
    modules.append(createElement("strong", "", normalizedModules(record).map(moduleLabel).join(" · ")));

    const actions = createElement("div", "access-user-actions");
    actions.append(createAdminButton("Edytuj", () => editAccessAccount(record)));
    actions.append(createAdminButton("Wyzeruj licznik", async () => {
      await updateDoc(accessDocument(record.email), {
        lastAuthTime: 0,
        lastLoginAt: null,
        loginCount: 0,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      setAdminStatus(`Licznik ${record.email} został wyzerowany.`);
    }));
    actions.append(createAdminButton(record.enabled ? "Wstrzymaj" : "Włącz", async () => {
      await updateDoc(accessDocument(record.email), {
        enabled: !record.enabled,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      setAdminStatus(record.enabled ? `Dostęp ${record.email} został wstrzymany.` : `Dostęp ${record.email} został włączony.`);
    }, record.enabled ? "warning" : "positive"));
    actions.append(createAdminButton("Usuń dostęp", async () => {
      if (!window.confirm(`Odebrać i usunąć dostęp dla ${record.email}?`)) return;
      await updateDoc(accessDocument(record.email), {
        deleted: true,
        enabled: false,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      if (state.editingEmail === record.email) resetAdminForm();
      setAdminStatus(`Dostęp ${record.email} został usunięty.`);
    }, "danger"));

    card.append(identity, period, logins, modules, actions);
    elements.accessUserList.append(card);
  }
}

function startAdminUsersListener() {
  if (state.adminUsersUnsubscribe) return;
  setAdminStatus("Pobieranie listy dostępów…");
  state.adminUsersUnsubscribe = onSnapshot(collection(state.db, ACCESS_COLLECTION), snapshot => {
    state.adminUsers = snapshot.docs.map(item => ({ id: item.id, ...item.data() }));
    renderAdminUsers();
    if (state.manifest) renderProjects();
    setAdminStatus("Zmiany są zapisywane i stosowane na żywo.");
  }, error => {
    setAdminStatus(
      error.code === "permission-denied"
        ? "Panel jest gotowy, ale nowe reguły Firestore nie zostały jeszcze opublikowane."
        : (error.message || "Nie udało się pobrać listy kont."),
      true
    );
  });
}

function showAdminPanel() {
  if (!isAdminUser()) return;
  document.body.classList.remove("login-mode");
  elements.portalFrame.src = "about:blank";
  elements.projectPanel.hidden = true;
  elements.dashboardPanel.hidden = true;
  elements.accessPanel.hidden = true;
  elements.adminPanel.hidden = false;
  document.title = "ADMIN — Panel projektowy";
  startAdminUsersListener();
}

function readAccessForm() {
  const email = normalizedEmail(elements.accessEmail.value);
  if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error("Wpisz poprawny adres e-mail.");
  if (email === ADMIN_EMAIL) throw new Error("Konto administratora nie wymaga rekordu dostępu.");

  const startsDate = elements.accessStartsAt.value ? new Date(elements.accessStartsAt.value) : null;
  if (startsDate && Number.isNaN(startsDate.getTime())) throw new Error("Nieprawidłowa data rozpoczęcia.");

  const duration = elements.accessDuration.value;
  let expiresDate = null;
  if (duration === "custom") {
    expiresDate = new Date(elements.accessExpiresAt.value);
    if (Number.isNaN(expiresDate.getTime())) throw new Error("Wybierz datę zakończenia dostępu.");
  } else if (duration !== "unlimited") {
    const durationMs = Number(duration);
    const base = startsDate?.getTime() || Date.now();
    expiresDate = new Date(base + durationMs);
  }
  if (expiresDate && expiresDate.getTime() <= (startsDate?.getTime() || Date.now())) {
    throw new Error("Data zakończenia musi być późniejsza niż rozpoczęcie dostępu.");
  }

  const maxLogins = Number(elements.accessMaxLogins.value);
  if (!Number.isInteger(maxLogins) || maxLogins < 0) throw new Error("Limit logowań musi być liczbą całkowitą od 0 wzwyż.");

  const modules = [
    elements.accessModuleCore.checked ? "core" : null,
    elements.accessModuleHawthorn.checked ? "hawthorn" : null
  ].filter(Boolean);
  if (!modules.length) throw new Error("Wybierz co najmniej jeden udostępniony moduł.");

  return {
    email,
    enabled: elements.accessEnabled.checked,
    startsAt: startsDate ? Timestamp.fromDate(startsDate) : null,
    expiresAt: expiresDate ? Timestamp.fromDate(expiresDate) : null,
    maxLogins,
    modules
  };
}

async function saveAccessAccount(event) {
  event.preventDefault();
  elements.accessSubmitButton.disabled = true;
  try {
    const values = readAccessForm();
    const reference = accessDocument(values.email);
    const existing = await getDoc(reference);
    const listed = state.adminUsers.find(record => record.email === values.email && !record.deleted);
    if (!state.editingEmail && listed) throw new Error("To konto już istnieje. Użyj przycisku Edytuj.");

    if (state.editingEmail) {
      await updateDoc(reference, {
        ...values,
        deleted: false,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      setAdminStatus(`Zapisano ustawienia ${values.email}.`);
    } else if (existing.exists()) {
      await updateDoc(reference, {
        ...values,
        deleted: false,
        lastAuthTime: 0,
        lastLoginAt: null,
        loginCount: 0,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      setAdminStatus(`Ponownie nadano dostęp ${values.email}.`);
    } else {
      await setDoc(reference, {
        ...values,
        deleted: false,
        lastAuthTime: 0,
        lastLoginAt: null,
        loginCount: 0,
        createdAt: serverTimestamp(),
        createdBy: ADMIN_EMAIL,
        updatedAt: serverTimestamp(),
        updatedBy: ADMIN_EMAIL
      });
      setAdminStatus(`Dodano dostęp dla ${values.email}.`);
    }
    resetAdminForm();
  } catch (error) {
    setAdminStatus(error.message || "Nie udało się zapisać konta.", true);
  } finally {
    elements.accessSubmitButton.disabled = false;
  }
}

async function bootstrapLegacyUsers() {
  if (!isAdminUser()) return;
  await Promise.all([...LEGACY_EMAILS].map(async email => {
    const reference = accessDocument(email);
    const snapshot = await getDoc(reference);
    if (snapshot.exists()) return;
    await setDoc(reference, {
      email,
      deleted: false,
      enabled: true,
      startsAt: null,
      expiresAt: null,
      maxLogins: 0,
      modules: [...ALL_MODULE_IDS],
      loginCount: 0,
      lastAuthTime: 0,
      lastLoginAt: null,
      createdAt: serverTimestamp(),
      createdBy: ADMIN_EMAIL,
      updatedAt: serverTimestamp(),
      updatedBy: ADMIN_EMAIL
    });
  })).catch(() => { /* Existing rules may still await deployment. */ });
}

function moduleDefinitions() {
  if (state.config.modules) return state.config.modules;
  return {
    core: {
      keyDocumentPath: state.config.keyDocumentPath,
      expectedKeyId: state.config.expectedKeyId,
      manifestPath: "vault/manifest.bin",
      manifestAad: MANIFEST_AAD
    }
  };
}

async function readVaultModule(moduleId) {
  const definition = moduleDefinitions()[moduleId];
  if (!definition) throw new Error(`Moduł ${moduleLabel(moduleId)} nie został jeszcze opublikowany.`);
  let keySnapshot;
  try {
    keySnapshot = await getDoc(doc(state.db, definition.keyDocumentPath));
  } catch (error) {
    if (error.code === "permission-denied") throw accessFailure(`Brak dostępu do modułu: ${moduleLabel(moduleId)}.`);
    throw new Error(`Nie można potwierdzić dostępu do modułu: ${moduleLabel(moduleId)}.`);
  }
  if (!keySnapshot.exists()) throw new Error(`Moduł ${moduleLabel(moduleId)} oczekuje na inicjalizację administratora.`);
  const keyDocument = keySnapshot.data();
  const rawKey = base64urlToBytes(keyDocument.key || "");
  if (rawKey.length !== 32 || keyDocument.key_id !== definition.expectedKeyId) {
    throw new Error(`Nie można potwierdzić integralności modułu: ${moduleLabel(moduleId)}.`);
  }
  const manifestResponse = await fetch(definition.manifestPath, { cache: "no-store" });
  if (!manifestResponse.ok) throw new Error(`Nie można pobrać indeksu modułu: ${moduleLabel(moduleId)}.`);
  const manifestRaw = await decryptEnvelope(
    rawKey,
    await manifestResponse.arrayBuffer(),
    definition.manifestAad || MANIFEST_AAD
  );
  const manifest = JSON.parse(new TextDecoder().decode(manifestRaw));
  if (manifest.key_id !== keyDocument.key_id || !Array.isArray(manifest.files) || !Array.isArray(manifest.projects)) {
    throw new Error(`Kontrola integralności modułu ${moduleLabel(moduleId)} nie powiodła się.`);
  }
  return { id: moduleId, key: rawKey, manifest };
}

async function initializeHawthornKey(coreModule) {
  const definition = moduleDefinitions().hawthorn;
  if (!definition) return;
  const reference = doc(state.db, definition.keyDocumentPath);
  const current = await getDoc(reference);
  if (current.exists()) return;
  const key = await deriveModuleKey(coreModule.key, "hawthorn");
  if (await bytesKeyId(key) !== definition.expectedKeyId) {
    throw new Error("Nie można zainicjalizować klucza mapy głogu.");
  }
  await setDoc(reference, {
    key: bytesToBase64url(key),
    key_id: definition.expectedKeyId,
    module: "hawthorn",
    createdAt: serverTimestamp(),
    createdBy: ADMIN_EMAIL,
    updatedAt: serverTimestamp(),
    updatedBy: ADMIN_EMAIL
  });
}

async function unlock(user) {
  if (state.unlocking || state.user) return;
  state.unlocking = true;
  try {
    if (!user.email || !user.emailVerified) throw new Error("Google nie potwierdził adresu e-mail.");
    setStatus("Sprawdzanie uprawnień…");

    state.accessRecord = await claimPortalAccess(user);

    setStatus("Przygotowywanie prywatnej przestrzeni…");
    const allowedModules = normalizedModules(state.accessRecord);
    const loadedModules = [];
    let coreModule = null;
    if (allowedModules.includes("core") || isAdminUser(user)) {
      coreModule = await readVaultModule("core");
      loadedModules.push(coreModule);
    }
    if (isAdminUser(user) && moduleDefinitions().hawthorn) await initializeHawthornKey(coreModule);
    if (allowedModules.includes("hawthorn") && moduleDefinitions().hawthorn) {
      loadedModules.push(await readVaultModule("hawthorn"));
    }
    if (!loadedModules.length) throw accessFailure("To konto nie ma udostępnionych modułów.");
    const manifest = {
      projects: loadedModules.flatMap(module => module.manifest.projects),
      files: loadedModules.flatMap(module => module.manifest.files)
    };

    const registration = state.workerRegistration || await navigator.serviceWorker.ready;
    state.workerRegistration = registration;
    await sendWorkerMessage(registration, {
      type: "unlock",
      modules: loadedModules,
      expiresAt: state.sessionStartedAt + SESSION_TTL_MS
    });

    state.vaultModules = loadedModules;
    state.manifest = manifest;
    state.user = user;
    elements.securityState.dataset.state = "open";
    elements.dashboardIdentity.textContent = user.email;
    elements.userAvatar.textContent = initials(user);
    renderProjects();
    showDashboard();
    scheduleExpiry();
    startAccessWatcher(user);
    void bootstrapLegacyUsers();
  } finally {
    state.unlocking = false;
    updateLoginAvailability();
  }
}

async function login() {
  if (!state.deviceTrusted) {
    setStatus("Najpierw ułóż zdanie w nurcie.", true);
    return;
  }
  try {
    elements.loginButton.disabled = true;
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
  } finally {
    updateLoginAvailability();
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
  stopAccessWatcher();
  if (state.adminUsersUnsubscribe) state.adminUsersUnsubscribe();
  state.adminUsersUnsubscribe = null;
  await lockWorker();
  clearSessionStart();
  state.accessRecord = null;
  state.adminUsers = [];
  state.authTime = 0;
  state.manifest = null;
  for (const module of state.vaultModules) module.key?.fill(0);
  state.vaultModules = [];
  state.pendingUser = null;
  state.user = null;
  state.currentProject = null;
  elements.portalFrame.src = "about:blank";
  delete elements.portalFrame.dataset.contentUrl;
  elements.projectPanel.hidden = true;
  elements.adminPanel.hidden = true;
  elements.dashboardPanel.hidden = true;
  elements.accessPanel.hidden = false;
  document.body.classList.add("login-mode");
  elements.securityState.dataset.state = "locked";
  elements.securityLabel.textContent = "Dostęp zablokowany";
  document.title = "Portal prywatny — dostęp";
  setStatus(message);
  updateLoginAvailability();
  if (state.auth?.currentUser) {
    state.suppressReadyOnce = true;
    await signOut(state.auth).catch(() => {});
  }
}

async function restoreSession(user) {
  if (!user) {
    state.pendingUser = null;
    updateLoginAvailability();
    if (state.suppressReadyOnce) {
      state.suppressReadyOnce = false;
      return;
    }
    if (state.user) {
      await logout("Sesja autoryzacyjna została zakończona. Zaloguj się ponownie.");
      return;
    }
    if (!state.user) setStatus(state.deviceTrusted ? "Możesz kontynuować." : "Nowe urządzenie.");
    return;
  }

  if (!state.deviceTrusted) {
    state.pendingUser = user;
    setStatus("Potwierdź nowe urządzenie, układając zdanie.");
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
    accessCancelButton: $("accessCancelButton"),
    accessDuration: $("accessDuration"),
    accessEmail: $("accessEmail"),
    accessEnabled: $("accessEnabled"),
    accessExpiresAt: $("accessExpiresAt"),
    accessExpiryField: $("accessExpiryField"),
    accessForm: $("accessForm"),
    accessFormTitle: $("accessFormTitle"),
    accessMaxLogins: $("accessMaxLogins"),
    accessModuleCore: $("accessModuleCore"),
    accessModuleHawthorn: $("accessModuleHawthorn"),
    accessStartsAt: $("accessStartsAt"),
    accessSubmitButton: $("accessSubmitButton"),
    accessUserList: $("accessUserList"),
    adminBackButton: $("adminBackButton"),
    adminLogoutButton: $("adminLogoutButton"),
    adminPanel: $("adminPanel"),
    adminStatus: $("adminStatus"),
    adminUserCount: $("adminUserCount"),
    backButton: $("backButton"),
    dashboardIdentity: $("dashboardIdentity"),
    dashboardLogoutButton: $("dashboardLogoutButton"),
    dashboardPanel: $("dashboardPanel"),
    challengeStatus: $("challengeStatus"),
    deviceChallenge: $("deviceChallenge"),
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
    userAvatar: $("userAvatar"),
    sentenceRiver: $("sentenceRiver"),
    wordBank: $("wordBank")
  });

  elements.loginButton.addEventListener("click", login);
  elements.logoutButton.addEventListener("click", () => logout());
  elements.dashboardLogoutButton.addEventListener("click", () => logout());
  elements.backButton.addEventListener("click", showDashboard);
  elements.adminBackButton.addEventListener("click", showDashboard);
  elements.adminLogoutButton.addEventListener("click", () => logout());
  elements.accessDuration.addEventListener("change", updateDurationControl);
  elements.accessCancelButton.addEventListener("click", resetAdminForm);
  elements.accessForm.addEventListener("submit", saveAccessAccount);
  elements.portalFrame.addEventListener("load", () => { elements.portalLoading.hidden = true; });
  window.addEventListener("focus", () => {
    updateSessionLabel();
    if (state.user) void recoverEmbeddedSession();
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      updateSessionLabel();
      if (state.user) void recoverEmbeddedSession();
    }
  });
  window.addEventListener("message", event => {
    if (event.origin === location.origin && event.source === elements.portalFrame.contentWindow && event.data?.type === "sittaigen-vault-session-missing") {
      void recoverEmbeddedSession(true);
    }
  });
  navigator.serviceWorker?.addEventListener("message", event => {
    if (event.data?.type === "sittaigen-vault-session-request") void recoverEmbeddedSession();
  });
  window.addEventListener("storage", event => {
    if (event.key === SESSION_STARTED_KEY && !event.newValue && state.user) void logout();
  });

  try {
    await initializeDeviceTrust();
    resetAdminForm();
    state.config = await fetchJson("config.json");
    state.workerRegistration = await registerWorker();
    const values = Object.values(state.config.firebase || {});
    if (!values.length || values.some(value => !value || String(value).startsWith("CONFIGURE_"))) {
      throw new Error("Administrator nie zakończył jeszcze konfiguracji dostępu.");
    }
    const firebaseApp = initializeApp(state.config.firebase);
    state.auth = getAuth(firebaseApp);
    state.db = getFirestore(firebaseApp);
    await setPersistence(state.auth, browserLocalPersistence);
    state.firebaseReady = true;
    updateLoginAvailability();
    onAuthStateChanged(state.auth, user => { void restoreSession(user); });
  } catch (error) {
    state.firebaseReady = false;
    updateLoginAvailability();
    setStatus(error.message || "Nie udało się zainicjalizować portalu.", true);
  }
}

window.addEventListener("DOMContentLoaded", init);
