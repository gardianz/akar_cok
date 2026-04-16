#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const process = require("node:process");
const crypto = require("node:crypto");
const { pathToFileURL } = require("node:url");
const readline = require("node:readline/promises");
const { setTimeout: sleep } = require("node:timers/promises");

let puppeteer;
let StealthPlugin;
try {
  puppeteer = require("puppeteer-extra");
  StealthPlugin = require("puppeteer-extra-plugin-stealth");
  puppeteer.use(StealthPlugin());
} catch {
  try {
    puppeteer = require("puppeteer");
  } catch {
    puppeteer = null;
  }
}

const DEFAULT_CONFIG_FILE = "config.json";
const DEFAULT_ACCOUNTS_FILE = "accounts.json";
const DEFAULT_TOKENS_FILE = "tokens.json";
const DEFAULT_INTERNAL_PLANNER_STATE_FILE = "internal-planner-state.json";

const rawBrowserChallengeConcurrency = Number(process.env.ROOTSFI_MAX_BROWSER_CONCURRENCY);
const BROWSER_CHALLENGE_MAX_CONCURRENT =
  Number.isFinite(rawBrowserChallengeConcurrency) && rawBrowserChallengeConcurrency > 0
    ? Math.floor(rawBrowserChallengeConcurrency)
    : 1;
const BROWSER_LAUNCH_TIMEOUT_MS = 120000;
const BROWSER_CHALLENGE_MAX_ATTEMPTS = 20;
const BROWSER_CHALLENGE_MAX_ATTEMPTS_ON_429 = 20;
const BROWSER_CHALLENGE_RETRY_ATTEMPTS_ON_429 = 10;
const BROWSER_CHALLENGE_RETRY_DELAY_MS = 15000;
const rawSessionReuseConcurrency = Number(process.env.ROOTSFI_MAX_SESSION_REUSE_CONCURRENCY);
let SESSION_REUSE_MAX_CONCURRENT =
  Number.isFinite(rawSessionReuseConcurrency) && rawSessionReuseConcurrency > 0
    ? Math.floor(rawSessionReuseConcurrency)
    : 1;
let activeBrowserChallenges = 0;
const browserChallengeWaitQueue = [];
let activeSessionReuseChallenges = 0;
const sessionReuseWaitQueue = [];
const cachedSecurityCookies = new Map();
let browserChallengeRateLimitedUntilMs = 0;

// Track all spawned Chromium PIDs so we can kill zombies
const trackedBrowserPids = new Set();

function trackBrowserPid(browser) {
  try {
    const proc = browser.process();
    if (proc && proc.pid) {
      trackedBrowserPids.add(proc.pid);
      return proc.pid;
    }
  } catch {}
  return null;
}

function untrackBrowserPid(pid) {
  if (pid) trackedBrowserPids.delete(pid);
}

function killZombieBrowsers() {
  for (const pid of trackedBrowserPids) {
    try {
      process.kill(pid, 0); // test if alive
      process.kill(pid, "SIGKILL");
      console.log(`[browser-cleanup] Killed zombie Chromium pid ${pid}`);
    } catch {
      // Process already dead — clean up tracking
    }
    trackedBrowserPids.delete(pid);
  }
}

// Run zombie cleanup every 2 minutes
setInterval(killZombieBrowsers, 120000).unref();

// Also clean up on exit
process.on("exit", killZombieBrowsers);

// ============================================================================
// CONNECTION POOL RESET FOR SOFT RESTART RECOVERY
// ============================================================================
// Node.js native fetch uses undici under the hood with a global connection pool.
// When timeouts happen repeatedly, the connection pool can get "stuck".
// This function resets the global dispatcher to force fresh connections.
// ============================================================================

let undiciAvailable = false;
let undiciModule = null;
let connectionPoolResetInFlight = null;
let lastConnectionPoolResetAt = 0;
const CONNECTION_POOL_RESET_MIN_INTERVAL_MS = 12000;

try {
  undiciModule = require("undici");
  undiciAvailable = true;
} catch {
  // undici not available as explicit dependency, will try global reset
}

/**
 * Reset the global fetch connection pool.
 * This helps recover from "stuck" connections that cause repeated timeouts.
 * After calling this, subsequent fetch requests will use fresh connections.
 */
async function resetConnectionPool(options = {}) {
  const forceReset = Boolean(options.forceReset);

  if (connectionPoolResetInFlight) {
    console.log("[connection] Reset already in progress, waiting for existing reset...");
    return connectionPoolResetInFlight;
  }

  const nowMs = Date.now();
  const sinceLastResetMs = nowMs - lastConnectionPoolResetAt;
  if (!forceReset && lastConnectionPoolResetAt > 0 && sinceLastResetMs < CONNECTION_POOL_RESET_MIN_INTERVAL_MS) {
    const remainingSeconds = Math.max(1, Math.ceil((CONNECTION_POOL_RESET_MIN_INTERVAL_MS - sinceLastResetMs) / 1000));
    console.log(`[connection] Reset skipped (throttled), retry window in ${remainingSeconds}s`);
    return true;
  }

  if (forceReset) {
    console.log("[connection] Force reset requested (bypass throttle)");
  }

  connectionPoolResetInFlight = (async () => {
    console.log("[connection] Attempting to reset connection pool...");

    try {
      if (undiciAvailable && undiciModule) {
        // Create a new Agent with fresh settings
        const newAgent = new undiciModule.Agent({
          keepAliveTimeout: 10000,  // 10 seconds
          keepAliveMaxTimeout: 30000,  // 30 seconds max
          connections: 100,
          pipelining: 1
        });
        undiciModule.setGlobalDispatcher(newAgent);
        lastConnectionPoolResetAt = Date.now();
        console.log("[connection] Connection pool reset via undici.setGlobalDispatcher()");
        return true;
      }

      // Fallback: try to access undici through global symbol (Node.js 18+)
      const dispatcherSymbol = Symbol.for("undici.globalDispatcher.1");
      if (globalThis[dispatcherSymbol]) {
        // Close existing connections
        try {
          const currentDispatcher = globalThis[dispatcherSymbol];
          if (typeof currentDispatcher.close === "function") {
            await currentDispatcher.close();
            console.log("[connection] Closed existing dispatcher connections");
          }
        } catch (closeErr) {
          const closeMessage = String(closeErr && closeErr.message ? closeErr.message : closeErr || "");
          if (closeMessage.toLowerCase().includes("destroyed")) {
            console.log("[connection] Dispatcher already destroyed, continuing with fresh reset");
          } else {
            console.log(`[connection] Could not close dispatcher: ${closeMessage}`);
          }
        }

        // Force garbage collection if available (Node.js with --expose-gc)
        if (typeof global.gc === "function") {
          global.gc();
          console.log("[connection] Forced garbage collection");
        }

        lastConnectionPoolResetAt = Date.now();
        console.log("[connection] Connection pool soft reset completed");
        return true;
      }

      console.log("[connection] No undici dispatcher found, connection pool not reset");
      return false;
    } catch (error) {
      console.log(`[connection] Failed to reset connection pool: ${error.message}`);
      return false;
    }
  })();

  try {
    return await connectionPoolResetInFlight;
  } finally {
    connectionPoolResetInFlight = null;
  }
}

// ============================================================================
// COVERAGE-FIRST INTERNAL RECIPIENT STRATEGY
// ============================================================================
// Goals:
// - Setiap sender eventually mengirim ke semua recipient internal lain
// - Urutan recipient tetap acak (shuffled per coverage epoch)
// - Hindari kirim balik langsung ke sender sebelumnya (server cooldown 10m)
// - Tetap support fallback recipient saat target coverage sedang cooldown
// ============================================================================

const SEND_PAIR_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes
const SEND_PAIR_COOLDOWN_BUFFER_SECONDS = 45; // Safety buffer near expiry

// key: "sender=>recipient", value: timestamp (ms) of successful send
const sendPairHistory = new Map();
// key: "sender=>recipient", value: block-until timestamp (ms)
const reciprocalSendCooldowns = new Map();
// key: senderName, value: { rosterKey, epoch, pendingRecipients[] }
const internalCoverageQueues = new Map();
let internalPlannerStatePath = "";
let internalPlannerValidAccountNames = new Set();
let internalPlannerStateSaveQueue = Promise.resolve();

let roundRobinOffset = 0;
let lastRoundPrimaryOffset = 0;
const cachedRoundOffsets = new Map();

function buildSendPairKey(senderName, recipientName) {
  return `${String(senderName || "").trim()}=>${String(recipientName || "").trim()}`;
}

function cleanupExpiredSendPairs() {
  const nowMs = Date.now();

  for (const [pairKey, timestamp] of sendPairHistory.entries()) {
    if (!Number.isFinite(Number(timestamp))) {
      sendPairHistory.delete(pairKey);
      continue;
    }

    if (nowMs - Number(timestamp) > SEND_PAIR_COOLDOWN_MS) {
      sendPairHistory.delete(pairKey);
    }
  }

  for (const [pairKey, expiresAt] of reciprocalSendCooldowns.entries()) {
    if (!Number.isFinite(Number(expiresAt)) || Number(expiresAt) <= nowMs) {
      reciprocalSendCooldowns.delete(pairKey);
    }
  }
}

function normalizeInternalPlannerState(rawState) {
  const raw = isObject(rawState) ? rawState : {};
  const coverageQueuesInput = isObject(raw.coverageQueues) ? raw.coverageQueues : {};
  const sendPairHistoryInput = isObject(raw.sendPairHistory) ? raw.sendPairHistory : {};
  const reciprocalCooldownsInput = isObject(raw.reciprocalSendCooldowns) ? raw.reciprocalSendCooldowns : {};
  const validNames = internalPlannerValidAccountNames instanceof Set
    ? internalPlannerValidAccountNames
    : new Set();

  const coverageQueues = {};
  for (const [senderName, entry] of Object.entries(coverageQueuesInput)) {
    const sender = String(senderName || "").trim();
    if (!sender || (validNames.size > 0 && !validNames.has(sender))) {
      continue;
    }

    const pendingRecipients = Array.isArray(entry && entry.pendingRecipients)
      ? Array.from(
          new Set(
            entry.pendingRecipients
              .map((recipient) => String(recipient || "").trim())
              .filter(
                (recipient) =>
                  Boolean(recipient) &&
                  recipient !== sender &&
                  (validNames.size === 0 || validNames.has(recipient))
              )
          )
        )
      : [];

    if (pendingRecipients.length === 0) {
      continue;
    }

    coverageQueues[sender] = {
      rosterKey: String(entry && entry.rosterKey ? entry.rosterKey : "").trim(),
      epoch: Math.max(1, clampToNonNegativeInt(entry && entry.epoch, 1)),
      pendingRecipients
    };
  }

  const normalizedSendPairHistory = {};
  for (const [pairKey, timestamp] of Object.entries(sendPairHistoryInput)) {
    const key = String(pairKey || "").trim();
    const numericTimestamp = Number(timestamp);
    if (!key || !Number.isFinite(numericTimestamp) || numericTimestamp <= 0) {
      continue;
    }
    normalizedSendPairHistory[key] = numericTimestamp;
  }

  const normalizedReciprocalCooldowns = {};
  for (const [pairKey, expiresAt] of Object.entries(reciprocalCooldownsInput)) {
    const key = String(pairKey || "").trim();
    const numericExpiresAt = Number(expiresAt);
    if (!key || !Number.isFinite(numericExpiresAt) || numericExpiresAt <= 0) {
      continue;
    }
    normalizedReciprocalCooldowns[key] = numericExpiresAt;
  }

  return {
    version: 1,
    updatedAt: String(raw.updatedAt || new Date().toISOString()),
    coverageQueues,
    sendPairHistory: sortObjectKeys(normalizedSendPairHistory),
    reciprocalSendCooldowns: sortObjectKeys(normalizedReciprocalCooldowns)
  };
}

function exportInternalPlannerState() {
  const coverageQueues = {};
  for (const [senderName, entry] of internalCoverageQueues.entries()) {
    const sender = String(senderName || "").trim();
    if (!sender) {
      continue;
    }

    const pendingRecipients = Array.isArray(entry && entry.pendingRecipients)
      ? entry.pendingRecipients
          .map((recipient) => String(recipient || "").trim())
          .filter((recipient) => Boolean(recipient) && recipient !== sender)
      : [];

    if (pendingRecipients.length === 0) {
      continue;
    }

    coverageQueues[sender] = {
      rosterKey: String(entry && entry.rosterKey ? entry.rosterKey : "").trim(),
      epoch: Math.max(1, clampToNonNegativeInt(entry && entry.epoch, 1)),
      pendingRecipients
    };
  }

  const sendPairHistoryState = {};
  for (const [pairKey, timestamp] of sendPairHistory.entries()) {
    const key = String(pairKey || "").trim();
    const numericTimestamp = Number(timestamp);
    if (!key || !Number.isFinite(numericTimestamp) || numericTimestamp <= 0) {
      continue;
    }
    sendPairHistoryState[key] = numericTimestamp;
  }

  const reciprocalCooldownsState = {};
  for (const [pairKey, expiresAt] of reciprocalSendCooldowns.entries()) {
    const key = String(pairKey || "").trim();
    const numericExpiresAt = Number(expiresAt);
    if (!key || !Number.isFinite(numericExpiresAt) || numericExpiresAt <= 0) {
      continue;
    }
    reciprocalCooldownsState[key] = numericExpiresAt;
  }

  return normalizeInternalPlannerState({
    version: 1,
    updatedAt: new Date().toISOString(),
    coverageQueues,
    sendPairHistory: sendPairHistoryState,
    reciprocalSendCooldowns: reciprocalCooldownsState
  });
}

function applyInternalPlannerState(rawState) {
  const normalized = normalizeInternalPlannerState(rawState);
  internalCoverageQueues.clear();
  sendPairHistory.clear();
  reciprocalSendCooldowns.clear();

  for (const [senderName, entry] of Object.entries(normalized.coverageQueues)) {
    internalCoverageQueues.set(senderName, {
      rosterKey: String(entry && entry.rosterKey ? entry.rosterKey : "").trim(),
      epoch: Math.max(1, clampToNonNegativeInt(entry && entry.epoch, 1)),
      pendingRecipients: Array.isArray(entry && entry.pendingRecipients) ? [...entry.pendingRecipients] : []
    });
  }

  for (const [pairKey, timestamp] of Object.entries(normalized.sendPairHistory)) {
    sendPairHistory.set(pairKey, Number(timestamp));
  }

  for (const [pairKey, expiresAt] of Object.entries(normalized.reciprocalSendCooldowns)) {
    reciprocalSendCooldowns.set(pairKey, Number(expiresAt));
  }

  cleanupExpiredSendPairs();
  return normalized;
}

function configureInternalPlannerPersistence(statePath, accountsConfig) {
  internalPlannerStatePath = String(statePath || "").trim();
  internalPlannerValidAccountNames = new Set(
    Array.isArray(accountsConfig && accountsConfig.accounts)
      ? accountsConfig.accounts
          .map((account) => String(account && account.name ? account.name : "").trim())
          .filter((name) => Boolean(name))
      : []
  );
}

async function saveInternalPlannerState() {
  if (!internalPlannerStatePath) {
    return null;
  }

  const payload = exportInternalPlannerState();
  await fs.writeFile(internalPlannerStatePath, JSON.stringify(payload, null, 2), "utf8");
  return payload;
}

async function saveInternalPlannerStateSerial() {
  if (!internalPlannerStatePath) {
    return null;
  }

  internalPlannerStateSaveQueue = internalPlannerStateSaveQueue
    .then(() => saveInternalPlannerState())
    .catch((error) => {
      console.warn(
        `[internal] Failed to save planner state: ${error && error.message ? error.message : String(error)}`
      );
      return null;
    });

  return internalPlannerStateSaveQueue;
}

function buildInternalRosterKey(sortedAccounts) {
  return Array.isArray(sortedAccounts)
    ? sortedAccounts
        .map((account) => String(account && account.name ? account.name : "").trim())
        .filter((name) => Boolean(name))
        .join("||")
    : "";
}

function getInternalRecipientOffsetByName(sortedAccounts, senderName, recipientName) {
  if (!Array.isArray(sortedAccounts) || sortedAccounts.length < 2) {
    return 1;
  }

  const senderIndex = sortedAccounts.findIndex((account) => String(account && account.name ? account.name : "").trim() === senderName);
  const recipientIndex = sortedAccounts.findIndex((account) => String(account && account.name ? account.name : "").trim() === recipientName);
  if (senderIndex < 0 || recipientIndex < 0 || senderIndex === recipientIndex) {
    return 1;
  }

  return (recipientIndex - senderIndex + sortedAccounts.length) % sortedAccounts.length || 1;
}

function buildInternalCoverageQueue(senderName, sortedAccounts, epoch = 1) {
  if (!Array.isArray(sortedAccounts) || sortedAccounts.length < 2) {
    return null;
  }

  const sender = String(senderName || "").trim();
  const senderIndex = sortedAccounts.findIndex((account) => String(account && account.name ? account.name : "").trim() === sender);
  if (senderIndex < 0) {
    return null;
  }

  const offsetOrder = shuffleArray(
    Array.from({ length: Math.max(0, sortedAccounts.length - 1) }, (_, index) => index + 1)
  );
  const pendingRecipients = offsetOrder
    .map((offset) => {
      const recipient = sortedAccounts[(senderIndex + offset) % sortedAccounts.length];
      return String(recipient && recipient.name ? recipient.name : "").trim();
    })
    .filter((recipientName) => Boolean(recipientName) && recipientName !== sender);

  return {
    rosterKey: buildInternalRosterKey(sortedAccounts),
    epoch: Math.max(1, clampToNonNegativeInt(epoch, 1)),
    pendingRecipients
  };
}

function prepareInternalCoverageQueue(senderName, sortedAccounts) {
  const sender = String(senderName || "").trim();
  const rosterKey = buildInternalRosterKey(sortedAccounts);
  const validRecipientNames = new Set(
    Array.isArray(sortedAccounts)
      ? sortedAccounts
          .map((account) => String(account && account.name ? account.name : "").trim())
          .filter((name) => Boolean(name) && name !== sender)
      : []
  );

  const existing = internalCoverageQueues.get(sender);
  if (
    existing &&
    existing.rosterKey === rosterKey &&
    Array.isArray(existing.pendingRecipients)
  ) {
    existing.pendingRecipients = existing.pendingRecipients.filter((recipientName) => validRecipientNames.has(recipientName));
    if (existing.pendingRecipients.length > 0) {
      internalCoverageQueues.set(sender, existing);
      return {
        entry: existing,
        restartedEpoch: false,
        completedEpoch: false
      };
    }

    const nextEpoch = Math.max(1, clampToNonNegativeInt(existing.epoch, 1) + 1);
    const rebuilt = buildInternalCoverageQueue(sender, sortedAccounts, nextEpoch);
    if (rebuilt) {
      internalCoverageQueues.set(sender, rebuilt);
    }
    return {
      entry: rebuilt,
      restartedEpoch: true,
      completedEpoch: true
    };
  }

  const fresh = buildInternalCoverageQueue(sender, sortedAccounts, 1);
  if (fresh) {
    internalCoverageQueues.set(sender, fresh);
  }
  return {
    entry: fresh,
    restartedEpoch: false,
    completedEpoch: false
  };
}

function markInternalCoverageSuccess(senderName, recipientName) {
  const sender = String(senderName || "").trim();
  const recipient = String(recipientName || "").trim();
  if (!sender || !recipient || sender === recipient) {
    return { removed: false, completedEpoch: false, remainingRecipients: 0, epoch: 0 };
  }

  const entry = internalCoverageQueues.get(sender);
  if (!entry || !Array.isArray(entry.pendingRecipients)) {
    return { removed: false, completedEpoch: false, remainingRecipients: 0, epoch: 0 };
  }

  const beforeCount = entry.pendingRecipients.length;
  entry.pendingRecipients = entry.pendingRecipients.filter((candidate) => candidate !== recipient);
  const removed = entry.pendingRecipients.length !== beforeCount;
  internalCoverageQueues.set(sender, entry);

  return {
    removed,
    completedEpoch: removed && entry.pendingRecipients.length === 0,
    remainingRecipients: entry.pendingRecipients.length,
    epoch: Math.max(1, clampToNonNegativeInt(entry.epoch, 1))
  };
}

function getReciprocalCooldownSeconds(senderName, recipientName) {
  const key = buildSendPairKey(senderName, recipientName);
  const expiresAt = Number(reciprocalSendCooldowns.get(key));
  if (!Number.isFinite(expiresAt)) {
    return 0;
  }

  const remainingMs = expiresAt - Date.now();
  if (remainingMs <= 0) {
    reciprocalSendCooldowns.delete(key);
    return 0;
  }

  return Math.max(1, Math.ceil(remainingMs / 1000) + SEND_PAIR_COOLDOWN_BUFFER_SECONDS);
}

function recordSendPair(senderName, recipientName) {
  const sender = String(senderName || "").trim();
  const recipient = String(recipientName || "").trim();
  if (!sender || !recipient || sender === recipient) {
    return;
  }

  const nowMs = Date.now();
  const pairKey = buildSendPairKey(sender, recipient);
  const reciprocalKey = buildSendPairKey(recipient, sender);

  sendPairHistory.set(pairKey, nowMs);
  reciprocalSendCooldowns.set(reciprocalKey, nowMs + SEND_PAIR_COOLDOWN_MS);

  const coverageUpdate = markInternalCoverageSuccess(sender, recipient);
  if (coverageUpdate.removed) {
    console.log(
      `[internal] coverage ${sender}: ${recipient} recorded ` +
      `(${Math.max(0, coverageUpdate.remainingRecipients)} target left in epoch ${coverageUpdate.epoch})`
    );
  }

  void saveInternalPlannerStateSerial();
}

function isReciprocalPairInCooldown(senderName, recipientName) {
  return getReciprocalCooldownSeconds(senderName, recipientName) > 0;
}

function getShortestReciprocalCooldownSeconds(senderName, sortedAccounts) {
  if (!Array.isArray(sortedAccounts) || sortedAccounts.length === 0) {
    return 0;
  }

  let shortest = 0;
  for (const account of sortedAccounts) {
    const recipientName = String(account && account.name ? account.name : "").trim();
    if (!recipientName || recipientName === senderName) {
      continue;
    }

    const cooldownSeconds = getReciprocalCooldownSeconds(senderName, recipientName);
    if (cooldownSeconds <= 0) {
      continue;
    }

    shortest = shortest === 0 ? cooldownSeconds : Math.min(shortest, cooldownSeconds);
  }

  return shortest;
}

function getRoundRobinOffset() {
  return roundRobinOffset;
}

function getRotatingOffset(totalAccounts, loopRound = null) {
  const normalizedTotal = clampToNonNegativeInt(totalAccounts, 0);
  if (normalizedTotal < 2) {
    return 1;
  }

  const maxOffset = normalizedTotal - 1;
  const roundSeed = Number.isFinite(Number(loopRound))
    ? Math.max(1, clampToNonNegativeInt(loopRound, 1))
    : Math.max(1, clampToNonNegativeInt(getRoundRobinOffset(), 1));
  const cacheKey = `${normalizedTotal}:${roundSeed}`;
  const cachedOffset = Number(cachedRoundOffsets.get(cacheKey));
  if (Number.isFinite(cachedOffset) && cachedOffset > 0) {
    return cachedOffset;
  }

  let selectedOffset = ((roundSeed - 1) % maxOffset) + 1;

  // Avoid immediate inverse mapping vs previous round whenever possible.
  if (maxOffset > 1 && lastRoundPrimaryOffset > 0) {
    const inverseOffset = (normalizedTotal - (lastRoundPrimaryOffset % normalizedTotal)) % normalizedTotal;
    if (inverseOffset > 0 && selectedOffset === inverseOffset) {
      selectedOffset = (selectedOffset % maxOffset) + 1;
    }
  }

  cachedRoundOffsets.set(cacheKey, selectedOffset);
  lastRoundPrimaryOffset = selectedOffset;
  return selectedOffset;
}

function buildInternalOffsetPriority(totalAccounts, primaryOffset) {
  const normalizedTotal = clampToNonNegativeInt(totalAccounts, 0);
  const maxOffset = normalizedTotal - 1;
  if (maxOffset < 1) {
    return [];
  }

  const safePrimary = Math.min(
    maxOffset,
    Math.max(1, clampToNonNegativeInt(primaryOffset, 1))
  );

  const offsets = [];
  const selfInverseOffset = normalizedTotal % 2 === 0 ? normalizedTotal / 2 : 0;
  for (let step = 0; step < maxOffset; step += 1) {
    const offset = ((safePrimary - 1 + step) % maxOffset) + 1;
    if (maxOffset > 1 && selfInverseOffset > 0 && offset === selfInverseOffset) {
      continue;
    }
    offsets.push(offset);
  }

  if (offsets.length === 0) {
    offsets.push(safePrimary);
  }
  return offsets;
}

function incrementRoundRobinOffset() {
  roundRobinOffset += 1;
}

function resetRoundRobinOffset() {
  roundRobinOffset = 0;
  lastRoundPrimaryOffset = 0;
  cachedRoundOffsets.clear();
}

/**
 * Build internal send candidates using rotating offsets + reciprocal cooldown guard.
 * The first candidate is primary target; remaining entries are fallback recipients.
 */
function buildInternalSendRequests(
  accounts,
  senderName,
  sendPolicy,
  loopRound = null,
  avoidRecipientNames = [],
  preferredRecipientNames = [],
  fixedAmountInput = null,
  options = null
) {
  const validAccounts = Array.isArray(accounts)
    ? accounts.filter((acc) => String(acc && acc.address ? acc.address : "").trim())
    : [];
  const avoidRecipientsSet = new Set(
    Array.isArray(avoidRecipientNames)
      ? avoidRecipientNames
          .map((item) => String(item || "").trim())
          .filter((item) => Boolean(item))
      : []
  );
  const quiet = isObject(options) && options.quiet === true;

  if (validAccounts.length < 2) {
    console.log(
      `[internal] Internal mode requires at least 2 accounts with valid addresses. ` +
      `Found ${validAccounts.length} valid accounts.`
    );
    return {
      requests: [],
      reason: "not-enough-accounts",
      retryAfterSeconds: 0,
      primaryOffset: 1
    };
  }

  const sortedAccounts = [...validAccounts].sort((a, b) => a.name.localeCompare(b.name));
  const senderIndex = sortedAccounts.findIndex((acc) => acc.name === senderName);
  if (senderIndex === -1) {
    console.log(`[internal] Sender ${senderName} not found in sorted account list`);
    return {
      requests: [],
      reason: "sender-not-found",
      retryAfterSeconds: 0,
      primaryOffset: 1
    };
  }

  cleanupExpiredSendPairs();
  const senderTierKey = getAccountTierKey(senderName);
  const senderRange = getEffectiveAmountRangeForSender(sendPolicy, senderName, senderTierKey);
  const amount = fixedAmountInput
    ? normalizeCcAmount(fixedAmountInput)
    : generateRandomCcAmount(senderRange, senderTierKey);
  const preferredOrder = Array.isArray(preferredRecipientNames)
    ? preferredRecipientNames.map((name) => String(name || "").trim()).filter(Boolean)
    : [];
  const preferredIndex = new Map();
  preferredOrder.forEach((name, index) => {
    if (!preferredIndex.has(name)) {
      preferredIndex.set(name, index);
    }
  });
  const primaryOffset = getRotatingOffset(sortedAccounts.length, loopRound);
  const offsetPriority = buildInternalOffsetPriority(sortedAccounts.length, primaryOffset);
  const requests = [];
  let shortestBlockedCooldownSeconds = 0;
  let skippedByAvoidCount = 0;

  for (const offset of offsetPriority) {
    const recipientIndex = (senderIndex + offset) % sortedAccounts.length;
    const recipient = sortedAccounts[recipientIndex];
    if (!recipient || recipient.name === senderName) {
      continue;
    }

    if (avoidRecipientsSet.has(recipient.name)) {
      skippedByAvoidCount += 1;
      continue;
    }

    if (isAccountQuarantined(recipient.name)) {
      continue;
    }

    const reciprocalCooldownSeconds = getReciprocalCooldownSeconds(senderName, recipient.name);
    if (reciprocalCooldownSeconds > 0) {
      shortestBlockedCooldownSeconds = shortestBlockedCooldownSeconds === 0
        ? reciprocalCooldownSeconds
        : Math.min(shortestBlockedCooldownSeconds, reciprocalCooldownSeconds);
      continue;
    }

    requests.push({
      amount,
      label: recipient.name,
      address: recipient.address,
      source: "internal-chain",
      offset,
      internalRecipientCandidate: true
    });
  }

  const preferSet = new Set(preferredOrder);
  if (preferSet.size > 0 && requests.length > 0) {
    requests.sort((left, right) => {
      const leftPreferred = preferSet.has(left.label);
      const rightPreferred = preferSet.has(right.label);
      if (leftPreferred !== rightPreferred) {
        return leftPreferred ? -1 : 1;
      }
      if (leftPreferred && rightPreferred) {
        return Number(preferredIndex.get(left.label) || 0) - Number(preferredIndex.get(right.label) || 0);
      }
      return 0;
    });
    if (!quiet) {
      const matched = requests.filter((item) => preferSet.has(item.label)).map((item) => item.label);
      if (matched.length > 0) {
        console.log(
          `[internal] Prefer recipients for ${senderName}: [${preferredOrder.join(", ")}] ` +
          `matched=${matched.join(", ")}`
        );
      }
    }
  }

  if (requests.length > 2) {
    const primary = requests[0];
    const shuffledFallbacks = shuffleArray(requests.slice(1));
    requests.length = 0;
    requests.push(primary, ...shuffledFallbacks);
  }

  if (requests.length === 0) {
    const shortestCooldownSeconds =
      shortestBlockedCooldownSeconds > 0
        ? shortestBlockedCooldownSeconds
        : getShortestReciprocalCooldownSeconds(senderName, sortedAccounts);
    const sendBackGuardSeconds = Math.ceil(SEND_PAIR_COOLDOWN_MS / 1000);
    const hasAvoidOnlyBlock = skippedByAvoidCount > 0 && shortestCooldownSeconds <= 0;
    const retryAfterSeconds = hasAvoidOnlyBlock
      ? sendBackGuardSeconds
      : (shortestCooldownSeconds || 0);
    const reason = hasAvoidOnlyBlock
      ? "internal-avoid-sendback"
      : "internal-reciprocal-cooldown";
    if (!quiet) {
      console.log(
        `[internal] ${senderName}: no eligible recipient. ` +
        `cooldownRetry=${shortestCooldownSeconds || 0}s avoidBlocked=${skippedByAvoidCount} ` +
        `(retryAfter=${retryAfterSeconds}s reason=${reason})`
      );
    }
    return {
      requests: [],
      reason,
      retryAfterSeconds,
      primaryOffset
    };
  }

  const preview = requests.slice(0, 4).map((entry) => entry.label).join(", ");
  const suffix = requests.length > 4 ? ` (+${requests.length - 4} more)` : "";
  if (!quiet) {
    console.log(
      `[internal] ${senderName}: offset=${primaryOffset} candidates=${requests.length}/${offsetPriority.length} ` +
      `primary=${requests[0].label} | pool=[${preview}${suffix}]`
    );
  }

  return {
    requests,
    reason: null,
    retryAfterSeconds: 0,
    primaryOffset
  };
}

// ============================================================================

// Global TX Tracking - accumulates totals across all accounts for dashboard banner
let globalSwapsTotal = 0;
let globalSwapsOk = 0;
let globalSwapsFail = 0;
let txStatsUtcDayKey = "";
let txStatsUtcHourKey = "";

// Per-account TX tracking - accumulates totals per account for TX Progress column
const perAccountTxStats = {};
const perAccountHourlyTxStats = {};

function getCurrentUTCDayKey() {
  return new Date().toISOString().slice(0, 10);
}

function getCurrentUTCHourKey() {
  return new Date().toISOString().slice(0, 13);
}

function ensureTxStatsCurrentUtcDay() {
  const currentDayKey = getCurrentUTCDayKey();
  if (!txStatsUtcDayKey) {
    txStatsUtcDayKey = currentDayKey;
    return false;
  }

  if (txStatsUtcDayKey === currentDayKey) {
    return false;
  }

  txStatsUtcDayKey = currentDayKey;
  globalSwapsTotal = 0;
  globalSwapsOk = 0;
  globalSwapsFail = 0;
  for (const key of Object.keys(perAccountTxStats)) {
    delete perAccountTxStats[key];
  }
  console.log(`[tx-progress] Reset daily TX counters for new UTC day: ${currentDayKey}`);
  return true;
}

function ensureTxStatsCurrentUtcHour() {
  const currentHourKey = getCurrentUTCHourKey();
  if (!txStatsUtcHourKey) {
    txStatsUtcHourKey = currentHourKey;
    return false;
  }

  if (txStatsUtcHourKey === currentHourKey) {
    return false;
  }

  txStatsUtcHourKey = currentHourKey;
  for (const key of Object.keys(perAccountHourlyTxStats)) {
    delete perAccountHourlyTxStats[key];
  }
  console.log(`[tx-progress] Reset hourly TX counters for new UTC hour: ${currentHourKey}:00Z`);
  return true;
}

function getGlobalTxStatsSnapshot() {
  ensureTxStatsCurrentUtcDay();
  return {
    total: globalSwapsTotal,
    ok: globalSwapsOk,
    fail: globalSwapsFail
  };
}

function resetGlobalTxStats() {
  txStatsUtcDayKey = getCurrentUTCDayKey();
  txStatsUtcHourKey = getCurrentUTCHourKey();
  globalSwapsTotal = 0;
  globalSwapsOk = 0;
  globalSwapsFail = 0;
  // Clear per-account stats
  for (const key of Object.keys(perAccountTxStats)) {
    delete perAccountTxStats[key];
  }
  for (const key of Object.keys(perAccountHourlyTxStats)) {
    delete perAccountHourlyTxStats[key];
  }
}

function addGlobalTxStats(completed, failed) {
  ensureTxStatsCurrentUtcDay();
  globalSwapsTotal += completed + failed;
  globalSwapsOk += completed;
  globalSwapsFail += failed;
}

function addPerAccountTxStats(accountName, completed, failed) {
  ensureTxStatsCurrentUtcDay();
  ensureTxStatsCurrentUtcHour();
  if (!perAccountTxStats[accountName]) {
    perAccountTxStats[accountName] = { total: 0, ok: 0, fail: 0 };
  }
  perAccountTxStats[accountName].total += completed + failed;
  perAccountTxStats[accountName].ok += completed;
  perAccountTxStats[accountName].fail += failed;

  if (!perAccountHourlyTxStats[accountName]) {
    perAccountHourlyTxStats[accountName] = { total: 0, ok: 0, fail: 0 };
  }
  perAccountHourlyTxStats[accountName].total += completed + failed;
  perAccountHourlyTxStats[accountName].ok += completed;
  perAccountHourlyTxStats[accountName].fail += failed;
}

function getPerAccountTxStats(accountName) {
  ensureTxStatsCurrentUtcDay();
  return perAccountTxStats[accountName] || { total: 0, ok: 0, fail: 0 };
}

function getPerAccountHourlyTxStats(accountName) {
  ensureTxStatsCurrentUtcHour();
  return perAccountHourlyTxStats[accountName] || { total: 0, ok: 0, fail: 0 };
}

const qualityScoreByAccount = new Map();
const quarantinedAccounts = new Set();
const rewardsThisWeekByAccount = new Map();
const rewardsInitialByAccount = new Map();

function parseQualityScoreNumber(rawValue) {
  const numeric = Number(rawValue);
  if (Number.isFinite(numeric)) {
    return Math.max(0, Math.min(100, Math.round(numeric)));
  }

  const text = String(rawValue || "").trim();
  if (!text) {
    return null;
  }

  const match = text.match(/(\d{1,3})\s*\/\s*100/i);
  if (!match || !match[1]) {
    return null;
  }

  const parsed = Number(match[1]);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  return Math.max(0, Math.min(100, Math.round(parsed)));
}

function getAccountQualityScore(accountName) {
  const normalizedName = String(accountName || "").trim();
  if (!normalizedName || !qualityScoreByAccount.has(normalizedName)) {
    return null;
  }

  return qualityScoreByAccount.get(normalizedName);
}

function isAccountQuarantined(accountName) {
  const normalizedName = String(accountName || "").trim();
  return Boolean(normalizedName) && quarantinedAccounts.has(normalizedName);
}

function updateAccountQualityState(accountName, score, minScoreThreshold, accountLogTag = null) {
  const normalizedName = String(accountName || "").trim();
  const numericScore = parseQualityScoreNumber(score);
  const threshold = Math.max(
    0,
    clampToNonNegativeInt(minScoreThreshold, INTERNAL_API_DEFAULTS.safety.minScoreThreshold)
  );

  if (!normalizedName || numericScore === null) {
    return null;
  }

  qualityScoreByAccount.set(normalizedName, numericScore);

  if (numericScore < threshold) {
    if (!quarantinedAccounts.has(normalizedName)) {
      quarantinedAccounts.add(normalizedName);
      console.log(
        withAccountTag(
          accountLogTag,
          `[quarantine] Account '${normalizedName}' quarantined (score ${numericScore} < ${threshold})`
        )
      );
    }
  } else if (quarantinedAccounts.delete(normalizedName)) {
    console.log(
      withAccountTag(
        accountLogTag,
        `[quarantine] Account '${normalizedName}' released (score ${numericScore} >= ${threshold})`
      )
    );
  }

  return numericScore;
}

function parseRewardMetricNumber(rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "" || typeof rawValue === "boolean") {
    return null;
  }

  const numeric = Number(rawValue);
  if (Number.isFinite(numeric)) {
    return numeric;
  }

  const text = String(rawValue).trim();
  if (!text) {
    return null;
  }

  const normalized = text.replace(/,/g, "").replace(/[^0-9.+-]/g, "");
  if (!normalized) {
    return null;
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function extractThisWeekRewardMetricsFromResponse(payload) {
  const data = isObject(payload && payload.data) ? payload.data : {};
  const tierProgress = isObject(data.tierProgress) ? data.tierProgress : {};
  const thisWeek = isObject(data.thisWeek) ? data.thisWeek : {};
  const weekly = isObject(data.weekly) ? data.weekly : {};

  const ccCandidates = [
    data.earnedThisWeekCc,
    data.thisWeekCc,
    data.rewardThisWeekCc,
    data.rewardsThisWeekCc,
    data.thisWeekRewardCc,
    data.weeklyRewardCc,
    tierProgress.earnedThisWeekCc,
    tierProgress.thisWeekRewardCc,
    tierProgress.rewardThisWeekCc,
    tierProgress.thisWeekCc,
    tierProgress.rewardsThisWeekCc,
    thisWeek.cc,
    thisWeek.amount,
    weekly.cc,
    weekly.amount
  ];

  const usdCandidates = [
    data.accruedThisWeekUsd,
    data.thisWeekRewardUsd,
    data.rewardThisWeekUsd,
    data.rewardsThisWeekUsd,
    data.weeklyRewardUsd,
    tierProgress.accruedThisWeekUsd,
    tierProgress.thisWeekRewardUsd,
    tierProgress.rewardThisWeekUsd,
    tierProgress.rewardsThisWeekUsd,
    thisWeek.usd,
    thisWeek.valueUsd,
    weekly.usd,
    weekly.valueUsd
  ];

  let cc = null;
  let usd = null;

  for (const candidate of ccCandidates) {
    const parsed = parseRewardMetricNumber(candidate);
    if (parsed !== null) {
      cc = parsed;
      break;
    }
  }

  for (const candidate of usdCandidates) {
    const parsed = parseRewardMetricNumber(candidate);
    if (parsed !== null) {
      usd = parsed;
      break;
    }
  }

  return { cc, usd };
}

function getAccountRewardsThisWeek(accountName) {
  const normalizedName = String(accountName || "").trim();
  if (!normalizedName || !rewardsThisWeekByAccount.has(normalizedName)) {
    return null;
  }
  return rewardsThisWeekByAccount.get(normalizedName);
}

function getAccountRewardsInitial(accountName) {
  const normalizedName = String(accountName || "").trim();
  if (!normalizedName || !rewardsInitialByAccount.has(normalizedName)) {
    return null;
  }
  return rewardsInitialByAccount.get(normalizedName);
}

function getAccountRewardsDiff(accountName) {
  const current = getAccountRewardsThisWeek(accountName);
  const initial = getAccountRewardsInitial(accountName);
  if (!isObject(current) || !isObject(initial)) {
    return null;
  }

  const diffCc =
    Number.isFinite(current.cc) && Number.isFinite(initial.cc)
      ? current.cc - initial.cc
      : null;
  const diffUsd =
    Number.isFinite(current.usd) && Number.isFinite(initial.usd)
      ? current.usd - initial.usd
      : null;

  if (diffCc === null && diffUsd === null) {
    return null;
  }

  return { cc: diffCc, usd: diffUsd };
}

function getTotalRewardsThisWeek() {
  let totalCc = 0;
  let totalUsd = 0;
  let hasCc = false;
  let hasUsd = false;

  for (const entry of rewardsThisWeekByAccount.values()) {
    if (!isObject(entry)) {
      continue;
    }
    if (Number.isFinite(entry.cc)) {
      totalCc += entry.cc;
      hasCc = true;
    }
    if (Number.isFinite(entry.usd)) {
      totalUsd += entry.usd;
      hasUsd = true;
    }
  }

  return {
    cc: hasCc ? totalCc : null,
    usd: hasUsd ? totalUsd : null
  };
}

function getTotalRewardsDiff() {
  let totalCc = 0;
  let totalUsd = 0;
  let hasCc = false;
  let hasUsd = false;

  for (const accountName of rewardsThisWeekByAccount.keys()) {
    const diff = getAccountRewardsDiff(accountName);
    if (!isObject(diff)) {
      continue;
    }
    if (Number.isFinite(diff.cc)) {
      totalCc += diff.cc;
      hasCc = true;
    }
    if (Number.isFinite(diff.usd)) {
      totalUsd += diff.usd;
      hasUsd = true;
    }
  }

  return {
    cc: hasCc ? totalCc : null,
    usd: hasUsd ? totalUsd : null
  };
}

const INTERNAL_API_DEFAULTS = {
  baseUrl: "https://bridge.rootsfi.com",
  paths: {
    onboard: "/onboard",
    send: "/send",
    bridge: "/bridge",
    rewards: "/rewards",
    syncAccount: "/api/auth/sync-account",
    authPending: "/api/auth/pending",
    sendOtp: "/api/auth/email/send-otp",
    verifyOtp: "/api/auth/email/verify-otp",
    finalizeReturning: "/api/auth/finalize-returning",
    walletBalances: "/api/wallet/balances",
    sendCcCooldown: "/api/send/cc-cooldown",
    sendResolve: "/api/send/resolve",
    sendTransfer: "/api/send/transfer",
    sendHistory: "/api/send/history",
    walletCcOutgoing: "/api/wallet/cc-outgoing",
    recipientPreview: "/api/send/recipient-preview",
    rewardsOverview: "/api/rewards",
    rewardsLottery: "/api/rewards/lottery",
    rewardsSendLoyaltyDailyTaper: "/api/rewards/send-loyalty-daily-taper"
  },
  headers: {
    userAgent:
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    acceptLanguage: "en-US,en;q=0.9,id;q=0.8",
    sendBrowserClientHints: true,
    secChUa: '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    secChUaMobile: "?0",
    secChUaPlatform: '"macOS"',
    secFetchDest: "empty",
    secFetchMode: "cors",
    secFetchSite: "same-origin",
    priority: "u=1, i"
  },
  http: {
    timeoutMs: 30000,
    maxRetries: 2,
    retryBaseDelayMs: 800
  },
  requestPacing: {
    minDelayMs: 450,
    jitterMs: 250
  },
  session: {
    preflightOnboard: false,
    autoRefreshCheckpoint: true,
    proactiveVercelRefreshMinutes: 45,
    maxSessionReuseRefreshAttempts: 3,
    maxSessionReuseTransientAttempts: 6,
    maxSessionReuseLightResets: 1,
    maxSessionReuseTransientBrowserRefreshes: 1,
    transientBrowserRefreshTriggerFailures: 2,
    sessionReuseTransientRetryAfterSeconds: 45,
    browserChallengeRetryAfterSeconds: 120,
    softRestartRetryAfterSeconds: 45,
    sessionReuseRetryJitterSeconds: 12,
    maxConcurrentSessionReuse: 1,
    checkpointSettleDelayMs: 3500,
    maxOtpRefreshAttempts: 3,
    fallbackToOtpOnPersistentCheckpoint: true
  },
  send: {
    maxTransfersPerHour: 1,
    minDelayTxSeconds: 120,
    maxDelayTxSeconds: 120,
    parallelJitterMinSeconds: 5,
    parallelJitterMaxSeconds: 15,
    delayCycleSeconds: 300,
    hourlyCapPollSeconds: 60,
    sequentialAllRounds: true,
    workers: 1,
    maxDeferredWaitSeconds: 45,
    tierAmounts: {
      unranked: { min: "25", max: "50", decimals: 3 },
      newbie: { min: "25", max: "50", decimals: 3 },
      advanced: { min: "50", max: "100", decimals: 3 },
      pro: { min: "75", max: "150", decimals: 3 },
      elite: { min: "150", max: "300", decimals: 3 }
    },
    tierDailyTxCap: {
      unranked: 96,
      newbie: 120,
      advanced: 180,
      pro: 240,
      elite: 360
    },
    randomAmount: {
      enabled: false,
      min: "0.10",
      max: "0.50",
      decimals: 2
    }
  },
  ui: {
    dashboard: true,
    logLines: 20
  },
  telegram: {
    enabled: false,
    botToken: "",
    chatId: "",
    messageThreadId: "",
    updateIntervalSeconds: 15,
    logsPerUpdate: 8,
    accountsPerUpdate: 10,
    sendCycleSummary: true
  },
  walleyRefund: {
    enabled: false,
    projectDir: "../walley",
    tokenSymbol: "CC",
    reasonPrefix: "rootsfi-refund",
    autoSyncSenderMap: true,
    parallelEnabled: true,
    maxConcurrency: 3,
    parallelJitterMinSeconds: 1,
    parallelJitterMaxSeconds: 10,
    senderMap: {}
  },
  safety: {
    minScoreThreshold: 30,
    minHoldBalanceCc: 10
  }
};

function getTimeStamp() {
  return new Date().toISOString().slice(11, 19);
}

function getJakartaTimeStamp() {
  return new Date().toLocaleString("id-ID", {
    hour12: false,
    timeZone: "Asia/Jakarta"
  });
}

function parseBooleanFlag(value) {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (["1", "true", "yes", "y", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "n", "off"].includes(normalized)) {
    return false;
  }

  return null;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function writeTelegramDebug(message) {
  try {
    process.stderr.write(`[telegram] ${message}\n`);
  } catch {}
}

class TelegramDashboardReporter {
  constructor(options = {}) {
    this.enabled = Boolean(options.enabled);
    this.botToken = String(options.botToken || "").trim();
    this.chatId = String(options.chatId || "").trim();
    this.messageThreadId = String(options.messageThreadId || "").trim();
    this.updateIntervalMs = Math.max(
      5000,
      clampToNonNegativeInt(options.updateIntervalSeconds, INTERNAL_API_DEFAULTS.telegram.updateIntervalSeconds) * 1000
    );
    this.logsPerUpdate = Math.max(
      1,
      clampToNonNegativeInt(options.logsPerUpdate, INTERNAL_API_DEFAULTS.telegram.logsPerUpdate)
    );
    this.accountsPerUpdate = Math.max(
      1,
      clampToNonNegativeInt(options.accountsPerUpdate, INTERNAL_API_DEFAULTS.telegram.accountsPerUpdate)
    );
    this.sendCycleSummary = Boolean(options.sendCycleSummary);
    this.projectName = String(options.projectName || "RootsFi Bot").trim() || "RootsFi Bot";
    this.pendingText = "";
    this.pendingIsHtml = false;
    this.lastSentText = "";
    this.lastSentAt = 0;
    this.statusMessageId = null;
    this.flushTimer = null;
    this.queue = Promise.resolve();
    this.lastErrorLogAt = 0;
  }

  isActive() {
    return this.enabled && Boolean(this.botToken) && Boolean(this.chatId);
  }

  buildPayload(text) {
    const safeText = String(text || "").trim();
    const maxPreformattedLength = 3600;
    const truncatedText =
      safeText.length > maxPreformattedLength
        ? `${safeText.slice(0, maxPreformattedLength - 17)}\n...(truncated)`
        : safeText;
    const payload = {
      chat_id: this.chatId,
      text: `<b>${escapeHtml(this.projectName)}</b>\n<pre>${escapeHtml(truncatedText)}</pre>`,
      parse_mode: "HTML",
      disable_web_page_preview: true
    };

    if (this.messageThreadId) {
      payload.message_thread_id = this.messageThreadId;
    }

    return payload;
  }

  buildHtmlPayload(html) {
    const safeHtml = String(html || "").trim();
    const payload = {
      chat_id: this.chatId,
      text: safeHtml,
      parse_mode: "HTML",
      disable_web_page_preview: true
    };

    if (this.messageThreadId) {
      payload.message_thread_id = this.messageThreadId;
    }

    return payload;
  }

  async callApi(method, payload) {
    const response = await fetch(`https://api.telegram.org/bot${this.botToken}/${method}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    let parsed = null;
    try {
      parsed = await response.json();
    } catch {}

    if (!response.ok || !parsed || parsed.ok === false) {
      const description = parsed && parsed.description
        ? parsed.description
        : `HTTP ${response.status}`;
      throw new Error(description);
    }

    return parsed.result;
  }

  enqueue(task) {
    this.queue = this.queue
      .then(async () => {
        try {
          return await task();
        } catch (error) {
          const nowMs = Date.now();
          if (nowMs - this.lastErrorLogAt >= 30000) {
            this.lastErrorLogAt = nowMs;
            writeTelegramDebug(error && error.message ? error.message : String(error));
          }
          return null;
        }
      })
      .catch(() => null);

    return this.queue;
  }

  async flushPending() {
    if (!this.isActive()) {
      return null;
    }

    const text = String(this.pendingText || "").trim();
    if (!text || text === this.lastSentText) {
      return null;
    }

    this.pendingText = "";
    const isHtml = Boolean(this.pendingIsHtml);
    this.pendingIsHtml = false;
    return this.enqueue(async () => {
      const payload = isHtml ? this.buildHtmlPayload(text) : this.buildPayload(text);

      if (this.statusMessageId) {
        try {
          await this.callApi("editMessageText", {
            ...payload,
            message_id: this.statusMessageId
          });
          this.lastSentText = text;
          this.lastSentAt = Date.now();
          return true;
        } catch (error) {
          const message = String(error && error.message ? error.message : error).toLowerCase();
          if (message.includes("message is not modified")) {
            this.lastSentText = text;
            this.lastSentAt = Date.now();
            return true;
          }

          this.statusMessageId = null;
        }
      }

      const result = await this.callApi("sendMessage", payload);
      if (result && result.message_id) {
        this.statusMessageId = result.message_id;
      }
      this.lastSentText = text;
      this.lastSentAt = Date.now();
      return true;
    });
  }

  scheduleText(text, options = {}) {
    if (!this.isActive()) {
      return;
    }

    const safeText = String(text || "").trim();
    if (!safeText) {
      return;
    }

    this.pendingText = safeText;
    this.pendingIsHtml = Boolean(options.isHtml);

    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    const immediate = Boolean(options.immediate);
    const elapsedMs = Date.now() - this.lastSentAt;
    const waitMs = immediate ? 0 : Math.max(0, this.updateIntervalMs - elapsedMs);

    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flushPending().catch(() => null);
    }, waitMs);
  }

  scheduleFromDashboard(dashboard) {
    if (!this.isActive() || !dashboard || typeof dashboard.getTelegramSnapshotHtml !== "function") {
      return;
    }

    const snapshot = dashboard.getTelegramSnapshotHtml({
      accountLimit: this.accountsPerUpdate,
      logLimit: this.logsPerUpdate
    });
    this.scheduleText(snapshot, { isHtml: true });
  }

  async sendEvent(text, options = {}) {
    if (!this.isActive() || !this.sendCycleSummary) {
      return null;
    }

    const body = String(text || "").trim();
    if (!body) {
      return null;
    }

    const lines = [
      `${options.label || "EVENT"} | ${getJakartaTimeStamp()} WIB`,
      "",
      body
    ];

    return this.enqueue(async () => {
      await this.callApi("sendMessage", this.buildPayload(lines.join("\n")));
      return true;
    });
  }

  async close() {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    await this.flushPending();
  }
}

class WalleyRefundBridge {
  constructor(options = {}) {
    this.enabled = Boolean(options.enabled);
    this.projectDir = path.resolve(
      process.cwd(),
      String(options.projectDir || INTERNAL_API_DEFAULTS.walleyRefund.projectDir).trim()
    );
    this.tokenSymbol = String(options.tokenSymbol || INTERNAL_API_DEFAULTS.walleyRefund.tokenSymbol).trim() || "CC";
    this.reasonPrefix = String(options.reasonPrefix || INTERNAL_API_DEFAULTS.walleyRefund.reasonPrefix).trim() || "rootsfi-refund";
    this.parallelEnabled =
      typeof options.parallelEnabled === "boolean"
        ? options.parallelEnabled
        : INTERNAL_API_DEFAULTS.walleyRefund.parallelEnabled;
    this.maxConcurrency = Math.max(
      1,
      clampToNonNegativeInt(options.maxConcurrency, INTERNAL_API_DEFAULTS.walleyRefund.maxConcurrency)
    );
    this.parallelJitterMinSeconds = Math.max(
      0,
      clampToNonNegativeInt(
        options.parallelJitterMinSeconds,
        INTERNAL_API_DEFAULTS.walleyRefund.parallelJitterMinSeconds
      )
    );
    this.parallelJitterMaxSeconds = Math.max(
      this.parallelJitterMinSeconds,
      clampToNonNegativeInt(
        options.parallelJitterMaxSeconds,
        INTERNAL_API_DEFAULTS.walleyRefund.parallelJitterMaxSeconds
      )
    );
    this.senderMap = isObject(options.senderMap) ? { ...options.senderMap } : {};
    this.runtimePromise = null;
  }

  isActive() {
    return this.enabled;
  }

  async loadRuntime() {
    if (!this.runtimePromise) {
      const modulePath = pathToFileURL(path.resolve(this.projectDir, "src", "index.js")).href;
      this.runtimePromise = import(modulePath);
    }
    return this.runtimePromise;
  }

  resolveWalleySender(transfer) {
    const partyId = String(transfer && transfer.walleyPartyId ? transfer.walleyPartyId : "").trim();
    const alias = String(transfer && transfer.walleyAlias ? transfer.walleyAlias : "").trim();

    if (partyId && this.senderMap[partyId]) {
      return String(this.senderMap[partyId]).trim();
    }
    if (alias && this.senderMap[alias]) {
      return String(this.senderMap[alias]).trim();
    }
    if (partyId) {
      return partyId;
    }
    return alias;
  }

  buildReason(rootsfiAccount, transfer) {
    const sourceName = String(rootsfiAccount && rootsfiAccount.name ? rootsfiAccount.name : "").trim() || "rootsfi";
    const walleyAlias = String(transfer && transfer.walleyAlias ? transfer.walleyAlias : "").trim() || "walley";
    return `${this.reasonPrefix}:${sourceName}:${walleyAlias}`.slice(0, 120);
  }

  buildRuntimeRefundTransfers(rootsfiAccount, transfers, accountLogTag = null) {
    const senderAddress = String(rootsfiAccount && rootsfiAccount.address ? rootsfiAccount.address : "").trim();
    if (!senderAddress) {
      console.warn(
        withAccountTag(
          accountLogTag,
          `[walley-refund] Skip refund: account ${rootsfiAccount && rootsfiAccount.name ? rootsfiAccount.name : "unknown"} has no RootsFi address`
        )
      );
      return [];
    }

    return Array.isArray(transfers)
      ? transfers
          .map((transfer) => {
            const from = this.resolveWalleySender(transfer);
            const amount = String(transfer && transfer.amount ? transfer.amount : "").trim();
            const targetPartyId = String(
              transfer && transfer.refundTargetPartyId ? transfer.refundTargetPartyId : senderAddress
            ).trim();
            if (!from || !amount) {
              console.warn(
                withAccountTag(
                  accountLogTag,
                  `[walley-refund] Skip transfer: missing sender mapping or amount for ${JSON.stringify({
                    walleyAlias: transfer && transfer.walleyAlias,
                    walleyPartyId: transfer && transfer.walleyPartyId,
                    amount: transfer && transfer.amount
                  })}`
                )
              );
              return null;
            }
            if (!targetPartyId) {
              console.warn(
                withAccountTag(
                  accountLogTag,
                  `[walley-refund] Skip transfer: missing refund target for ${JSON.stringify({
                    walleyAlias: transfer && transfer.walleyAlias,
                    amount: transfer && transfer.amount
                  })}`
                )
              );
              return null;
            }

            return {
              from,
              toPartyId: targetPartyId,
              amount,
              tokenSymbol: this.tokenSymbol,
              reason: this.buildReason(rootsfiAccount, transfer)
            };
          })
          .filter((entry) => Boolean(entry))
      : [];
  }

  async refundPreparedBatch(runtimeTransfers, accountLogTag = null, runtimeOptions = {}) {
    if (!this.isActive()) {
      return {
        ok: true,
        results: [],
        successCount: 0,
        failureCount: 0
      };
    }

    const normalizedTransfers = Array.isArray(runtimeTransfers)
      ? runtimeTransfers.filter((entry) => entry && entry.from && entry.toPartyId && entry.amount)
      : [];

    if (normalizedTransfers.length === 0) {
      return {
        ok: true,
        results: [],
        successCount: 0,
        failureCount: 0
      };
    }

    const parallelEnabled =
      typeof runtimeOptions.parallelEnabled === "boolean"
        ? runtimeOptions.parallelEnabled
        : this.parallelEnabled;
    const transferConcurrency = parallelEnabled
      ? Math.max(
          1,
          clampToNonNegativeInt(
            runtimeOptions.transferConcurrency,
            this.maxConcurrency
          )
        )
      : 1;
    const parallelJitterMinMs = parallelEnabled
      ? Math.max(
          0,
          clampToNonNegativeInt(
            runtimeOptions.parallelJitterMinMs,
            this.parallelJitterMinSeconds * 1000
          )
        )
      : 0;
    const parallelJitterMaxMs = parallelEnabled
      ? Math.max(
          parallelJitterMinMs,
          clampToNonNegativeInt(
            runtimeOptions.parallelJitterMaxMs,
            this.parallelJitterMaxSeconds * 1000
          )
        )
      : 0;

    console.log(
      withAccountTag(
        accountLogTag,
        `[walley-refund] Processing ${normalizedTransfers.length} refund(s) via ${this.projectDir} ` +
        `(parallel=${parallelEnabled ? "on" : "off"}, concurrency=${transferConcurrency}, jitter=${Math.round(parallelJitterMinMs / 1000)}-${Math.round(parallelJitterMaxMs / 1000)}s)`
      )
    );

    const runtime = await this.loadRuntime();
    if (!runtime || typeof runtime.runWalleyTransfers !== "function") {
      throw new Error("Walley runtime export runWalleyTransfers is unavailable");
    }

    return runtime.runWalleyTransfers({
      rootDir: this.projectDir,
      transfers: normalizedTransfers,
      logger: (message) => {
        console.log(withAccountTag(accountLogTag, `[walley] ${message}`));
      },
      transferConcurrency,
      parallelJitterMinMs,
      parallelJitterMaxMs
    });
  }

  async refundBatch(rootsfiAccount, transfers, accountLogTag = null) {
    if (!this.isActive()) {
      return {
        ok: true,
        results: [],
        successCount: 0,
        failureCount: 0
      };
    }

    const normalizedTransfers = this.buildRuntimeRefundTransfers(
      rootsfiAccount,
      transfers,
      accountLogTag
    );

    return this.refundPreparedBatch(normalizedTransfers, accountLogTag);
  }
}

class PinnedDashboard {
  constructor({ enabled, logLines, accountSnapshots, reporter }) {
    this.terminalEnabled = Boolean(enabled && process.stdout.isTTY);
    this.captureEnabled = Boolean(this.terminalEnabled || reporter);
    this.logLines = Math.min(
      20,
      Math.max(1, clampToNonNegativeInt(logLines, INTERNAL_API_DEFAULTS.ui.logLines))
    );
    this.logs = [];
    this.accountSnapshots = isObject(accountSnapshots) ? accountSnapshots : {};
    this.reporter = reporter || null;
    this.state = {
      phase: "init",
      selectedAccount: "-",
      accounts: "-",
      cookie: "-",
      balance: "-",
      send: "-",
      transfer: "-",
      reward: "-",
      rewardsThisWeek: "-",
      rewardsDiff: "-",
      rewardQuality: "-",
      rewardTier: "-",
      rewardTodayPoints: "-",
      rewardVolume: "-",
      rewardDailyCheckin: "-",
      mode: "BALANCE",
      strategy: "balanced_human",
      swapsTotal: 0,
      swapsOk: 0,
      swapsFail: 0,
      targetPerDay: 0,
      cooldown: "0/0"
    };
    this.originalConsole = null;
  }

  attach() {
    if (!this.captureEnabled || this.originalConsole) {
      return;
    }

    this.originalConsole = {
      log: console.log,
      warn: console.warn,
      error: console.error
    };

    console.log = (...args) => {
      if (!this.terminalEnabled) {
        this.originalConsole.log(...args);
      }
      this.pushLog("INFO", args);
    };
    console.warn = (...args) => {
      if (!this.terminalEnabled) {
        this.originalConsole.warn(...args);
      }
      this.pushLog("WARN", args);
    };
    console.error = (...args) => {
      if (!this.terminalEnabled) {
        this.originalConsole.error(...args);
      }
      this.pushLog("ERROR", args);
    };
    this.render();
  }

  detach() {
    if (!this.originalConsole) {
      return;
    }

    console.log = this.originalConsole.log;
    console.warn = this.originalConsole.warn;
    console.error = this.originalConsole.error;
    this.originalConsole = null;
    if (this.terminalEnabled) {
      process.stdout.write("\n");
    }
  }

  setState(patch) {
    this.state = { ...this.state, ...patch };
    this.syncSelectedAccountSnapshot();
    this.render();
  }

  stringifyArg(value) {
    if (typeof value === "string") {
      return value;
    }
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }

  pushLog(level, args) {
    let message = args.map((item) => this.stringifyArg(item)).join(" ").trim();
    let logLevel = level;

    const accountTagMatch = message.match(/^\[(A\d+\/\d+)\]\s*/i);
    if (accountTagMatch) {
      logLevel = String(accountTagMatch[1] || level).toUpperCase();
      message = message.slice(accountTagMatch[0].length).trim();
    }

    this.logs.push({
      time: getTimeStamp(),
      level: logLevel,
      message
    });

    if (this.logs.length > this.logLines) {
      this.logs.splice(0, this.logs.length - this.logLines);
    }

    this.render();
  }

  clip(text, maxLength) {
    const value = String(text || "");
    if (value.length <= maxLength) {
      return value;
    }
    return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
  }

  formatCell(text, width) {
    const value = this.clip(String(text || "-"), width);
    return value.padEnd(width, " ");
  }

  escapeTelegramCode(value) {
    return escapeHtml(String(value || "").replace(/\r?\n/g, " "));
  }

  formatRewardsThisWeek(accountName, snapshotFallback = "-") {
    const entry = getAccountRewardsThisWeek(accountName);
    if (isObject(entry)) {
      const ccLabel = Number.isFinite(entry.cc) ? entry.cc.toFixed(2) : "?";
      const usdLabel = Number.isFinite(entry.usd) ? entry.usd.toFixed(2) : "?";
      return `${ccLabel} CC ($${usdLabel})`;
    }
    const fallback = String(snapshotFallback || "-").trim();
    return fallback || "-";
  }

  formatRewardsDiff(accountName, snapshotFallback = "-") {
    const diff = getAccountRewardsDiff(accountName);
    if (isObject(diff)) {
      const ccLabel = Number.isFinite(diff.cc) ? `${diff.cc >= 0 ? "+" : ""}${diff.cc.toFixed(2)} CC` : "?";
      const usdLabel = Number.isFinite(diff.usd) ? `${diff.usd >= 0 ? "+" : ""}$${diff.usd.toFixed(2)}` : "?";
      return `${ccLabel} (${usdLabel})`;
    }
    const fallback = String(snapshotFallback || "-").trim();
    return fallback || "-";
  }

  buildRewardSummaryLabel(reward, quality, tier, todayPoints, volume, dailyCheckin) {
    const parts = [];
    const rewardValue = String(reward || "-").trim();
    const qualityValue = String(quality || "-").trim();
    const tierValue = String(tier || "-").trim();
    const todayPointsValue = String(todayPoints || "-").trim();
    const volumeValue = String(volume || "-").trim();
    const dailyCheckinValue = String(dailyCheckin || "-").trim();

    if (rewardValue && rewardValue !== "-") {
      parts.push(rewardValue);
    }
    if (tierValue && tierValue !== "-") {
      parts.push(`Tier ${tierValue}`);
    }
    if (qualityValue && qualityValue !== "-") {
      parts.push(`Q ${qualityValue}`);
    }
    if (todayPointsValue && todayPointsValue !== "-") {
      parts.push(`Today ${todayPointsValue}`);
    }
    if (volumeValue && volumeValue !== "-") {
      parts.push(`Vol ${volumeValue}`);
    }
    if (dailyCheckinValue && dailyCheckinValue !== "-") {
      parts.push(`Check-in ${dailyCheckinValue}`);
    }

    return parts.length > 0 ? parts.join(" | ") : "-";
  }

  parseSelectedAccountName() {
    const raw = String(this.state.selectedAccount || "").trim();
    const indexPrefix = raw.match(/^\[\d+\/\d+\]\s*(.+)$/);
    const value = indexPrefix ? indexPrefix[1] : raw;
    const open = value.indexOf(" (");
    if (open > 0) {
      return value.slice(0, open).trim();
    }
    return value;
  }

  mapPhaseToStatus(phase) {
    const key = String(phase || "").toLowerCase();
    const map = {
      init: "IDLE",
      preflight: "SYNC",
      "vercel-refresh": "SECURITY",
      "browser-checkpoint": "SECURITY",
      "session-reuse": "SESSION",
      "otp-send": "OTP-WAIT",
      "otp-verify": "OTP-VERIFY",
      "otp-fallback": "OTP-FALLBACK",
      "sync-onboard": "SYNC",
      "sync-bridge": "SYNC",
      "finalize-returning": "FINALIZE",
      balances: "IDLE",
      send: "SEND",
      cooldown: "COOLDOWN",
      completed: "IDLE",
      "session-reused": "IDLE",
      "dry-run": "DRY-RUN"
    };
    return map[key] || String(phase || "-").toUpperCase();
  }

  parseBalanceFields() {
    const raw = String(this.state.balance || "");
    const matchCc = raw.match(/CC=([^|]+)/i);
    return {
      cc: matchCc ? String(matchCc[1]).trim() : "-"
    };
  }

  parseCcNumeric(value) {
    const text = String(value || "").trim();
    if (!text || text === "-") {
      return null;
    }

    const match = text.match(/-?\d+(?:\.\d+)?/);
    if (!match) {
      return null;
    }

    const numeric = Number(match[0]);
    return Number.isFinite(numeric) ? numeric : null;
  }

  getAggregateCcBalanceSummary(rows = []) {
    let total = 0;
    let count = 0;

    for (const row of Array.isArray(rows) ? rows : []) {
      const numeric = this.parseCcNumeric(row && row.cc);
      if (!Number.isFinite(numeric)) {
        continue;
      }
      total += numeric;
      count += 1;
    }

    return {
      total: count > 0 ? total : null,
      count
    };
  }

  syncSelectedAccountSnapshot() {
    const selected = this.parseSelectedAccountName();
    if (!selected || selected === "-") {
      return;
    }

    const prev = isObject(this.accountSnapshots[selected]) ? this.accountSnapshots[selected] : {};
    const balances = this.parseBalanceFields();
    const currentSend = String(this.state.send || "-").trim();
    const currentReward = String(this.state.reward || "-").trim();
    const currentRewardsThisWeek = String(this.state.rewardsThisWeek || "-").trim();
    const currentRewardsDiff = String(this.state.rewardsDiff || "-").trim();
    const currentRewardQuality = String(this.state.rewardQuality || "-").trim();
    const currentRewardTier = String(this.state.rewardTier || "-").trim();
    const currentRewardTodayPoints = String(this.state.rewardTodayPoints || "-").trim();
    const currentRewardVolume = String(this.state.rewardVolume || "-").trim();
    const currentRewardDailyCheckin = String(this.state.rewardDailyCheckin || "-").trim();
    // Use per-account stats for TX Progress column (not global state)
    const accountStats = getPerAccountTxStats(selected);
    const currentProgress = `${accountStats.total} (ok:${accountStats.ok}|fail:${accountStats.fail})`;

    this.accountSnapshots[selected] = {
      status: this.mapPhaseToStatus(this.state.phase),
      cc: balances.cc !== "-" ? balances.cc : String(prev.cc || "-"),
      progress: currentProgress !== "-" ? currentProgress : String(prev.progress || "-"),
      send: currentSend !== "-" ? currentSend : String(prev.send || "-"),
      reward: currentReward !== "-" ? currentReward : String(prev.reward || "-"),
      rewardsThisWeek:
        currentRewardsThisWeek !== "-" ? currentRewardsThisWeek : String(prev.rewardsThisWeek || "-"),
      rewardsDiff:
        currentRewardsDiff !== "-" ? currentRewardsDiff : String(prev.rewardsDiff || "-"),
      rewardQuality:
        currentRewardQuality !== "-" ? currentRewardQuality : String(prev.rewardQuality || "-"),
      rewardTier: currentRewardTier !== "-" ? currentRewardTier : String(prev.rewardTier || "-"),
      rewardTodayPoints:
        currentRewardTodayPoints !== "-" ? currentRewardTodayPoints : String(prev.rewardTodayPoints || "-"),
      rewardVolume:
        currentRewardVolume !== "-" ? currentRewardVolume : String(prev.rewardVolume || "-"),
      rewardDailyCheckin:
        currentRewardDailyCheckin !== "-" ? currentRewardDailyCheckin : String(prev.rewardDailyCheckin || "-")
    };
  }

  parseAccountRows() {
    const selected = this.parseSelectedAccountName();
    const balances = this.parseBalanceFields();
    const raw = String(this.state.accounts || "").trim();
    const chunks = raw && raw !== "-" ? raw.split("|") : [];
    const rows = [];

    for (const chunk of chunks) {
      const text = chunk.trim();
      if (!text) {
        continue;
      }

      const marked = text.startsWith("*");
      const cleaned = marked ? text.slice(1).trim() : text;
      const match = cleaned.match(/^([^\(]+)\(([^\)]+)\)$/);
      const name = match ? String(match[1]).trim() : cleaned;
      const token = match ? String(match[2]).trim() : "-";
      const isSelected = name === selected || (marked && selected === "-");
      const snapshot = isObject(this.accountSnapshots[name]) ? this.accountSnapshots[name] : {};
      // Use per-account stats for TX Progress column (not global state)
      const accountStats = getPerAccountTxStats(name);
      const currentProgress = `${accountStats.total} (ok:${accountStats.ok}|fail:${accountStats.fail})`;

      rows.push({
        name,
        status: isSelected
          ? this.mapPhaseToStatus(this.state.phase)
          : (snapshot.status || (token && token !== "-" ? String(token).toUpperCase() : "IDLE")),
        token,
        active: isSelected,
        cc: isSelected
          ? (balances.cc !== "-" ? balances.cc : String(snapshot.cc || "-"))
          : String(snapshot.cc || "-"),
        progress: currentProgress,
        send: isSelected
          ? (String(this.state.send || "-") !== "-" ? String(this.state.send || "-") : String(snapshot.send || "-"))
          : String(snapshot.send || "-"),
        reward: isSelected
          ? (String(this.state.reward || "-") !== "-" ? String(this.state.reward || "-") : String(snapshot.reward || "-"))
          : String(snapshot.reward || "-"),
        rewardsThisWeek: isSelected
          ? this.formatRewardsThisWeek(name, String(this.state.rewardsThisWeek || snapshot.rewardsThisWeek || "-"))
          : this.formatRewardsThisWeek(name, String(snapshot.rewardsThisWeek || "-")),
        rewardsDiff: isSelected
          ? this.formatRewardsDiff(name, String(this.state.rewardsDiff || snapshot.rewardsDiff || "-"))
          : this.formatRewardsDiff(name, String(snapshot.rewardsDiff || "-")),
        rewardQuality: isSelected
          ? (String(this.state.rewardQuality || "-") !== "-" ? String(this.state.rewardQuality || "-") : String(snapshot.rewardQuality || "-"))
          : String(snapshot.rewardQuality || "-"),
        rewardTier: isSelected
          ? (String(this.state.rewardTier || "-") !== "-" ? String(this.state.rewardTier || "-") : String(snapshot.rewardTier || "-"))
          : String(snapshot.rewardTier || "-"),
        rewardTodayPoints: isSelected
          ? (String(this.state.rewardTodayPoints || "-") !== "-" ? String(this.state.rewardTodayPoints || "-") : String(snapshot.rewardTodayPoints || "-"))
          : String(snapshot.rewardTodayPoints || "-"),
        rewardVolume: isSelected
          ? (String(this.state.rewardVolume || "-") !== "-" ? String(this.state.rewardVolume || "-") : String(snapshot.rewardVolume || "-"))
          : String(snapshot.rewardVolume || "-"),
        rewardDailyCheckin: isSelected
          ? (String(this.state.rewardDailyCheckin || "-") !== "-" ? String(this.state.rewardDailyCheckin || "-") : String(snapshot.rewardDailyCheckin || "-"))
          : String(snapshot.rewardDailyCheckin || "-")
      });
    }

    if (rows.length === 0 && selected && selected !== "-") {
      const snapshot = isObject(this.accountSnapshots[selected]) ? this.accountSnapshots[selected] : {};
      // Use per-account stats for TX Progress column (not global state)
      const accountStats = getPerAccountTxStats(selected);
      const currentProgress = `${accountStats.total} (ok:${accountStats.ok}|fail:${accountStats.fail})`;
      rows.push({
        name: selected,
        status: this.mapPhaseToStatus(this.state.phase),
        token: "-",
        active: true,
        cc: balances.cc !== "-" ? balances.cc : String(snapshot.cc || "-"),
        progress: currentProgress,
        send: String(this.state.send || "-") !== "-" ? String(this.state.send || "-") : String(snapshot.send || "-"),
        reward: String(this.state.reward || "-") !== "-" ? String(this.state.reward || "-") : String(snapshot.reward || "-"),
        rewardsThisWeek: this.formatRewardsThisWeek(selected, String(this.state.rewardsThisWeek || snapshot.rewardsThisWeek || "-")),
        rewardsDiff: this.formatRewardsDiff(selected, String(this.state.rewardsDiff || snapshot.rewardsDiff || "-")),
        rewardQuality:
          String(this.state.rewardQuality || "-") !== "-"
            ? String(this.state.rewardQuality || "-")
            : String(snapshot.rewardQuality || "-"),
        rewardTier:
          String(this.state.rewardTier || "-") !== "-"
            ? String(this.state.rewardTier || "-")
            : String(snapshot.rewardTier || "-"),
        rewardTodayPoints:
          String(this.state.rewardTodayPoints || "-") !== "-"
            ? String(this.state.rewardTodayPoints || "-")
            : String(snapshot.rewardTodayPoints || "-"),
        rewardVolume:
          String(this.state.rewardVolume || "-") !== "-"
            ? String(this.state.rewardVolume || "-")
            : String(snapshot.rewardVolume || "-"),
        rewardDailyCheckin:
          String(this.state.rewardDailyCheckin || "-") !== "-"
            ? String(this.state.rewardDailyCheckin || "-")
            : String(snapshot.rewardDailyCheckin || "-")
      });
    }

    for (const row of rows) {
      row.rewardSummary = this.buildRewardSummaryLabel(
        row.rewardsThisWeek && row.rewardsThisWeek !== "-" ? row.rewardsThisWeek : row.reward,
        row.rewardQuality,
        row.rewardTier,
        row.rewardTodayPoints,
        row.rewardVolume,
        row.rewardDailyCheckin
      );
    }

    return rows;
  }

  buildTelegramAccountBlock(row) {
    const name = String(row && row.name ? row.name : "-").trim() || "-";
    const status = String(row && row.status ? row.status : "-").trim() || "-";
    const cc = String(row && row.cc ? row.cc : "-").trim() || "-";
    const progress = String(row && row.progress ? row.progress : "-").trim() || "-";
    const send = String(row && row.send ? row.send : "-").trim() || "-";
    const rewardSummary = this.buildRewardSummaryLabel(
      row && row.reward,
      row && row.rewardQuality,
      row && row.rewardTier,
      row && row.rewardTodayPoints,
      row && row.rewardVolume,
      row && row.rewardDailyCheckin
    );

    const lines = [
      `- ${name} [${status}]`,
      `  CC ${cc} | TX ${progress}`
    ];

    if (send && send !== "-") {
      lines.push(`  Send ${this.clip(send, 72)}`);
    }

    const rewardsThisWeek = String(row && row.rewardsThisWeek ? row.rewardsThisWeek : "-").trim() || "-";
    const rewardsDiff = String(row && row.rewardsDiff ? row.rewardsDiff : "-").trim() || "-";
    if ((rewardsThisWeek && rewardsThisWeek !== "-") || (rewardsDiff && rewardsDiff !== "-")) {
      const weekDiffParts = [];
      if (rewardsThisWeek && rewardsThisWeek !== "-") {
        weekDiffParts.push(`Week ${rewardsThisWeek}`);
      }
      if (rewardsDiff && rewardsDiff !== "-") {
        weekDiffParts.push(`Diff ${rewardsDiff}`);
      }
      lines.push(`  ${this.clip(weekDiffParts.join(" | "), 72)}`);
    }

    const rewardParts = [];
    if (row && row.rewardTier && row.rewardTier !== "-") {
      rewardParts.push(`Tier ${escapeHtml(row.rewardTier)}`);
    }
    if (row && row.rewardQuality && row.rewardQuality !== "-") {
      rewardParts.push(`Q ${row.rewardQuality}`);
    }
    if (row && row.rewardTodayPoints && row.rewardTodayPoints !== "-") {
      rewardParts.push(`Today ${row.rewardTodayPoints}`);
    }
    if (rewardParts.length > 0) {
      lines.push(`  Rewards ${this.clip(rewardParts.join(" | "), 72)}`);
    }

    const rewardMetaParts = [];
    if (row && row.rewardVolume && row.rewardVolume !== "-") {
      rewardMetaParts.push(`Vol ${row.rewardVolume}`);
    }
    if (row && row.rewardDailyCheckin && row.rewardDailyCheckin !== "-") {
      rewardMetaParts.push(`Check-in ${row.rewardDailyCheckin}`);
    }
    if (rewardMetaParts.length > 0) {
      lines.push(`  ${this.clip(rewardMetaParts.join(" | "), 72)}`);
    } else if (rewardSummary && rewardSummary !== "-") {
      lines.push(`  Rewards ${this.clip(rewardSummary, 72)}`);
    }

    return lines;
  }

  buildTelegramSelectedRewardsLines() {
    const rewardsThisWeek = String(this.state.rewardsThisWeek || "-").trim();
    const reward = String(this.state.reward || "-").trim();
    const rewardsDiff = String(this.state.rewardsDiff || "-").trim();
    const tier = String(this.state.rewardTier || "-").trim();
    const quality = String(this.state.rewardQuality || "-").trim();
    const todayPoints = String(this.state.rewardTodayPoints || "-").trim();
    const volume = String(this.state.rewardVolume || "-").trim();
    const dailyCheckin = String(this.state.rewardDailyCheckin || "-").trim();

    const lines = [];
    const primaryParts = [];
    const secondaryParts = [];

    if (rewardsThisWeek && rewardsThisWeek !== "-") {
      primaryParts.push(rewardsThisWeek);
    } else if (reward && reward !== "-") {
      primaryParts.push(reward);
    }
    if (tier && tier !== "-") {
      primaryParts.push(`Tier ${tier}`);
    }
    if (quality && quality !== "-") {
      primaryParts.push(`Q ${quality}`);
    }
    if (todayPoints && todayPoints !== "-") {
      primaryParts.push(`Today ${todayPoints}`);
    }

    if (volume && volume !== "-") {
      secondaryParts.push(`Vol ${volume}`);
    }
    if (dailyCheckin && dailyCheckin !== "-") {
      secondaryParts.push(`Check-in ${dailyCheckin}`);
    }

    if (primaryParts.length > 0) {
      lines.push(`Rewards ${this.clip(primaryParts.join(" | "), 86)}`);
    }
    if (secondaryParts.length > 0) {
      lines.push(`        ${this.clip(secondaryParts.join(" | "), 86)}`);
    }
    if (rewardsDiff && rewardsDiff !== "-") {
      lines.push(`        ${this.clip(`Diff ${rewardsDiff}`, 86)}`);
    }

    return lines;
  }

  buildTelegramHeaderHtml(options = {}) {
    const rows = this.parseAccountRows();
    const modeLabel = String(this.state.mode || "-").toUpperCase();
    const selectedAccount = this.parseSelectedAccountName() || "-";
    const rewardsThisWeek = String(this.state.rewardsThisWeek || "-").trim();
    const rewardsDiff = String(this.state.rewardsDiff || "-").trim();
    const reward = String(this.state.reward || "-").trim();
    const tier = String(this.state.rewardTier || "-").trim();
    const quality = String(this.state.rewardQuality || "-").trim();
    const todayPoints = String(this.state.rewardTodayPoints || "-").trim();
    const volume = String(this.state.rewardVolume || "-").trim();
    const dailyCheckin = String(this.state.rewardDailyCheckin || "-").trim();
    const txStats = getGlobalTxStatsSnapshot();
    const txProgressLabel = `${txStats.total}/${txStats.total}`;
    const rewardsTotals = getTotalRewardsThisWeek();
    const rewardsDiffTotals = getTotalRewardsDiff();
    const aggregateBalance = this.getAggregateCcBalanceSummary(rows);
    const shownAccountCount = Math.min(
      rows.length,
      Math.max(
        1,
        clampToNonNegativeInt(options.accountLimit, rows.length || INTERNAL_API_DEFAULTS.telegram.accountsPerUpdate)
      )
    );

    const lines = [
      `🤖 <b>${escapeHtml(this.projectName)}</b>`,
      `🕒 Time  <code>${this.escapeTelegramCode(`${getJakartaTimeStamp()} WIB`)}</code>`,
      `🚦 Run   <b>${escapeHtml(modeLabel)}</b> | ${escapeHtml(String(this.state.phase || "-"))}`,
      `👤 Acct  <b>${escapeHtml(selectedAccount)}</b> | <code>${this.escapeTelegramCode(`${shownAccountCount}/${rows.length || 0}`)}</code> shown`,
      `📊 TX    <code>${this.escapeTelegramCode(txProgressLabel)}</code> | ok <code>${this.escapeTelegramCode(String(txStats.ok))}</code> | fail <code>${this.escapeTelegramCode(String(txStats.fail))}</code> | target <code>${this.escapeTelegramCode(`${this.state.targetPerDay}/hour`)}</code>`
    ];

    if (Number.isFinite(aggregateBalance.total)) {
      lines.push(
        `🏦 Total CC <code>${this.escapeTelegramCode(aggregateBalance.total.toFixed(4))}</code> | acct <code>${this.escapeTelegramCode(String(aggregateBalance.count))}</code>`
      );
    }

    const rewardPrimaryParts = [];
    if (reward && reward !== "-") {
      rewardPrimaryParts.push(`<code>${this.escapeTelegramCode(reward)}</code>`);
    }
    if (tier && tier !== "-") {
      rewardPrimaryParts.push(`Tier ${escapeHtml(tier)}`);
    }
    if (quality && quality !== "-") {
      rewardPrimaryParts.push(`Q <code>${this.escapeTelegramCode(quality)}</code>`);
    }
    if (todayPoints && todayPoints !== "-") {
      rewardPrimaryParts.push(`Today <code>${this.escapeTelegramCode(todayPoints)}</code>`);
    }
    if (rewardPrimaryParts.length > 0) {
      lines.push(`🏆 Rewards ${rewardPrimaryParts.join(" | ")}`);
    }

    const rewardMetaParts = [];
    if (volume && volume !== "-") {
      rewardMetaParts.push(`Vol <code>${this.escapeTelegramCode(volume)}</code>`);
    }
    if (dailyCheckin && dailyCheckin !== "-") {
      rewardMetaParts.push(`Check-in <code>${this.escapeTelegramCode(dailyCheckin)}</code>`);
    }
    if (rewardMetaParts.length > 0) {
      lines.push(`📈 ${rewardMetaParts.join(" | ")}`);
    }

    const selectedWeekDiffParts = [];
    if (rewardsThisWeek && rewardsThisWeek !== "-") {
      selectedWeekDiffParts.push(`Week <code>${this.escapeTelegramCode(rewardsThisWeek)}</code>`);
    } else if (reward && reward !== "-") {
      selectedWeekDiffParts.push(`Week <code>${this.escapeTelegramCode(reward)}</code>`);
    }
    if (rewardsDiff && rewardsDiff !== "-") {
      selectedWeekDiffParts.push(`Diff <code>${this.escapeTelegramCode(rewardsDiff)}</code>`);
    }
    if (selectedWeekDiffParts.length > 0) {
      lines.push(`💵 ${selectedWeekDiffParts.join(" | ")}`);
    }

    if (Number.isFinite(rewardsTotals.cc) || Number.isFinite(rewardsTotals.usd)) {
      const totalCcLabel = Number.isFinite(rewardsTotals.cc) ? `${rewardsTotals.cc.toFixed(2)} CC` : "?";
      const totalUsdLabel = Number.isFinite(rewardsTotals.usd) ? `$${rewardsTotals.usd.toFixed(2)}` : "?";
      lines.push(`💰 Week Total <code>${this.escapeTelegramCode(totalCcLabel)}</code> | <code>${this.escapeTelegramCode(totalUsdLabel)}</code>`);
    }

    if (Number.isFinite(rewardsDiffTotals.cc) || Number.isFinite(rewardsDiffTotals.usd)) {
      const totalDiffCc = Number.isFinite(rewardsDiffTotals.cc)
        ? `${rewardsDiffTotals.cc >= 0 ? "+" : ""}${rewardsDiffTotals.cc.toFixed(2)} CC`
        : "?";
      const totalDiffUsd = Number.isFinite(rewardsDiffTotals.usd)
        ? `${rewardsDiffTotals.usd >= 0 ? "+" : ""}$${rewardsDiffTotals.usd.toFixed(2)}`
        : "?";
      lines.push(`📈 Session Earn <code>${this.escapeTelegramCode(totalDiffCc)}</code> | <code>${this.escapeTelegramCode(totalDiffUsd)}</code>`);
    }

    return lines;
  }

  buildTelegramAccountBlockHtml(row) {
    const name = String(row && row.name ? row.name : "-").trim() || "-";
    const status = String(row && row.status ? row.status : "-").trim() || "-";
    const cc = String(row && row.cc ? row.cc : "-").trim() || "-";
    const progress = String(row && row.progress ? row.progress : "-").trim() || "-";
    const send = String(row && row.send ? row.send : "-").trim() || "-";
    const lines = [
      `🔹 <b>${escapeHtml(name)}</b> [${escapeHtml(status)}]`,
      `<code>CC ${this.escapeTelegramCode(cc)} | TX ${this.escapeTelegramCode(progress)}</code>`
    ];

    if (send && send !== "-") {
      lines.push(`📤 ${escapeHtml(this.clip(send, 96))}`);
    }

    const rewardsThisWeek = String(row && row.rewardsThisWeek ? row.rewardsThisWeek : "-").trim() || "-";
    const rewardsDiff = String(row && row.rewardsDiff ? row.rewardsDiff : "-").trim() || "-";
    if ((rewardsThisWeek && rewardsThisWeek !== "-") || (rewardsDiff && rewardsDiff !== "-")) {
      const weekDiffParts = [];
      if (rewardsThisWeek && rewardsThisWeek !== "-") {
        weekDiffParts.push(`Week <code>${this.escapeTelegramCode(rewardsThisWeek)}</code>`);
      }
      if (rewardsDiff && rewardsDiff !== "-") {
        weekDiffParts.push(`Diff <code>${this.escapeTelegramCode(rewardsDiff)}</code>`);
      }
      lines.push(`💵 ${weekDiffParts.join(" | ")}`);
    }

    const rewardParts = [];
    if (row && row.rewardTier && row.rewardTier !== "-") {
      rewardParts.push(`Tier ${row.rewardTier}`);
    }
    if (row && row.rewardQuality && row.rewardQuality !== "-") {
      rewardParts.push(`Q <code>${this.escapeTelegramCode(row.rewardQuality)}</code>`);
    }
    if (row && row.rewardTodayPoints && row.rewardTodayPoints !== "-") {
      rewardParts.push(`Today <code>${this.escapeTelegramCode(row.rewardTodayPoints)}</code>`);
    }
    if (rewardParts.length > 0) {
      lines.push(`🏆 ${rewardParts.join(" | ")}`);
    }

    const rewardMetaParts = [];
    if (row && row.rewardVolume && row.rewardVolume !== "-") {
      rewardMetaParts.push(`Vol <code>${this.escapeTelegramCode(row.rewardVolume)}</code>`);
    }
    if (row && row.rewardDailyCheckin && row.rewardDailyCheckin !== "-") {
      rewardMetaParts.push(`Check-in <code>${this.escapeTelegramCode(row.rewardDailyCheckin)}</code>`);
    }
    if (rewardMetaParts.length > 0) {
      lines.push(`📈 ${rewardMetaParts.join(" | ")}`);
    }

    return lines;
  }

  getTelegramSnapshotHtml(options = {}) {
    const rows = this.parseAccountRows();
    const accountLimit = Math.max(
      1,
      clampToNonNegativeInt(options.accountLimit, rows.length || INTERNAL_API_DEFAULTS.telegram.accountsPerUpdate)
    );
    const logLimit = Math.max(
      1,
      clampToNonNegativeInt(options.logLimit, this.logs.length || INTERNAL_API_DEFAULTS.telegram.logsPerUpdate)
    );

    const lines = [...this.buildTelegramHeaderHtml({ accountLimit })];
    lines.push("");

    if (rows.length === 0) {
      lines.push("🔹 <i>(no account rows yet)</i>");
    } else {
      for (const row of rows.slice(0, accountLimit)) {
        lines.push(...this.buildTelegramAccountBlockHtml(row));
        lines.push("");
      }
      if (rows.length > accountLimit) {
        lines.push(`➕ <i>${rows.length - accountLimit} akun lainnya</i>`);
      }
    }

    while (lines.length > 0 && !String(lines[lines.length - 1]).trim()) {
      lines.pop();
    }

    const logLines = [];
    if (this.logs.length === 0) {
      logLines.push("- [--:--:--] INFO (no logs yet)");
    } else {
      for (const log of this.logs.slice(-logLimit)) {
        logLines.push(`- ${log.time} ${log.level} ${this.clip(log.message, 96)}`);
      }
    }

    lines.push("");
    lines.push(`📜 <b>Latest Logs</b> <code>${this.escapeTelegramCode(`${Math.min(this.logs.length, logLimit)}/${this.logs.length}`)}</code>`);
    lines.push(`<pre>${escapeHtml(logLines.join("\n"))}</pre>`);
    return lines.join("\n");
  }

  getTelegramSnapshot(options = {}) {
    const now = getJakartaTimeStamp();
    const rows = this.parseAccountRows();
    const accountLimit = Math.max(
      1,
      clampToNonNegativeInt(options.accountLimit, rows.length || INTERNAL_API_DEFAULTS.telegram.accountsPerUpdate)
    );
    const logLimit = Math.max(
      1,
      clampToNonNegativeInt(options.logLimit, this.logs.length || INTERNAL_API_DEFAULTS.telegram.logsPerUpdate)
    );
    const modeLabel = String(this.state.mode || "-").toUpperCase();
    const selectedAccount = this.parseSelectedAccountName() || "-";
    const txStats = getGlobalTxStatsSnapshot();
    const txProgressLabel = `${txStats.total}/${txStats.total}`;
    const rewardsTotals = getTotalRewardsThisWeek();
    const rewardsDiffTotals = getTotalRewardsDiff();
    const aggregateBalance = this.getAggregateCcBalanceSummary(rows);
    const shownAccountCount = Math.min(rows.length, accountLimit);

    const lines = [
      `Time  ${now} WIB`,
      `Run   ${modeLabel} | ${this.state.phase}`,
      `Acct  ${selectedAccount} | ${shownAccountCount}/${rows.length || 0} shown`,
      `TX    ${txProgressLabel} | ok ${txStats.ok} | fail ${txStats.fail} | target ${this.state.targetPerDay}/hour`
    ];

    if (Number.isFinite(aggregateBalance.total)) {
      lines.push(`Total CC ${aggregateBalance.total.toFixed(4)} | acct ${aggregateBalance.count}`);
    }

    const selectedRewardLines = this.buildTelegramSelectedRewardsLines();
    if (selectedRewardLines.length > 0) {
      lines.push(...selectedRewardLines);
    }
    if (Number.isFinite(rewardsTotals.cc) || Number.isFinite(rewardsTotals.usd)) {
      const totalCcLabel = Number.isFinite(rewardsTotals.cc) ? `${rewardsTotals.cc.toFixed(2)} CC` : "?";
      const totalUsdLabel = Number.isFinite(rewardsTotals.usd) ? `$${rewardsTotals.usd.toFixed(2)}` : "?";
      lines.push(`Week Total ${totalCcLabel} | ${totalUsdLabel}`);
    }
    if (Number.isFinite(rewardsDiffTotals.cc) || Number.isFinite(rewardsDiffTotals.usd)) {
      const totalDiffCc = Number.isFinite(rewardsDiffTotals.cc)
        ? `${rewardsDiffTotals.cc >= 0 ? "+" : ""}${rewardsDiffTotals.cc.toFixed(2)} CC`
        : "?";
      const totalDiffUsd = Number.isFinite(rewardsDiffTotals.usd)
        ? `${rewardsDiffTotals.usd >= 0 ? "+" : ""}$${rewardsDiffTotals.usd.toFixed(2)}`
        : "?";
      lines.push(`Session Earn ${totalDiffCc} | ${totalDiffUsd}`);
    }

    lines.push(
      ""
    );

    if (rows.length === 0) {
      lines.push("- (no account rows yet)");
    } else {
      for (const row of rows.slice(0, accountLimit)) {
        lines.push(...this.buildTelegramAccountBlock(row));
        lines.push("");
      }
      if (rows.length > accountLimit) {
        lines.push(`- ... ${rows.length - accountLimit} akun lainnya`);
      }
    }

    if (lines[lines.length - 1] === "") {
      lines.pop();
    }

    lines.push("");
    lines.push(`Latest Logs (${Math.min(this.logs.length, logLimit)}/${this.logs.length})`);
    if (this.logs.length === 0) {
      lines.push("- [--:--:--] INFO (no logs yet)");
    } else {
      for (const log of this.logs.slice(-logLimit)) {
        lines.push(`- ${log.time} ${log.level} ${this.clip(log.message, 96)}`);
      }
    }

    return lines.join("\n");
  }

  render() {
    if (this.terminalEnabled) {
      const now = getJakartaTimeStamp();
      const rows = this.parseAccountRows();
      const accountCount = rows.length;
      const terminalWidth = Number(process.stdout.columns || 132);
      const frameWidth = Math.max(118, Math.min(170, terminalWidth));
      const contentWidth = frameWidth - 4;
      const modeLabel = String(this.state.mode || "-").toUpperCase();
      const txStats = getGlobalTxStatsSnapshot();
      const aggregateBalance = this.getAggregateCcBalanceSummary(rows);
      const topBorder = `+${"=".repeat(frameWidth - 2)}+`;
      const midBorder = `+${"-".repeat(frameWidth - 2)}+`;
      const bannerLine = (text) => `| ${this.formatCell(text, contentWidth)} |`;

      const columnCount = 7;
      const separatorWidth = 3 * (columnCount - 1);
      const accountWidth = 12;
      const statusWidth = 8;
      const ccWidth = 10;
      const txProgressWidth = 16;
      const diffWidth = 22;
      const rewardWidth = 34;
      const sendPlanWidth = Math.max(
        18,
        contentWidth - separatorWidth - (accountWidth + statusWidth + ccWidth + txProgressWidth + rewardWidth + diffWidth)
      );
      const tableWidths = [accountWidth, statusWidth, ccWidth, txProgressWidth, sendPlanWidth, rewardWidth, diffWidth];
      const tableRow = (cells) => `| ${cells.map((cell, idx) => this.formatCell(cell, tableWidths[idx])).join(" | ")} |`;
      const tableRule = (char) => `| ${tableWidths.map((width) => char.repeat(width)).join(" | ")} |`;
      const rewardsTotals = getTotalRewardsThisWeek();
      const rewardsDiffTotals = getTotalRewardsDiff();

      const lines = [];
      lines.push(topBorder);
      lines.push(
        bannerLine(
          `RootFiBot Auto-Send V1  |  ${now} WIB  |  ${accountCount} akun  |  Mode: ${modeLabel}`
        )
      );
      lines.push(
        bannerLine(
          `Sends: ${txStats.total}/${txStats.total} total  ${txStats.ok} ok  ${txStats.fail} fail  |  Target: ${this.state.targetPerDay}/hour`
        )
      );
      if (Number.isFinite(aggregateBalance.total)) {
        lines.push(
          bannerLine(
            `Total balance (all accounts): ${aggregateBalance.total.toFixed(4)} CC  |  Accounts with balance: ${aggregateBalance.count}/${accountCount}`
          )
        );
      }
      if (Number.isFinite(rewardsTotals.cc) || Number.isFinite(rewardsTotals.usd)) {
        const totalCcLabel = Number.isFinite(rewardsTotals.cc) ? `${rewardsTotals.cc.toFixed(2)} CC` : "?";
        const totalUsdLabel = Number.isFinite(rewardsTotals.usd) ? `$${rewardsTotals.usd.toFixed(2)}` : "?";
        lines.push(
          bannerLine(
            `Rewards this week (all accounts): ${totalCcLabel}  |  ${totalUsdLabel}`
          )
        );
      }
      if (Number.isFinite(rewardsDiffTotals.cc) || Number.isFinite(rewardsDiffTotals.usd)) {
        const totalDiffCc = Number.isFinite(rewardsDiffTotals.cc)
          ? `${rewardsDiffTotals.cc >= 0 ? "+" : ""}${rewardsDiffTotals.cc.toFixed(2)} CC`
          : "?";
        const totalDiffUsd = Number.isFinite(rewardsDiffTotals.usd)
          ? `${rewardsDiffTotals.usd >= 0 ? "+" : ""}$${rewardsDiffTotals.usd.toFixed(2)}`
          : "?";
        lines.push(
          bannerLine(
            `Session earnings (all accounts): ${totalDiffCc}  |  ${totalDiffUsd}`
          )
        );
      }
      lines.push(
        bannerLine(
          `State: ${this.state.phase}`
        )
      );
      lines.push(midBorder);
      lines.push(tableRow(["Akun", "Status", "CC", "TX Progress", "Send Plan", "Rewards / Score / Tier", "Diff Reward"]));
      lines.push(tableRule("-"));

      if (rows.length === 0) {
        lines.push(tableRow(["-", "IDLE", "-", "-", "-", "-", "-"]));
      } else {
        for (const row of rows) {
          const progressLabel = String(row.progress || "-");
          const sendLabel = String(row.send || "-");
          const rewardLabel = String(row.rewardSummary || "-");
          const diffLabel = String(row.rewardsDiff || "-");
          lines.push(tableRow([row.name, row.status, row.cc, progressLabel, sendLabel, rewardLabel, diffLabel]));
        }
      }

      lines.push(midBorder);
      lines.push("");
      lines.push(`--- Execution Logs (last ${this.logLines}) ---`);

      if (this.logs.length === 0) {
        lines.push("[--:--:--] INFO  (no logs yet)");
      } else {
        const logMessageWidth = Math.max(48, frameWidth - 24);
        for (const log of this.logs) {
          lines.push(`[${log.time}] ${log.level.padEnd(5)} ${this.clip(log.message, logMessageWidth)}`);
        }
      }

      lines.push("");
      lines.push("Ctrl+C to stop  |  Round delay: config.send.delayCycleSeconds");

      process.stdout.write(`\x1b[2J\x1b[H${lines.join("\n")}\n`);
    }

    if (this.reporter) {
      this.reporter.scheduleFromDashboard(this);
    }
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clampToNonNegativeInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function randomIntInclusive(min, max) {
  const lo = Math.ceil(min);
  const hi = Math.floor(max);
  return Math.floor(Math.random() * (hi - lo + 1)) + lo;
}

function humanLikeDelay(minSec, maxSec) {
  const range = maxSec - minSec;
  if (range <= 0) {
    return Math.round(minSec);
  }
  const r1 = Math.random();
  const r2 = Math.random();
  const centered = (r1 + r2) / 2;
  return Math.round(minSec + (centered * range));
}

function shuffleArray(items) {
  const array = Array.isArray(items) ? [...items] : [];
  for (let i = array.length - 1; i > 0; i -= 1) {
    const j = randomIntInclusive(0, i);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
  return array;
}

function withAccountTag(accountLogTag, message) {
  if (!accountLogTag) {
    return message;
  }
  return `[${accountLogTag}] ${message}`;
}

function maskSecret(value, head = 4, tail = 4) {
  const text = String(value || "");
  if (!text) {
    return "<empty>";
  }
  if (text.length <= head + tail) {
    return "*".repeat(text.length);
  }
  return `${text.slice(0, head)}...${text.slice(-tail)}`;
}

function maskEmail(email) {
  const value = String(email || "").trim();
  if (!value.includes("@")) {
    return maskSecret(value, 2, 2);
  }

  const [local, domain] = value.split("@");
  const localMasked = local.length <= 2 ? `${local[0] || "*"}*` : `${local.slice(0, 2)}***${local.slice(-1)}`;
  return `${localMasked}@${domain}`;
}

function parseArgs(argv) {
  const args = {
    configFile: DEFAULT_CONFIG_FILE,
    accountsFile: DEFAULT_ACCOUNTS_FILE,
    tokensFile: DEFAULT_TOKENS_FILE,
    accountName: null,
    sendCcAmount: null,
    sendTo: null,
    sendIdempotencyKey: null,
    dryRun: false,
    noDashboard: false,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];

    if (token === "-h" || token === "--help") {
      args.help = true;
      continue;
    }

    if (token === "--dry-run") {
      args.dryRun = true;
      continue;
    }

    if (token === "--no-dashboard") {
      args.noDashboard = true;
      continue;
    }

    if (token.startsWith("--config=")) {
      args.configFile = token.slice("--config=".length).trim();
      continue;
    }

    if (token === "--config") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --config");
      }
      args.configFile = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--accounts=")) {
      args.accountsFile = token.slice("--accounts=".length).trim();
      continue;
    }

    if (token === "--accounts") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --accounts");
      }
      args.accountsFile = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--tokens=")) {
      args.tokensFile = token.slice("--tokens=".length).trim();
      continue;
    }

    if (token === "--tokens") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --tokens");
      }
      args.tokensFile = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--account=")) {
      args.accountName = token.slice("--account=".length).trim();
      continue;
    }

    if (token === "--account") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --account");
      }
      args.accountName = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--send-cc=")) {
      args.sendCcAmount = token.slice("--send-cc=".length).trim();
      continue;
    }

    if (token === "--send-cc") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --send-cc");
      }
      args.sendCcAmount = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--send-to=")) {
      args.sendTo = token.slice("--send-to=".length).trim();
      continue;
    }

    if (token === "--send-to") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --send-to");
      }
      args.sendTo = argv[i + 1].trim();
      i += 1;
      continue;
    }

    if (token.startsWith("--send-idempotency-key=")) {
      args.sendIdempotencyKey = token.slice("--send-idempotency-key=".length).trim();
      continue;
    }

    if (token === "--send-idempotency-key") {
      if (!argv[i + 1]) {
        throw new Error("Missing value for --send-idempotency-key");
      }
      args.sendIdempotencyKey = argv[i + 1].trim();
      i += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  return args;
}

function printHelp() {
  console.log(`RootsFi API Login + Balance Bot (API-only)

Usage:
  node index.js [options]

Options:
  --config <path>      Config file (default: config.json)
  --accounts <path>    Accounts file (default: accounts.json)
  --tokens <path>      Generated token storage (default: tokens.json)
  --account <name>     Account name from accounts.json
  --send-cc <amount>   Send CC amount (example: 10.25)
  --send-to <target>   Recipient alias or canton address
  --send-idempotency-key <key>
                       Optional idempotency key for transfer request
  --no-dashboard       Disable pinned dashboard UI
  --dry-run            Validate files and print summary only
  -h, --help           Show this help

Environment overrides:
  ROOTSFI_EMAIL        Override email from accounts.json
  ROOTSFI_NO_DASHBOARD Set to 1 to disable dashboard
  ROOTSFI_SEND_CC      Send CC amount
  ROOTSFI_SEND_TO      Recipient alias or canton address
  ROOTSFI_SEND_IDEMPOTENCY_KEY
                       Transfer idempotency key override
`);
}

async function readJson(filePath, label) {
  let text;
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error(`${label} file not found: ${filePath}`);
    }
    throw error;
  }

  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid JSON in ${label} file ${filePath}: ${error.message}`);
  }
}

async function readOptionalJson(filePath, label) {
  try {
    const text = await fs.readFile(filePath, "utf8");
    return JSON.parse(text);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON in ${label} file ${filePath}: ${error.message}`);
    }
    throw error;
  }
}

function sortObjectKeys(input) {
  const output = {};
  for (const key of Object.keys(isObject(input) ? input : {}).sort()) {
    output[key] = input[key];
  }
  return output;
}

function normalizeWalleyAccountRefs(rawAccounts) {
  if (!Array.isArray(rawAccounts)) {
    return [];
  }

  return rawAccounts
    .map((entry) => {
      const name = String(entry && entry.name ? entry.name : "").trim();
      const partyHint = String(entry && entry.partyHint ? entry.partyHint : "").trim();
      if (!name || !partyHint) {
        return null;
      }
      return { name, partyHint };
    })
    .filter(Boolean);
}

async function syncWalleyRefundSenderMap(configPath, rawConfig) {
  if (!isObject(rawConfig)) {
    return rawConfig;
  }

  const walleyRefundInput = isObject(rawConfig.walleyRefund) ? rawConfig.walleyRefund : {};
  const walleyRefundEnabled =
    typeof walleyRefundInput.enabled === "boolean"
      ? walleyRefundInput.enabled
      : INTERNAL_API_DEFAULTS.walleyRefund.enabled;
  const autoSyncSenderMap =
    typeof walleyRefundInput.autoSyncSenderMap === "boolean"
      ? walleyRefundInput.autoSyncSenderMap
      : INTERNAL_API_DEFAULTS.walleyRefund.autoSyncSenderMap;

  if (!walleyRefundEnabled || !autoSyncSenderMap) {
    return rawConfig;
  }

  const walleyProjectDir = path.resolve(
    process.cwd(),
    String(walleyRefundInput.projectDir || INTERNAL_API_DEFAULTS.walleyRefund.projectDir).trim()
  );
  const walleyAccountsPath = path.resolve(walleyProjectDir, DEFAULT_ACCOUNTS_FILE);

  let rawWalleyAccounts;
  try {
    rawWalleyAccounts = await readJson(walleyAccountsPath, "walley accounts");
  } catch (error) {
    console.warn(
      `[walley-refund] Auto-sync senderMap skipped: ${error && error.message ? error.message : String(error)}`
    );
    return rawConfig;
  }

  const walleyAccounts = normalizeWalleyAccountRefs(rawWalleyAccounts);
  if (walleyAccounts.length === 0) {
    console.warn("[walley-refund] Auto-sync senderMap skipped: walley/accounts.json has no valid accounts");
    return rawConfig;
  }

  const recipientFile = String(rawConfig.recipientFile || "recipient.txt").trim() || "recipient.txt";
  let recipientsInfo = {
    recipients: [],
    missing: true
  };
  try {
    recipientsInfo = await loadRecipients(recipientFile);
  } catch (error) {
    console.warn(
      `[walley-refund] Auto-sync senderMap could not read recipient file: ${error && error.message ? error.message : String(error)}`
    );
  }

  const validTargetRefs = new Map();
  for (const account of walleyAccounts) {
    validTargetRefs.set(account.name, account.name);
    validTargetRefs.set(account.partyHint, account.name);
  }

  const nextSenderMap = {};
  const existingSenderMap = isObject(walleyRefundInput.senderMap) ? walleyRefundInput.senderMap : {};
  for (const [rawKey, rawValue] of Object.entries(existingSenderMap)) {
    const key = String(rawKey || "").trim();
    const value = String(rawValue || "").trim();
    const canonicalTarget = validTargetRefs.get(value);
    if (key && canonicalTarget) {
      nextSenderMap[key] = canonicalTarget;
    }
  }

  for (const account of walleyAccounts) {
    nextSenderMap[account.partyHint] = account.name;
  }

  for (const recipient of Array.isArray(recipientsInfo.recipients) ? recipientsInfo.recipients : []) {
    const alias = String(recipient && recipient.alias ? recipient.alias : "").trim();
    const partyId = String(recipient && recipient.partyId ? recipient.partyId : "").trim();
    const canonicalTarget = validTargetRefs.get(alias);
    if (!canonicalTarget) {
      continue;
    }
    nextSenderMap[alias] = canonicalTarget;
    if (partyId) {
      nextSenderMap[partyId] = canonicalTarget;
    }
  }

  const sortedSenderMap = sortObjectKeys(nextSenderMap);
  const previousSenderMapText = JSON.stringify(sortObjectKeys(existingSenderMap));
  const nextSenderMapText = JSON.stringify(sortedSenderMap);
  if (previousSenderMapText === nextSenderMapText) {
    return rawConfig;
  }

  const updatedRawConfig = {
    ...rawConfig,
    walleyRefund: {
      ...walleyRefundInput,
      autoSyncSenderMap,
      senderMap: sortedSenderMap
    }
  };

  await fs.writeFile(configPath, JSON.stringify(updatedRawConfig, null, 2), "utf8");
  console.log(
    `[init] Auto-synced walleyRefund.senderMap: ${Object.keys(sortedSenderMap).length} entries from ${walleyAccountsPath}`
  );
  return updatedRawConfig;
}

function generateBrowserHeaderProfile(deviceId) {
  const chromeMajor = randomIntInclusive(143, 146);

  return {
    userAgent:
      `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ` +
      `(KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 Safari/537.36`,
    acceptLanguage: INTERNAL_API_DEFAULTS.headers.acceptLanguage,
    sendBrowserClientHints: true,
    secChUa: `"Chromium";v="${chromeMajor}", "Not-A.Brand";v="24", "Google Chrome";v="${chromeMajor}"`,
    secChUaMobile: INTERNAL_API_DEFAULTS.headers.secChUaMobile,
    secChUaPlatform: INTERNAL_API_DEFAULTS.headers.secChUaPlatform,
    secFetchDest: INTERNAL_API_DEFAULTS.headers.secFetchDest,
    secFetchMode: INTERNAL_API_DEFAULTS.headers.secFetchMode,
    secFetchSite: INTERNAL_API_DEFAULTS.headers.secFetchSite,
    priority: INTERNAL_API_DEFAULTS.headers.priority,
    extra: {
      "x-device-id": deviceId
    }
  };
}

function normalizeTokenProfile(rawProfile) {
  const input = isObject(rawProfile) ? rawProfile : {};
  const deviceId = String(input.deviceId || crypto.randomUUID()).trim() || crypto.randomUUID();
  const generatedHeaders = generateBrowserHeaderProfile(deviceId);
  const headersInput = isObject(input.headers) ? input.headers : {};
  const securityInput = isObject(input.security) ? input.security : {};
  const now = new Date().toISOString();

  return {
    cookie: String(input.cookie || "").trim(),
    deviceId,
    headers: {
      ...generatedHeaders,
      ...headersInput,
      extra: {
        ...generatedHeaders.extra,
        ...(isObject(headersInput.extra) ? headersInput.extra : {}),
        "x-device-id": deviceId
      }
    },
    security: {
      strategy: "browser-challenge-cookie-reuse",
      antiBotNonce: String(securityInput.antiBotNonce || crypto.randomBytes(16).toString("hex")),
      createdAt: String(securityInput.createdAt || now),
      updatedAt: String(securityInput.updatedAt || now),
      lastVercelRefreshAt: String(securityInput.lastVercelRefreshAt || "").trim(),
      hasSecurityCookie: Boolean(securityInput.hasSecurityCookie),
      hasSessionCookie: Boolean(securityInput.hasSessionCookie),
      checkpointRefreshCount: clampToNonNegativeInt(
        securityInput.checkpointRefreshCount,
        0
      )
    }
  };
}

function normalizeTokens(rawTokens, accountsConfig) {
  const raw = isObject(rawTokens) ? rawTokens : {};
  const rawAccounts = isObject(raw.accounts) ? raw.accounts : {};
  const rawDailyProgress = isObject(raw.dailyProgress) ? raw.dailyProgress : {};
  const accountMap = {};

  for (const account of accountsConfig.accounts) {
    accountMap[account.name] = normalizeTokenProfile(rawAccounts[account.name]);
  }

  for (const [accountName, profile] of Object.entries(rawAccounts)) {
    if (!Object.prototype.hasOwnProperty.call(accountMap, accountName)) {
      accountMap[accountName] = normalizeTokenProfile(profile);
    }
  }

  return {
    version: 1,
    updatedAt: String(raw.updatedAt || new Date().toISOString()),
    accounts: accountMap,
    dailyProgress: {
      date: String(rawDailyProgress.date || "").trim(),
      completedTxTotal: clampToNonNegativeInt(rawDailyProgress.completedTxTotal, 0),
      perAccount: isObject(rawDailyProgress.perAccount) ? { ...rawDailyProgress.perAccount } : {}
    }
  };
}

function applyTokenProfileToConfig(config, profile) {
  const tokenHeaders = isObject(profile.headers) ? profile.headers : {};

  config.headers = {
    ...config.headers,
    ...tokenHeaders,
    extra: {
      ...(isObject(tokenHeaders.extra) ? tokenHeaders.extra : {}),
      "x-device-id": profile.deviceId
    },
    cookie: String(profile.cookie || "").trim()
  };
}

function applyClientStateToTokenProfile(profile, client, checkpointRefreshCount, lastVercelRefreshAt) {
  const nextProfile = normalizeTokenProfile(profile);
  const now = new Date().toISOString();
  const currentCookie = client.getCookieHeader();

  if (currentCookie) {
    nextProfile.cookie = currentCookie;
  }

  nextProfile.headers.extra = {
    ...(isObject(nextProfile.headers.extra) ? nextProfile.headers.extra : {}),
    "x-device-id": nextProfile.deviceId
  };

  nextProfile.security = {
    ...nextProfile.security,
    updatedAt: now,
    lastVercelRefreshAt:
      String(lastVercelRefreshAt || nextProfile.security.lastVercelRefreshAt || "").trim(),
    hasSecurityCookie: client.hasSecurityCookie(),
    hasSessionCookie: client.hasAccountSessionCookie(),
    checkpointRefreshCount:
      clampToNonNegativeInt(nextProfile.security.checkpointRefreshCount, 0) +
      clampToNonNegativeInt(checkpointRefreshCount, 0)
  };

  return nextProfile;
}

async function saveTokens(tokensPath, tokensState) {
  const payload = {
    ...tokensState,
    version: 1,
    updatedAt: new Date().toISOString()
  };

  await fs.writeFile(tokensPath, JSON.stringify(payload, null, 2), "utf8");
}

let tokensSaveQueue = Promise.resolve();

async function saveTokensSerial(tokensPath, tokensState) {
  tokensSaveQueue = tokensSaveQueue.then(() => saveTokens(tokensPath, tokensState));
  return tokensSaveQueue;
}

function loadDailyProgress(tokensState) {
  const raw = isObject(tokensState && tokensState.dailyProgress) ? tokensState.dailyProgress : {};
  const currentDay = getCurrentUTCDayKey();
  if (String(raw.date || "").trim() !== currentDay) {
    return {
      date: currentDay,
      completedTxTotal: 0,
      perAccount: {}
    };
  }

  return {
    date: currentDay,
    completedTxTotal: clampToNonNegativeInt(raw.completedTxTotal, 0),
    perAccount: isObject(raw.perAccount) ? { ...raw.perAccount } : {}
  };
}

function saveDailyProgress(tokensState) {
  if (!isObject(tokensState)) {
    return;
  }

  const perAccount = {};
  for (const [accountName, stats] of Object.entries(perAccountTxStats)) {
    perAccount[accountName] = {
      total: clampToNonNegativeInt(stats && stats.total, 0),
      ok: clampToNonNegativeInt(stats && stats.ok, 0),
      fail: clampToNonNegativeInt(stats && stats.fail, 0)
    };
  }

  tokensState.dailyProgress = {
    date: getCurrentUTCDayKey(),
    completedTxTotal: clampToNonNegativeInt(globalSwapsTotal, 0),
    perAccount
  };
}

function hydrateDailyProgressIntoRuntime(progressState) {
  const progress = isObject(progressState) ? progressState : {};
  txStatsUtcDayKey = getCurrentUTCDayKey();
  globalSwapsTotal = clampToNonNegativeInt(progress.completedTxTotal, 0);
  globalSwapsOk = 0;
  globalSwapsFail = 0;

  for (const key of Object.keys(perAccountTxStats)) {
    delete perAccountTxStats[key];
  }

  const perAccount = isObject(progress.perAccount) ? progress.perAccount : {};
  for (const [accountName, stats] of Object.entries(perAccount)) {
    perAccountTxStats[accountName] = {
      total: clampToNonNegativeInt(stats && stats.total, 0),
      ok: clampToNonNegativeInt(stats && stats.ok, 0),
      fail: clampToNonNegativeInt(stats && stats.fail, 0)
    };
    globalSwapsOk += perAccountTxStats[accountName].ok;
    globalSwapsFail += perAccountTxStats[accountName].fail;
  }

  if (globalSwapsTotal < (globalSwapsOk + globalSwapsFail)) {
    globalSwapsTotal = globalSwapsOk + globalSwapsFail;
  }
}

function cloneRuntimeConfig(config) {
  const sessionConfig = {
    ...INTERNAL_API_DEFAULTS.session,
    ...(isObject(config && config.session) ? config.session : {})
  };
  return {
    ...config,
    paths: { ...config.paths },
    headers: {
      ...config.headers,
      extra: {
        ...(isObject(config.headers && config.headers.extra) ? config.headers.extra : {})
      }
    },
    http: { ...config.http },
    requestPacing: { ...config.requestPacing },
    session: sessionConfig,
    send: {
      ...config.send,
      tierAmounts: {
        ...(isObject(config.send && config.send.tierAmounts) ? config.send.tierAmounts : {})
      },
      tierDailyTxCap: {
        ...(isObject(config.send && config.send.tierDailyTxCap) ? config.send.tierDailyTxCap : {})
      },
      randomAmount: {
        ...(isObject(config.send && config.send.randomAmount) ? config.send.randomAmount : {})
      }
    },
    ui: { ...config.ui },
    safety: { ...(isObject(config.safety) ? config.safety : {}) }
  };
}

async function loadRecipients(relativePath) {
  const absolutePath = path.resolve(process.cwd(), relativePath);
  let text;

  try {
    text = await fs.readFile(absolutePath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return {
        absolutePath,
        missing: true,
        recipients: [],
        invalidLines: []
      };
    }
    throw error;
  }

  const recipients = [];
  const invalidLines = [];
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index].trim();
    if (!raw || raw.startsWith("#")) {
      continue;
    }

    const sepIndex = raw.indexOf("::");
    if (sepIndex <= 0 || sepIndex >= raw.length - 2) {
      invalidLines.push({ line: index + 1, value: raw });
      continue;
    }

    const alias = raw.slice(0, sepIndex).trim();
    const address = raw.slice(sepIndex + 2).trim();

    if (!alias || !address) {
      invalidLines.push({ line: index + 1, value: raw });
      continue;
    }

    recipients.push({ alias, address, partyId: `${alias}::${address}` });
  }

  return {
    absolutePath,
    missing: false,
    recipients,
    invalidLines
  };
}

function getRandomRecipient(recipients) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("No recipients available for random selection");
  }
  const index = randomIntInclusive(0, recipients.length - 1);
  return recipients[index];
}

async function promptSendMode() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    console.log("\n=== RootsFi Bot - Send Mode ===");
    console.log("1. External Address (random dari recipient.txt)");
    console.log("2. Internal Address (ke address masing-masing akun)");
    console.log("3. Balance Only (cek saldo saja)");
    console.log("4. Hybrid Strategy (kadang internal, kadang external)");
    console.log("");

    const answer = await rl.question("Pilih mode [1/2/3/4]: ");
    const choice = answer.trim();

    if (choice === "1") {
      return "external";
    } else if (choice === "2") {
      return "internal";
    } else if (choice === "3") {
      return "balance-only";
    } else if (choice === "4") {
      return "hybrid";
    } else {
      console.log("[warn] Pilihan tidak valid, default ke balance-only");
      return "balance-only";
    }
  } finally {
    rl.close();
  }
}

async function promptAccountSelection(accounts) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    console.log("\n=== Pilih Akun untuk TX ===");
    console.log("0. Semua akun");
    
    for (let i = 0; i < accounts.length; i++) {
      console.log(`${i + 1}. ${accounts[i].name} (${maskEmail(accounts[i].email)})`);
    }
    console.log("");

    const answer = await rl.question(`Pilih akun [0-${accounts.length}]: `);
    const choice = answer.trim();

    if (choice === "0" || choice === "") {
      return { mode: "all", selectedAccounts: accounts };
    }

    // Check if multiple accounts selected (comma separated)
    if (choice.includes(",")) {
      const indices = choice.split(",").map(s => parseInt(s.trim(), 10));
      const selectedAccounts = [];
      
      for (const idx of indices) {
        if (idx >= 1 && idx <= accounts.length) {
          selectedAccounts.push(accounts[idx - 1]);
        }
      }

      if (selectedAccounts.length === 0) {
        console.log("[warn] Tidak ada akun valid dipilih, menggunakan semua akun");
        return { mode: "all", selectedAccounts: accounts };
      }

      return { mode: "selected", selectedAccounts };
    }

    // Single account selected
    const idx = parseInt(choice, 10);
    if (idx >= 1 && idx <= accounts.length) {
      return { mode: "single", selectedAccounts: [accounts[idx - 1]] };
    }

    console.log("[warn] Pilihan tidak valid, menggunakan semua akun");
    return { mode: "all", selectedAccounts: accounts };
  } finally {
    rl.close();
  }
}

function normalizeCcAmount(rawAmount) {
  const text = String(rawAmount || "").trim();
  if (!text) {
    throw new Error("CC amount is required");
  }

  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new Error(`Invalid CC amount format: ${text}`);
  }

  const numeric = Number(text);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`CC amount must be greater than zero: ${text}`);
  }

  return text;
}

const TIER_KEYS = ["unranked", "newbie", "advanced", "pro", "elite"];
const tierDisplayNameByAccount = new Map();
const tierMinSendByAccount = new Map();

function resolveTierKey(tierDisplayName) {
  const key = String(tierDisplayName || "").trim().toLowerCase();
  return TIER_KEYS.includes(key) ? key : "unranked";
}

function getAccountTierKey(accountName) {
  const normalizedName = String(accountName || "").trim();
  if (!normalizedName) {
    return "unranked";
  }
  return resolveTierKey(tierDisplayNameByAccount.get(normalizedName));
}

function getAccountTierMinSend(accountName) {
  const normalizedName = String(accountName || "").trim();
  if (!normalizedName) {
    return 0;
  }
  const numeric = Number(tierMinSendByAccount.get(normalizedName));
  return Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
}

function normalizeRandomAmountConfig(rawRandomAmount, fallback, pathLabel) {
  const base = isObject(fallback) ? fallback : INTERNAL_API_DEFAULTS.send.randomAmount;
  const input = isObject(rawRandomAmount) ? rawRandomAmount : {};

  const enabled =
    typeof input.enabled === "boolean"
      ? input.enabled
      : Boolean(base.enabled);

  const min = normalizeCcAmount(
    Object.prototype.hasOwnProperty.call(input, "min") ? input.min : base.min
  );
  const max = normalizeCcAmount(
    Object.prototype.hasOwnProperty.call(input, "max") ? input.max : base.max
  );
  const decimals = clampToNonNegativeInt(
    input.decimals,
    clampToNonNegativeInt(base.decimals, 2)
  );

  if (decimals > 8) {
    throw new Error(`${pathLabel}.decimals must be <= 8`);
  }

  if (Number(min) > Number(max)) {
    throw new Error(`${pathLabel}.min must be <= ${pathLabel}.max`);
  }

  return {
    enabled,
    min,
    max,
    decimals
  };
}

function normalizeTierAmountsConfig(rawTierAmounts, fallback, pathLabel) {
  const defaults = isObject(fallback) ? fallback : INTERNAL_API_DEFAULTS.send.tierAmounts;
  const input = isObject(rawTierAmounts) ? rawTierAmounts : {};
  const result = {};

  for (const key of TIER_KEYS) {
    const tierInput = isObject(input[key]) ? input[key] : {};
    const tierDefault = isObject(defaults[key]) ? defaults[key] : defaults.unranked;
    const min = normalizeCcAmount(
      Object.prototype.hasOwnProperty.call(tierInput, "min") ? tierInput.min : tierDefault.min
    );
    const max = normalizeCcAmount(
      Object.prototype.hasOwnProperty.call(tierInput, "max") ? tierInput.max : tierDefault.max
    );
    const decimals = clampToNonNegativeInt(
      tierInput.decimals,
      clampToNonNegativeInt(tierDefault.decimals, 3)
    );

    if (decimals > 8) {
      throw new Error(`${pathLabel}.${key}.decimals must be <= 8`);
    }
    if (Number(min) > Number(max)) {
      throw new Error(`${pathLabel}.${key}.min must be <= ${pathLabel}.${key}.max`);
    }

    result[key] = { min, max, decimals };
  }

  return result;
}

function normalizeTierDailyTxCapConfig(rawTierCaps, fallback, pathLabel) {
  const defaults = isObject(fallback) ? fallback : INTERNAL_API_DEFAULTS.send.tierDailyTxCap;
  const input = isObject(rawTierCaps) ? rawTierCaps : {};
  const result = {};

  for (const key of TIER_KEYS) {
    const tierDefault = clampToNonNegativeInt(defaults[key], 0);
    result[key] = Math.max(
      0,
      clampToNonNegativeInt(
        Object.prototype.hasOwnProperty.call(input, key) ? input[key] : tierDefault,
        tierDefault
      )
    );
  }

  return result;
}

function resolveAmountRangeForTier(sendPolicyOrRange, tierKey) {
  if (!isObject(sendPolicyOrRange)) {
    return INTERNAL_API_DEFAULTS.send.randomAmount;
  }

  if (
    Object.prototype.hasOwnProperty.call(sendPolicyOrRange, "min") &&
    Object.prototype.hasOwnProperty.call(sendPolicyOrRange, "max")
  ) {
    return sendPolicyOrRange;
  }

  const normalizedTierKey = resolveTierKey(tierKey);
  const tierAmounts = isObject(sendPolicyOrRange.tierAmounts) ? sendPolicyOrRange.tierAmounts : null;
  if (tierAmounts && isObject(tierAmounts[normalizedTierKey])) {
    return tierAmounts[normalizedTierKey];
  }

  if (isObject(sendPolicyOrRange.randomAmount)) {
    return sendPolicyOrRange.randomAmount;
  }

  return INTERNAL_API_DEFAULTS.send.randomAmount;
}

function getEffectiveAmountRangeForSender(sendPolicyOrRange, senderName, fallbackTierKey = null) {
  const normalizedSender = String(senderName || "").trim();
  const tierKey = fallbackTierKey || getAccountTierKey(normalizedSender);
  const baseRange = resolveAmountRangeForTier(sendPolicyOrRange, tierKey);
  const decimals = clampToNonNegativeInt(baseRange && baseRange.decimals, 3);
  const baseMin = Number(baseRange && baseRange.min);
  const baseMax = Number(baseRange && baseRange.max);
  const tierMinSend = getAccountTierMinSend(normalizedSender);
  const effectiveMinNumeric = Math.max(
    Number.isFinite(baseMin) ? baseMin : 0,
    Number.isFinite(tierMinSend) ? tierMinSend : 0
  );
  const effectiveMaxNumeric = Math.max(
    effectiveMinNumeric,
    Number.isFinite(baseMax) ? baseMax : effectiveMinNumeric
  );

  return {
    min: normalizeCcAmount(effectiveMinNumeric.toFixed(decimals)),
    max: normalizeCcAmount(effectiveMaxNumeric.toFixed(decimals)),
    decimals
  };
}

function getAccountTierDailyTxCap(config, accountName) {
  const tierKey = getAccountTierKey(accountName);
  const caps = isObject(config && config.send && config.send.tierDailyTxCap)
    ? config.send.tierDailyTxCap
    : INTERNAL_API_DEFAULTS.send.tierDailyTxCap;
  const cap = Number(caps[tierKey]);
  if (!Number.isFinite(cap) || cap <= 0) {
    return 0;
  }
  return Math.max(0, Math.floor(cap));
}

function hasReachedAccountTierDailyTxCap(config, accountName) {
  const cap = getAccountTierDailyTxCap(config, accountName);
  if (cap <= 0) {
    return false;
  }
  const stats = getPerAccountTxStats(accountName);
  return stats.total >= cap;
}

function getAccountHourlyTxCap(config) {
  const cap = Number(
    config &&
    config.send &&
    Object.prototype.hasOwnProperty.call(config.send, "maxTransfersPerHour")
      ? config.send.maxTransfersPerHour
      : INTERNAL_API_DEFAULTS.send.maxTransfersPerHour
  );
  if (!Number.isFinite(cap) || cap <= 0) {
    return 0;
  }
  return Math.max(0, Math.floor(cap));
}

function hasReachedAccountHourlyTxCap(config, accountName) {
  const cap = getAccountHourlyTxCap(config);
  if (cap <= 0) {
    return false;
  }
  const stats = getPerAccountHourlyTxStats(accountName);
  return stats.total >= cap;
}

function getHourlyCapReadyAccounts(config, accounts, sendMode) {
  const safeAccounts = Array.isArray(accounts) ? accounts : [];
  if (sendMode === "balance-only") {
    return safeAccounts.slice();
  }
  return safeAccounts.filter((account) => !hasReachedAccountHourlyTxCap(config, account.name));
}

function generateRandomCcAmount(sendPolicyOrRange, tierKey = null) {
  const amountRange = resolveAmountRangeForTier(sendPolicyOrRange, tierKey);
  const decimals = clampToNonNegativeInt(amountRange.decimals, 2);
  const factor = Math.pow(10, decimals);
  const minUnits = Math.ceil(Number(amountRange.min) * factor);
  const maxUnits = Math.floor(Number(amountRange.max) * factor);

  if (minUnits <= 0 || maxUnits <= 0 || minUnits > maxUnits) {
    throw new Error("Random amount range is invalid. Check config.send.randomAmount or config.send.tierAmounts settings.");
  }

  const units = randomIntInclusive(minUnits, maxUnits);
  const amount = (units / factor).toFixed(decimals);
  return normalizeCcAmount(amount);
}

function buildSendRequestsWithRandomRecipients(recipients, sendPolicy, senderName = null) {
  const requests = [];
  const txCount = clampToNonNegativeInt(sendPolicy.maxLoopTx || sendPolicy.maxTx, 1);
  const senderRange = getEffectiveAmountRangeForSender(sendPolicy, senderName);

  for (let index = 0; index < txCount; index += 1) {
    const amount = generateRandomCcAmount(senderRange, getAccountTierKey(senderName));
    const target = getRandomRecipient(recipients);

    requests.push({
      amount,
      label: target.alias,
      address: target.partyId,
      source: "external-random"
    });
  }

  return requests;
}

function buildSingleExternalRandomRequest(recipients, sendPolicy, source = "external-random", senderName = null) {
  const amount = generateRandomCcAmount(
    getEffectiveAmountRangeForSender(sendPolicy, senderName),
    getAccountTierKey(senderName)
  );
  const target = getRandomRecipient(recipients);

  return {
    amount,
    label: target.alias,
    address: target.partyId,
    source
  };
}

function buildHybridExternalRequest(recipients, sendPolicy, refundTargetAccount, senderName = null) {
  const request = buildSingleExternalRandomRequest(recipients, sendPolicy, "hybrid-external-random", senderName);
  if (refundTargetAccount && String(refundTargetAccount.address || "").trim()) {
    request.refundTargetAlias = String(refundTargetAccount.name || "").trim();
    request.refundTargetPartyId = String(refundTargetAccount.address || "").trim();
  }
  return request;
}

// Build internal recipients from accounts.json (exclude self)
function buildInternalRecipients(accounts, currentAccountName) {
  const recipients = [];
  
  for (const account of accounts) {
    // Skip self
    if (account.name === currentAccountName) {
      continue;
    }
    
    // Skip accounts without address
    const address = String(account.address || "").trim();
    if (!address) {
      continue;
    }
    
    recipients.push({
      alias: account.name,
      address: address,
      partyId: address // For internal, address IS the full cantonPartyId
    });
  }
  
  return recipients;
}

function buildSendRequests(target, sendPolicy, fixedAmountInput, idempotencySeed, senderName = null) {
  const requests = [];
  const txCount = clampToNonNegativeInt(sendPolicy.maxLoopTx || sendPolicy.maxTx, 1);
  const senderTierKey = getAccountTierKey(senderName);
  const senderRange = getEffectiveAmountRangeForSender(sendPolicy, senderName, senderTierKey);

  for (let index = 0; index < txCount; index += 1) {
    const amount = fixedAmountInput
      ? normalizeCcAmount(fixedAmountInput)
      : generateRandomCcAmount(senderRange, senderTierKey);

    let idempotencyKey = null;
    if (idempotencySeed) {
      idempotencyKey = txCount === 1 ? idempotencySeed : `${idempotencySeed}-${index + 1}`;
    }

    requests.push({
      amount,
      label: target.label,
      address: target.address,
      source: target.source,
      idempotencyKey
    });
  }

  return requests;
}

function buildHybridRoundAssignments(accounts) {
  const eligibleAccounts = Array.isArray(accounts)
    ? accounts.filter((acc) => String(acc && acc.address ? acc.address : "").trim())
    : [];

  if (eligibleAccounts.length === 0) {
    return {
      externalNames: new Set(),
      internalNames: new Set(),
      externalCount: 0,
      internalCount: 0
    };
  }

  let externalCount = 0;
  if (eligibleAccounts.length === 1) {
    externalCount = 1;
  } else if (eligibleAccounts.length === 2) {
    externalCount = 1;
  } else {
    externalCount = randomIntInclusive(2, Math.min(3, eligibleAccounts.length - 1));
  }

  const shuffledNames = shuffleArray(eligibleAccounts.map((account) => String(account.name || "").trim()));
  const externalNames = new Set(shuffledNames.slice(0, externalCount).filter((name) => Boolean(name)));
  const internalNames = new Set(
    shuffledNames.filter((name) => Boolean(name) && !externalNames.has(name))
  );

  return {
    externalNames,
    internalNames,
    externalCount: externalNames.size,
    internalCount: internalNames.size
  };
}

function parseSnapshotCcBalance(value) {
  const text = String(value || "").trim();
  if (!text || text === "-") {
    return Number.POSITIVE_INFINITY;
  }

  const match = text.match(/-?\d+(\.\d+)?/);
  if (!match) {
    return Number.POSITIVE_INFINITY;
  }

  const numeric = Number(match[0]);
  return Number.isFinite(numeric) ? numeric : Number.POSITIVE_INFINITY;
}

function getPlanningCcBalance(accountName, accountSnapshots = {}, fallback = 0) {
  const name = String(accountName || "").trim();
  if (!name) {
    return fallback;
  }

  const snapshot = isObject(accountSnapshots) && isObject(accountSnapshots[name])
    ? accountSnapshots[name]
    : {};
  const balance = parseSnapshotCcBalance(snapshot.cc);
  return Number.isFinite(balance) ? balance : fallback;
}

function computeBalanceDistribution(accountNames, accountSnapshots = {}) {
  const safeNames = Array.isArray(accountNames)
    ? accountNames.map((name) => String(name || "").trim()).filter(Boolean)
    : [];
  const entries = safeNames.map((name) => ({
    name,
    cc: getPlanningCcBalance(name, accountSnapshots, Number.NaN)
  }));
  const tracked = entries.filter((entry) => Number.isFinite(entry.cc));
  if (tracked.length === 0) {
    return {
      tracked: 0,
      averageCc: 0,
      surplus: [],
      deficit: []
    };
  }

  const averageCc = tracked.reduce((sum, entry) => sum + entry.cc, 0) / tracked.length;
  const surplus = tracked
    .filter((entry) => entry.cc > averageCc)
    .sort((left, right) => right.cc - left.cc);
  const deficit = tracked
    .filter((entry) => entry.cc < averageCc)
    .sort((left, right) => left.cc - right.cc);

  return {
    tracked: tracked.length,
    averageCc,
    surplus,
    deficit
  };
}

function logBalanceDistribution(accountNames, roundLabel, accountSnapshots = {}) {
  const dist = computeBalanceDistribution(accountNames, accountSnapshots);
  if (dist.tracked === 0) {
    console.log(
      `[balance-smart] ${roundLabel} Waiting for balance data (0/${accountNames.length} tracked)`
    );
    return;
  }

  const avgLabel = dist.averageCc.toFixed(1);
  const surplusLabel =
    dist.surplus.map((entry) => `${entry.name}(${entry.cc.toFixed(0)})`).join(", ") || "none";
  const deficitLabel =
    dist.deficit.map((entry) => `${entry.name}(${entry.cc.toFixed(0)})`).join(", ") || "none";
  console.log(
    `[balance-smart] ${roundLabel} avg=${avgLabel} CC | ` +
    `surplus=[${surplusLabel}] | deficit=[${deficitLabel}]`
  );
}

function sortChainCandidates(candidateNames, projectedBalances, accountTxStats) {
  return [...candidateNames].sort((left, right) => {
    const leftBalance = Number(projectedBalances.get(left));
    const rightBalance = Number(projectedBalances.get(right));
    const leftKey = Number.isFinite(leftBalance) ? leftBalance : Number.POSITIVE_INFINITY;
    const rightKey = Number.isFinite(rightBalance) ? rightBalance : Number.POSITIVE_INFINITY;
    if (leftKey !== rightKey) {
      return leftKey - rightKey;
    }

    const leftTx = Number(accountTxStats.get(left) || 0);
    const rightTx = Number(accountTxStats.get(right) || 0);
    if (leftTx !== rightTx) {
      return leftTx - rightTx;
    }

    return left.localeCompare(right);
  });
}

function buildChainRecipientPriority(senderName, allNames, unsentNames, projectedBalances, accountTxStats) {
  const sender = String(senderName || "").trim();
  const unsentPool = sortChainCandidates(
    Array.from(unsentNames).filter((name) => name && name !== sender),
    projectedBalances,
    accountTxStats
  );
  const remainingPool = sortChainCandidates(
    allNames.filter((name) => name && name !== sender && !unsentNames.has(name)),
    projectedBalances,
    accountTxStats
  );

  const ordered = [];
  for (const candidate of [...unsentPool, ...remainingPool]) {
    if (!ordered.includes(candidate)) {
      ordered.push(candidate);
    }
  }

  if (ordered.length <= 1) {
    return ordered;
  }

  const unlocked = ordered.filter((candidate) => getReciprocalCooldownSeconds(sender, candidate) <= 0);
  const blocked = ordered.filter((candidate) => getReciprocalCooldownSeconds(sender, candidate) > 0);
  return [...unlocked, ...blocked];
}

function computeRoundSendPlan(sortedAccounts, accountSnapshots = {}, sendPolicy = {}, config = {}) {
  const safeAccounts = Array.isArray(sortedAccounts)
    ? sortedAccounts.filter((account) => {
        const name = String(account && account.name ? account.name : "").trim();
        const address = String(account && account.address ? account.address : "").trim();
        return Boolean(name) && Boolean(address) && !isAccountQuarantined(name);
      })
    : [];
  const plan = new Map();
  if (safeAccounts.length < 2) {
    return plan;
  }

  const holdBalance = Math.max(
    0,
    Number(
      isObject(config) && isObject(config.safety)
        ? config.safety.minHoldBalanceCc
        : INTERNAL_API_DEFAULTS.safety.minHoldBalanceCc
    ) || 0
  );
  const allNames = safeAccounts.map((account) => String(account.name || "").trim()).filter(Boolean);
  const accountByName = new Map(safeAccounts.map((account) => [String(account.name || "").trim(), account]));
  const projectedBalances = new Map();
  const accountTxStats = new Map();

  for (const name of allNames) {
    projectedBalances.set(name, getPlanningCcBalance(name, accountSnapshots, 0));
    accountTxStats.set(name, getPerAccountTxStats(name).ok);
  }

  const sortedByBalanceDesc = [...allNames].sort((left, right) => {
    const leftBalance = Number(projectedBalances.get(left));
    const rightBalance = Number(projectedBalances.get(right));
    if (leftBalance !== rightBalance) {
      return rightBalance - leftBalance;
    }
    const leftTx = Number(accountTxStats.get(left) || 0);
    const rightTx = Number(accountTxStats.get(right) || 0);
    if (leftTx !== rightTx) {
      return leftTx - rightTx;
    }
    return left.localeCompare(right);
  });

  const unsentNames = new Set(allNames);
  let currentSender = sortedByBalanceDesc[0] || "";
  let expectedInboundFrom = "";
  const planParts = [];

  while (unsentNames.size > 0) {
    if (!unsentNames.has(currentSender)) {
      currentSender = [...unsentNames].sort((left, right) => {
        const leftBalance = Number(projectedBalances.get(left));
        const rightBalance = Number(projectedBalances.get(right));
        if (leftBalance !== rightBalance) {
          return rightBalance - leftBalance;
        }
        return left.localeCompare(right);
      })[0] || "";
    }
    if (!currentSender) {
      break;
    }

    unsentNames.delete(currentSender);
    const preferredRecipients = buildChainRecipientPriority(
      currentSender,
      allNames,
      unsentNames,
      projectedBalances,
      accountTxStats
    );
    const primaryRecipient = String(preferredRecipients[0] || "").trim();
    const senderProjectedBalance = Number(projectedBalances.get(currentSender));
    const senderSpendable = Number.isFinite(senderProjectedBalance)
      ? Math.max(0, senderProjectedBalance - holdBalance)
      : 0;
    let plannedAmount = generateTierBalancedAmount(sendPolicy, currentSender, senderSpendable);
    const tierMinimumAmount = getTierMinimumAmountForSender(sendPolicy, currentSender);
    if (plannedAmount) {
      const numericAmount = Number(plannedAmount);
      if (!Number.isFinite(numericAmount) || numericAmount < tierMinimumAmount) {
        plannedAmount = null;
      }
    }

    plan.set(currentSender, {
      preferredRecipients,
      plannedAmount,
      projectedBalance: senderProjectedBalance,
      expectedInboundFrom
    });

    if (primaryRecipient) {
      const numericAmount = Number(plannedAmount);
      if (Number.isFinite(numericAmount)) {
        const senderNext = Number(projectedBalances.get(currentSender));
        const recipientNext = Number(projectedBalances.get(primaryRecipient));
        if (Number.isFinite(senderNext)) {
          projectedBalances.set(currentSender, senderNext - numericAmount);
        }
        if (Number.isFinite(recipientNext)) {
          projectedBalances.set(primaryRecipient, recipientNext + numericAmount);
        }
      }
      planParts.push(
        `${currentSender}->${primaryRecipient}${plannedAmount ? `(${plannedAmount} CC)` : ""}`
      );
      expectedInboundFrom = currentSender;
      currentSender = primaryRecipient;
      continue;
    }

    planParts.push(`${currentSender}->(none)`);
    expectedInboundFrom = "";
    currentSender = "";
  }

  if (planParts.length > 0) {
    console.log(
      `[internal-chain] Round plan (${planParts.length} send${planParts.length > 1 ? "s" : ""}): ${planParts.join(" | ")}`
    );
  }

  return plan;
}

function buildBalanceAwareRecipientPriority(
  candidateNames,
  projectedBalances,
  projectedRecipientLoads,
  senderName
) {
  const sender = String(senderName || "").trim();
  const uniqueCandidates = Array.from(
    new Set(
      Array.isArray(candidateNames)
        ? candidateNames
            .map((name) => String(name || "").trim())
            .filter((name) => Boolean(name) && name !== sender)
        : []
    )
  );
  const originalOrder = new Map();
  uniqueCandidates.forEach((candidate, index) => {
    if (!originalOrder.has(candidate)) {
      originalOrder.set(candidate, index);
    }
  });

  return uniqueCandidates.sort((left, right) => {
    const leftBalance = Number(projectedBalances.get(left));
    const rightBalance = Number(projectedBalances.get(right));
    const leftBalanceKey = Number.isFinite(leftBalance) ? leftBalance : Number.POSITIVE_INFINITY;
    const rightBalanceKey = Number.isFinite(rightBalance) ? rightBalance : Number.POSITIVE_INFINITY;
    if (leftBalanceKey !== rightBalanceKey) {
      return leftBalanceKey - rightBalanceKey;
    }

    const leftTx = getPerAccountTxStats(left).total;
    const rightTx = getPerAccountTxStats(right).total;
    if (leftTx !== rightTx) {
      return leftTx - rightTx;
    }

    const leftLoad = Number(projectedRecipientLoads.get(left) || 0);
    const rightLoad = Number(projectedRecipientLoads.get(right) || 0);
    if (leftLoad !== rightLoad) {
      return leftLoad - rightLoad;
    }

    const leftOrder = Number(originalOrder.get(left));
    const rightOrder = Number(originalOrder.get(right));
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }

    return left.localeCompare(right);
  });
}

function getTierMinimumAmountForSender(sendPolicy, senderName) {
  const tierRange = getEffectiveAmountRangeForSender(sendPolicy, senderName);
  const tierMin = Number(tierRange && tierRange.min);
  return Number.isFinite(tierMin) ? tierMin : 0;
}

function generateTierBalancedAmount(sendPolicy, senderName, spendableAmount) {
  const tierKey = getAccountTierKey(senderName);
  const tierRange = getEffectiveAmountRangeForSender(sendPolicy, senderName, tierKey);
  const minAmount = Number(tierRange && tierRange.min);
  const maxAmount = Number(tierRange && tierRange.max);
  const decimals = clampToNonNegativeInt(tierRange && tierRange.decimals, 3);
  const spendable = Number(spendableAmount);

  if (!Number.isFinite(spendable) || spendable <= 0 || !Number.isFinite(minAmount) || !Number.isFinite(maxAmount)) {
    return null;
  }

  const upperBound = Math.min(maxAmount, spendable);
  if (!(upperBound >= minAmount)) {
    return null;
  }

  return generateRandomCcAmount(
    {
      min: minAmount.toFixed(decimals),
      max: upperBound.toFixed(decimals),
      decimals
    },
    tierKey
  );
}

function applyPreferredRecipientOrder(candidateNames, preferredRecipientNames) {
  const safeCandidates = Array.isArray(candidateNames) ? candidateNames.slice() : [];
  if (safeCandidates.length === 0) {
    return [];
  }

  const preferredIndexByName = new Map();
  if (Array.isArray(preferredRecipientNames)) {
    preferredRecipientNames.forEach((name, index) => {
      const normalized = String(name || "").trim();
      if (normalized && !preferredIndexByName.has(normalized)) {
        preferredIndexByName.set(normalized, index);
      }
    });
  }

  if (preferredIndexByName.size === 0) {
    return safeCandidates;
  }

  const originalIndexByName = new Map();
  safeCandidates.forEach((name, index) => {
    const normalized = String(name || "").trim();
    if (normalized && !originalIndexByName.has(normalized)) {
      originalIndexByName.set(normalized, index);
    }
  });

  return safeCandidates.sort((left, right) => {
    const leftName = String(left || "").trim();
    const rightName = String(right || "").trim();
    const leftPreferred = preferredIndexByName.has(leftName);
    const rightPreferred = preferredIndexByName.has(rightName);
    if (leftPreferred !== rightPreferred) {
      return leftPreferred ? -1 : 1;
    }
    if (leftPreferred && rightPreferred) {
      return preferredIndexByName.get(leftName) - preferredIndexByName.get(rightName);
    }
    return (originalIndexByName.get(leftName) || 0) - (originalIndexByName.get(rightName) || 0);
  });
}

function buildInternalFairRoundExecutionPlan(
  readyEntries,
  sortedAccounts,
  accountSnapshots,
  sendPolicy,
  sendMode,
  hybridRoundAssignments = null,
  holdBufferCc = 0,
  loopRound = null
) {
  const safeReadyEntries = Array.isArray(readyEntries) ? readyEntries.filter((entry) => entry && entry.account) : [];
  const safeSortedAccounts = Array.isArray(sortedAccounts) ? sortedAccounts.filter((account) => account && account.name) : [];
  if (safeReadyEntries.length === 0 || safeSortedAccounts.length === 0) {
    return {
      entries: safeReadyEntries.slice(),
      orderLabel: "",
      summaryLabel: ""
    };
  }

  const projectedBalances = new Map();
  const projectedRecipientLoads = new Map();
  for (const account of safeSortedAccounts) {
    const accountName = String(account && account.name ? account.name : "").trim();
    if (!accountName) {
      continue;
    }
    projectedBalances.set(accountName, getPlanningCcBalance(accountName, accountSnapshots, 0));
    projectedRecipientLoads.set(accountName, 0);
  }

  const planningState = safeReadyEntries.map((entry, index) => {
    const account = entry.account;
    const accountName = String(account && account.name ? account.name : "").trim();
    const assignedMode =
      sendMode === "hybrid"
        ? (
            hybridRoundAssignments &&
            hybridRoundAssignments.externalNames &&
            hybridRoundAssignments.externalNames.has(accountName)
              ? "external"
              : "internal"
          )
        : sendMode;
    return {
      ...entry,
      planningBaseIndex: index,
      assignedMode
    };
  });

  const remainingEntries = planningState.slice();
  const plannedEntries = [];
  const heldBackEntries = [];
  const orderParts = [];

  while (remainingEntries.length > 0) {
    remainingEntries.sort((left, right) => {
      const leftName = String(left.account && left.account.name ? left.account.name : "").trim();
      const rightName = String(right.account && right.account.name ? right.account.name : "").trim();
      const leftModeRank = left.assignedMode === "internal" ? 0 : (left.assignedMode === "external" ? 1 : 2);
      const rightModeRank = right.assignedMode === "internal" ? 0 : (right.assignedMode === "external" ? 1 : 2);
      if (leftModeRank !== rightModeRank) {
        return leftModeRank - rightModeRank;
      }

      const leftProjectedBalance = Number(projectedBalances.get(leftName));
      const rightProjectedBalance = Number(projectedBalances.get(rightName));
      const leftSpendable = Number.isFinite(leftProjectedBalance) ? leftProjectedBalance - holdBufferCc : Number.NEGATIVE_INFINITY;
      const rightSpendable = Number.isFinite(rightProjectedBalance) ? rightProjectedBalance - holdBufferCc : Number.NEGATIVE_INFINITY;
      const leftCanSend = left.assignedMode !== "internal"
        ? Number.isFinite(leftSpendable) && leftSpendable > 0
        : leftSpendable >= getTierMinimumAmountForSender(sendPolicy, leftName);
      const rightCanSend = right.assignedMode !== "internal"
        ? Number.isFinite(rightSpendable) && rightSpendable > 0
        : rightSpendable >= getTierMinimumAmountForSender(sendPolicy, rightName);
      if (leftCanSend !== rightCanSend) {
        return leftCanSend ? -1 : 1;
      }

      if (leftSpendable !== rightSpendable) {
        return rightSpendable - leftSpendable;
      }

      const leftTx = getPerAccountTxStats(leftName).total;
      const rightTx = getPerAccountTxStats(rightName).total;
      if (leftTx !== rightTx) {
        return leftTx - rightTx;
      }

      return left.planningBaseIndex - right.planningBaseIndex;
    });

    const currentEntry = remainingEntries.shift();
    const senderName = String(currentEntry.account && currentEntry.account.name ? currentEntry.account.name : "").trim();
    const senderProjectedBalance = Number(projectedBalances.get(senderName));
    const senderSpendable = Number.isFinite(senderProjectedBalance)
      ? Math.max(0, senderProjectedBalance - holdBufferCc)
      : 0;
    let preferredInternalRecipients = [];
    let plannedInternalAmount = null;
    let plannedInternalPrimaryRecipient = "";

    if (currentEntry.assignedMode === "internal") {
      const internalPlan = buildInternalSendRequests(
        safeSortedAccounts,
        senderName,
        sendPolicy,
        loopRound,
        Array.isArray(currentEntry.smartFillBlockRecipients) ? currentEntry.smartFillBlockRecipients : [],
        [],
        null,
        { quiet: true }
      );
      const candidateNames = Array.isArray(internalPlan && internalPlan.requests)
        ? internalPlan.requests.map((request) => String(request && request.label ? request.label : "").trim()).filter((name) => Boolean(name))
        : [];

      preferredInternalRecipients = buildBalanceAwareRecipientPriority(
        candidateNames,
        projectedBalances,
        projectedRecipientLoads,
        senderName
      );
      plannedInternalAmount = generateTierBalancedAmount(sendPolicy, senderName, senderSpendable);
      plannedInternalPrimaryRecipient = String(preferredInternalRecipients[0] || "").trim();

      if (plannedInternalPrimaryRecipient && plannedInternalAmount) {
        const plannedAmountNumeric = Number(plannedInternalAmount);
        if (Number.isFinite(plannedAmountNumeric)) {
          if (Number.isFinite(senderProjectedBalance)) {
            projectedBalances.set(senderName, senderProjectedBalance - plannedAmountNumeric);
          }
          const targetProjectedBalance = Number(projectedBalances.get(plannedInternalPrimaryRecipient));
          if (Number.isFinite(targetProjectedBalance)) {
            projectedBalances.set(plannedInternalPrimaryRecipient, targetProjectedBalance + plannedAmountNumeric);
          }
          projectedRecipientLoads.set(
            plannedInternalPrimaryRecipient,
            Number(projectedRecipientLoads.get(plannedInternalPrimaryRecipient) || 0) + 1
          );
        }
      }
    }

    const tierMinimumAmount = getTierMinimumAmountForSender(sendPolicy, senderName);
    const planningSendEligible =
      currentEntry.assignedMode !== "internal"
        ? true
        : (
            Boolean(plannedInternalPrimaryRecipient) &&
            Boolean(plannedInternalAmount) &&
            Number.isFinite(Number(plannedInternalAmount)) &&
            Number(plannedInternalAmount) >= tierMinimumAmount
          );
    const planningHoldReason =
      currentEntry.assignedMode !== "internal"
        ? ""
        : (
            !plannedInternalPrimaryRecipient
              ? "recipient-unavailable"
              : (!plannedInternalAmount ? "awaiting-inbound" : "")
          );

    const planningEntry = {
      ...currentEntry,
      preferredInternalRecipients,
      plannedInternalAmount,
      plannedInternalPrimaryRecipient,
      planningProjectedBalance: senderProjectedBalance,
      planningSpendable: senderSpendable,
      planningSendEligible,
      planningHoldReason,
      planningTierMinimumAmount: tierMinimumAmount
    };

    if (!planningSendEligible) {
      heldBackEntries.push(planningEntry);
      orderParts.push(`${senderName}[hold:${planningHoldReason || "balance"}]`);
      continue;
    }

    plannedEntries.push(planningEntry);

    const summaryParts = [];
    summaryParts.push(`${senderName}[${currentEntry.assignedMode}]`);
    if (currentEntry.assignedMode === "internal" && plannedInternalPrimaryRecipient) {
      summaryParts.push(`-> ${plannedInternalPrimaryRecipient}`);
    }
    if (currentEntry.assignedMode === "internal" && plannedInternalAmount) {
      summaryParts.push(`(${plannedInternalAmount} CC)`);
    }
    orderParts.push(summaryParts.join(" "));
  }

  const totalProjectedBalance = plannedEntries.reduce((sum, entry) => {
    return sum + (Number.isFinite(entry.planningProjectedBalance) ? entry.planningProjectedBalance : 0);
  }, 0);
  const summaryLabel =
    `planned=${plannedEntries.length} ` +
    `internal=${plannedEntries.filter((entry) => entry.assignedMode === "internal").length} ` +
    `external=${plannedEntries.filter((entry) => entry.assignedMode === "external").length} ` +
    `projectedTotal=${formatRewardsVolumeLabel(totalProjectedBalance)} CC`;

  return {
    entries: plannedEntries,
    heldBackEntries,
    orderLabel: orderParts.join(" | "),
    summaryLabel
  };
}

function buildDependencyAwareWorkerBatches(executionEntries, workerCount) {
  const remainingEntries = Array.isArray(executionEntries) ? executionEntries.slice() : [];
  const effectiveWorkerCount = Math.max(1, clampToNonNegativeInt(workerCount, 1));
  const batches = [];

  const entryPrioritySorter = (left, right) => {
    const leftModeRank = left && left.assignedMode === "internal" ? 0 : 1;
    const rightModeRank = right && right.assignedMode === "internal" ? 0 : 1;
    if (leftModeRank !== rightModeRank) {
      return leftModeRank - rightModeRank;
    }

    const leftReady = left && left.planningSendEligible !== false;
    const rightReady = right && right.planningSendEligible !== false;
    if (leftReady !== rightReady) {
      return leftReady ? -1 : 1;
    }

    const leftSpendable = Number(left && left.planningSpendable);
    const rightSpendable = Number(right && right.planningSpendable);
    if (leftSpendable !== rightSpendable) {
      return rightSpendable - leftSpendable;
    }

    const leftTx = getPerAccountTxStats(String(left && left.account && left.account.name ? left.account.name : "")).total;
    const rightTx = getPerAccountTxStats(String(right && right.account && right.account.name ? right.account.name : "")).total;
    if (leftTx !== rightTx) {
      return leftTx - rightTx;
    }

    return clampToNonNegativeInt(left && left.planningBaseIndex, 0) - clampToNonNegativeInt(right && right.planningBaseIndex, 0);
  };

  while (remainingEntries.length > 0) {
    remainingEntries.sort(entryPrioritySorter);

    const batch = [];
    const selectedSenderNames = new Set();
    const selectedRecipientNames = new Set();

    for (const candidate of remainingEntries) {
      if (batch.length >= effectiveWorkerCount) {
        break;
      }

      const senderName = String(candidate && candidate.account && candidate.account.name ? candidate.account.name : "").trim();
      const recipientName = String(candidate && candidate.plannedInternalPrimaryRecipient ? candidate.plannedInternalPrimaryRecipient : "").trim();

      if (!senderName) {
        continue;
      }

      const conflictsWithBatch =
        selectedSenderNames.has(senderName) ||
        (recipientName && selectedSenderNames.has(recipientName)) ||
        (recipientName && selectedRecipientNames.has(recipientName)) ||
        selectedRecipientNames.has(senderName);

      if (conflictsWithBatch) {
        continue;
      }

      batch.push(candidate);
      selectedSenderNames.add(senderName);
      if (recipientName) {
        selectedRecipientNames.add(recipientName);
      }
    }

    if (batch.length === 0) {
      batch.push(remainingEntries[0]);
    }

    const batchEntriesSet = new Set(batch);
    batches.push(batch);

    for (let index = remainingEntries.length - 1; index >= 0; index -= 1) {
      if (batchEntriesSet.has(remainingEntries[index])) {
        remainingEntries.splice(index, 1);
      }
    }
  }

  return batches;
}

function selectHybridRefundTarget(sourceAccount, selectedAccounts, accountSnapshots) {
  const sourceName = String(sourceAccount && sourceAccount.name ? sourceAccount.name : "").trim();
  const candidates = Array.isArray(selectedAccounts)
    ? selectedAccounts
        .filter((account) => {
          const name = String(account && account.name ? account.name : "").trim();
          const address = String(account && account.address ? account.address : "").trim();
          return Boolean(name) && Boolean(address) && name !== sourceName && !isAccountQuarantined(name);
        })
        .map((account) => {
          const name = String(account.name || "").trim();
          const snapshot = isObject(accountSnapshots) && isObject(accountSnapshots[name])
            ? accountSnapshots[name]
            : {};
          return {
            account,
            balance: parseSnapshotCcBalance(snapshot.cc)
          };
        })
    : [];

  if (candidates.length === 0) {
    return null;
  }

  const knownBalances = candidates
    .filter((entry) => Number.isFinite(entry.balance))
    .sort((a, b) => {
      if (a.balance !== b.balance) {
        return a.balance - b.balance;
      }
      return String(a.account.name || "").localeCompare(String(b.account.name || ""));
    });

  const pool = knownBalances.length > 0
    ? knownBalances.slice(0, Math.min(3, knownBalances.length))
    : shuffleArray(candidates).slice(0, Math.min(3, candidates.length));

  if (pool.length === 0) {
    return null;
  }

  return pool[randomIntInclusive(0, pool.length - 1)].account || null;
}

function buildRoundRefundPriorityTargets(selectedAccounts, accountSnapshots) {
  const candidates = Array.isArray(selectedAccounts)
    ? selectedAccounts
        .filter((account) => {
          const name = String(account && account.name ? account.name : "").trim();
          const address = String(account && account.address ? account.address : "").trim();
          return Boolean(address) && !isAccountQuarantined(name);
        })
        .map((account) => {
          const name = String(account && account.name ? account.name : "").trim();
          const snapshot = isObject(accountSnapshots) && isObject(accountSnapshots[name])
            ? accountSnapshots[name]
            : {};
          const balance = parseSnapshotCcBalance(snapshot.cc);
          return {
            account,
            balance,
            balanceLabel: Number.isFinite(balance) ? balance.toFixed(10) : "unknown"
          };
        })
    : [];

  candidates.sort((left, right) => {
    const leftFinite = Number.isFinite(left.balance);
    const rightFinite = Number.isFinite(right.balance);
    if (leftFinite && rightFinite && left.balance !== right.balance) {
      return left.balance - right.balance;
    }
    if (leftFinite !== rightFinite) {
      return leftFinite ? -1 : 1;
    }
    return String(left.account && left.account.name ? left.account.name : "").localeCompare(
      String(right.account && right.account.name ? right.account.name : "")
    );
  });

  return candidates;
}

function assignHybridRefundTargetsForRoundPass(roundResults, selectedAccounts, accountSnapshots) {
  const priorityTargets = buildRoundRefundPriorityTargets(selectedAccounts, accountSnapshots).map((entry) => ({
    ...entry,
    projectedBalance: Number.isFinite(entry.balance) ? entry.balance : Number.POSITIVE_INFINITY
  }));

  const assignments = [];
  if (priorityTargets.length === 0) {
    return {
      priorityTargets,
      assignments
    };
  }

  for (const roundResult of Array.isArray(roundResults) ? roundResults : []) {
    const entry = roundResult && roundResult.entry ? roundResult.entry : null;
    const senderName = String(entry && entry.account && entry.account.name ? entry.account.name : "").trim();
    const completedTransfers = Array.isArray(roundResult && roundResult.result && roundResult.result.completedTransfers)
      ? roundResult.result.completedTransfers
      : [];

    for (const transfer of completedTransfers) {
      const source = String(transfer && transfer.source ? transfer.source : "").trim();
      const amount = Number(transfer && transfer.amount ? transfer.amount : 0);
      if (!source.includes("external")) {
        continue;
      }

      const eligibleTargets = priorityTargets
        .filter((target) => String(target.account && target.account.name ? target.account.name : "").trim() !== senderName)
        .sort((left, right) => {
          if (left.projectedBalance !== right.projectedBalance) {
            return left.projectedBalance - right.projectedBalance;
          }
          return String(left.account && left.account.name ? left.account.name : "").localeCompare(
            String(right.account && right.account.name ? right.account.name : "")
          );
        });

      const selectedTarget = eligibleTargets[0] || null;
      if (!selectedTarget) {
        continue;
      }

      transfer.refundTargetAlias = String(selectedTarget.account.name || "").trim();
      transfer.refundTargetPartyId = String(selectedTarget.account.address || "").trim();
      transfer.refundTargetPriorityBalance = selectedTarget.balanceLabel;

      if (Number.isFinite(amount) && Number.isFinite(selectedTarget.projectedBalance)) {
        selectedTarget.projectedBalance += amount;
      }

      assignments.push({
        senderName,
        targetName: String(selectedTarget.account.name || "").trim(),
        amount: String(transfer.amount || "").trim(),
        targetPriorityBalance: selectedTarget.balanceLabel
      });
    }
  }

  return {
    priorityTargets,
    assignments
  };
}

function buildHybridSendRequests(
  accounts,
  senderName,
  recipients,
  sendPolicy,
  loopRound = null,
  avoidRecipientNames = [],
  preferredModeInput = null,
  preferredInternalRecipients = [],
  plannedInternalAmount = null
) {
  const safeRecipients = Array.isArray(recipients) ? recipients : [];
  const internalPlan = buildInternalSendRequests(
    accounts,
    senderName,
    sendPolicy,
    loopRound,
    avoidRecipientNames,
    preferredInternalRecipients,
    plannedInternalAmount
  );
  const hasInternalRoute = Array.isArray(internalPlan && internalPlan.requests) && internalPlan.requests.length > 0;
  const hasExternalRoute = safeRecipients.length > 0;

  if (!hasInternalRoute && !hasExternalRoute) {
    return {
      selectedMode: "none",
      requests: [],
      reason:
        internalPlan && internalPlan.reason
          ? internalPlan.reason
          : "hybrid-recipient-unavailable",
      retryAfterSeconds: clampToNonNegativeInt(
        internalPlan && internalPlan.retryAfterSeconds,
        0
      ),
      primaryOffset: clampToNonNegativeInt(internalPlan && internalPlan.primaryOffset, 1),
      fallbackUsed: false
    };
  }

  const preferredMode =
    preferredModeInput === "internal" || preferredModeInput === "external"
      ? preferredModeInput
      : (Math.random() < 0.5 ? "internal" : "external");

  if (preferredMode === "internal" && hasInternalRoute) {
    return {
      selectedMode: "internal",
      requests: internalPlan.requests,
      reason: null,
      retryAfterSeconds: 0,
      primaryOffset: clampToNonNegativeInt(internalPlan.primaryOffset, 1),
      fallbackUsed: false
    };
  }

  if (preferredMode === "external" && hasExternalRoute) {
    return {
      selectedMode: "external",
      requests: [buildSingleExternalRandomRequest(safeRecipients, sendPolicy, "hybrid-external-random", senderName)],
      reason: null,
      retryAfterSeconds: 0,
      primaryOffset: 0,
      fallbackUsed: false
    };
  }

  if (hasInternalRoute) {
    return {
      selectedMode: "internal",
      requests: internalPlan.requests,
      reason: null,
      retryAfterSeconds: 0,
      primaryOffset: clampToNonNegativeInt(internalPlan.primaryOffset, 1),
      fallbackUsed: true
    };
  }

  return {
    selectedMode: "external",
    requests: [buildSingleExternalRandomRequest(safeRecipients, sendPolicy, "hybrid-external-random", senderName)],
    reason: null,
    retryAfterSeconds: 0,
    primaryOffset: 0,
    fallbackUsed: true
  };
}

function shouldRefreshVercelCookie(lastRefreshAt, refreshEveryMinutes) {
  const minutes = clampToNonNegativeInt(refreshEveryMinutes, 0);
  if (minutes <= 0) {
    return false;
  }

  const parsed = Date.parse(String(lastRefreshAt || "").trim());
  if (!Number.isFinite(parsed)) {
    return true;
  }

  const ageMs = Date.now() - parsed;
  return ageMs >= minutes * 60 * 1000;
}

function resolveSendRecipientTarget(input, recipients) {
  const value = String(input || "").trim();
  if (!value) {
    throw new Error("Recipient target is required for send mode");
  }

  if (value.includes("::")) {
    return {
      label: value,
      address: value,
      source: "direct"
    };
  }

  const found = recipients.find((entry) => entry.alias === value);
  if (!found) {
    throw new Error(`Recipient alias '${value}' not found in recipient file`);
  }

  const resolvedPartyId = String(
    found.partyId ||
      (String(found.address || "").includes("::") ? found.address : `${found.alias}::${found.address}`)
  ).trim();

  return {
    label: found.alias,
    address: resolvedPartyId,
    source: "alias"
  };
}

function isVercelCheckpointError(error) {
  const message = String(error && error.message ? error.message : error || "");
  return message.includes("Vercel Security Checkpoint");
}

function isCheckpointOr429Error(error) {
  const status = Number(error && error.status);
  if (status === 429) {
    return true;
  }

  if (isVercelCheckpointError(error)) {
    return true;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("http 429") ||
    message.includes("failed preflight get /onboard") ||
    message.includes("fetch failed")
  );
}

function isSessionReuseTimeoutError(error) {
  const status = Number(error && error.status);
  if (Number.isFinite(status)) {
    return false;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("timed out") ||
    message.includes("timeout") ||
    message.includes("aborted") ||
    message.includes("fetch failed") ||
    message.includes("network")
  );
}

function isFetchFailedTransientError(error) {
  const status = Number(error && error.status);
  if (Number.isFinite(status)) {
    return false;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("fetch failed") ||
    message.includes("socket hang up") ||
    message.includes("econnreset") ||
    message.includes("client network socket disconnected")
  );
}

function isSessionReuseImmediateFetchRestartError(error) {
  if (!error) {
    return false;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("trigger immediate client hot-restart") ||
    message.includes("fetch/network failure detected") ||
    message.includes("fetch failed")
  );
}

function isInvalidSessionError(error) {
  const status = Number(error && error.status);
  if (status === 401 || status === 403) {
    return true;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("invalid session") ||
    message.includes("session expired") ||
    message.includes("no active session") ||
    message.includes("not authenticated") ||
    message.includes("unauthorized") ||
    message.includes("authentication required")
  );
}

function isTimeoutError(error) {
  if (!error) {
    return false;
  }

  const message = String(
    error && error.message ? error.message : error || ""
  ).toLowerCase();

  return (
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("aborted") ||
    message.includes("etimedout") ||
    message.includes("econnreset") ||
    message.includes("request timed out")
  );
}

function isTransientSendFlowError(error) {
  if (!error) {
    return false;
  }

  if (isSendEligibilityDelayError(error)) {
    return false;
  }

  const status = Number(error && error.status);
  if (status === 429 || (status >= 500 && status < 600)) {
    return true;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    isTimeoutError(error) ||
    message.includes("fetch failed") ||
    message.includes("network") ||
    message.includes("socket") ||
    message.includes("econnreset") ||
    message.includes("eai_again") ||
    message.includes("connection") ||
    message.includes("terminated")
  );
}

function isSendEligibilityDelayError(error) {
  const status = Number(error && error.status);
  if (status === 409 || status === 423) {
    return true;
  }

  const message = String(error && error.message ? error.message : error || "").toLowerCase();
  return (
    message.includes("cooldown") ||
    message.includes("retry after") ||
    message.includes("too soon") ||
    message.includes("wait before") ||
    message.includes("temporarily unavailable") ||
    (message.includes("recent") && message.includes("send"))
  );
}

function isBalanceContractFragmentationError(error) {
  const status = Number(error && error.status);
  const message = String(error && error.message ? error.message : error || "").toLowerCase();

  if (status !== 400) {
    return false;
  }

  return (
    message.includes("split across too many contracts") ||
    (message.includes("too many contracts") && message.includes("would be needed")) ||
    (message.includes("contracts") && message.includes("one transaction"))
  );
}

function getReducedAmountForFragmentedBalance(currentAmount, sendPolicy) {
  const current = Number(currentAmount);
  if (!Number.isFinite(current) || current <= 0) {
    return null;
  }

  const tierAmounts = isObject(sendPolicy && sendPolicy.tierAmounts) ? sendPolicy.tierAmounts : {};
  const randomAmount = isObject(sendPolicy && sendPolicy.randomAmount) ? sendPolicy.randomAmount : null;
  let maxDecimals = clampToNonNegativeInt(
    randomAmount && Object.prototype.hasOwnProperty.call(randomAmount, "decimals")
      ? randomAmount.decimals
      : 3,
    3
  );
  for (const tierRange of Object.values(tierAmounts)) {
    if (isObject(tierRange) && Object.prototype.hasOwnProperty.call(tierRange, "decimals")) {
      maxDecimals = Math.max(maxDecimals, clampToNonNegativeInt(tierRange.decimals, 3));
    }
  }
  const decimals = Math.min(8, Math.max(0, maxDecimals));

  const emergencyFloor = 0.1;
  const reducedRaw = current * 0.6;
  const candidate = Math.max(emergencyFloor, reducedRaw);
  if (!(candidate > 0) || candidate >= current) {
    return null;
  }

  const rounded = Number(candidate.toFixed(decimals));
  if (!Number.isFinite(rounded) || rounded <= 0 || rounded >= current) {
    return null;
  }

  return normalizeCcAmount(rounded.toFixed(decimals));
}

function parseRetryAfterSeconds(errorLike, fallbackSeconds = 15) {
  const message = String(errorLike && errorLike.message ? errorLike.message : errorLike || "");
  const normalizedFallback = Math.max(1, clampToNonNegativeInt(fallbackSeconds, 15));

  const parseUnit = (valueRaw, unitRaw) => {
    const value = Number(valueRaw);
    if (!Number.isFinite(value) || value <= 0) {
      return null;
    }

    const unit = String(unitRaw || "s").toLowerCase();
    if (unit.startsWith("ms")) {
      return Math.max(1, Math.ceil(value / 1000));
    }
    if (unit.startsWith("m")) {
      return Math.max(1, Math.ceil(value * 60));
    }
    return Math.max(1, Math.ceil(value));
  };

  const patterns = [
    /retry\s+after\s+(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|sec|secs|seconds?|m|min|mins|minutes?)?/i,
    /wait\s+(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|sec|secs|seconds?|m|min|mins|minutes?)?/i,
    /cooldown(?:[^\d]{0,12})(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|sec|secs|seconds?|m|min|mins|minutes?)?/i
  ];

  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (!match) {
      continue;
    }

    const parsed = parseUnit(match[1], match[2]);
    if (parsed !== null) {
      return parsed;
    }
  }

  return normalizedFallback;
}

function normalizeConfig(rawConfig) {
  if (!isObject(rawConfig)) {
    throw new Error("config.json must be a JSON object");
  }

  const httpInput = isObject(rawConfig.http) ? rawConfig.http : {};
  const http = {
    timeoutMs: clampToNonNegativeInt(httpInput.timeoutMs, INTERNAL_API_DEFAULTS.http.timeoutMs),
    maxRetries: clampToNonNegativeInt(httpInput.maxRetries, INTERNAL_API_DEFAULTS.http.maxRetries),
    retryBaseDelayMs: clampToNonNegativeInt(
      httpInput.retryBaseDelayMs,
      INTERNAL_API_DEFAULTS.http.retryBaseDelayMs
    )
  };

  if (http.timeoutMs < 1000) {
    throw new Error("config.http.timeoutMs must be >= 1000 ms");
  }

  const pacingInput = isObject(rawConfig.requestPacing) ? rawConfig.requestPacing : {};
  const requestPacing = {
    minDelayMs: clampToNonNegativeInt(
      pacingInput.minDelayMs,
      INTERNAL_API_DEFAULTS.requestPacing.minDelayMs
    ),
    jitterMs: clampToNonNegativeInt(
      pacingInput.jitterMs,
      INTERNAL_API_DEFAULTS.requestPacing.jitterMs
    )
  };

  const recipientFile = String(rawConfig.recipientFile || "recipient.txt").trim();
  if (!recipientFile) {
    throw new Error("config.recipientFile must be a non-empty string");
  }

  const sessionInput = isObject(rawConfig.session) ? rawConfig.session : {};
  const session = {
    preflightOnboard:
      typeof sessionInput.preflightOnboard === "boolean"
        ? sessionInput.preflightOnboard
        : false,
    autoRefreshCheckpoint:
      typeof sessionInput.autoRefreshCheckpoint === "boolean"
        ? sessionInput.autoRefreshCheckpoint
        : true,
    proactiveVercelRefreshMinutes: clampToNonNegativeInt(
      sessionInput.proactiveVercelRefreshMinutes,
      45
    ),
    maxSessionReuseRefreshAttempts: Math.max(
      1,
      clampToNonNegativeInt(sessionInput.maxSessionReuseRefreshAttempts, 3)
    ),
    maxSessionReuseTransientAttempts: Math.max(
      1,
      clampToNonNegativeInt(sessionInput.maxSessionReuseTransientAttempts, 6)
    ),
    maxSessionReuseLightResets: Math.max(
      0,
      clampToNonNegativeInt(sessionInput.maxSessionReuseLightResets, 1)
    ),
    maxSessionReuseTransientBrowserRefreshes: Math.max(
      0,
      clampToNonNegativeInt(sessionInput.maxSessionReuseTransientBrowserRefreshes, 1)
    ),
    transientBrowserRefreshTriggerFailures: Math.max(
      1,
      clampToNonNegativeInt(sessionInput.transientBrowserRefreshTriggerFailures, 2)
    ),
    sessionReuseTransientRetryAfterSeconds: Math.max(
      15,
      clampToNonNegativeInt(sessionInput.sessionReuseTransientRetryAfterSeconds, 45)
    ),
    browserChallengeRetryAfterSeconds: Math.max(
      60,
      clampToNonNegativeInt(sessionInput.browserChallengeRetryAfterSeconds, 120)
    ),
    softRestartRetryAfterSeconds: Math.max(
      15,
      clampToNonNegativeInt(sessionInput.softRestartRetryAfterSeconds, 45)
    ),
    sessionReuseRetryJitterSeconds: Math.max(
      0,
      clampToNonNegativeInt(sessionInput.sessionReuseRetryJitterSeconds, 12)
    ),
    maxConcurrentSessionReuse: Math.max(
      1,
      clampToNonNegativeInt(sessionInput.maxConcurrentSessionReuse, 1)
    ),
    checkpointSettleDelayMs: Math.max(
      500,
      clampToNonNegativeInt(sessionInput.checkpointSettleDelayMs, 3500)
    ),
    maxOtpRefreshAttempts: Math.max(
      1,
      clampToNonNegativeInt(sessionInput.maxOtpRefreshAttempts, 3)
    ),
    fallbackToOtpOnPersistentCheckpoint:
      typeof sessionInput.fallbackToOtpOnPersistentCheckpoint === "boolean"
        ? sessionInput.fallbackToOtpOnPersistentCheckpoint
        : true
  };

  if (session.maxOtpRefreshAttempts < 1) {
    throw new Error("config.session.maxOtpRefreshAttempts must be >= 1");
  }

  if (session.maxSessionReuseRefreshAttempts < 1) {
    throw new Error("config.session.maxSessionReuseRefreshAttempts must be >= 1");
  }

  const uiInput = isObject(rawConfig.ui) ? rawConfig.ui : {};
  const uiLogLinesInput = Object.prototype.hasOwnProperty.call(uiInput, "logLines")
    ? uiInput.logLines
    : uiInput.maxExecutionLogLines;
  const ui = {
    dashboard:
      typeof uiInput.dashboard === "boolean"
        ? uiInput.dashboard
        : INTERNAL_API_DEFAULTS.ui.dashboard,
    logLines: Math.min(
      20,
      Math.max(
        1,
        clampToNonNegativeInt(uiLogLinesInput, INTERNAL_API_DEFAULTS.ui.logLines)
      )
    )
  };

  const telegramInput = isObject(rawConfig.telegram) ? rawConfig.telegram : {};
  const telegramEnabledFlag = parseBooleanFlag(process.env.ROOTSFI_TELEGRAM_ENABLED);
  const telegram = {
    enabled:
      telegramEnabledFlag !== null
        ? telegramEnabledFlag
        : (
            typeof telegramInput.enabled === "boolean"
              ? telegramInput.enabled
              : INTERNAL_API_DEFAULTS.telegram.enabled
          ),
    botToken: String(process.env.ROOTSFI_TELEGRAM_BOT_TOKEN || telegramInput.botToken || "").trim(),
    chatId: String(process.env.ROOTSFI_TELEGRAM_CHAT_ID || telegramInput.chatId || "").trim(),
    messageThreadId: String(
      process.env.ROOTSFI_TELEGRAM_THREAD_ID || telegramInput.messageThreadId || ""
    ).trim(),
    updateIntervalSeconds: Math.max(
      5,
      clampToNonNegativeInt(
        process.env.ROOTSFI_TELEGRAM_UPDATE_INTERVAL_SECONDS || telegramInput.updateIntervalSeconds,
        INTERNAL_API_DEFAULTS.telegram.updateIntervalSeconds
      )
    ),
    logsPerUpdate: Math.max(
      1,
      clampToNonNegativeInt(
        process.env.ROOTSFI_TELEGRAM_LOGS_PER_UPDATE || telegramInput.logsPerUpdate,
        INTERNAL_API_DEFAULTS.telegram.logsPerUpdate
      )
    ),
    accountsPerUpdate: Math.max(
      1,
      clampToNonNegativeInt(
        process.env.ROOTSFI_TELEGRAM_ACCOUNTS_PER_UPDATE || telegramInput.accountsPerUpdate,
        INTERNAL_API_DEFAULTS.telegram.accountsPerUpdate
      )
    ),
    sendCycleSummary:
      typeof telegramInput.sendCycleSummary === "boolean"
        ? telegramInput.sendCycleSummary
        : INTERNAL_API_DEFAULTS.telegram.sendCycleSummary
  };

  if (telegram.enabled && (!telegram.botToken || !telegram.chatId)) {
    throw new Error(
      "Telegram enabled but botToken/chatId missing. Set config.telegram.botToken + config.telegram.chatId or ROOTSFI_TELEGRAM_BOT_TOKEN + ROOTSFI_TELEGRAM_CHAT_ID."
    );
  }

  const walleyRefundInput = isObject(rawConfig.walleyRefund) ? rawConfig.walleyRefund : {};
  const walleyRefundEnabledFlag = parseBooleanFlag(process.env.ROOTSFI_WALLEY_REFUND_ENABLED);
  const walleyRefundParallelEnabledFlag = parseBooleanFlag(process.env.ROOTSFI_WALLEY_REFUND_PARALLEL_ENABLED);
  const walleyRefund = {
    enabled:
      walleyRefundEnabledFlag !== null
        ? walleyRefundEnabledFlag
        : (
            typeof walleyRefundInput.enabled === "boolean"
              ? walleyRefundInput.enabled
              : INTERNAL_API_DEFAULTS.walleyRefund.enabled
          ),
    projectDir: String(
      process.env.ROOTSFI_WALLEY_PROJECT_DIR ||
      walleyRefundInput.projectDir ||
      INTERNAL_API_DEFAULTS.walleyRefund.projectDir
    ).trim(),
    tokenSymbol: String(
      process.env.ROOTSFI_WALLEY_TOKEN_SYMBOL ||
      walleyRefundInput.tokenSymbol ||
      INTERNAL_API_DEFAULTS.walleyRefund.tokenSymbol
    ).trim() || "CC",
    reasonPrefix: String(
      process.env.ROOTSFI_WALLEY_REASON_PREFIX ||
      walleyRefundInput.reasonPrefix ||
      INTERNAL_API_DEFAULTS.walleyRefund.reasonPrefix
    ).trim() || "rootsfi-refund",
    autoSyncSenderMap:
      typeof walleyRefundInput.autoSyncSenderMap === "boolean"
        ? walleyRefundInput.autoSyncSenderMap
        : INTERNAL_API_DEFAULTS.walleyRefund.autoSyncSenderMap,
    parallelEnabled:
      walleyRefundParallelEnabledFlag !== null
        ? walleyRefundParallelEnabledFlag
        : (
            typeof walleyRefundInput.parallelEnabled === "boolean"
              ? walleyRefundInput.parallelEnabled
              : INTERNAL_API_DEFAULTS.walleyRefund.parallelEnabled
          ),
    maxConcurrency: Math.max(
      1,
      clampToNonNegativeInt(
        process.env.ROOTSFI_WALLEY_REFUND_MAX_CONCURRENCY || walleyRefundInput.maxConcurrency,
        INTERNAL_API_DEFAULTS.walleyRefund.maxConcurrency
      )
    ),
    parallelJitterMinSeconds: Math.max(
      0,
      clampToNonNegativeInt(
        process.env.ROOTSFI_WALLEY_REFUND_PARALLEL_JITTER_MIN_SECONDS || walleyRefundInput.parallelJitterMinSeconds,
        INTERNAL_API_DEFAULTS.walleyRefund.parallelJitterMinSeconds
      )
    ),
    parallelJitterMaxSeconds: Math.max(
      0,
      clampToNonNegativeInt(
        process.env.ROOTSFI_WALLEY_REFUND_PARALLEL_JITTER_MAX_SECONDS || walleyRefundInput.parallelJitterMaxSeconds,
        INTERNAL_API_DEFAULTS.walleyRefund.parallelJitterMaxSeconds
      )
    ),
    senderMap: isObject(walleyRefundInput.senderMap) ? { ...walleyRefundInput.senderMap } : {}
  };

  if (walleyRefund.parallelJitterMaxSeconds < walleyRefund.parallelJitterMinSeconds) {
    throw new Error(
      "config.walleyRefund.parallelJitterMaxSeconds must be >= config.walleyRefund.parallelJitterMinSeconds"
    );
  }

  if (walleyRefund.enabled && !walleyRefund.projectDir) {
    throw new Error("config.walleyRefund.projectDir must be a non-empty string when enabled");
  }

  const sendInput = isObject(rawConfig.send) ? rawConfig.send : {};
  const maxTransfersPerHour = Math.max(
    1,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(sendInput, "maxTransfersPerHour")
        ? sendInput.maxTransfersPerHour
        : INTERNAL_API_DEFAULTS.send.maxTransfersPerHour,
      INTERNAL_API_DEFAULTS.send.maxTransfersPerHour
    )
  );
  if (maxTransfersPerHour < 1) {
    throw new Error("config.send.maxTransfersPerHour must be >= 1");
  }

  const legacyDelayBetweenTx = isObject(sendInput.delayBetweenTx)
    ? sendInput.delayBetweenTx
    : sendInput.delayBetweenTx;
  const legacyDelayBetweenTxMin = isObject(legacyDelayBetweenTx)
    ? (
        Object.prototype.hasOwnProperty.call(legacyDelayBetweenTx, "min")
          ? legacyDelayBetweenTx.min
          : legacyDelayBetweenTx.max
      )
    : legacyDelayBetweenTx;
  const legacyDelayBetweenTxMax = isObject(legacyDelayBetweenTx)
    ? (
        Object.prototype.hasOwnProperty.call(legacyDelayBetweenTx, "max")
          ? legacyDelayBetweenTx.max
          : legacyDelayBetweenTx.min
      )
    : legacyDelayBetweenTx;

  const minDelayTxSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "minDelayTxSeconds")
      ? sendInput.minDelayTxSeconds
      : (
          Object.prototype.hasOwnProperty.call(sendInput, "mindelayTxSeconds")
            ? sendInput.mindelayTxSeconds
            : (
                Object.prototype.hasOwnProperty.call(sendInput, "delayTxSeconds")
                  ? sendInput.delayTxSeconds
                  : legacyDelayBetweenTxMin
              )
        ),
    INTERNAL_API_DEFAULTS.send.minDelayTxSeconds
  );
  const maxDelayTxSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "maxDelayTxSeconds")
      ? sendInput.maxDelayTxSeconds
      : (
          Object.prototype.hasOwnProperty.call(sendInput, "maxdelayTxSeconds")
            ? sendInput.maxdelayTxSeconds
            : (
                Object.prototype.hasOwnProperty.call(sendInput, "delayTxSeconds")
                  ? sendInput.delayTxSeconds
                  : legacyDelayBetweenTxMax
              )
        ),
    INTERNAL_API_DEFAULTS.send.maxDelayTxSeconds
  );

  if (maxDelayTxSeconds < minDelayTxSeconds) {
    throw new Error("config.send.maxDelayTxSeconds must be >= config.send.minDelayTxSeconds");
  }

  const parallelJitterMinSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "parallelJitterMinSeconds")
      ? sendInput.parallelJitterMinSeconds
      : minDelayTxSeconds,
    minDelayTxSeconds
  );
  const parallelJitterMaxSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "parallelJitterMaxSeconds")
      ? sendInput.parallelJitterMaxSeconds
      : maxDelayTxSeconds,
    maxDelayTxSeconds
  );

  if (parallelJitterMaxSeconds < parallelJitterMinSeconds) {
    throw new Error("config.send.parallelJitterMaxSeconds must be >= config.send.parallelJitterMinSeconds");
  }

  const delayCycleSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "delayCycleSeconds")
      ? sendInput.delayCycleSeconds
      : (
          Object.prototype.hasOwnProperty.call(sendInput, "delayBetweenCycles")
            ? sendInput.delayBetweenCycles
            : (
                Object.prototype.hasOwnProperty.call(sendInput, "delayBetweenCycle")
                  ? sendInput.delayBetweenCycle
                  : sendInput.loopDelaySeconds
              )
        ),
    INTERNAL_API_DEFAULTS.send.delayCycleSeconds
  );
  const hourlyCapPollSeconds = Math.max(
    5,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(sendInput, "hourlyCapPollSeconds")
        ? sendInput.hourlyCapPollSeconds
        : (
            Object.prototype.hasOwnProperty.call(sendInput, "hourlyCapCheckSeconds")
              ? sendInput.hourlyCapCheckSeconds
              : INTERNAL_API_DEFAULTS.send.hourlyCapPollSeconds
          ),
      INTERNAL_API_DEFAULTS.send.hourlyCapPollSeconds
    )
  );

  const randomAmount = normalizeRandomAmountConfig(
    sendInput.randomAmount,
    INTERNAL_API_DEFAULTS.send.randomAmount,
    "config.send.randomAmount"
  );
  const tierAmounts = normalizeTierAmountsConfig(
    sendInput.tierAmounts,
    INTERNAL_API_DEFAULTS.send.tierAmounts,
    "config.send.tierAmounts"
  );

  const sequentialAllRounds =
    typeof sendInput.sequentialAllRounds === "boolean"
      ? sendInput.sequentialAllRounds
      : (
          typeof sendInput.parallelEnabled === "boolean"
            ? !sendInput.parallelEnabled
            : INTERNAL_API_DEFAULTS.send.sequentialAllRounds
        );

  const workers = Math.max(
    1,
    clampToNonNegativeInt(
      sendInput.workers,
      INTERNAL_API_DEFAULTS.send.workers
    )
  );
  const maxDeferredWaitSeconds = Math.max(
    1,
    clampToNonNegativeInt(
      sendInput.maxDeferredWaitSeconds,
      INTERNAL_API_DEFAULTS.send.maxDeferredWaitSeconds
    )
  );
  const tierDailyTxCap = normalizeTierDailyTxCapConfig(
    sendInput.tierDailyTxCap,
    INTERNAL_API_DEFAULTS.send.tierDailyTxCap,
    "config.send.tierDailyTxCap"
  );

  const send = {
    maxLoopTx: maxTransfersPerHour,
    maxTransfersPerHour,
    minDelayTxSeconds,
    maxDelayTxSeconds,
    parallelJitterMinSeconds,
    parallelJitterMaxSeconds,
    delayCycleSeconds,
    hourlyCapPollSeconds,
    sequentialAllRounds,
    workers,
    maxDeferredWaitSeconds,
    tierAmounts,
    tierDailyTxCap,
    randomAmount
  };

  const safetyInput = isObject(rawConfig.safety) ? rawConfig.safety : {};
  const safety = {
    minScoreThreshold: clampToNonNegativeInt(
      safetyInput.minScoreThreshold,
      INTERNAL_API_DEFAULTS.safety.minScoreThreshold
    ),
    minHoldBalanceCc: clampToNonNegativeInt(
      safetyInput.minHoldBalanceCc,
      INTERNAL_API_DEFAULTS.safety.minHoldBalanceCc
    )
  };

  return {
    baseUrl: INTERNAL_API_DEFAULTS.baseUrl,
    paths: { ...INTERNAL_API_DEFAULTS.paths },
    headers: {
      ...INTERNAL_API_DEFAULTS.headers,
      extra: {},
      cookie: ""
    },
    http,
    requestPacing,
    recipientFile,
    session,
    send,
    ui,
    telegram,
    walleyRefund,
    safety
  };
}

function normalizeAccounts(rawAccounts) {
  if (!isObject(rawAccounts)) {
    throw new Error("accounts.json must be a JSON object");
  }

  if (!Array.isArray(rawAccounts.accounts) || rawAccounts.accounts.length === 0) {
    throw new Error("accounts.json must contain a non-empty accounts array");
  }

  const accounts = rawAccounts.accounts.map((entry, index) => {
    if (!isObject(entry)) {
      throw new Error(`accounts[${index}] must be an object`);
    }

    const name = String(entry.name || "").trim();
    const email = String(entry.email || "").trim();
    const address = String(entry.address || entry.cantonPartyId || "").trim();

    if (!name) {
      throw new Error(`accounts[${index}].name is required`);
    }

    if (!email || !email.includes("@")) {
      throw new Error(`accounts[${index}].email is invalid`);
    }

    return {
      name,
      email,
      address
    };
  });

  const names = new Set();
  for (const account of accounts) {
    if (names.has(account.name)) {
      throw new Error(`Duplicate account name in accounts.json: ${account.name}`);
    }
    names.add(account.name);
  }

  const defaultAccount = String(rawAccounts.defaultAccount || accounts[0].name).trim();
  return { defaultAccount, accounts };
}

function extractLegacyAccountCookies(rawAccounts) {
  const cookieMap = new Map();
  if (!isObject(rawAccounts) || !Array.isArray(rawAccounts.accounts)) {
    return cookieMap;
  }

  for (const entry of rawAccounts.accounts) {
    if (!isObject(entry)) {
      continue;
    }

    const name = String(entry.name || "").trim();
    const cookie = String(entry.cookie || "").trim();
    if (name && cookie) {
      cookieMap.set(name, cookie);
    }
  }

  return cookieMap;
}

function selectAccount(accountsConfig, preferredName) {
  const targetName = String(preferredName || accountsConfig.defaultAccount || "").trim();
  const found = accountsConfig.accounts.find((account) => account.name === targetName);
  if (!found) {
    const available = accountsConfig.accounts.map((account) => account.name).join(", ");
    throw new Error(`Account '${targetName}' not found. Available accounts: ${available}`);
  }
  return found;
}

async function promptOtpCode() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const code = await rl.question("Enter OTP code: ");
    return String(code || "").trim();
  } finally {
    rl.close();
  }
}

async function acquireBrowserChallengeSlot() {
  if (activeBrowserChallenges < BROWSER_CHALLENGE_MAX_CONCURRENT) {
    activeBrowserChallenges += 1;
    console.log(
      `[browser-queue] Slot acquired (${activeBrowserChallenges}/${BROWSER_CHALLENGE_MAX_CONCURRENT})`
    );
    return;
  }

  const queuePosition = browserChallengeWaitQueue.length + 1;
  const queuedAt = Date.now();
  console.log(
    `[browser-queue] Challenge queued (position ${queuePosition}), ` +
      `active=${activeBrowserChallenges}/${BROWSER_CHALLENGE_MAX_CONCURRENT}`
  );

  await new Promise((resolve) => {
    browserChallengeWaitQueue.push(resolve);
  });

  const waitedSeconds = Math.max(1, Math.round((Date.now() - queuedAt) / 1000));
  console.log(
    `[browser-queue] Slot acquired after waiting ${waitedSeconds}s ` +
      `(${activeBrowserChallenges}/${BROWSER_CHALLENGE_MAX_CONCURRENT})`
  );
}

function applySessionReuseConcurrencyLimit(limitCandidate) {
  const parsed = clampToNonNegativeInt(limitCandidate, SESSION_REUSE_MAX_CONCURRENT);
  SESSION_REUSE_MAX_CONCURRENT = Math.max(1, parsed);
}

async function acquireSessionReuseSlot(accountLogTag = null) {
  const prefix = accountLogTag ? `[${accountLogTag}] ` : "";

  if (activeSessionReuseChallenges < SESSION_REUSE_MAX_CONCURRENT) {
    activeSessionReuseChallenges += 1;
    console.log(
      `${prefix}[session-queue] Slot acquired (${activeSessionReuseChallenges}/${SESSION_REUSE_MAX_CONCURRENT})`
    );
    return;
  }

  const queuePosition = sessionReuseWaitQueue.length + 1;
  const queuedAt = Date.now();
  console.log(
    `${prefix}[session-queue] Session reuse queued (position ${queuePosition}), ` +
      `active=${activeSessionReuseChallenges}/${SESSION_REUSE_MAX_CONCURRENT}`
  );

  await new Promise((resolve) => {
    sessionReuseWaitQueue.push(resolve);
  });

  const waitedSeconds = Math.max(1, Math.round((Date.now() - queuedAt) / 1000));
  console.log(
    `${prefix}[session-queue] Slot acquired after waiting ${waitedSeconds}s ` +
      `(${activeSessionReuseChallenges}/${SESSION_REUSE_MAX_CONCURRENT})`
  );
}

function releaseSessionReuseSlot(accountLogTag = null) {
  const prefix = accountLogTag ? `[${accountLogTag}] ` : "";

  if (activeSessionReuseChallenges > 0) {
    activeSessionReuseChallenges -= 1;
  }

  const next = sessionReuseWaitQueue.shift();
  if (next) {
    activeSessionReuseChallenges += 1;
    next();
  }

  console.log(
    `${prefix}[session-queue] Slot released ` +
      `(active=${activeSessionReuseChallenges}/${SESSION_REUSE_MAX_CONCURRENT}, queue=${sessionReuseWaitQueue.length})`
  );
}

function releaseBrowserChallengeSlot() {
  if (activeBrowserChallenges > 0) {
    activeBrowserChallenges -= 1;
  }

  const next = browserChallengeWaitQueue.shift();
  if (next) {
    activeBrowserChallenges += 1;
    next();
  }

  console.log(
    `[browser-queue] Slot released ` +
      `(active=${activeBrowserChallenges}/${BROWSER_CHALLENGE_MAX_CONCURRENT}, queue=${browserChallengeWaitQueue.length})`
  );
}

function isSecurityCookieName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  return normalized === "_vcrcs" || normalized.startsWith("_vc");
}

function cacheSecurityCookiesFromMap(cookieMap, sourceLabel = "unknown") {
  if (!(cookieMap instanceof Map)) {
    return 0;
  }

  let updated = 0;
  for (const [name, value] of cookieMap.entries()) {
    if (!isSecurityCookieName(name)) {
      continue;
    }

    const key = String(name || "").trim();
    const val = String(value || "").trim();
    if (!key || !val) {
      continue;
    }

    const previousValue = cachedSecurityCookies.get(key);
    if (previousValue !== val) {
      cachedSecurityCookies.set(key, val);
      updated += 1;
    }
  }

  if (updated > 0) {
    console.log(`[cookie-cache] Updated ${updated} security cookie(s) from ${sourceLabel}`);
  }

  return updated;
}

function buildCachedSecurityCookieMap() {
  return new Map(cachedSecurityCookies);
}

async function readAllBrowserCookies(page) {
  const merged = new Map();

  try {
    const pageCookies = await page.cookies();
    for (const cookie of pageCookies) {
      if (cookie && cookie.name) {
        merged.set(cookie.name, cookie.value);
      }
    }
  } catch (error) {
    console.log(`[browser] page.cookies() issue: ${error.message}`);
  }

  try {
    const contextCookies = await page.browserContext().cookies();
    for (const cookie of contextCookies) {
      if (cookie && cookie.name) {
        merged.set(cookie.name, cookie.value);
      }
    }
  } catch (error) {
    console.log(`[browser] browserContext.cookies() issue: ${error.message}`);
  }

  return Array.from(merged.entries()).map(([name, value]) => ({ name, value }));
}

function getBrowserChallengeCooldownRemainingSeconds() {
  if (!Number.isFinite(browserChallengeRateLimitedUntilMs) || browserChallengeRateLimitedUntilMs <= 0) {
    return 0;
  }

  const remainingMs = browserChallengeRateLimitedUntilMs - Date.now();
  if (remainingMs <= 0) {
    browserChallengeRateLimitedUntilMs = 0;
    return 0;
  }

  return Math.max(1, Math.ceil(remainingMs / 1000));
}

function markBrowserChallengeRateLimited(cooldownSeconds = 120) {
  const boundedSeconds = Math.max(30, clampToNonNegativeInt(cooldownSeconds, 120));
  const nextUntilMs = Date.now() + (boundedSeconds * 1000);
  browserChallengeRateLimitedUntilMs = Math.max(browserChallengeRateLimitedUntilMs, nextUntilMs);
  console.log(`[browser] Rate-limit cooldown armed for ${boundedSeconds}s`);
}

async function solveBrowserChallenge(baseUrl, onboardPath, userAgent, headless = true) {
  if (!puppeteer) {
    throw new Error("Puppeteer is not installed. Run: npm install puppeteer-extra puppeteer-extra-plugin-stealth");
  }

  await acquireBrowserChallengeSlot();
  let browser = null;
  let trackedPid = null;
  try {
    console.log("[browser] Launching browser to solve Vercel challenge...");
    console.log("[browser] Mode: " + (headless ? "headless" : "visible"));
    console.log(`[browser] Launch timeout: ${Math.round(BROWSER_LAUNCH_TIMEOUT_MS / 1000)}s`);

    browser = await puppeteer.launch({
      headless: headless,
      timeout: BROWSER_LAUNCH_TIMEOUT_MS,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
        "--disable-dev-shm-usage",
        "--window-size=1280,800"
      ],
      defaultViewport: null
    });
    trackedPid = trackBrowserPid(browser);

    const page = await browser.newPage();

    // Keep browser challenge fingerprint close to API requests.
    await page.setUserAgent(String(userAgent || INTERNAL_API_DEFAULTS.headers.userAgent));

    await page.setExtraHTTPHeaders({
      "Accept-Language": "en-US,en;q=0.9"
    });

    const targetUrl = new URL(onboardPath, baseUrl).toString();
    console.log(`[browser] Navigating to ${targetUrl}`);

    let response;
    try {
      response = await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: 30000
      });
    } catch (navError) {
      console.log(`[browser] Navigation issue: ${navError.message}`);
    }

    const status = response ? response.status() : 0;
    console.log(`[browser] Initial response status: ${status}`);
    const probeAttempts = status === 429
      ? BROWSER_CHALLENGE_MAX_ATTEMPTS_ON_429
      : BROWSER_CHALLENGE_MAX_ATTEMPTS;

    if (status === 429) {
      console.log(`[browser] 429 detected, using 429 challenge mode (${probeAttempts} checks).`);
    }

    console.log("[browser] Waiting for Vercel challenge to resolve...");

    for (let i = 0; i < probeAttempts; i++) {
      await sleep(2000);
      const currentUrl = page.url();
      const cookies = await page.cookies();

      console.log(`[browser] Attempt ${i + 1}: URL=${currentUrl.slice(0, 60)}..., ${cookies.length} cookies`);

      const hasVercelCookie = cookies.some(c => c.name.startsWith("_vc"));
      if (hasVercelCookie) {
        console.log("[browser] Vercel security cookies obtained!");
        break;
      }

      if (currentUrl.includes("/onboard") && cookies.length > 0) {
        console.log("[browser] Page loaded with cookies");
        break;
      }
    }

    console.log("[browser] Final cookie extraction...");
    await sleep(1000);

    let cookies = await page.cookies();

    if (cookies.length === 0 && status === 429) {
      console.log(
        `[browser] Still no cookies after challenge on HTTP 429. ` +
          `Cooling down ${Math.round(BROWSER_CHALLENGE_RETRY_DELAY_MS / 1000)}s then running quick retry...`
      );
      await sleep(BROWSER_CHALLENGE_RETRY_DELAY_MS);

      try {
        await page.reload({
          waitUntil: "domcontentloaded",
          timeout: 30000
        });
      } catch (reloadError) {
        console.log(`[browser] Reload issue after 429: ${reloadError.message}`);
      }

      for (let i = 0; i < BROWSER_CHALLENGE_RETRY_ATTEMPTS_ON_429; i += 1) {
        await sleep(2000);
        cookies = await page.cookies();
        const hasVercelCookie = cookies.some((cookie) => String(cookie.name || "").startsWith("_vc"));
        console.log(`[browser] Retry attempt ${i + 1}: ${cookies.length} cookies`);
        if (hasVercelCookie || cookies.length > 0) {
          console.log("[browser] Cookies detected after 429 retry.");
          break;
        }
      }
    }

    console.log(`[browser] Extracted ${cookies.length} cookies:`);

    const cookieMap = new Map();
    for (const cookie of cookies) {
      cookieMap.set(cookie.name, cookie.value);
      const valuePreview = cookie.value.length > 40 ? cookie.value.slice(0, 40) + "..." : cookie.value;
      console.log(`[browser]   ${cookie.name}=${valuePreview}`);
    }

    cacheSecurityCookiesFromMap(cookieMap, "browser-challenge");

    return cookieMap;
  } finally {
    if (browser) {
      try {
        await browser.close();
        console.log("[browser] Browser closed");
      } catch (closeError) {
        const closeMessage = String(
          closeError && closeError.message ? closeError.message : closeError || "unknown"
        );
        console.log(`[browser] Browser close warning: ${closeMessage}`);
        // Force kill Chromium if close() failed to prevent zombie
        if (trackedPid) {
          try { process.kill(trackedPid, "SIGKILL"); console.log(`[browser] Force-killed Chromium pid ${trackedPid}`); }
          catch {}
        }
      }
      untrackBrowserPid(trackedPid);
    }
    releaseBrowserChallengeSlot();
  }
}

class RootsFiApiClient {
  constructor(config) {
    this.baseUrl = config.baseUrl;
    this.paths = config.paths;
    this.headers = config.headers;
    this.http = config.http;
    this.requestPacing = config.requestPacing;
    this.cookieJar = new Map();
    this.initializeCookiesFromConfig();
  }

  initializeCookiesFromConfig() {
    const configCookie = this.headers.cookie;
    if (configCookie) {
      this.parseCookieString(configCookie);
    }
  }

  parseCookieString(cookieStr) {
    if (!cookieStr) return;
    const pairs = cookieStr.split(";");
    for (const pair of pairs) {
      const eqIndex = pair.indexOf("=");
      if (eqIndex > 0) {
        const name = pair.slice(0, eqIndex).trim();
        const value = pair.slice(eqIndex + 1).trim();
        if (name) {
          this.cookieJar.set(name, value);
        }
      }
    }
  }

  parseSetCookieHeaders(headers) {
    const setCookieHeaders = [];

    if (typeof headers.getSetCookie === "function") {
      const values = headers.getSetCookie();
      if (Array.isArray(values) && values.length > 0) {
        setCookieHeaders.push(...values);
      }
    }

    if (setCookieHeaders.length === 0) {
      const combined = headers.get("set-cookie");
      if (combined) {
        setCookieHeaders.push(...this.splitCombinedSetCookieHeader(combined));
      }
    }

    for (const setCookie of setCookieHeaders) {
      const parts = setCookie.split(";")[0];
      const eqIndex = parts.indexOf("=");
      if (eqIndex > 0) {
        const name = parts.slice(0, eqIndex).trim();
        const value = parts.slice(eqIndex + 1).trim();
        if (name) {
          this.cookieJar.set(name, value);
        }
      }
    }
  }

  splitCombinedSetCookieHeader(headerValue) {
    if (!headerValue) {
      return [];
    }

    const parts = [];
    let current = "";
    let inExpiresAttr = false;

    for (let i = 0; i < headerValue.length; i += 1) {
      const next8 = headerValue.slice(i, i + 8).toLowerCase();
      if (next8 === "expires=") {
        inExpiresAttr = true;
      }

      const ch = headerValue[i];
      if (ch === "," && !inExpiresAttr) {
        const trimmed = current.trim();
        if (trimmed) {
          parts.push(trimmed);
        }
        current = "";
        continue;
      }

      current += ch;

      if (inExpiresAttr && ch === ";") {
        inExpiresAttr = false;
      }
    }

    const last = current.trim();
    if (last) {
      parts.push(last);
    }

    return parts;
  }

  mergeCookies(cookieMap) {
    for (const [name, value] of cookieMap) {
      this.cookieJar.set(name, value);
    }
  }

  hasValidSession() {
    return this.hasSecurityCookie() || this.hasAccountSessionCookie();
  }

  hasSecurityCookie() {
    return this.cookieJar.has("_vcrcs");
  }

  hasAccountSessionCookie() {
    return this.cookieJar.has("cantonbridge_session");
  }

  logCookieStatus(context) {
    console.log(
      `[info] Cookie status (${context}): _vcrcs=${this.hasSecurityCookie()} cantonbridge_session=${this.hasAccountSessionCookie()} total=${this.cookieJar.size}`
    );
  }

  getCookieStatus() {
    return {
      security: this.hasSecurityCookie(),
      session: this.hasAccountSessionCookie(),
      total: this.cookieJar.size
    };
  }

  getCookieHeader() {
    if (this.cookieJar.size === 0) {
      return "";
    }
    const pairs = [];
    for (const [name, value] of this.cookieJar) {
      pairs.push(`${name}=${value}`);
    }
    return pairs.join("; ");
  }

  buildUrl(endpointPath) {
    return new URL(endpointPath, this.baseUrl).toString();
  }

  buildHeaders(method, refererPath, hasBody, accept = "*/*") {
    const headers = {
      accept,
      "accept-language": this.headers.acceptLanguage,
      referer: this.buildUrl(refererPath),
      "user-agent": this.headers.userAgent
    };

    if (this.headers.sendBrowserClientHints) {
      headers["sec-ch-ua"] = this.headers.secChUa;
      headers["sec-ch-ua-mobile"] = this.headers.secChUaMobile;
      headers["sec-ch-ua-platform"] = this.headers.secChUaPlatform;
      headers["sec-fetch-dest"] = this.headers.secFetchDest;
      headers["sec-fetch-mode"] = this.headers.secFetchMode;
      headers["sec-fetch-site"] = this.headers.secFetchSite;
      headers.priority = this.headers.priority;
    }

    const cookieHeader = this.getCookieHeader();
    if (cookieHeader) {
      headers.cookie = cookieHeader;
    }

    for (const [key, value] of Object.entries(this.headers.extra)) {
      headers[key] = value;
    }

    if (method !== "GET") {
      headers.origin = this.baseUrl;
      if (hasBody) {
        headers["content-type"] = "application/json";
      }
    }

    return headers;
  }

  extractApiError(payload) {
    if (!isObject(payload)) {
      return "unknown API error";
    }

    if (isObject(payload.error)) {
      if (typeof payload.error.message === "string" && payload.error.message.trim()) {
        return payload.error.message;
      }
      if (typeof payload.error.code === "string" && payload.error.code.trim()) {
        return payload.error.code;
      }
    }

    if (typeof payload.error === "string" && payload.error.trim()) {
      return payload.error;
    }
    if (typeof payload.message === "string" && payload.message.trim()) {
      return payload.message;
    }

    if (isObject(payload.data) && typeof payload.data.message === "string" && payload.data.message.trim()) {
      return payload.data.message;
    }

    const compact = JSON.stringify(payload);
    if (compact && compact !== "{}") {
      return compact.slice(0, 240);
    }

    return "unknown API error";
  }

  shouldRetry(error) {
    const status = Number(error && error.status);
    if (status === 429 || (status >= 500 && status < 600)) {
      return true;
    }

    const message = String(error && error.message ? error.message : "").toLowerCase();
    return (
      message.includes("timed out") ||
      message.includes("fetch failed") ||
      message.includes("network") ||
      message.includes("aborted")
    );
  }

  async waitForPacing() {
    const min = this.requestPacing.minDelayMs;
    const jitter = this.requestPacing.jitterMs;
    const delay = min + (jitter > 0 ? randomIntInclusive(0, jitter) : 0);

    if (delay > 0) {
      await sleep(delay);
    }
  }

  async waitForBackoff(attempt) {
    const base = this.http.retryBaseDelayMs;
    if (base <= 0) {
      return;
    }

    const exponential = base * Math.pow(2, attempt - 1);
    const jitter = randomIntInclusive(0, Math.max(1, Math.floor(base / 2)));
    await sleep(exponential + jitter);
  }

  async requestJson(method, endpointPath, options = {}) {
    const body = options.body;
    const refererPath = options.refererPath || this.paths.onboard;
    const accept = options.accept || "*/*";
    const timeoutMs = clampToNonNegativeInt(options.timeoutMs, this.http.timeoutMs);
    const maxAttempts = 1 + this.http.maxRetries;
    // Allow disabling infinite timeout retry for non-critical endpoints
    const skipInfiniteTimeoutRetry = Boolean(options.skipInfiniteTimeoutRetry);

    let lastError = null;
    let attempt = 0;
    let consecutiveTimeouts = 0;

    while (true) {
      attempt += 1;
      const abortController = new AbortController();
      const timeoutId = setTimeout(() => abortController.abort(new Error("Request timed out")), timeoutMs);

      try {
        const response = await fetch(this.buildUrl(endpointPath), {
          method,
          headers: this.buildHeaders(method, refererPath, body !== undefined, accept),
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: abortController.signal
        });

        clearTimeout(timeoutId);
        
        // Reset consecutive timeout counter on success
        consecutiveTimeouts = 0;

        this.parseSetCookieHeaders(response.headers);

        const contentType = String(response.headers.get("content-type") || "");
        const vercelMitigated = String(response.headers.get("x-vercel-mitigated") || "");
        const vercelRequestId = String(response.headers.get("x-vercel-id") || "");
        const text = await response.text();
        let payload = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch {
            if (text.trim().startsWith("<")) {
              if (vercelMitigated.toLowerCase() === "challenge") {
                const requestRef = vercelRequestId ? ` requestId=${vercelRequestId}` : "";
                throw new Error(
                  `Blocked by Vercel Security Checkpoint at ${endpointPath} (HTTP ${response.status}).` +
                    `${requestRef} Complete browser verification first, then place your session cookie in ` +
                    "tokens.json (selected account token profile) and retry."
                );
              }

              throw new Error(
                `Expected JSON from ${endpointPath}, but received HTML content (HTTP ${response.status}, content-type=${contentType || "unknown"}).`
              );
            }
            throw new Error(`Expected JSON response from ${endpointPath}, got: ${text.slice(0, 200)}`);
          }
        }

        if (!response.ok) {
          const requestError = new Error(
            `HTTP ${response.status} from ${endpointPath}: ${this.extractApiError(payload)}`
          );
          requestError.status = response.status;
          throw requestError;
        }

        if (isObject(payload) && Object.prototype.hasOwnProperty.call(payload, "success") && payload.success === false) {
          throw new Error(`API failure from ${endpointPath}: ${this.extractApiError(payload)}`);
        }

        await this.waitForPacing();
        return payload;
      } catch (error) {
        clearTimeout(timeoutId);
        lastError = error;

        // TIMEOUT errors: retry dengan exponential backoff, tapi limit consecutive timeouts
        // UNLESS skipInfiniteTimeoutRetry is set (for non-critical endpoints)
        if (isTimeoutError(error)) {
          if (skipInfiniteTimeoutRetry) {
            // For non-critical endpoints, just throw timeout error immediately
            throw error;
          }
          
          consecutiveTimeouts += 1;
          
          // Check if we've hit max consecutive timeouts - trigger soft restart
          if (consecutiveTimeouts >= TIMEOUT_MAX_CONSECUTIVE) {
            console.log(
              `[timeout-retry] ${method} ${endpointPath} hit ${consecutiveTimeouts} consecutive timeouts. ` +
              `Triggering SOFT RESTART for this account...`
            );
            throw new SoftRestartError(
              `Max consecutive timeouts (${TIMEOUT_MAX_CONSECUTIVE}) reached for ${method} ${endpointPath}`,
              consecutiveTimeouts
            );
          }
          
          const backoffMs = calculateTimeoutBackoffMs(attempt);
          const backoffSec = Math.round(backoffMs / 1000);
          console.log(
            `[timeout-retry] ${method} ${endpointPath} timed out (attempt ${attempt}, consecutive: ${consecutiveTimeouts}/${TIMEOUT_MAX_CONSECUTIVE}). ` +
            `Retrying in ${backoffSec}s (max: ${TIMEOUT_BACKOFF_MAX_MS / 1000}s)...`
          );
          await sleep(backoffMs);
          continue; // infinite retry untuk timeout
        }

        // Non-timeout errors: gunakan maxAttempts normal
        if (attempt < maxAttempts && this.shouldRetry(error)) {
          await this.waitForBackoff(attempt);
          continue;
        }

        throw error;
      }
    }
  }

  async preflightOnboard() {
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(new Error("Request timed out")), this.http.timeoutMs);

    try {
      const cookieHeader = this.getCookieHeader();
      const headers = {
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": this.headers.acceptLanguage,
        "user-agent": this.headers.userAgent
      };
      if (cookieHeader) {
        headers.cookie = cookieHeader;
      }

      const response = await fetch(this.buildUrl(this.paths.onboard), {
        method: "GET",
        headers,
        signal: abortController.signal
      });

      this.parseSetCookieHeaders(response.headers);

      if (!response.ok) {
        const err = new Error(`Failed preflight GET ${this.paths.onboard}: HTTP ${response.status}`);
        err.status = response.status;
        throw err;
      }

      // Preflight only needs headers/cookies. Avoid waiting full HTML body to prevent stalls.
      if (response.body && typeof response.body.cancel === "function") {
        try {
          await response.body.cancel();
        } catch {
          // Ignore body cancel errors; cookies have already been captured from headers.
        }
      }
      await this.waitForPacing();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async syncAccount(refererPath) {
    return this.requestJson("POST", this.paths.syncAccount, { refererPath });
  }

  async getPending(refererPath) {
    return this.requestJson("GET", this.paths.authPending, { refererPath });
  }

  async sendOtp(email) {
    return this.requestJson("POST", this.paths.sendOtp, {
      refererPath: this.paths.onboard,
      body: { email }
    });
  }

  async verifyOtp(payload) {
    return this.requestJson("POST", this.paths.verifyOtp, {
      refererPath: this.paths.onboard,
      body: payload
    });
  }

  async finalizeReturning() {
    return this.requestJson("POST", this.paths.finalizeReturning, {
      refererPath: this.paths.onboard
    });
  }

  async getBalances() {
    return this.requestJson("GET", this.paths.walletBalances, {
      refererPath: this.paths.bridge
    });
  }

  async checkCcCooldown(recipient) {
    return this.requestJson("POST", this.paths.sendCcCooldown, {
      refererPath: this.paths.send,
      body: {
        recipientType: "canton_wallet",
        recipient,
        preferredNetwork: "canton",
        tokenType: "CC",
        instrumentId: "Amulet"
      }
    });
  }

  async resolveSendRecipient(recipient) {
    return this.requestJson("POST", this.paths.sendResolve, {
      refererPath: this.paths.send,
      body: {
        cantonPartyId: recipient,
        preferredNetwork: "canton"
      }
    });
  }

  async recipientPreview(partyId) {
    return this.requestJson("POST", this.paths.recipientPreview, {
      refererPath: this.paths.send,
      body: { partyId }
    });
  }

  async sendCcTransfer(recipient, amount, idempotencyKey) {
    return this.requestJson("POST", this.paths.sendTransfer, {
      refererPath: this.paths.send,
      timeoutMs: 60000,
      // Let upper-layer send flow perform web-like refresh recovery on timeout.
      skipInfiniteTimeoutRetry: true,
      body: {
        recipientType: "canton_wallet",
        recipient,
        amount,
        idempotencyKey,
        preferredNetwork: "canton",
        tokenType: "CC",
        instrumentId: "Amulet"
      }
    });
  }

  async sendCcTransferByUsername(username, amount, idempotencyKey) {
    return this.requestJson("POST", this.paths.sendTransfer, {
      refererPath: this.paths.send,
      timeoutMs: 60000,
      skipInfiniteTimeoutRetry: true,
      body: {
        recipientType: "user",
        recipient: username,
        amount,
        idempotencyKey,
        preferredNetwork: "canton",
        tokenType: "CC",
        instrumentId: "Amulet"
      }
    });
  }

  async getSendHistory() {
    return this.requestJson("GET", this.paths.sendHistory, {
      refererPath: this.paths.send
    });
  }

  async getCcOutgoing() {
    return this.requestJson("GET", this.paths.walletCcOutgoing, {
      refererPath: this.paths.send
    });
  }

  async getRewardsLottery() {
    const endpointPath = this.paths.rewardsLottery || this.paths.rewardsSendLoyaltyDailyTaper;
    // Non-critical endpoint: single attempt with short timeout, no retry
    const abortController = new AbortController();
    const timeoutMs = 10000; // 10 second timeout for rewards
    const timeoutId = setTimeout(() => abortController.abort(new Error("Rewards timeout")), timeoutMs);
    
    try {
      const response = await fetch(this.buildUrl(endpointPath), {
        method: "GET",
        headers: this.buildHeaders("GET", this.paths.rewards || this.paths.bridge, false, "*/*"),
        signal: abortController.signal
      });
      
      clearTimeout(timeoutId);
      this.parseSetCookieHeaders(response.headers);
      
      const text = await response.text();
      if (!text) return {};
      
      try {
        return JSON.parse(text);
      } catch {
        return {};
      }
    } catch (error) {
      clearTimeout(timeoutId);
      // Non-critical - just throw, caller will catch and ignore
      throw error;
    }
  }

  async getRewardsThisWeek() {
    // Non-critical endpoint: single attempt with short timeout, no retry
    const abortController = new AbortController();
    const timeoutMs = 10000; // 10 second timeout for rewards
    const timeoutId = setTimeout(() => abortController.abort(new Error("Rewards timeout")), timeoutMs);
    
    try {
      const response = await fetch(this.buildUrl(this.paths.rewardsSendLoyaltyDailyTaper), {
        method: "GET",
        headers: this.buildHeaders("GET", this.paths.rewards || this.paths.bridge, false, "*/*"),
        signal: abortController.signal
      });
      
      clearTimeout(timeoutId);
      this.parseSetCookieHeaders(response.headers);
      
      const text = await response.text();
      if (!text) return {};
      
      try {
        return JSON.parse(text);
      } catch {
        return {};
      }
    } catch (error) {
      clearTimeout(timeoutId);
      // Non-critical - just throw, caller will catch and ignore
      throw error;
    }
  }

  async getRewardsOverview() {
    const abortController = new AbortController();
    const timeoutMs = 10000;
    const timeoutId = setTimeout(() => abortController.abort(new Error("Rewards overview timeout")), timeoutMs);

    try {
      const response = await fetch(this.buildUrl(this.paths.rewardsOverview), {
        method: "GET",
        headers: this.buildHeaders("GET", this.paths.rewards || this.paths.bridge, false, "*/*"),
        signal: abortController.signal
      });

      clearTimeout(timeoutId);
      this.parseSetCookieHeaders(response.headers);

      const text = await response.text();
      if (!text) return {};

      try {
        return JSON.parse(text);
      } catch {
        return {};
      }
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  async getRewardsPageHtml() {
    const abortController = new AbortController();
    const timeoutMs = 12000;
    const timeoutId = setTimeout(() => abortController.abort(new Error("Rewards page timeout")), timeoutMs);

    try {
      const headers = {
        ...this.buildHeaders(
          "GET",
          this.paths.rewards || this.paths.bridge,
          false,
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin"
      };
      const response = await fetch(this.buildUrl(this.paths.rewards), {
        method: "GET",
        headers,
        signal: abortController.signal
      });

      clearTimeout(timeoutId);
      this.parseSetCookieHeaders(response.headers);

      const text = await response.text();
      const lowerText = String(text || "").toLowerCase();
      if (lowerText.includes("vercel security checkpoint") || lowerText.includes("failed to verify your browser")) {
        const checkpointError = new Error(`Blocked by Vercel Security Checkpoint at ${this.paths.rewards} (HTTP ${response.status}).`);
        checkpointError.status = response.status;
        throw checkpointError;
      }

      if (!response.ok) {
        const error = new Error(`Rewards page request failed (HTTP ${response.status})`);
        error.status = response.status;
        error.bodySnippet = String(text || "").slice(0, 200);
        throw error;
      }

      return String(text || "");
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
}

function printBalanceSummary(data) {
  const balances = isObject(data.balances) ? data.balances : {};
  const wallets = isObject(data.wallets) ? data.wallets : {};

  const ethereum = isObject(balances.ethereum) ? balances.ethereum : {};
  const canton = isObject(balances.canton) ? balances.canton : {};

  const holdingsBySymbol = new Map();
  const pushHoldings = (items) => {
    if (!Array.isArray(items)) {
      return;
    }

    for (const holding of items) {
      if (!isObject(holding)) {
        continue;
      }

      const metadata = isObject(holding.metadata) ? holding.metadata : {};
      const rawSymbol = String(metadata.symbol || holding.instrumentId || "UNKNOWN").trim();
      const symbol = rawSymbol.toUpperCase();
      const amount = String(
        holding.amountDecimal ??
          holding.amount ??
          holding.amountBaseUnits ??
          "0"
      ).trim();

      if (!symbol) {
        continue;
      }

      if (!holdingsBySymbol.has(symbol)) {
        holdingsBySymbol.set(symbol, amount || "0");
      }
    }
  };

  // tokenHoldings usually has richer amount fields; use it before otherHoldings.
  pushHoldings(canton.tokenHoldings);
  pushHoldings(canton.otherHoldings);

  const ccBalance = holdingsBySymbol.get("CC") || "0";
  const cbtcBalance = holdingsBySymbol.get("CBTC") || "0";

  console.log("[balance] Ethereum");
  console.log(`  ETH: ${ethereum.eth ?? "n/a"}`);
  console.log(`  USDC: ${ethereum.usdc ?? "n/a"}`);

  console.log("[balance] Canton");
  console.log(`  USDCx: ${canton.usdcx ?? "n/a"}`);
  console.log(`  CC: ${ccBalance}`);
  console.log(`  Available: ${canton.available ?? "n/a"}`);

  if (holdingsBySymbol.size > 0) {
    console.log("[balance] Canton Holdings");
    for (const [symbol, amount] of holdingsBySymbol.entries()) {
      console.log(`  ${symbol}: ${amount}`);
    }
  }

  console.log("[wallets]");
  console.log(`  ethAddress: ${wallets.ethAddress ?? "n/a"}`);
  console.log(`  cantonPartyId: ${wallets.cantonPartyId ?? "n/a"}`);

  return {
    eth: String(ethereum.eth ?? "n/a"),
    usdc: String(ethereum.usdc ?? "n/a"),
    usdcx: String(canton.usdcx ?? "n/a"),
    cc: String(ccBalance ?? "0"),
    cbtc: String(cbtcBalance ?? "0"),
    ccNumeric: Number(ccBalance) || 0,
    available: canton.available === true || canton.available === "true",
    cantonPartyId: String(wallets.cantonPartyId ?? "n/a")
  };
}

// API call with timeout wrapper
const API_CALL_TIMEOUT_MS = 30000; // 30 seconds
const API_CALL_MAX_RETRIES = 2;

// Timeout infinite backoff settings
const TIMEOUT_BACKOFF_BASE_MS = 5000;       // 5 detik base delay
const TIMEOUT_BACKOFF_MAX_MS = 300000;      // 5 menit max delay
const TIMEOUT_BACKOFF_JITTER_MS = 30000;    // 0-30 detik random jitter
const TIMEOUT_MAX_CONSECUTIVE = 5;          // Max consecutive timeouts before soft restart

// Custom error class for soft restart
class SoftRestartError extends Error {
  constructor(message, consecutiveTimeouts) {
    super(message);
    this.name = "SoftRestartError";
    this.consecutiveTimeouts = consecutiveTimeouts;
    this.isSoftRestart = true;
  }
}

function calculateTimeoutBackoffMs(attempt) {
  // Exponential backoff: 5s, 10s, 20s, 40s, 80s, 160s, 300s (capped)
  const exponential = Math.min(
    TIMEOUT_BACKOFF_BASE_MS * Math.pow(2, attempt - 1),
    TIMEOUT_BACKOFF_MAX_MS
  );
  const jitter = randomIntInclusive(0, TIMEOUT_BACKOFF_JITTER_MS);
  return exponential + jitter;
}

async function apiCallWithTimeout(apiCall, label, timeoutMs = API_CALL_TIMEOUT_MS) {
  const startTime = Date.now();
  
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`${label} timeout after ${timeoutMs}ms`)), timeoutMs);
  });
  
  const result = await Promise.race([apiCall(), timeoutPromise]);
  const elapsed = Date.now() - startTime;
  console.log(`[info] ${label} completed in ${elapsed}ms`);
  return result;
}

async function apiCallWithRetry(
  apiCall,
  label,
  maxRetries = API_CALL_MAX_RETRIES,
  timeoutMs = API_CALL_TIMEOUT_MS,
  options = {}
) {
  let lastError = null;
  let attempt = 0;
  let consecutiveTimeouts = 0;
  const maxConsecutiveTimeouts = Math.max(
    1,
    clampToNonNegativeInt(options.maxConsecutiveTimeouts, TIMEOUT_MAX_CONSECUTIVE)
  );

  while (true) {
    attempt += 1;

    try {
      const attemptLabel = lastError && isTimeoutError(lastError)
        ? `${label} (timeout retry ${attempt})`
        : `${label} (attempt ${attempt}/${maxRetries})`;

      const result = await apiCallWithTimeout(apiCall, attemptLabel, timeoutMs);
      
      // Reset consecutive timeout counter on success
      consecutiveTimeouts = 0;
      return result;
    } catch (error) {
      lastError = error;

      // TIMEOUT errors: retry dengan exponential backoff, tapi limit consecutive timeouts
      if (isTimeoutError(error)) {
        consecutiveTimeouts += 1;
        
        // Check if we've hit max consecutive timeouts - trigger soft restart
        if (consecutiveTimeouts >= maxConsecutiveTimeouts) {
          console.log(
            `[timeout-retry] ${label} hit ${consecutiveTimeouts} consecutive timeouts. ` +
            `Triggering SOFT RESTART for this account...`
          );
          throw new SoftRestartError(
            `Max consecutive timeouts (${maxConsecutiveTimeouts}) reached for ${label}`,
            consecutiveTimeouts
          );
        }
        
        const backoffMs = calculateTimeoutBackoffMs(attempt);
        const backoffSec = Math.round(backoffMs / 1000);
        console.log(
          `[timeout-retry] ${label} timed out (attempt ${attempt}, consecutive: ${consecutiveTimeouts}/${maxConsecutiveTimeouts}). ` +
          `Retrying in ${backoffSec}s (max: ${TIMEOUT_BACKOFF_MAX_MS / 1000}s)...`
        );
        await sleep(backoffMs);
        continue;
      }

      // Non-timeout errors: gunakan maxRetries normal
      console.log(
        `[warn] ${label} attempt ${attempt}/${maxRetries} failed: ${error.message}`
      );

      if (attempt < maxRetries) {
        const retryDelay = 3000 * attempt; // 3s, 6s, etc
        console.log(`[info] Retrying ${label} in ${retryDelay / 1000}s...`);
        await sleep(retryDelay);
        continue;
      }

      // Max retries reached untuk non-timeout errors
      throw lastError;
    }
  }
}

async function recoverSendFlowByRefresh(
  client,
  config,
  onCheckpointRefresh,
  accountLogTag,
  recoveryAttempt,
  maxRecoveryAttempts,
  options = {}
) {
  const recoveryMode = String(options.mode || "light").toLowerCase();
  const reasonLabel = String(options.reason || "send-flow-transient");
  const withBrowserRefresh = recoveryMode === "full-browser";
  const forceConnectionReset = Boolean(options.forceConnectionReset);
  const runPreflight =
    typeof options.runPreflight === "boolean"
      ? options.runPreflight
      : withBrowserRefresh;
  const taggedLog = (message) => console.log(withAccountTag(accountLogTag, message));
  taggedLog(
    `[send-recovery] ${reasonLabel} ${recoveryAttempt}/${maxRecoveryAttempts}: ` +
      (withBrowserRefresh ? "reset connection + browser refresh" : "light reset (no browser)")
  );

  await resetConnectionPool({ forceReset: forceConnectionReset });

  if (withBrowserRefresh && config.session.autoRefreshCheckpoint === false) {
    taggedLog("[send-recovery] Browser refresh is disabled in config. Using connection reset only.");
  } else if (withBrowserRefresh) {
    try {
      const browserCookies = await solveBrowserChallenge(
        config.baseUrl,
        config.paths.onboard,
        config.headers.userAgent,
        true
      );
      client.mergeCookies(browserCookies);
      if (typeof onCheckpointRefresh === "function") {
        onCheckpointRefresh();
      }
      client.logCookieStatus("after send-recovery browser refresh");
    } catch (error) {
      taggedLog(`[warn] Send recovery browser refresh failed: ${error.message}`);
    }
  }

  if (runPreflight) {
    try {
      await client.preflightOnboard();
      taggedLog("[send-recovery] Preflight check completed");
    } catch (error) {
      taggedLog(`[warn] Send recovery preflight failed: ${error.message}`);
    }
  } else {
    taggedLog("[send-recovery] Skipping preflight in light mode");
  }

  const settleDelayMs = runPreflight
    ? Math.max(
        1000,
        clampToNonNegativeInt(config.session.checkpointSettleDelayMs, 3500)
      )
    : 2000;
  await sleep(settleDelayMs);
}

async function executeCcSendFlow(client, sendRequest, config, onCheckpointRefresh, accountLogTag = null) {
  const stepLog = (message) => console.log(withAccountTag(accountLogTag, message));

  console.log(`[send] Target (${sendRequest.source}): ${sendRequest.label}`);
  console.log(`[send] Canton recipient: ${sendRequest.address}`);
  console.log(`[send] Amount: ${sendRequest.amount} CC`);

  // Step 1: Cooldown check with retry
  stepLog("[step] Send cooldown check");
  const cooldownResponse = await apiCallWithRetry(
    () => client.checkCcCooldown(sendRequest.address),
    "Cooldown check"
  );
  const cooldownData = isObject(cooldownResponse.data) ? cooldownResponse.data : {};

  if (cooldownData.blocked) {
    throw new Error(
      `CC send cooldown is active. Retry after ${cooldownData.retryAfterSeconds ?? "unknown"} seconds.`
    );
  }
  console.log(
    `[info] Cooldown passed (retryAfterSeconds=${cooldownData.retryAfterSeconds ?? 0}, cooldownMinutes=${cooldownData.cooldownMinutes ?? "n/a"})`
  );

  // Step 2a: Recipient preview (matches browser flow, non-critical)
  stepLog("[step] Recipient preview");
  try {
    await apiCallWithTimeout(
      () => client.recipientPreview(sendRequest.address),
      "Recipient preview",
      10000
    );
  } catch (error) {
    console.log(`[warn] Recipient preview failed (non-critical): ${error.message}`);
  }

  // Step 2b: Resolve recipient and prefer username route when available
  stepLog("[step] Resolve recipient");
  let resolvedUsername = null;
  try {
    const resolveResponse = await apiCallWithTimeout(
      () => client.resolveSendRecipient(sendRequest.address),
      "Resolve recipient",
      15000
    );
    const resolveData = isObject(resolveResponse.data) ? resolveResponse.data : {};
    resolvedUsername = String(resolveData.username || "").trim() || null;
    console.log(
      `[info] Resolved: username=${resolvedUsername || "n/a"} route=${resolveData.route || "n/a"}`
    );
  } catch (error) {
    const message = String(error && error.message ? error.message : "");
    if (message.includes("No Roots user is linked to this Canton address")) {
      console.log("[info] External wallet (not a Roots user), proceeding with direct transfer.");
    } else {
      console.log(`[warn] Resolve check failed: ${message}`);
    }
  }

  // Step 3: Get history before transfer (for matching later)
  stepLog("[step] Get send history (before transfer)");
  let beforeSendIds = new Set();
  try {
    const beforeHistoryResponse = await apiCallWithRetry(
      () => client.getSendHistory(),
      "Get history (before)"
    );
    const beforeSends = isObject(beforeHistoryResponse.data) && Array.isArray(beforeHistoryResponse.data.sends)
      ? beforeHistoryResponse.data.sends
      : [];
    beforeSendIds = new Set(beforeSends.map((item) => (isObject(item) ? item.id : null)).filter(Boolean));
  } catch (error) {
    console.log(`[warn] Could not get history before transfer: ${error.message}`);
    console.log("[info] Continuing with transfer anyway...");
  }

  // Step 4: Transfer CC with timeout recovery (web-like refresh + retry)
  if (!sendRequest.idempotencyKey) {
    sendRequest.idempotencyKey = crypto.randomUUID();
  }
  const idempotencyKey = sendRequest.idempotencyKey;
  stepLog(`[step] Transfer CC (idempotencyKey=${idempotencyKey})`);

  let transferResponse = null;
  try {
    transferResponse = await apiCallWithRetry(
      () => (
        resolvedUsername
          ? client.sendCcTransferByUsername(resolvedUsername, sendRequest.amount, idempotencyKey)
          : client.sendCcTransfer(sendRequest.address, sendRequest.amount, idempotencyKey)
      ),
      "Transfer CC",
      API_CALL_MAX_RETRIES,
      75000,
      {
        // Timeout transfer should restart account immediately without timeout backoff delay.
        maxConsecutiveTimeouts: 1
      }
    );
  } catch (error) {
    if (error && error.isSoftRestart) {
      throw error;
    }

    if (isTimeoutError(error)) {
      throw new SoftRestartError(
        `Transfer CC timeout for ${sendRequest.label}. Triggering immediate account restart.`,
        1
      );
    }

    throw error;
  }

  const transferData = isObject(transferResponse && transferResponse.data) ? transferResponse.data : {};
  const transferId = String(transferData.id || "").trim();
  const transferUpdateId = isObject(transferData.command_result) && isObject(transferData.command_result.transfer)
    ? String(transferData.command_result.transfer.updateId || "").trim()
    : "";

  if (transferId) {
    console.log(
      `[info] Transfer submitted: id=${transferId}${transferUpdateId ? ` updateId=${transferUpdateId}` : ""}`
    );
  }

  // Step 5: Check send history (to confirm transfer)
  stepLog("[step] Check send history");
  let matchedSend = null;
  try {
    const historyResponse = await apiCallWithRetry(
      () => client.getSendHistory(),
      "Get history (after)"
    );
    const sends = isObject(historyResponse.data) && Array.isArray(historyResponse.data.sends)
      ? historyResponse.data.sends
      : [];

    if (transferId) {
      matchedSend = sends.find((item) => isObject(item) && item.id === transferId) || null;
    }

    if (!matchedSend) {
      matchedSend = sends.find((item) => {
        if (!isObject(item) || !item.id || beforeSendIds.has(item.id)) {
          return false;
        }
        return String(item.direction || "").toLowerCase() === "sent" && String(item.amount || "") === sendRequest.amount;
      }) || null;
    }

    if (matchedSend) {
      console.log(
        `[info] Transfer history: id=${matchedSend.id} status=${matchedSend.status ?? "unknown"} amount=${matchedSend.amount ?? sendRequest.amount} token=${matchedSend.tokenType ?? "CC"}`
      );
    } else {
      console.log("[warn] Could not find a matching transfer in immediate history response.");
    }
  } catch (error) {
    console.log(`[warn] Could not check history after transfer: ${error.message}`);
  }

  // Step 6: Check outgoing (optional, non-fatal)
  try {
    const outgoingResponse = await apiCallWithTimeout(
      () => client.getCcOutgoing(),
      "Get outgoing",
      15000
    );
    const outgoing = isObject(outgoingResponse.data) && Array.isArray(outgoingResponse.data.outgoing)
      ? outgoingResponse.data.outgoing
      : [];
    console.log(`[info] Pending outgoing CC count: ${outgoing.length}`);
  } catch (error) {
    console.log(`[warn] Could not read cc-outgoing: ${error.message}`);
  }

  return {
    transferId: matchedSend && matchedSend.id ? String(matchedSend.id) : transferId,
    status: matchedSend && matchedSend.status ? String(matchedSend.status) : transferId ? "submitted" : "unknown",
    amount: String(sendRequest.amount),
    recipient: String(sendRequest.label)
  };
}

async function executeCcSendFlowWithCheckpointRecovery(
  client,
  sendRequest,
  config,
  onCheckpointRefresh,
  accountLogTag = null
) {
  const MAX_CHECKPOINT_REFRESH_ATTEMPTS = 1;
  const MAX_TRANSIENT_REFRESH_ATTEMPTS = 2;
  let checkpointRefreshAttempt = 0;
  let transientRefreshAttempt = 0;

  while (true) {
    try {
      return await executeCcSendFlow(client, sendRequest, config, onCheckpointRefresh, accountLogTag);
    } catch (error) {
      if (error && error.isSoftRestart) {
        throw error;
      }

      if (isVercelCheckpointError(error)) {
        if (!config.session.autoRefreshCheckpoint) {
          throw new Error(
            "Send flow hit Vercel checkpoint and auto refresh is disabled (config.session.autoRefreshCheckpoint=false)."
          );
        }

        if (checkpointRefreshAttempt >= MAX_CHECKPOINT_REFRESH_ATTEMPTS) {
          throw error;
        }

        checkpointRefreshAttempt += 1;
        console.log("[info] Send flow hit Vercel checkpoint, refreshing browser security cookies...");
        const browserCookies = await solveBrowserChallenge(
          config.baseUrl,
          config.paths.onboard,
          config.headers.userAgent,
          true
        );
        client.mergeCookies(browserCookies);
        if (typeof onCheckpointRefresh === "function") {
          onCheckpointRefresh();
        }
        client.logCookieStatus("after browser refresh for send");
        continue;
      }

      if (isTransientSendFlowError(error) && transientRefreshAttempt < MAX_TRANSIENT_REFRESH_ATTEMPTS) {
        transientRefreshAttempt += 1;
        await recoverSendFlowByRefresh(
          client,
          config,
          onCheckpointRefresh,
          accountLogTag,
          transientRefreshAttempt,
          MAX_TRANSIENT_REFRESH_ATTEMPTS,
          {
            mode: "light",
            reason: "send-flow-transient",
            runPreflight: false,
            forceConnectionReset: transientRefreshAttempt >= MAX_TRANSIENT_REFRESH_ATTEMPTS
          }
        );
        console.log(
          `[info] Retrying full send flow after transient recovery (${transientRefreshAttempt}/${MAX_TRANSIENT_REFRESH_ATTEMPTS})...`
        );
        continue;
      }

      throw error;
    }
  }
}

// Balance check with timeout - returns null if timeout/error (proceed with TX anyway)
const BALANCE_CHECK_TIMEOUT_MS = 10000;
const TX_RETRY_INITIAL_DELAY_SECONDS = 15;
const TX_RETRY_DELAY_STEP_SECONDS = 30;
const SESSION_REUSE_TIMEOUT_BACKOFF_SECONDS = 15;

async function getBalanceWithTimeout(client, timeoutMs = BALANCE_CHECK_TIMEOUT_MS) {
  const startTime = Date.now();
  
  try {
    const balancePromise = client.getBalances();
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Balance check timeout")), timeoutMs);
    });
    
    const balanceResponse = await Promise.race([balancePromise, timeoutPromise]);
    const elapsed = Date.now() - startTime;
    console.log(`[info] Balance check completed in ${elapsed}ms`);
    
    const balanceData = balanceResponse && balanceResponse.data ? balanceResponse.data : {};
    return printBalanceSummary(balanceData);
  } catch (error) {
    const elapsed = Date.now() - startTime;
    console.log(`[warn] Balance check failed after ${elapsed}ms: ${error.message}`);
    return null; // Return null to indicate balance check failed/timeout
  }
}

function formatThisWeekRewardLabel(rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "" || typeof rawValue === "boolean") {
    return "-";
  }

  const numeric = Number(rawValue);
  if (Number.isFinite(numeric)) {
    return `CC${numeric.toFixed(2)}`;
  }

  const text = String(rawValue).trim();
  if (!text) {
    return "-";
  }

  return /^cc/i.test(text) ? text.toUpperCase() : `CC${text}`;
}

function stripHtmlTags(value) {
  return String(value || "")
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function extractRewardsInsightsFromHtml(html) {
  const source = String(html || "");
  if (!source) {
    return { quality: "-", tier: "-" };
  }

  const compact = source.replace(/\s+/g, " ");
  const text = stripHtmlTags(source);
  let quality = "-";
  let tier = "-";

  const htmlQualityMatch = compact.match(
    /Quality this week<\/p>[\s\S]{0,1400}?<p[^>]*>\s*(\d{1,3}\s*\/\s*100)\s*<\/p>/i
  );
  const textQualityMatch = text.match(/Quality this week\s+(?:\d{1,3}\s+)?(\d{1,3}\s*\/\s*100)/i);
  const tierMatch =
    compact.match(/Protected floor:\s*([^<]+)/i) ||
    text.match(/Protected floor:\s*([A-Za-z][A-Za-z0-9 _-]{0,40})/i);

  if (htmlQualityMatch && htmlQualityMatch[1]) {
    quality = String(htmlQualityMatch[1]).replace(/\s+/g, "");
  } else if (textQualityMatch && textQualityMatch[1]) {
    quality = String(textQualityMatch[1]).replace(/\s+/g, "");
  }

  if (tierMatch && tierMatch[1]) {
    tier = String(tierMatch[1]).trim();
  }

  return { quality: quality || "-", tier: tier || "-" };
}

function buildRewardsSummaryLabel(rewardLabel, qualityLabel, tierLabel, todayPointsLabel = "-", volumeLabel = "-", dailyCheckinLabel = "-") {
  const parts = [];
  const reward = String(rewardLabel || "-").trim();
  const quality = String(qualityLabel || "-").trim();
  const tier = String(tierLabel || "-").trim();
  const todayPoints = String(todayPointsLabel || "-").trim();
  const volume = String(volumeLabel || "-").trim();
  const dailyCheckin = String(dailyCheckinLabel || "-").trim();

  if (reward && reward !== "-") {
    parts.push(reward);
  }
  if (quality && quality !== "-") {
    parts.push(`Q ${quality}`);
  }
  if (tier && tier !== "-") {
    parts.push(`Tier ${tier}`);
  }
  if (todayPoints && todayPoints !== "-") {
    parts.push(`Today ${todayPoints}`);
  }
  if (volume && volume !== "-") {
    parts.push(`Vol ${volume}`);
  }
  if (dailyCheckin && dailyCheckin !== "-") {
    parts.push(`Check-in ${dailyCheckin}`);
  }

  return parts.length > 0 ? parts.join(" | ") : "-";
}

function extractThisWeekRewardLabelFromResponse(payload) {
  const data = isObject(payload && payload.data) ? payload.data : {};
  const candidates = [];

  candidates.push(
    data.earnedThisWeekCc,
    data.thisWeekCc,
    data.rewardThisWeekCc,
    data.rewardsThisWeekCc,
    data.rewardsThisWeek
  );

  if (isObject(data.tierProgress)) {
    candidates.push(
      data.tierProgress.earnedThisWeekCc,
      data.tierProgress.thisWeekRewardCc,
      data.tierProgress.rewardThisWeekCc,
      data.tierProgress.thisWeekCc,
      data.tierProgress.rewardsThisWeekCc,
      data.tierProgress.rewardsThisWeek
    );
  }

  candidates.push(data.thisWeekRewardCc, data.thisWeekReward, data.weeklyRewardCc, data.weeklyReward);

  if (isObject(data.thisWeek)) {
    candidates.push(data.thisWeek.cc, data.thisWeek.amount, data.thisWeek.reward, data.thisWeek.value);
  }

  if (isObject(data.weekly)) {
    candidates.push(data.weekly.cc, data.weekly.amount, data.weekly.reward, data.weekly.value);
  }

  candidates.push(data.accrualsWeek, data.accrualsThisWeek, data.accrualsToday);

  for (const value of candidates) {
    const label = formatThisWeekRewardLabel(value);
    if (label !== "-") {
      return label;
    }
  }

  return "-";
}

function formatRewardsQualityLabel(rawValue) {
  const numeric = Number(rawValue);
  if (Number.isFinite(numeric)) {
    const bounded = Math.max(0, Math.min(100, Math.round(numeric)));
    return `${bounded}/100`;
  }

  const text = String(rawValue || "").trim();
  if (!text) {
    return "-";
  }

  const match = text.match(/(\d{1,3})\s*\/\s*100/);
  if (match && match[1]) {
    return `${Math.max(0, Math.min(100, Number(match[1])) )}/100`;
  }

  return "-";
}

function formatRewardsTodayPointsLabel(rawValue) {
  const numeric = Number(rawValue);
  if (Number.isFinite(numeric)) {
    return `${Math.max(0, Math.round(numeric))}pts`;
  }
  return "-";
}

function formatRewardsVolumeLabel(rawValue) {
  const numeric = Number(rawValue);
  if (!Number.isFinite(numeric)) {
    return "-";
  }

  return numeric.toLocaleString("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2
  });
}

function formatRewardsDailyCheckinLabel(streakDays, checkedIn) {
  const numeric = Number(streakDays);
  if (!Number.isFinite(numeric)) {
    return checkedIn ? "today" : "-";
  }

  const rounded = Math.max(0, Math.round(numeric));
  return checkedIn ? `${rounded}d` : `${rounded}d (pending)`;
}

function extractRewardsInsightsFromResponse(payload) {
  const data = isObject(payload && payload.data) ? payload.data : {};
  const tierProgress = isObject(data.tierProgress) ? data.tierProgress : {};
  const weeklyQuality = isObject(tierProgress.weeklyQuality) ? tierProgress.weeklyQuality : {};
  const currentTier = isObject(tierProgress.currentTier) ? tierProgress.currentTier : {};
  const legacyFloor = isObject(tierProgress.legacyFloor) ? tierProgress.legacyFloor : {};
  const today = isObject(tierProgress.today) ? tierProgress.today : {};
  const rolling30d = isObject(tierProgress.rolling30d) ? tierProgress.rolling30d : {};

  let quality = "-";
  let tier = "-";
  let todayPoints = "-";
  let volume = "-";
  let dailyCheckin = "-";
  let score = null;

  const qualityCandidates = [
    weeklyQuality.score,
    weeklyQuality.displayScore,
    Number.isFinite(Number(weeklyQuality.displayScoreBps))
      ? Number(weeklyQuality.displayScoreBps) / 100
      : null,
    tierProgress.weeklyQualityScore,
    data.weeklyQualityScore
  ];

  for (const candidate of qualityCandidates) {
    const label = formatRewardsQualityLabel(candidate);
    if (label !== "-") {
      quality = label;
      score = parseQualityScoreNumber(candidate);
      break;
    }
  }

  const tierCandidates = [
    tierProgress.currentTierDisplayName,
    currentTier.displayName,
    data.currentTierDisplayName,
    data.currentTierName,
    legacyFloor.displayName,
    data.legacyFloorDisplayName
  ];

  for (const candidate of tierCandidates) {
    const label = String(candidate || "").trim();
    if (label) {
      tier = label;
      break;
    }
  }

  const todayPointsCandidates = [
    today.totalPoints,
    today.points,
    data.todayPoints
  ];
  for (const candidate of todayPointsCandidates) {
    const label = formatRewardsTodayPointsLabel(candidate);
    if (label !== "-") {
      todayPoints = label;
      break;
    }
  }

  const volumeCandidates = [
    rolling30d.qualifiedCcVolumeTokens,
    rolling30d.volumeCcTokens,
    tierProgress.volume30dCcTokens,
    data.volume30dCcTokens
  ];
  for (const candidate of volumeCandidates) {
    const label = formatRewardsVolumeLabel(candidate);
    if (label !== "-") {
      volume = label;
      break;
    }
  }

  dailyCheckin = formatRewardsDailyCheckinLabel(today.streakDays, Boolean(today.checkedIn));
  if (dailyCheckin === "-" && Number.isFinite(Number(data.streakDays))) {
    dailyCheckin = formatRewardsDailyCheckinLabel(data.streakDays, Boolean(data.checkedIn));
  }

  return { quality, tier, todayPoints, volume, dailyCheckin, score };
}

async function refreshThisWeekRewardDashboard(client, dashboard, accountLogTag = null, accountName = null, minScoreThreshold = null) {
  let overviewResponse = null;
  let rewardLabel = "-";
  let rewardsThisWeekLabel = "-";
  let rewardsDiffLabel = "-";
  let qualityLabel = "-";
  let tierLabel = "-";
  let todayPointsLabel = "-";
  let volumeLabel = "-";
  let dailyCheckinLabel = "-";
  let qualityScore = null;

  try {
    overviewResponse = await client.getRewardsOverview();
    rewardLabel = extractThisWeekRewardLabelFromResponse(overviewResponse);
    const rewardMetrics = extractThisWeekRewardMetricsFromResponse(overviewResponse);
    if (accountName && (Number.isFinite(rewardMetrics.cc) || Number.isFinite(rewardMetrics.usd))) {
      const normalizedName = String(accountName).trim();
      const nextMetrics = {
        cc: Number.isFinite(rewardMetrics.cc) ? rewardMetrics.cc : 0,
        usd: Number.isFinite(rewardMetrics.usd) ? rewardMetrics.usd : 0
      };
      rewardsThisWeekByAccount.set(normalizedName, nextMetrics);
      if (!rewardsInitialByAccount.has(normalizedName)) {
        rewardsInitialByAccount.set(normalizedName, { ...nextMetrics });
      }
      rewardsThisWeekLabel = dashboard.formatRewardsThisWeek(normalizedName, rewardLabel);
      rewardsDiffLabel = dashboard.formatRewardsDiff(normalizedName, "-");
    }
    const insights = extractRewardsInsightsFromResponse(overviewResponse);
    qualityLabel = insights.quality;
    tierLabel = insights.tier;
    todayPointsLabel = insights.todayPoints;
    volumeLabel = insights.volume;
    dailyCheckinLabel = insights.dailyCheckin;
    qualityScore = parseQualityScoreNumber(insights.score);
  } catch (error) {
    if (!isTimeoutError(error) && !isCheckpointOr429Error(error)) {
      console.log(withAccountTag(accountLogTag, `[warn] Rewards overview endpoint failed: ${error.message}`));
    }
  }

  if (qualityLabel === "-" || tierLabel === "-") {
    try {
      const rewardsPageHtml = await client.getRewardsPageHtml();
      const rewardsInsights = extractRewardsInsightsFromHtml(rewardsPageHtml);
      if (qualityLabel === "-") {
        qualityLabel = String(rewardsInsights.quality || "-").trim() || "-";
      }
      if (tierLabel === "-") {
        tierLabel = String(rewardsInsights.tier || "-").trim() || "-";
      }
      if (qualityScore === null && qualityLabel !== "-") {
        qualityScore = parseQualityScoreNumber(qualityLabel);
      }
    } catch (error) {
      if (!isTimeoutError(error) && !isCheckpointOr429Error(error)) {
        console.log(withAccountTag(accountLogTag, `[warn] Rewards page scrape failed: ${error.message}`));
      }
    }
  }

  if (qualityScore === null && qualityLabel !== "-") {
    qualityScore = parseQualityScoreNumber(qualityLabel);
  }

  if (accountName && tierLabel !== "-") {
    tierDisplayNameByAccount.set(String(accountName).trim(), tierLabel);
  }

  if (accountName) {
    const data = isObject(overviewResponse && overviewResponse.data) ? overviewResponse.data : {};
    const tierProgress = isObject(data.tierProgress) ? data.tierProgress : {};
    const currentTier = isObject(tierProgress.currentTier) ? tierProgress.currentTier : {};
    const tierMinCandidates = [
      currentTier.minCcWholeTokensPerQualifyingSend,
      tierProgress.minCcWholeTokensPerQualifyingSend,
      data.minCcWholeTokensPerQualifyingSend
    ];
    for (const candidate of tierMinCandidates) {
      const numeric = Number(candidate);
      if (Number.isFinite(numeric) && numeric > 0) {
        tierMinSendByAccount.set(String(accountName).trim(), numeric);
        break;
      }
    }
  }

  if (accountName && qualityScore !== null) {
    updateAccountQualityState(accountName, qualityScore, minScoreThreshold, accountLogTag);
  }

  if (
    rewardLabel !== "-" ||
    rewardsThisWeekLabel !== "-" ||
    rewardsDiffLabel !== "-" ||
    qualityLabel !== "-" ||
    tierLabel !== "-" ||
    todayPointsLabel !== "-" ||
    volumeLabel !== "-" ||
    dailyCheckinLabel !== "-"
  ) {
    const summaryLabel = buildRewardsSummaryLabel(
      rewardLabel,
      qualityLabel,
      tierLabel,
      todayPointsLabel,
      volumeLabel,
      dailyCheckinLabel
    );
    dashboard.setState({
      reward: rewardLabel,
      rewardsThisWeek: rewardsThisWeekLabel,
      rewardsDiff: rewardsDiffLabel,
      rewardQuality: qualityLabel,
      rewardTier: tierLabel,
      rewardTodayPoints: todayPointsLabel,
      rewardVolume: volumeLabel,
      rewardDailyCheckin: dailyCheckinLabel
    });
    console.log(withAccountTag(accountLogTag, `[info] Rewards stats: ${summaryLabel}`));
    if (rewardsThisWeekLabel !== "-" || rewardsDiffLabel !== "-") {
      console.log(
        withAccountTag(
          accountLogTag,
          `[info] Rewards week/diff: ${rewardsThisWeekLabel !== "-" ? rewardsThisWeekLabel : "-"} | ${rewardsDiffLabel !== "-" ? rewardsDiffLabel : "-"}`
        )
      );
    }
  }
  // Don't log warning for timeout - just silently skip
  return {
    reward: rewardLabel,
    quality: qualityLabel,
    tier: tierLabel,
    todayPoints: todayPointsLabel,
    volume: volumeLabel,
    dailyCheckin: dailyCheckinLabel,
    score: qualityScore
  };
}

async function executeSendBatch(client, sendRequests, config, dashboard, onCheckpointRefresh, accountLogTag = null, senderAccountName = null) {
  if (!Array.isArray(sendRequests) || sendRequests.length === 0) {
    return {
      completedTx: 0,
      skippedTx: 0,
      deferred: false,
      deferReason: null,
      deferRetryAfterSeconds: 0,
      deferRequiredAmount: null,
      deferAvailableAmount: null,
      deferProgress: null,
      deferSendLabel: null,
      sentRecipientLabels: [],
      completedTransfers: []
    };
  }

  const stepLog = (message) => console.log(withAccountTag(accountLogTag, message));
  const minDelayTxSec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "minDelayTxSeconds")
      ? config.send.minDelayTxSeconds
      : config.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.minDelayTxSeconds
  );
  const maxDelayTxSec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "maxDelayTxSeconds")
      ? config.send.maxDelayTxSeconds
      : config.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.maxDelayTxSeconds
  );
  const delayTxMinSec = Math.min(minDelayTxSec, maxDelayTxSec);
  const delayTxMaxSec = Math.max(minDelayTxSec, maxDelayTxSec);

  let completedTx = 0;
  let skippedTx = 0;
  let deferredState = null;
  const sentRecipientLabels = [];
  const completedTransfers = [];
  const MAX_SEND_FLOW_RETRY_ATTEMPTS = 4;
  const BALANCE_GUARD_RETRY_DELAY_MS = 2000;
  const BALANCE_GUARD_RETRY_TIMEOUT_MS = BALANCE_CHECK_TIMEOUT_MS + 5000;
  const BALANCE_GUARD_MIN_BUFFER_CC = Math.max(
    0,
    Number(
      isObject(config && config.safety)
        ? config.safety.minHoldBalanceCc
        : INTERNAL_API_DEFAULTS.safety.minHoldBalanceCc
    ) || 0
  );
  const recipientCandidateMode = sendRequests.every(
    (entry) => isObject(entry) && entry.internalRecipientCandidate === true
  );
  const expectedTxCount = recipientCandidateMode ? 1 : sendRequests.length;

  dashboard.setState({
    swapsTotal: `0/${expectedTxCount}`,
    swapsOk: "0",
    swapsFail: "0"
  });

  for (let index = 0; index < sendRequests.length; index += 1) {
    if (recipientCandidateMode && completedTx > 0) {
      break;
    }

    const sendRequest = sendRequests[index];
    const progress = `${index + 1}/${sendRequests.length}`;
    const progressForDashboard = `${Math.min(index + 1, expectedTxCount)}/${expectedTxCount}`;

    // Check balance before each TX (with timeout fallback)
    stepLog(`[step] Check balance before tx ${progress} (timeout=${BALANCE_CHECK_TIMEOUT_MS}ms)`);
    let currentBalance = await getBalanceWithTimeout(client);

    if (currentBalance === null) {
      stepLog(`[step] Balance guard retry before tx ${progress} (timeout=${BALANCE_GUARD_RETRY_TIMEOUT_MS}ms)`);
      await sleep(BALANCE_GUARD_RETRY_DELAY_MS);
      currentBalance = await getBalanceWithTimeout(client, BALANCE_GUARD_RETRY_TIMEOUT_MS);
    }
    
    if (currentBalance !== null) {
      dashboard.setState({
        balance: `CC=${currentBalance.cc} | USDCx=${currentBalance.usdcx} | CBTC=${currentBalance.cbtc}`
      });
      
      console.log(`[info] Current balance: CC=${currentBalance.cc} (${currentBalance.ccNumeric}) | Available=${currentBalance.available}`);
      
      // Check if balance is sufficient (use ccNumeric for comparison)
      const requiredAmount = Number(sendRequest.amount);
      const requiredWithBuffer = requiredAmount + BALANCE_GUARD_MIN_BUFFER_CC;
      const availableAmount = currentBalance.ccNumeric;

      if (currentBalance.available === false) {
        const retryAfterSeconds = TX_RETRY_INITIAL_DELAY_SECONDS;
        console.log(
          `[warn] Deferring tx ${progress} because balance is not available yet ` +
          `(amount=${requiredAmount}, cc=${currentBalance.cc})`
        );
        dashboard.setState({
          phase: "cooldown",
          swapsTotal: progressForDashboard,
          swapsOk: String(completedTx),
          swapsFail: String(skippedTx),
          transfer: `deferred (balance-not-available) (${progress})`,
          cooldown: `${retryAfterSeconds}s`,
          send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} (balance unavailable)`
        });

        deferredState = {
          reason: "balance-not-available",
          retryAfterSeconds,
          requiredAmount,
          availableAmount,
          progress,
          sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
        };
        break;
      }

      if (!Number.isFinite(availableAmount) || availableAmount < requiredWithBuffer) {
        const maxSendableAmount = Number.isFinite(availableAmount)
          ? Math.max(0, availableAmount - BALANCE_GUARD_MIN_BUFFER_CC)
          : 0;
        const reducedAmount = senderAccountName
          ? generateTierBalancedAmount(config.send, senderAccountName, maxSendableAmount)
          : null;

        if (
          reducedAmount &&
          Number.isFinite(Number(reducedAmount)) &&
          Number(reducedAmount) > 0 &&
          Number(reducedAmount) < requiredAmount
        ) {
          const previousAmount = sendRequest.amount;
          sendRequest.amount = reducedAmount;

          if (recipientCandidateMode) {
            for (let candidateIndex = index; candidateIndex < sendRequests.length; candidateIndex += 1) {
              sendRequests[candidateIndex].amount = reducedAmount;
            }
          }

          console.log(
            `[info] Auto-reduced tx ${progress} amount ${previousAmount} -> ${reducedAmount} ` +
            `to stay within current balance ${availableAmount} CC ` +
            `(+hold ${BALANCE_GUARD_MIN_BUFFER_CC})`
          );
          dashboard.setState({
            phase: "send",
            swapsTotal: progressForDashboard,
            swapsOk: String(completedTx),
            swapsFail: String(skippedTx),
            transfer: `adjust-amount (${progress})`,
            send: `${reducedAmount} CC -> ${sendRequest.label} (tier-safe reduce)`
          });
        } else {
        const retryAfterSeconds = TX_RETRY_INITIAL_DELAY_SECONDS;
        console.log(
          `[warn] Deferring tx ${progress} due insufficient balance: ` +
          `need ${requiredAmount} CC (+buffer ${BALANCE_GUARD_MIN_BUFFER_CC}), have ${availableAmount} CC ` +
          `(retry in ${retryAfterSeconds}s)`
        );
        dashboard.setState({
          phase: "cooldown",
          swapsTotal: progressForDashboard,
          swapsOk: String(completedTx),
          swapsFail: String(skippedTx),
          transfer: `deferred (insufficient) (${progress})`,
          cooldown: `${retryAfterSeconds}s`,
          send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} (waiting inbound)`
        });

        deferredState = {
          reason: "insufficient-balance",
          retryAfterSeconds,
          requiredAmount,
          availableAmount,
          progress,
          sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
        };
        break;
        }
      }
    } else {
      // Balance check is required to avoid useless transfer timeouts when funds are not ready.
      const retryAfterSeconds = TX_RETRY_INITIAL_DELAY_SECONDS;
      console.log(
        `[warn] Deferring tx ${progress} because balance check is unavailable after retry ` +
        `(retry in ${retryAfterSeconds}s)`
      );
      dashboard.setState({
        phase: "cooldown",
        swapsTotal: progressForDashboard,
        swapsOk: String(completedTx),
        swapsFail: String(skippedTx),
        transfer: `deferred (balance-check-unavailable) (${progress})`,
        cooldown: `${retryAfterSeconds}s`,
        send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} (balance check unavailable)`
      });

      deferredState = {
        reason: "balance-check-unavailable",
        retryAfterSeconds,
        requiredAmount: Number(sendRequest.amount),
        availableAmount: null,
        progress,
        sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
      };
      break;
    }

    dashboard.setState({
      phase: "send",
      send: `${sendRequest.amount} CC -> ${sendRequest.label} (${progress})`,
      swapsTotal: progressForDashboard,
      swapsOk: String(completedTx),
      swapsFail: String(skippedTx)
    });

    stepLog(`[step] Send tx ${progress}: ${sendRequest.amount} CC -> ${sendRequest.label}`);

    let sendResult = null;
    let retryAttempt = 0;
    let skipToNextCandidate = false;
    let hardReloginAttempt = 0;
    const MAX_HARD_RELOGIN_ATTEMPTS = 1;
    let fragmentedAmountReductionCount = 0;
    const MAX_FRAGMENTED_BALANCE_REDUCTIONS = 4;
    while (sendResult === null && deferredState === null) {
      try {
        sendResult = await executeCcSendFlowWithCheckpointRecovery(
          client,
          sendRequest,
          config,
          onCheckpointRefresh,
          accountLogTag
        );
      } catch (error) {
        if (error && error.isSoftRestart) {
          throw error;
        }

        if (isBalanceContractFragmentationError(error)) {
          const errorMessage = String(error && error.message ? error.message : error);

          if (fragmentedAmountReductionCount < MAX_FRAGMENTED_BALANCE_REDUCTIONS) {
            const nextAmount = getReducedAmountForFragmentedBalance(sendRequest.amount, config.send);
            if (nextAmount && Number(nextAmount) < Number(sendRequest.amount)) {
              const previousAmount = sendRequest.amount;
              fragmentedAmountReductionCount += 1;
              sendRequest.amount = nextAmount;

              if (recipientCandidateMode) {
                for (let candidateIndex = index + 1; candidateIndex < sendRequests.length; candidateIndex += 1) {
                  sendRequests[candidateIndex].amount = nextAmount;
                }
              }

              console.warn(
                `[warn] TX ${progress} fragmented balance contracts. ` +
                `Reducing amount ${previousAmount} -> ${nextAmount} ` +
                `(step ${fragmentedAmountReductionCount}/${MAX_FRAGMENTED_BALANCE_REDUCTIONS}) and retrying now. ` +
                `Detail: ${errorMessage}`
              );

              dashboard.setState({
                phase: "cooldown",
                transfer: `reduce-amount (${progress})`,
                send: `Fragmented balance: ${previousAmount} -> ${nextAmount}`,
                cooldown: "0s",
                swapsTotal: progressForDashboard,
                swapsOk: String(completedTx),
                swapsFail: String(skippedTx)
              });
              continue;
            }
          }

          const retryAfterSeconds = 180;
          console.warn(
            `[warn] TX ${progress} fragmented balance still blocking after reductions. ` +
            `Deferring ${retryAfterSeconds}s. Last error: ${errorMessage}`
          );
          dashboard.setState({
            phase: "cooldown",
            transfer: `deferred (fragmented-balance) (${progress})`,
            send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} for ${retryAfterSeconds}s`,
            cooldown: `${retryAfterSeconds}s`,
            swapsTotal: progressForDashboard,
            swapsOk: String(completedTx),
            swapsFail: String(skippedTx)
          });
          deferredState = {
            reason: "fragmented-balance",
            retryAfterSeconds,
            requiredAmount: Number(sendRequest.amount),
            availableAmount: null,
            progress,
            sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
          };
          break;
        }

        if (isSendEligibilityDelayError(error)) {
          // Server send cooldown floor is 10 minutes for reciprocal/internal safety.
          const SEND_COOLDOWN_MIN_DELAY_SECONDS = 600; // 10 minutes
          const serverRetryAfter = parseRetryAfterSeconds(error, SEND_COOLDOWN_MIN_DELAY_SECONDS);
          const retryAfterSeconds = Math.max(serverRetryAfter, SEND_COOLDOWN_MIN_DELAY_SECONDS);
          const errorMessage = String(error && error.message ? error.message : error);

          if (recipientCandidateMode && index < sendRequests.length - 1) {
            console.warn(
              `[warn] Recipient candidate ${sendRequest.label} blocked (${retryAfterSeconds}s). ` +
              `Trying next candidate...`
            );
            dashboard.setState({
              phase: "cooldown",
              transfer: `candidate-blocked (${progress})`,
              send: `Candidate blocked, trying next recipient...`,
              cooldown: `${retryAfterSeconds}s`,
              swapsTotal: progressForDashboard,
              swapsOk: String(completedTx),
              swapsFail: String(skippedTx)
            });
            skipToNextCandidate = true;
            break;
          }

          console.warn(
            `[warn] Deferring tx ${progress} due server send rule. Retry in ${retryAfterSeconds}s (min 10min): ${errorMessage}`
          );
          dashboard.setState({
            phase: "cooldown",
            transfer: `deferred (server-cooldown) (${progress})`,
            send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} for ${retryAfterSeconds}s`,
            cooldown: `${retryAfterSeconds}s`,
            swapsTotal: progressForDashboard,
            swapsOk: String(completedTx),
            swapsFail: String(skippedTx)
          });
          deferredState = {
            reason: "server-cooldown",
            retryAfterSeconds,
            requiredAmount: Number(sendRequest.amount),
            availableAmount: null,
            progress,
            sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
          };
          break;
        }

        retryAttempt += 1;
        const transientSendError = isTransientSendFlowError(error);
        const retryDelaySeconds = transientSendError
          ? Math.min(30, 6 + ((retryAttempt - 1) * 8))
          : TX_RETRY_INITIAL_DELAY_SECONDS + ((retryAttempt - 1) * TX_RETRY_DELAY_STEP_SECONDS);
        const errorMessage = String(error && error.message ? error.message : error);

        if (retryAttempt >= MAX_SEND_FLOW_RETRY_ATTEMPTS) {
          if (transientSendError && hardReloginAttempt < MAX_HARD_RELOGIN_ATTEMPTS) {
            hardReloginAttempt += 1;
            console.warn(
              `[warn] TX ${progress} transient send errors persist. ` +
              `Performing hard relogin recovery ${hardReloginAttempt}/${MAX_HARD_RELOGIN_ATTEMPTS}...`
            );
            dashboard.setState({
              phase: "session-reuse",
              transfer: `hard-relogin (${progress})`,
              send: `Hard relogin ${sendRequest.amount} CC -> ${sendRequest.label}`,
              cooldown: "0s",
              swapsTotal: progressForDashboard,
              swapsOk: String(completedTx),
              swapsFail: String(skippedTx)
            });

            try {
              await recoverSendFlowByRefresh(
                client,
                config,
                onCheckpointRefresh,
                accountLogTag,
                hardReloginAttempt,
                MAX_HARD_RELOGIN_ATTEMPTS,
                {
                  mode: "full-browser",
                  reason: "send-hard-relogin",
                  runPreflight: true,
                  forceConnectionReset: true
                }
              );

              await apiCallWithRetry(
                () => client.syncAccount(config.paths.bridge),
                "Sync account after hard relogin",
                2,
                20000,
                { maxConsecutiveTimeouts: 2 }
              );

              retryAttempt = 0;
              console.log(`[info] Hard relogin recovery completed. Retrying tx ${progress}...`);
              continue;
            } catch (reloginError) {
              const reloginMessage = String(
                reloginError && reloginError.message ? reloginError.message : reloginError
              );
              console.warn(
                `[warn] Hard relogin recovery failed for tx ${progress}: ${reloginMessage}`
              );
            }
          }

          const retryAfterSeconds = transientSendError ? 60 : retryDelaySeconds;
          console.warn(
            `[warn] TX ${progress} reached retry limit (${MAX_SEND_FLOW_RETRY_ATTEMPTS}). ` +
            `Deferring ${retryAfterSeconds}s. Last error: ${errorMessage}`
          );
          dashboard.setState({
            phase: "cooldown",
            transfer: `deferred (retry-limit) (${progress})`,
            send: `Deferred ${sendRequest.amount} CC -> ${sendRequest.label} for ${retryAfterSeconds}s`,
            cooldown: `${retryAfterSeconds}s`,
            swapsTotal: progressForDashboard,
            swapsOk: String(completedTx),
            swapsFail: String(skippedTx)
          });
          deferredState = {
            reason: transientSendError ? "send-flow-transient" : "send-flow-retry-limit",
            retryAfterSeconds,
            requiredAmount: Number(sendRequest.amount),
            availableAmount: null,
            progress,
            sendLabel: `${sendRequest.amount} CC -> ${sendRequest.label}`
          };
          break;
        }

        console.warn(
          `[warn] TX ${progress} failed (attempt ${retryAttempt}) and will retry in ${retryDelaySeconds}s: ${errorMessage}`
        );

        dashboard.setState({
          phase: "cooldown",
          transfer: `retry-${retryAttempt} (${progress})`,
          send: `Retrying ${sendRequest.amount} CC -> ${sendRequest.label} in ${retryDelaySeconds}s`,
          cooldown: `${retryDelaySeconds}s`,
          swapsTotal: progressForDashboard,
          swapsOk: String(completedTx),
          swapsFail: String(skippedTx)
        });

        await sleep(retryDelaySeconds * 1000);
      }
    }

    if (skipToNextCandidate) {
      continue;
    }

    if (deferredState) {
      break;
    }

    if (!sendResult) {
      skippedTx += 1;
      continue;
    }

    completedTx++;
    if (sendRequest.label) {
      sentRecipientLabels.push(String(sendRequest.label));
    }
    completedTransfers.push({
      amount: String(sendRequest.amount),
      walleyAlias: String(sendRequest.label || "").trim(),
      walleyPartyId: String(sendRequest.address || "").trim(),
      refundTargetAlias: String(sendRequest.refundTargetAlias || "").trim(),
      refundTargetPartyId: String(sendRequest.refundTargetPartyId || "").trim(),
      rootsfiTransferId: String(sendResult.transferId || "").trim(),
      rootsfiTransferStatus: String(sendResult.status || "").trim(),
      source: String(sendRequest.source || "").trim()
    });

    // Record send pair for internal transfers to avoid reciprocal cooldowns
    if (
      String(sendRequest.source || "").startsWith("internal-") &&
      senderAccountName &&
      sendRequest.label
    ) {
      recordSendPair(senderAccountName, sendRequest.label);
    }

    dashboard.setState({
      phase: "send",
      send: `${sendRequest.amount} CC -> ${sendRequest.label} (${progress})`,
      transfer: `${sendResult.status} | id=${sendResult.transferId || "n/a"} (${progress})`,
      swapsTotal: `${completedTx}/${expectedTxCount}`,
      swapsOk: String(completedTx),
      swapsFail: String(skippedTx)
    });

    const hasMoreTxAfterCurrent = index < sendRequests.length - 1 && !recipientCandidateMode;

    // Delay only before the next tx in the same account batch.
    if (hasMoreTxAfterCurrent && delayTxMaxSec > 0) {
      const delayTxSec = randomIntInclusive(delayTxMinSec, delayTxMaxSec);
      console.log(`[info] Waiting ${delayTxSec}s after successful tx before next tx...`);
      dashboard.setState({
        phase: "cooldown",
        cooldown: `${delayTxSec}s`,
        send: `${sendRequest.amount} CC -> ${sendRequest.label} | cooldown ${delayTxSec}s before next tx`
      });
      await sleep(delayTxSec * 1000);
    }

    if (recipientCandidateMode && completedTx >= expectedTxCount) {
      console.log(
        `[info] Internal recipient selected via candidate ${index + 1}/${sendRequests.length}: ${sendRequest.label}`
      );
      break;
    }
  }

  if (deferredState) {
    console.log(
      `[info] Batch deferred: reason=${deferredState.reason} retryAfter=${deferredState.retryAfterSeconds}s progress=${deferredState.progress}`
    );
    return {
      completedTx,
      skippedTx,
      deferred: true,
      deferReason: deferredState.reason,
      deferRetryAfterSeconds: deferredState.retryAfterSeconds,
      deferRequiredAmount: deferredState.requiredAmount,
      deferAvailableAmount: deferredState.availableAmount,
      deferProgress: deferredState.progress,
      deferSendLabel: deferredState.sendLabel,
      sentRecipientLabels,
      completedTransfers
    };
  }

  // Final balance check (with timeout)
  stepLog(`[step] Refresh balances after send batch (timeout=${BALANCE_CHECK_TIMEOUT_MS}ms)`);
  const postSendBalance = await getBalanceWithTimeout(client);
  if (postSendBalance !== null) {
    dashboard.setState({
      balance: `CC=${postSendBalance.cc} | USDCx=${postSendBalance.usdcx} | CBTC=${postSendBalance.cbtc}`,
      swapsTotal: `${Math.min(expectedTxCount, completedTx + skippedTx)}/${expectedTxCount}`,
      swapsOk: String(completedTx),
      swapsFail: String(skippedTx),
      cooldown: "-"
    });
    console.log(`[info] Final balance: CC=${postSendBalance.cc} | Available=${postSendBalance.available}`);
  } else {
    console.log(`[warn] Final balance check timeout/failed`);
    dashboard.setState({
      swapsTotal: `${Math.min(expectedTxCount, completedTx + skippedTx)}/${expectedTxCount}`,
      swapsOk: String(completedTx),
      swapsFail: String(skippedTx),
      cooldown: "-"
    });
  }

  console.log(
    `[info] Batch summary: completed=${completedTx}, skipped=${skippedTx}, total=${expectedTxCount}`
  );
  return {
    completedTx,
    skippedTx,
    deferred: false,
    deferReason: null,
    deferRetryAfterSeconds: 0,
    deferRequiredAmount: null,
    deferAvailableAmount: null,
    deferProgress: null,
    deferSendLabel: null,
    sentRecipientLabels,
    completedTransfers
  };
}

async function processWalleyRefundsForBatch(
  walleyRefundBridge,
  rootsfiAccount,
  sendMode,
  sendBatchResult,
  accountLogTag = null,
  selectedAccounts = [],
  accountSnapshots = {}
) {
  if (
    !walleyRefundBridge ||
    !walleyRefundBridge.isActive() ||
    (sendMode !== "external" && sendMode !== "hybrid")
  ) {
    return null;
  }

  const completedTransfers = Array.isArray(sendBatchResult && sendBatchResult.completedTransfers)
    ? sendBatchResult.completedTransfers.filter((entry) => {
        const source = String(entry && entry.source ? entry.source : "").trim();
        const amount = String(entry && entry.amount ? entry.amount : "").trim();
        return source.includes("external") && Boolean(amount);
      })
    : [];

  if (completedTransfers.length === 0) {
    console.log(
      withAccountTag(
        accountLogTag,
        `[walley-refund] Skip: no completed external transfer eligible for refund`
      )
    );
    return null;
  }

  const preparedTransfers = completedTransfers.map((transfer) => {
    if (sendMode !== "hybrid") {
      return transfer;
    }

    const predefinedTargetPartyId = String(
      transfer && transfer.refundTargetPartyId ? transfer.refundTargetPartyId : ""
    ).trim();
    const predefinedTargetAlias = String(
      transfer && transfer.refundTargetAlias ? transfer.refundTargetAlias : ""
    ).trim();

    if (predefinedTargetPartyId) {
      console.log(
        withAccountTag(
          accountLogTag,
          `[walley-refund] Hybrid target locked: ${rootsfiAccount.name} -> ${predefinedTargetAlias || predefinedTargetPartyId} ` +
          `(amount ${transfer.amount} ${walleyRefundBridge.tokenSymbol})`
        )
      );
      return transfer;
    }

    const refundTarget = selectHybridRefundTarget(
      rootsfiAccount,
      selectedAccounts,
      accountSnapshots
    );

    if (!refundTarget) {
      return transfer;
    }

    console.log(
      withAccountTag(
        accountLogTag,
        `[walley-refund] Hybrid target: ${rootsfiAccount.name} -> ${refundTarget.name} ` +
        `(prefer lower balance, amount ${transfer.amount} ${walleyRefundBridge.tokenSymbol})`
      )
    );

    return {
      ...transfer,
      refundTargetAlias: String(refundTarget.name || "").trim(),
      refundTargetPartyId: String(refundTarget.address || "").trim()
    };
  });

  try {
    const result = await walleyRefundBridge.refundBatch(
      rootsfiAccount,
      preparedTransfers,
      accountLogTag
    );

    const successCount = clampToNonNegativeInt(result && result.successCount, 0);
    const failureCount = clampToNonNegativeInt(result && result.failureCount, 0);

    console.log(
      withAccountTag(
        accountLogTag,
        `[walley-refund] Summary: ${successCount} success, ${failureCount} failed`
      )
    );

    return result;
  } catch (error) {
    console.warn(
      withAccountTag(
        accountLogTag,
        `[walley-refund] Failed: ${error && error.message ? error.message : String(error)}`
      )
    );
    return {
      ok: false,
      results: [],
      successCount: 0,
      failureCount: preparedTransfers.length
    };
  }
}

async function processWalleyRefundsForRoundPass(
  walleyRefundBridge,
  sendMode,
  roundResults,
  loopRound,
  totalLoopRounds,
  selectedAccounts,
  accountSnapshots,
  refundParallelOptions = {}
) {
  if (
    !walleyRefundBridge ||
    !walleyRefundBridge.isActive() ||
    (sendMode !== "external" && sendMode !== "hybrid")
  ) {
    return [];
  }

  const refundJobs = Array.isArray(roundResults)
    ? roundResults
        .filter(({ entry, result, error }) => {
          if (error || !entry || !result) {
            return false;
          }
          return Array.isArray(result.completedTransfers) && result.completedTransfers.some((transfer) => {
            const source = String(transfer && transfer.source ? transfer.source : "").trim();
            const amount = String(transfer && transfer.amount ? transfer.amount : "").trim();
            return source.includes("external") && Boolean(amount);
          });
        })
        .map(({ entry, result }) => ({
          account: entry.account,
          result,
          accountLogTag: null
        }))
    : [];

  if (refundJobs.length === 0) {
    return [];
  }

  if (sendMode === "hybrid") {
    const { priorityTargets, assignments } = assignHybridRefundTargetsForRoundPass(
      roundResults,
      selectedAccounts,
      accountSnapshots
    );

    if (priorityTargets.length > 0) {
      const priorityLabel = priorityTargets
        .map((target) => `${target.account.name}:${target.balanceLabel}`)
        .join(" -> ");
      console.log(
        `[walley-refund] Round ${loopRound}/${totalLoopRounds}: post-send balance priority ${priorityLabel}`
      );
    }

    if (assignments.length > 0) {
      for (const assignment of assignments) {
        console.log(
          `[walley-refund] Round ${loopRound}/${totalLoopRounds}: assign ${assignment.amount} ${walleyRefundBridge.tokenSymbol} ` +
          `${assignment.senderName} -> ${assignment.targetName}`
        );
      }
    } else {
      console.log(
        `[walley-refund] Round ${loopRound}/${totalLoopRounds}: no hybrid refund target assignments created`
      );
    }
  }

  const orderedRefundUnits = refundJobs
    .flatMap((job) => {
      const transfers = Array.isArray(job.result && job.result.completedTransfers)
        ? job.result.completedTransfers.filter((transfer) => {
            const source = String(transfer && transfer.source ? transfer.source : "").trim();
            const amount = String(transfer && transfer.amount ? transfer.amount : "").trim();
            return source.includes("external") && Boolean(amount);
          })
        : [];

      return transfers.map((transfer) => ({
        account: job.account,
        transfer,
        accountLogTag: job.accountLogTag
      }));
    })
    .sort((left, right) => {
      const leftBalance = parseSnapshotCcBalance(left.transfer && left.transfer.refundTargetPriorityBalance);
      const rightBalance = parseSnapshotCcBalance(right.transfer && right.transfer.refundTargetPriorityBalance);
      if (leftBalance !== rightBalance) {
        return leftBalance - rightBalance;
      }
      const leftTarget = String(left.transfer && left.transfer.refundTargetAlias ? left.transfer.refundTargetAlias : "");
      const rightTarget = String(right.transfer && right.transfer.refundTargetAlias ? right.transfer.refundTargetAlias : "");
      if (leftTarget !== rightTarget) {
        return leftTarget.localeCompare(rightTarget);
      }
      return String(left.account && left.account.name ? left.account.name : "").localeCompare(
        String(right.account && right.account.name ? right.account.name : "")
      );
    });

  console.log(
    `[walley-refund] Round ${loopRound}/${totalLoopRounds}: processing ${orderedRefundUnits.length} refund transfer(s) before round continues`
  );

  const preparedRuntimeTransfers = [];
  for (const unit of orderedRefundUnits) {
    if (sendMode === "hybrid") {
      const targetLabel = String(unit.transfer && unit.transfer.refundTargetAlias ? unit.transfer.refundTargetAlias : "").trim();
      console.log(
        `[walley-refund] Round ${loopRound}/${totalLoopRounds}: queued ${unit.transfer.amount} ${walleyRefundBridge.tokenSymbol} ` +
        `${unit.account.name} -> ${targetLabel || "unknown-target"}`
      );
    }
    preparedRuntimeTransfers.push(
      ...walleyRefundBridge.buildRuntimeRefundTransfers(unit.account, [unit.transfer], unit.accountLogTag)
    );
  }

  const runtimeBatchResult = await walleyRefundBridge.refundPreparedBatch(
    preparedRuntimeTransfers,
    null,
    refundParallelOptions
  );

  const refundResults = orderedRefundUnits.map((unit) => ({
    account: unit.account,
    result: runtimeBatchResult
  }));

  console.log(
    `[walley-refund] Round ${loopRound}/${totalLoopRounds}: all refund batch(es) finished`
  );

  return refundResults;
}

async function refreshVercelSecurityCookies(client, config, reasonLabel, onCheckpointRefresh) {
  console.log(`[info] ${reasonLabel}`);
  const hadSecurityCookie = client.hasSecurityCookie();
  const hadSessionCookie = client.hasAccountSessionCookie();
  const retryAfterSeconds = Math.max(
    60,
    clampToNonNegativeInt(config.session.browserChallengeRetryAfterSeconds, 120)
  );
  const cooldownRemainingSeconds = getBrowserChallengeCooldownRemainingSeconds();

  if (cooldownRemainingSeconds > 0 && (hadSecurityCookie || hadSessionCookie)) {
    console.log(
      `[warn] Browser challenge cooldown active (${cooldownRemainingSeconds}s). ` +
        "Skipping Puppeteer refresh and deferring."
    );
    return {
      refreshed: false,
      unavailable: true,
      retryAfterSeconds: Math.max(retryAfterSeconds, cooldownRemainingSeconds),
      reason: "browser-rate-limit-cooldown"
    };
  }

  cacheSecurityCookiesFromMap(client.cookieJar, "client-before-refresh");

  const browserCookies = await solveBrowserChallenge(
    config.baseUrl,
    config.paths.onboard,
    config.headers.userAgent,
    true
  );

  if (!browserCookies || browserCookies.size === 0) {
    markBrowserChallengeRateLimited(retryAfterSeconds);
    const cachedSecurityMap = buildCachedSecurityCookieMap();

    if (cachedSecurityMap.size > 0) {
      console.log(
        `[warn] Browser challenge returned no cookies. ` +
          `Applying ${cachedSecurityMap.size} cached security cookie(s) fallback.`
      );

      client.mergeCookies(cachedSecurityMap);
      try {
        await client.preflightOnboard();
        client.logCookieStatus("after cached security cookie fallback");
        return {
          refreshed: false,
          unavailable: false,
          retryAfterSeconds: 0,
          reason: "cached-security-cookie-fallback"
        };
      } catch (cacheError) {
        console.log(`[warn] Cached security cookie fallback failed: ${cacheError.message}`);
      }
    }

    if (hadSecurityCookie || hadSessionCookie) {
      console.log(
        "[warn] Browser challenge returned no cookies (likely rate-limited/429). " +
          "Keeping existing cookies and deferring refresh."
      );
      return {
        refreshed: false,
        unavailable: true,
        retryAfterSeconds,
        reason: "browser-no-cookies"
      };
    }

    const error = new Error("Browser challenge did not return any cookies.");
    error.code = "BROWSER_CHALLENGE_NO_COOKIES";
    error.retryAfterSeconds = retryAfterSeconds;
    throw error;
  }

  cacheSecurityCookiesFromMap(browserCookies, "refresh-browser-challenge");
  client.mergeCookies(browserCookies);
  if (typeof onCheckpointRefresh === "function") {
    onCheckpointRefresh();
  }
  browserChallengeRateLimitedUntilMs = 0;

  // Validate refreshed cookie against the same fetch path used by API client.
  try {
    await client.preflightOnboard();
    client.logCookieStatus("after refresh preflight");
  } catch (error) {
    console.log(`[warn] Refresh preflight still blocked: ${error.message}`);

    if (isCheckpointOr429Error(error)) {
      markBrowserChallengeRateLimited(retryAfterSeconds);
      return {
        refreshed: false,
        unavailable: true,
        retryAfterSeconds,
        reason: "refresh-preflight-blocked"
      };
    }
  }

  return {
    refreshed: true,
    unavailable: false,
    retryAfterSeconds: 0,
    reason: "ok"
  };
}

async function attemptSessionReuse(client, config, onCheckpointRefresh, accountLogTag = null) {
  const logSession = (message) => console.log(withAccountTag(accountLogTag, message));

  const maxCheckpointRefreshAttempts = Math.max(
    1,
    clampToNonNegativeInt(config.session.maxSessionReuseRefreshAttempts, 3)
  );
  const maxTransientAttempts = Math.max(
    1,
    clampToNonNegativeInt(config.session.maxSessionReuseTransientAttempts, 6)
  );
  const maxTransientLightResets = Math.max(
    0,
    clampToNonNegativeInt(config.session.maxSessionReuseLightResets, 1)
  );
  const maxTransientBrowserRefreshes = Math.max(
    0,
    clampToNonNegativeInt(config.session.maxSessionReuseTransientBrowserRefreshes, 1)
  );
  const transientBrowserRefreshTriggerFailures = Math.max(
    1,
    clampToNonNegativeInt(config.session.transientBrowserRefreshTriggerFailures, 2)
  );
  const transientRetryAfterSeconds = Math.max(
    15,
    clampToNonNegativeInt(config.session.sessionReuseTransientRetryAfterSeconds, 45)
  );
  const retryJitterSeconds = Math.max(
    0,
    clampToNonNegativeInt(config.session.sessionReuseRetryJitterSeconds, 12)
  );
  const settleDelayMs = Math.max(
    0,
    clampToNonNegativeInt(config.session.checkpointSettleDelayMs, 3500)
  );
  const browserChallengeRetryAfterSeconds = Math.max(
    60,
    clampToNonNegativeInt(config.session.browserChallengeRetryAfterSeconds, 120)
  );
  const buildTransientDeferral = (message) => {
    const transientLimitError = new Error(message);
    transientLimitError.code = "SESSION_REUSE_TRANSIENT_RETRY_LIMIT";
    transientLimitError.retryAfterSeconds = browserChallengeRetryAfterSeconds;
    return {
      ok: false,
      error: transientLimitError,
      retryAfterSeconds: browserChallengeRetryAfterSeconds
    };
  };

  const configuredSessionReuseConcurrency = Math.max(
    1,
    clampToNonNegativeInt(
      config.session.maxConcurrentSessionReuse,
      INTERNAL_API_DEFAULTS.session.maxConcurrentSessionReuse
    )
  );
  const workerModeSessionReuseConcurrency =
    config.send && config.send.sequentialAllRounds === false
      ? Math.max(
          1,
          clampToNonNegativeInt(
            config.send.workers,
            INTERNAL_API_DEFAULTS.send.workers
          )
        )
      : 1;
  applySessionReuseConcurrencyLimit(
    Math.max(configuredSessionReuseConcurrency, workerModeSessionReuseConcurrency)
  );

  let lastError = null;
  let attempt = 0;
  let checkpointRefreshAttempt = 0;
  let transientFailureCount = 0;
  let transientLightResetCount = 0;
  let transientBrowserRefreshCount = 0;

  while (true) {
    attempt += 1;
    try {
      // Step 1: Sync account (this validates session)
      await acquireSessionReuseSlot(accountLogTag);
      const syncStart = Date.now();
      try {
        logSession(`[info] Session reuse attempt ${attempt}: calling sync-account...`);
        await client.syncAccount(config.paths.bridge);
        logSession(`[info] Session reuse attempt ${attempt}: sync-account OK (${Date.now() - syncStart}ms)`);
      } finally {
        releaseSessionReuseSlot(accountLogTag);
      }
      
      // Step 2: Balance check (optional, timeout OK - session is still valid)
      logSession(`[info] Session reuse attempt ${attempt}: calling balances (timeout=15s)...`);
      const balanceStart = Date.now();
      
      let balancesData = {};
      try {
        const balancePromise = client.getBalances();
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Balance check timeout (15s)")), 15000);
        });
        
        const balancesResponse = await Promise.race([balancePromise, timeoutPromise]);
        balancesData = balancesResponse && balancesResponse.data ? balancesResponse.data : {};
        logSession(`[info] Session reuse attempt ${attempt}: balances OK (${Date.now() - balanceStart}ms)`);
      } catch (balanceError) {
        // Balance timeout is OK - session is still valid (sync-account passed)
        logSession(`[warn] Balance check failed: ${balanceError.message}`);
        logSession(`[info] Session is still valid (sync-account passed), continuing without balance data...`);
      }
      
      return {
        ok: true,
        balancesData
      };
    } catch (error) {
      logSession(`[info] Session reuse attempt ${attempt} failed: ${error.message}`);
      lastError = error;

      if (isSessionReuseTimeoutError(error)) {
        const fetchFailedTransient = isFetchFailedTransientError(error);

        // For fetch failures (likely Vercel 429 rate limit at TCP level),
        // do NOT immediately bail — wait with extended backoff and retry.
        // The 429 window typically clears within 30-60s.
        if (fetchFailedTransient) {
          logSession(
            `[warn] Session reuse fetch/network failure detected (possible 429 rate limit). ` +
            `Will retry with extended backoff instead of immediate restart.`
          );
        }

        transientFailureCount += 1;
        let browserRefreshAttemptedThisAttempt = false;

        if (transientLightResetCount < maxTransientLightResets) {
          transientLightResetCount += 1;
          logSession(
            `[info] Session reuse transient recovery (light reset ${transientLightResetCount}/${maxTransientLightResets})`
          );
          await resetConnectionPool({ forceReset: true });
        }

        // Only force browser refresh after 3+ fetch failures — early fetch failures
        // are likely 429 rate limits that just need time, not browser recovery.
        const shouldForceImmediateBrowserRefresh =
          fetchFailedTransient &&
          transientFailureCount >= 3 &&
          config.session.autoRefreshCheckpoint &&
          transientBrowserRefreshCount < maxTransientBrowserRefreshes;
        // For fetch failures (likely 429 rate limit), skip browser refresh entirely
        // on early attempts — browser launch adds more requests to Vercel, worsening
        // the rate limit. Only use browser refresh for non-fetch transient errors
        // (real timeouts, Vercel checkpoint blocks).
        const shouldRunTransientBrowserRefresh =
          !fetchFailedTransient &&
          config.session.autoRefreshCheckpoint &&
          transientBrowserRefreshCount < maxTransientBrowserRefreshes &&
          (transientFailureCount >= transientBrowserRefreshTriggerFailures ||
            shouldForceImmediateBrowserRefresh);

        if (shouldRunTransientBrowserRefresh) {
          transientBrowserRefreshCount += 1;
          browserRefreshAttemptedThisAttempt = true;
          if (
            shouldForceImmediateBrowserRefresh &&
            transientFailureCount < transientBrowserRefreshTriggerFailures
          ) {
            logSession(
              `[info] Session reuse fetch/network failure detected. ` +
                `Escalating to browser refresh immediately (${transientBrowserRefreshCount}/${maxTransientBrowserRefreshes}).`
            );
          }

          let refreshResult = null;
          try {
            refreshResult = await refreshVercelSecurityCookies(
              client,
              config,
              `Session reuse transient failures persist (browser refresh ${transientBrowserRefreshCount}/${maxTransientBrowserRefreshes})`,
              onCheckpointRefresh
            );
          } catch (refreshError) {
            if (refreshError && refreshError.code === "BROWSER_CHALLENGE_NO_COOKIES") {
              logSession(
                `[warn] Browser challenge unavailable during transient recovery. ` +
                `Deferring session reuse ${browserChallengeRetryAfterSeconds}s.`
              );
              return buildTransientDeferral(
                "Session reuse deferred: browser challenge unavailable (no cookies)."
              );
            }
            throw refreshError;
          }

          if (refreshResult && refreshResult.unavailable) {
            logSession(
              `[warn] Browser challenge temporarily unavailable. ` +
                `Deferring session reuse ${browserChallengeRetryAfterSeconds}s.`
            );
            return buildTransientDeferral(
              "Session reuse deferred: browser challenge temporarily unavailable."
            );
          }

          client.logCookieStatus(`after session transient browser refresh ${transientBrowserRefreshCount}`);
          if (settleDelayMs > 0) {
            logSession(`[info] Waiting ${settleDelayMs}ms for token settle before session reuse retry...`);
            await sleep(settleDelayMs);
          }
        }

        const browserRefreshRecoveryExhausted =
          !config.session.autoRefreshCheckpoint ||
          transientBrowserRefreshCount >= maxTransientBrowserRefreshes;
        const lightResetRecoveryExhausted =
          transientLightResetCount >= maxTransientLightResets;
        // For fetch failures (likely 429), don't bail early just because light reset
        // and browser refresh are exhausted. The maxTransientAttempts check below is
        // the proper guard — fetch failures just need time to clear the rate limit.
        if (
          fetchFailedTransient &&
          !browserRefreshAttemptedThisAttempt &&
          lightResetRecoveryExhausted &&
          browserRefreshRecoveryExhausted
        ) {
          logSession(
            `[info] Fetch/network failure after recovery actions exhausted. ` +
            `Continuing retry with backoff (${transientFailureCount}/${maxTransientAttempts})...`
          );
        }

        if (transientFailureCount >= maxTransientAttempts) {
          const transientLimitError = new Error(
            `Session reuse transient retry limit reached (${maxTransientAttempts}) after repeated network failures.`
          );
          transientLimitError.code = "SESSION_REUSE_TRANSIENT_RETRY_LIMIT";
          transientLimitError.retryAfterSeconds = transientRetryAfterSeconds;
          return {
            ok: false,
            error: transientLimitError,
            retryAfterSeconds: transientRetryAfterSeconds
          };
        }

        // For fetch failures (likely 429 rate limit), use significantly longer backoff.
        // Normal timeouts: base ~20s. Fetch failures: base ~45s to let rate limit window clear.
        const fetchFailedExtra = fetchFailedTransient ? 25 : 0;
        const retryBaseSeconds = Math.min(20, transientRetryAfterSeconds) + fetchFailedExtra;
        const retryStepSeconds = Math.min(12, (transientFailureCount - 1) * 3);
        const retryJitterAddSeconds = retryJitterSeconds > 0
          ? randomIntInclusive(0, retryJitterSeconds)
          : 0;
        const retryDelaySeconds = Math.max(
          fetchFailedTransient ? 30 : 5,
          Math.min(
            transientRetryAfterSeconds + retryJitterSeconds + fetchFailedExtra,
            retryBaseSeconds + retryStepSeconds + retryJitterAddSeconds
          )
        );
        logSession(
          `[info] Session reuse ${fetchFailedTransient ? "fetch failure (likely 429)" : "timeout"} detected. ` +
          `Retrying in ${retryDelaySeconds}s... (transient ${transientFailureCount}/${maxTransientAttempts})`
        );
        await sleep(retryDelaySeconds * 1000);
        continue;
      }

      if (
        isVercelCheckpointError(error) &&
        config.session.autoRefreshCheckpoint &&
        checkpointRefreshAttempt < maxCheckpointRefreshAttempts
      ) {
        checkpointRefreshAttempt += 1;
        let refreshResult = null;
        try {
          refreshResult = await refreshVercelSecurityCookies(
            client,
            config,
            `Session reuse blocked by Vercel checkpoint (refresh ${checkpointRefreshAttempt}/${maxCheckpointRefreshAttempts}), refreshing browser security cookies...`,
            onCheckpointRefresh
          );
        } catch (refreshError) {
          if (refreshError && refreshError.code === "BROWSER_CHALLENGE_NO_COOKIES") {
            logSession(
              `[warn] Browser challenge unavailable during checkpoint recovery. ` +
                `Deferring session reuse ${browserChallengeRetryAfterSeconds}s.`
            );
            return buildTransientDeferral(
              "Session reuse deferred: browser challenge unavailable (checkpoint recovery)."
            );
          }
          throw refreshError;
        }

        if (refreshResult && refreshResult.unavailable) {
          logSession(
            `[warn] Browser challenge temporarily unavailable during checkpoint recovery. ` +
              `Deferring session reuse ${browserChallengeRetryAfterSeconds}s.`
          );
          return buildTransientDeferral(
            "Session reuse deferred: browser challenge temporarily unavailable (checkpoint recovery)."
          );
        }

        client.logCookieStatus(`after session refresh attempt ${checkpointRefreshAttempt}`);
        if (settleDelayMs > 0) {
          logSession(`[info] Waiting ${settleDelayMs}ms for Vercel token settle before retry...`);
          await sleep(settleDelayMs);
        }
        continue;
      }

      return {
        ok: false,
        error
      };
    }
  }
}

async function sendOtpWithCheckpointRecovery(client, selectedEmail, config, onCheckpointRefresh) {
  const maxAttempts = Math.max(
    1,
    clampToNonNegativeInt(config.session.maxOtpRefreshAttempts, 3)
  );
  const otpCheckpointRetryAfterSeconds = Math.max(
    60,
    clampToNonNegativeInt(config.session.browserChallengeRetryAfterSeconds, 120)
  );
  const settleDelayMs = Math.max(
    0,
    clampToNonNegativeInt(config.session.checkpointSettleDelayMs, 3500)
  );

  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await client.sendOtp(selectedEmail);
    } catch (error) {
      lastError = error;

      if (error && error.code === "SEND_OTP_CHECKPOINT_DEFER") {
        throw error;
      }

      if (
        !isVercelCheckpointError(error) ||
        !config.session.autoRefreshCheckpoint
      ) {
        throw error;
      }

      if (attempt >= maxAttempts) {
        const deferError = new Error(
          `Send OTP checkpoint persisted after ${maxAttempts} attempts.`
        );
        deferError.code = "SEND_OTP_CHECKPOINT_DEFER";
        deferError.retryAfterSeconds = otpCheckpointRetryAfterSeconds;
        throw deferError;
      }

      let refreshResult = null;
      try {
        refreshResult = await refreshVercelSecurityCookies(
          client,
          config,
          `Send OTP blocked by Vercel checkpoint (attempt ${attempt}/${maxAttempts}), refreshing browser security cookies...`,
          onCheckpointRefresh
        );
      } catch (refreshError) {
        if (refreshError && refreshError.code === "BROWSER_CHALLENGE_NO_COOKIES") {
          const deferError = new Error(
            "Send OTP deferred: browser challenge returned no cookies."
          );
          deferError.code = "SEND_OTP_CHECKPOINT_DEFER";
          deferError.retryAfterSeconds = otpCheckpointRetryAfterSeconds;
          throw deferError;
        }
        throw refreshError;
      }

      if (refreshResult && refreshResult.unavailable) {
        const refreshRetryAfter = Math.max(
          otpCheckpointRetryAfterSeconds,
          clampToNonNegativeInt(refreshResult.retryAfterSeconds, otpCheckpointRetryAfterSeconds)
        );
        const deferError = new Error(
          "Send OTP deferred: browser challenge temporarily unavailable."
        );
        deferError.code = "SEND_OTP_CHECKPOINT_DEFER";
        deferError.retryAfterSeconds = refreshRetryAfter;
        throw deferError;
      }

      client.logCookieStatus(`after refresh before send-otp retry ${attempt}`);
      if (settleDelayMs > 0) {
        console.log(`[info] Waiting ${settleDelayMs}ms for Vercel token settle before send-otp retry...`);
        await sleep(settleDelayMs);
      }
    }
  }

  throw lastError || new Error("Send OTP failed after refresh retries");
}

async function processAccount(context) {
  const {
    account,
    accountToken,
    config,
    tokens,
    tokensPath,
    sendMode,
    recipientsInfo,
    args,
    accountIndex,
    totalAccounts,
    selectedAccounts,
    accountSnapshots,
    telegramReporter,
    walleyRefundBridge,
    loopRound,
    totalLoopRounds,
    hybridAssignedMode,
    deferWalleyRefundsToRoundLevel,
    maxLoopTxOverride,
    smartFillBlockRecipients,
    resumeFromDeferReason,
    preferredInternalRecipients,
    plannedInternalAmount
  } = context;
  const safeResumeFromDeferReason = String(resumeFromDeferReason || "").trim();

  const selectedEmail = String(process.env.ROOTSFI_EMAIL || account.email).trim();
  if (!selectedEmail || !selectedEmail.includes("@")) {
    throw new Error(`Account ${account.name}: email is invalid`);
  }
  const accountLogTag = `A${accountIndex + 1}/${totalAccounts}`;

  const selectedAccountList =
    Array.isArray(selectedAccounts) && selectedAccounts.length > 0
      ? selectedAccounts
      : [{ name: account.name, email: selectedEmail }];
  const accountRows = selectedAccountList
    .map((entry, idx) => {
      const entryName = String(entry && entry.name ? entry.name : `Account ${idx + 1}`);

      let marker = "queue";
      if (idx < accountIndex) {
        marker = "done";
      } else if (idx === accountIndex) {
        marker = "run";
      }

      return `*${entryName}(${marker})`;
    })
    .join(" | ");
  const accountConfig = cloneRuntimeConfig(config);

  if (safeResumeFromDeferReason) {
    const resumeNeedsCheckpointRefresh =
      safeResumeFromDeferReason === "session-reuse-transient" ||
      safeResumeFromDeferReason === "otp-checkpoint";

    accountConfig.session.maxSessionReuseTransientAttempts = resumeNeedsCheckpointRefresh ? 3 : 2;
    accountConfig.session.maxSessionReuseLightResets = 1;
    accountConfig.session.maxSessionReuseTransientBrowserRefreshes = resumeNeedsCheckpointRefresh
      ? Math.max(
          1,
          clampToNonNegativeInt(accountConfig.session.maxSessionReuseTransientBrowserRefreshes, 1)
        )
      : 0;
    accountConfig.session.transientBrowserRefreshTriggerFailures = resumeNeedsCheckpointRefresh ? 1 : 2;
    accountConfig.session.sessionReuseTransientRetryAfterSeconds = 20;
    console.log(
      `[session] Fast retry mode for deferred account (${safeResumeFromDeferReason}): ` +
      `transient=${accountConfig.session.maxSessionReuseTransientAttempts} ` +
      `lightResets=${accountConfig.session.maxSessionReuseLightResets} ` +
      `browserRefresh=${accountConfig.session.maxSessionReuseTransientBrowserRefreshes}`
    );
  }
  const configuredMaxTransfersPerHour = clampToNonNegativeInt(
    accountConfig.send.maxTransfersPerHour,
    INTERNAL_API_DEFAULTS.send.maxTransfersPerHour
  );
  const effectiveMaxLoopTx = Number.isFinite(Number(maxLoopTxOverride))
    ? Math.max(1, clampToNonNegativeInt(maxLoopTxOverride, 1))
    : configuredMaxTransfersPerHour;
  accountConfig.send.maxLoopTx = effectiveMaxLoopTx;
  accountConfig.send.maxTransfersPerHour = configuredMaxTransfersPerHour;

  const cycleLoopRounds = Math.max(
    1,
    clampToNonNegativeInt(totalLoopRounds, configuredMaxTransfersPerHour)
  );
  const accountTargetPerHour =
    cycleLoopRounds *
    Math.max(1, selectedAccountList.length);
  const defaultMinCooldownSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(accountConfig.send, "minDelayTxSeconds")
      ? accountConfig.send.minDelayTxSeconds
      : accountConfig.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.minDelayTxSeconds
  );
  const defaultMaxCooldownSeconds = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(accountConfig.send, "maxDelayTxSeconds")
      ? accountConfig.send.maxDelayTxSeconds
      : accountConfig.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.maxDelayTxSeconds
  );
  const cooldownLabel = defaultMaxCooldownSeconds > defaultMinCooldownSeconds
    ? `${defaultMinCooldownSeconds}-${defaultMaxCooldownSeconds}s`
    : `${defaultMinCooldownSeconds}s`;
  const minScoreThreshold = Math.max(
    0,
    clampToNonNegativeInt(
      isObject(accountConfig.safety) ? accountConfig.safety.minScoreThreshold : null,
      INTERNAL_API_DEFAULTS.safety.minScoreThreshold
    )
  );

  // Apply token profile to config for this account
  applyTokenProfileToConfig(accountConfig, accountToken);

  let checkpointRefreshCount = 0;
  let lastVercelRefreshAt = String(accountToken.security.lastVercelRefreshAt || "").trim();
  const markCheckpointRefresh = () => {
    checkpointRefreshCount += 1;
    lastVercelRefreshAt = new Date().toISOString();
  };

  const dashboard = new PinnedDashboard({
    enabled:
      accountConfig.ui.dashboard &&
      !args.noDashboard &&
      process.env.ROOTSFI_NO_DASHBOARD !== "1",
    logLines: accountConfig.ui.logLines,
    accountSnapshots,
    reporter: telegramReporter
  });

  const initialDashboardState = {
    phase: "init",
    selectedAccount: `[${accountIndex + 1}/${totalAccounts}] ${account.name} (${maskEmail(selectedEmail)})`,
    accounts: accountRows,
    targetPerDay: String(accountTargetPerHour),
    cooldown: cooldownLabel,
    swapsTotal: "0/0",
    swapsOk: "0",
    swapsFail: "0"
  };
  dashboard.setState(initialDashboardState);
  dashboard.attach();

  const updateCookieDashboard = (client, phase) => {
    const status = client.getCookieStatus();
    const patch = {
      cookie: `_vcrcs=${status.security} session=${status.session} total=${status.total}`
    };

    if (phase) {
      patch.phase = phase;
    }

    dashboard.setState(patch);
  };

  try {
    const currentRound = Math.max(1, clampToNonNegativeInt(loopRound, 1));
    const roundLabel = totalLoopRounds > 1 ? ` | Round ${currentRound}/${totalLoopRounds}` : "";
    console.log(`\n${"=".repeat(60)}`);
    console.log(`[account ${accountIndex + 1}/${totalAccounts}] Processing: ${account.name} (${maskEmail(selectedEmail)})${roundLabel}`);
    console.log(`${"=".repeat(60)}`);

    console.log(
      `[init] Token profile ready: deviceId=${maskSecret(accountToken.deviceId, 6, 6)} antiBot=${maskSecret(accountToken.security.antiBotNonce, 6, 6)}`
    );

    const sendPolicy = accountConfig.send;
    let sendRequests = [];
    let buildDeferResult = null;
    const buildSendRequestsNow = () => {
      const senderTierKey = getAccountTierKey(account.name);
      const senderTierRange = getEffectiveAmountRangeForSender(sendPolicy, account.name, senderTierKey);
      const senderTierAmountLabel = `${senderTierRange.min}-${senderTierRange.max}`;
      sendRequests = [];
      buildDeferResult = null;

      if (sendMode === "external") {
        if (recipientsInfo.missing || recipientsInfo.recipients.length === 0) {
          throw new Error("External mode requires recipient.txt with valid recipients");
        }

        if (!sendPolicy.randomAmount.enabled) {
          throw new Error("External mode requires config.send.randomAmount.enabled=true");
        }

        sendRequests = buildSendRequestsWithRandomRecipients(recipientsInfo.recipients, sendPolicy, account.name);
        const amountLabel = `${senderTierAmountLabel} [${senderTierKey}]`;
        const recipientsList = sendRequests.map((r) => r.label).join(", ");
        dashboard.setState({
          send: `${amountLabel} CC x${sendRequests.length} -> random recipients`,
          mode: "external"
        });
        console.log(`[init] Send plan: ${amountLabel} CC x${sendRequests.length} -> [${recipientsList}]`);
        return;
      }

      if (sendMode === "hybrid") {
        const internalRoutingAccounts =
          Array.isArray(preferredInternalRecipients) && preferredInternalRecipients.length > 0
            ? selectedAccounts.filter((entry) => {
                const name = String(entry && entry.name ? entry.name : "").trim();
                return name === account.name || preferredInternalRecipients.includes(name);
              })
            : selectedAccounts;
        if (recipientsInfo.missing || recipientsInfo.recipients.length === 0) {
          throw new Error("Hybrid mode requires recipient.txt with valid recipients");
        }

        if (!sendPolicy.randomAmount.enabled) {
          throw new Error("Hybrid mode requires config.send.randomAmount.enabled=true");
        }

        const hybridPlan = buildHybridSendRequests(
          internalRoutingAccounts,
          account.name,
          recipientsInfo.recipients,
          sendPolicy,
          currentRound,
          [],
          hybridAssignedMode,
          Array.isArray(preferredInternalRecipients) ? preferredInternalRecipients : [],
          plannedInternalAmount || null
        );

        if (!hybridPlan || hybridPlan.requests.length === 0) {
          const retryAfterSeconds = Math.max(
            TX_RETRY_INITIAL_DELAY_SECONDS,
            clampToNonNegativeInt(
              hybridPlan && hybridPlan.retryAfterSeconds,
              TX_RETRY_INITIAL_DELAY_SECONDS
            )
          );
          const deferReason =
            hybridPlan && hybridPlan.reason
              ? hybridPlan.reason
              : "hybrid-recipient-unavailable";

          console.log(
            `[hybrid] ${account.name}: defer send (${deferReason}) for ${retryAfterSeconds}s`
          );
          dashboard.setState({
            phase: "cooldown",
            send: `Deferred hybrid send for ${retryAfterSeconds}s`,
            transfer: "deferred (hybrid-recipient)",
            cooldown: `${retryAfterSeconds}s`,
            mode: "hybrid"
          });

          buildDeferResult = {
            success: true,
            account: account.name,
            mode: "hybrid-deferred",
            deferred: true,
            deferReason,
            deferRetryAfterSeconds: retryAfterSeconds,
            deferRequiredAmount: null,
            deferAvailableAmount: null,
            txCompleted: 0,
            txSkipped: 0
          };
          return;
        }

        sendRequests = hybridPlan.requests;
        if (hybridPlan.selectedMode === "internal") {
          const primaryRequest = sendRequests[0];
          const fallbackCount = Math.max(0, sendRequests.length - 1);
          const fallbackLabel = fallbackCount > 0 ? ` (+${fallbackCount} fallback)` : "";
          const fallbackSourceLabel = hybridPlan.fallbackUsed ? " [fallback from external]" : "";
          dashboard.setState({
            send: `${primaryRequest.amount} CC -> ${primaryRequest.label}${fallbackLabel}`,
            mode: "hybrid-internal"
          });
          console.log(
            `[init] Send plan (hybrid/internal): ${primaryRequest.amount} CC -> ${primaryRequest.label}` +
              `${fallbackLabel} | preferred-offset=${hybridPlan.primaryOffset} | tier=${senderTierKey} (${senderTierAmountLabel})${fallbackSourceLabel}`
          );
        } else {
          const primaryRequest = sendRequests[0];
          const fallbackSourceLabel = hybridPlan.fallbackUsed ? " [fallback from internal]" : "";
          dashboard.setState({
            send: `${primaryRequest.amount} CC -> ${primaryRequest.label}`,
            mode: "hybrid-external"
          });
          console.log(
            `[init] Send plan (hybrid/external): ${primaryRequest.amount} CC -> ${primaryRequest.label}` +
              `${fallbackSourceLabel} | tier=${senderTierKey} (${senderTierAmountLabel}) | refund=post-send-lowest-balance-priority`
          );
        }
        return;
      }

      if (sendMode === "internal") {
        if (!sendPolicy.randomAmount.enabled) {
          throw new Error("Internal mode requires config.send.randomAmount.enabled=true");
        }

        const internalRoutingAccounts =
          Array.isArray(preferredInternalRecipients) && preferredInternalRecipients.length > 0
            ? selectedAccounts.filter((entry) => {
                const name = String(entry && entry.name ? entry.name : "").trim();
                return name === account.name || preferredInternalRecipients.includes(name);
              })
            : selectedAccounts;
        const internalPlan = buildInternalSendRequests(
          internalRoutingAccounts,
          account.name,
          sendPolicy,
          currentRound,
          [],
          Array.isArray(preferredInternalRecipients) ? preferredInternalRecipients : [],
          plannedInternalAmount || null
        );

        if (!internalPlan || internalPlan.requests.length === 0) {
          const retryAfterSeconds = Math.max(
            TX_RETRY_INITIAL_DELAY_SECONDS,
            clampToNonNegativeInt(
              internalPlan && internalPlan.retryAfterSeconds,
              TX_RETRY_INITIAL_DELAY_SECONDS
            )
          );
          const deferReason =
            internalPlan && internalPlan.reason
              ? internalPlan.reason
              : "internal-recipient-unavailable";

          console.log(
            `[internal] ${account.name}: defer send (${deferReason}) for ${retryAfterSeconds}s`
          );
          dashboard.setState({
            phase: "cooldown",
            send: `Deferred internal send for ${retryAfterSeconds}s`,
            transfer: "deferred (internal-recipient)",
            cooldown: `${retryAfterSeconds}s`,
            mode: "internal-chain"
          });

          buildDeferResult = {
            success: true,
            account: account.name,
            mode: "internal-chain-deferred",
            deferred: true,
            deferReason,
            deferRetryAfterSeconds: retryAfterSeconds,
            deferRequiredAmount: null,
            deferAvailableAmount: null,
            txCompleted: 0,
            txSkipped: 0
          };
          return;
        }

        sendRequests = internalPlan.requests;
        const primaryRequest = sendRequests[0];
        const fallbackCount = Math.max(0, sendRequests.length - 1);
        const fallbackLabel = fallbackCount > 0 ? ` (+${fallbackCount} fallback)` : "";
        dashboard.setState({
          send: `${primaryRequest.amount} CC -> ${primaryRequest.label}${fallbackLabel}`,
          mode: "internal-chain"
        });
        console.log(
          `[init] Send plan (internal-chain): ${primaryRequest.amount} CC -> ${primaryRequest.label}` +
            `${fallbackLabel} | tier=${senderTierKey} (${senderTierAmountLabel})`
        );
        return;
      }

      dashboard.setState({ mode: "balance-only" });
      console.log("[init] Balance check only mode");
    };

    if (args.dryRun) {
      buildSendRequestsNow();
      if (buildDeferResult) {
        return buildDeferResult;
      }
      dashboard.setState({ phase: "dry-run" });
      console.log("[dry-run] Configuration parsed successfully. No API requests were sent.");
      return {
        success: true,
        account: account.name,
        mode: "dry-run",
        deferred: false,
        deferReason: null,
        deferRetryAfterSeconds: 0,
        deferRequiredAmount: null,
        deferAvailableAmount: null,
        txCompleted: 0,
        txSkipped: 0
      };
    }

    let client = new RootsFiApiClient(accountConfig);
    updateCookieDashboard(client, "startup");
    client.logCookieStatus("startup");

    if (accountConfig.session.preflightOnboard) {
      dashboard.setState({ phase: "preflight" });
      console.log(withAccountTag(accountLogTag, "[step] Preflight onboard page"));
      try {
        await client.preflightOnboard();
        console.log(withAccountTag(accountLogTag, "[step] Preflight onboard done"));
      } catch (error) {
        console.log(`[warn] Preflight failed: ${error.message}`);
      }
    }

    if (shouldRefreshVercelCookie(lastVercelRefreshAt, accountConfig.session.proactiveVercelRefreshMinutes)) {
      dashboard.setState({ phase: "vercel-refresh" });
      console.log(
        withAccountTag(
          accountLogTag,
          `[step] Proactive Vercel cookie refresh (interval=${accountConfig.session.proactiveVercelRefreshMinutes}m)`
        )
      );
      try {
        await refreshVercelSecurityCookies(
          client,
          accountConfig,
          "Proactive refresh started",
          markCheckpointRefresh
        );
        client.logCookieStatus("after proactive refresh");
        updateCookieDashboard(client);
      } catch (error) {
        console.log(`[warn] Proactive refresh failed: ${error.message}`);
      }
    }

    if (!client.hasValidSession()) {
      dashboard.setState({ phase: "browser-checkpoint" });
      console.log("[info] No valid session cookies found, launching browser...");
      await refreshVercelSecurityCookies(
        client,
        accountConfig,
        "Initial browser verification required",
        markCheckpointRefresh
      );
      console.log("[info] Browser cookies merged from challenge flow");
      client.logCookieStatus("after browser merge");
      updateCookieDashboard(client);
    } else {
      console.log("[info] Using existing session cookies from tokens.json");
    }

    // Prefer existing authenticated session and only use OTP flow when session is not reusable.
    if (client.hasAccountSessionCookie()) {
      dashboard.setState({ phase: "session-reuse" });
      console.log(withAccountTag(accountLogTag, "[step] Attempt existing session (skip OTP)"));
      let sessionReuse = await attemptSessionReuse(
        client,
        accountConfig,
        markCheckpointRefresh,
        accountLogTag
      );
      updateCookieDashboard(client);

      if (sessionReuse && !sessionReuse.ok && sessionReuse.error && sessionReuse.error.code === "SESSION_REUSE_TRANSIENT_RETRY_LIMIT") {
        const hotRestartCooldownSeconds = 30 + randomIntInclusive(5, 15);
        console.log(
          withAccountTag(
            accountLogTag,
            `[info] Session transient limit reached. Cooling down ${hotRestartCooldownSeconds}s before hot-restart (rerun-like recovery)...`
          )
        );
        await sleep(hotRestartCooldownSeconds * 1000);

        await resetConnectionPool({ forceReset: true });

        const hotRestartConfig = cloneRuntimeConfig(accountConfig);
        const isDeferredResume = Boolean(safeResumeFromDeferReason);
        hotRestartConfig.session.maxSessionReuseTransientAttempts = isDeferredResume
          ? 2
          : Math.max(
              3,
              Math.min(
                6,
                clampToNonNegativeInt(accountConfig.session.maxSessionReuseTransientAttempts, 6)
              )
            );
        hotRestartConfig.session.maxSessionReuseLightResets = isDeferredResume
          ? 1
          : Math.max(
              1,
              Math.min(
                1,
                clampToNonNegativeInt(accountConfig.session.maxSessionReuseLightResets, 1)
              )
            );
        hotRestartConfig.session.maxSessionReuseTransientBrowserRefreshes = Math.max(
          0,
          Math.min(
            1,
            clampToNonNegativeInt(accountConfig.session.maxSessionReuseTransientBrowserRefreshes, 0)
          )
        );
        hotRestartConfig.session.sessionReuseTransientRetryAfterSeconds = isDeferredResume ? 20 : 45;

        const hotRestartClient = new RootsFiApiClient(hotRestartConfig);
        hotRestartClient.parseCookieString(client.getCookieHeader());
        hotRestartClient.logCookieStatus("before session hot-restart attempt");

        const hotRestartReuse = await attemptSessionReuse(
          hotRestartClient,
          hotRestartConfig,
          markCheckpointRefresh,
          accountLogTag
        );

        if (hotRestartReuse.ok) {
          console.log(withAccountTag(accountLogTag, "[info] Session hot-restart succeeded."));
          client = hotRestartClient;
          sessionReuse = hotRestartReuse;
          updateCookieDashboard(client, "session-hot-restart");
        } else {
          const hotRestartError = hotRestartReuse.error;
          console.log(
            withAccountTag(
              accountLogTag,
              `[warn] Session hot-restart did not recover: ${hotRestartError ? hotRestartError.message : "unknown"}`
            )
          );
          client = hotRestartClient;
          sessionReuse = hotRestartReuse;

          if (isSessionReuseImmediateFetchRestartError(hotRestartError)) {
            dashboard.setState({ phase: "session-reuse-cold-rerun" });
            const coldRestartCooldownSeconds = 20 + randomIntInclusive(5, 10);
            console.log(
              withAccountTag(
                accountLogTag,
                `[warn] Fetch/network failure persists after hot-restart. Cooling down ${coldRestartCooldownSeconds}s before cold rerun (no OTP fallback)...`
              )
            );
            await sleep(coldRestartCooldownSeconds * 1000);

            await resetConnectionPool({ forceReset: true });

            const coldRestartConfig = cloneRuntimeConfig(accountConfig);
            applyTokenProfileToConfig(coldRestartConfig, accountToken);
            coldRestartConfig.session.maxSessionReuseTransientAttempts = 2;
            coldRestartConfig.session.maxSessionReuseLightResets = 1;
            coldRestartConfig.session.maxSessionReuseTransientBrowserRefreshes = Math.max(
              1,
              clampToNonNegativeInt(accountConfig.session.maxSessionReuseTransientBrowserRefreshes, 1)
            );
            coldRestartConfig.session.transientBrowserRefreshTriggerFailures = 1;
            coldRestartConfig.session.sessionReuseTransientRetryAfterSeconds = 20;

            const coldRestartClient = new RootsFiApiClient(coldRestartConfig);
            const cachedSecurityMap = buildCachedSecurityCookieMap();
            if (cachedSecurityMap.size > 0) {
              coldRestartClient.mergeCookies(cachedSecurityMap);
            }

            if (coldRestartConfig.session.autoRefreshCheckpoint) {
              try {
                await refreshVercelSecurityCookies(
                  coldRestartClient,
                  coldRestartConfig,
                  "Cold rerun-like browser verification after hot-restart fetch failure",
                  markCheckpointRefresh
                );
                coldRestartClient.logCookieStatus("after cold rerun browser verification");
              } catch (refreshError) {
                console.log(
                  withAccountTag(
                    accountLogTag,
                    `[warn] Cold rerun browser verification failed: ${refreshError.message}`
                  )
                );
              }
            }

            coldRestartClient.logCookieStatus("before cold rerun session attempt");

            const coldRestartReuse = await attemptSessionReuse(
              coldRestartClient,
              coldRestartConfig,
              markCheckpointRefresh,
              accountLogTag
            );

            if (coldRestartReuse.ok) {
              console.log(withAccountTag(accountLogTag, "[info] Cold rerun-like session restart succeeded."));
              client = coldRestartClient;
              sessionReuse = coldRestartReuse;
              updateCookieDashboard(client, "session-cold-rerun");
            } else {
              console.log(
                withAccountTag(
                  accountLogTag,
                  `[warn] Cold rerun-like session restart did not recover: ${coldRestartReuse.error ? coldRestartReuse.error.message : "unknown"}`
                )
              );
              client = coldRestartClient;
              sessionReuse = coldRestartReuse;
            }
          }

          updateCookieDashboard(client);
        }
      }

      if (sessionReuse.ok) {
        const balance = printBalanceSummary(sessionReuse.balancesData);
        dashboard.setState({
          balance: `CC=${balance.cc} | USDCx=${balance.usdcx} | CBTC=${balance.cbtc}`
        });

        await refreshThisWeekRewardDashboard(
          client,
          dashboard,
          accountLogTag,
          account.name,
          minScoreThreshold
        );

        buildSendRequestsNow();
        if (buildDeferResult) {
          client.logCookieStatus("after session reuse");
          updateCookieDashboard(client, "session-reused");
          tokens.accounts[account.name] = applyClientStateToTokenProfile(
            accountToken,
            client,
            checkpointRefreshCount,
            lastVercelRefreshAt
          );
          await saveTokensSerial(tokensPath, tokens);
          return buildDeferResult;
        }

        let sendBatchResult = {
          completedTx: 0,
          skippedTx: 0,
          deferred: false,
          deferReason: null,
          deferRetryAfterSeconds: 0,
          completedTransfers: []
        };

        const qualityScore1 = getAccountQualityScore(account.name);
        if (sendRequests.length > 0 && qualityScore1 !== null && qualityScore1 < minScoreThreshold) {
          dashboard.setState({
            transfer: `skipped (score ${qualityScore1}/100)`,
            send: `Skip send: quality ${qualityScore1}/100 < threshold ${minScoreThreshold}`
          });
          console.log(
            withAccountTag(
              accountLogTag,
              `[SKIP] Account quarantined (score ${qualityScore1} < ${minScoreThreshold}) - skipping send`
            )
          );
        } else if (sendRequests.length > 0) {
          sendBatchResult = await executeSendBatch(
            client,
            sendRequests,
            accountConfig,
            dashboard,
            markCheckpointRefresh,
            accountLogTag,
            account.name // senderAccountName for pair tracking
          );

          // Accumulate global and per-account TX stats
          const batchCompleted = clampToNonNegativeInt(sendBatchResult.completedTx, 0);
          const batchFailed = clampToNonNegativeInt(sendBatchResult.skippedTx, 0);
          addGlobalTxStats(batchCompleted, batchFailed);
          addPerAccountTxStats(account.name, batchCompleted, batchFailed);
          saveDailyProgress(tokens);
          await saveTokensSerial(tokensPath, tokens);

          // Update dashboard banner with global totals
          dashboard.setState({
            swapsTotal: globalSwapsTotal,
            swapsOk: globalSwapsOk,
            swapsFail: globalSwapsFail
          });

          if (!deferWalleyRefundsToRoundLevel) {
            await processWalleyRefundsForBatch(
              walleyRefundBridge,
              account,
              sendMode,
              sendBatchResult,
              accountLogTag,
              selectedAccounts,
              accountSnapshots
            );
          } else if (
            walleyRefundBridge &&
            walleyRefundBridge.isActive() &&
            (sendMode === "external" || sendMode === "hybrid")
          ) {
            console.log(
              withAccountTag(
                accountLogTag,
                `[walley-refund] Queued for round-level settlement after account send batch`
              )
            );
          }
        }

        client.logCookieStatus("after session reuse");
        updateCookieDashboard(client, "session-reused");
        console.log("[done] Login and balance check completed using existing session.");

        tokens.accounts[account.name] = applyClientStateToTokenProfile(
          accountToken,
          client,
          checkpointRefreshCount,
          lastVercelRefreshAt
        );
        await saveTokensSerial(tokensPath, tokens);
        console.log("[info] Session/header/device/security saved to tokens.json");
        return {
          success: true,
          account: account.name,
          mode: "session-reuse",
          deferred: Boolean(sendBatchResult.deferred),
          deferReason: sendBatchResult.deferReason || null,
          deferRetryAfterSeconds: clampToNonNegativeInt(
            sendBatchResult.deferRetryAfterSeconds,
            TX_RETRY_INITIAL_DELAY_SECONDS
          ),
          deferRequiredAmount: sendBatchResult.deferRequiredAmount,
          deferAvailableAmount: sendBatchResult.deferAvailableAmount,
          sentRecipientLabels: Array.isArray(sendBatchResult.sentRecipientLabels)
            ? sendBatchResult.sentRecipientLabels
            : [],
          completedTransfers: Array.isArray(sendBatchResult.completedTransfers)
            ? sendBatchResult.completedTransfers
            : [],
          txCompleted: clampToNonNegativeInt(sendBatchResult.completedTx, 0),
          txSkipped: clampToNonNegativeInt(sendBatchResult.skippedTx, 0)
        };
      }

      const sessionError = sessionReuse.error;
      if (sessionError && sessionError.code === "SESSION_REUSE_TRANSIENT_RETRY_LIMIT") {
        const retryAfterSeconds = Math.max(
          TX_RETRY_INITIAL_DELAY_SECONDS,
          clampToNonNegativeInt(
            sessionReuse.retryAfterSeconds,
            clampToNonNegativeInt(sessionError.retryAfterSeconds, 90)
          )
        );

        dashboard.setState({
          phase: "cooldown",
          transfer: "deferred (session-reuse-transient)",
          send: `Session reuse unstable. Deferred ${retryAfterSeconds}s`,
          cooldown: `${retryAfterSeconds}s`
        });
        console.log(
          withAccountTag(
            accountLogTag,
            `[warn] Session reuse deferred after transient retry limit. Retry in ${retryAfterSeconds}s.`
          )
        );

        tokens.accounts[account.name] = applyClientStateToTokenProfile(
          accountToken,
          client,
          checkpointRefreshCount,
          lastVercelRefreshAt
        );
        await saveTokensSerial(tokensPath, tokens);

        return {
          success: true,
          account: account.name,
          mode: "session-reuse-deferred",
          deferred: true,
          deferReason: "session-reuse-transient",
          deferRetryAfterSeconds: retryAfterSeconds,
          deferRequiredAmount: null,
          deferAvailableAmount: null,
          sentRecipientLabels: [],
          txCompleted: 0,
          txSkipped: 0
        };
      }

      if (isVercelCheckpointError(sessionError)) {
        tokens.accounts[account.name] = applyClientStateToTokenProfile(
          accountToken,
          client,
          checkpointRefreshCount,
          lastVercelRefreshAt
        );
        await saveTokensSerial(tokensPath, tokens);
        console.log("[info] Latest refreshed security cookies saved to tokens.json");

        if (!accountConfig.session.fallbackToOtpOnPersistentCheckpoint) {
          throw new Error(
            "Existing session still blocked by Vercel Security Checkpoint after refresh attempts. " +
              "Fallback to OTP is disabled by config.session.fallbackToOtpOnPersistentCheckpoint=false."
          );
        }

        dashboard.setState({ phase: "otp-fallback" });
        console.log(
          "[warn] Existing session still blocked by Vercel checkpoint after refresh attempts. Falling back to OTP flow as last resort."
        );

        // Force fresh browser challenge before OTP fallback to get valid security cookies
        console.log(withAccountTag(accountLogTag, "[step] Force fresh browser challenge before OTP fallback..."));
        await refreshVercelSecurityCookies(
          client,
          accountConfig,
          "Fresh browser verification for OTP fallback",
          markCheckpointRefresh
        );
        client.logCookieStatus("after fresh browser for OTP fallback");
        updateCookieDashboard(client);

        const settleDelayMs = Math.max(
          0,
          clampToNonNegativeInt(accountConfig.session.checkpointSettleDelayMs, 3500)
        );
        if (settleDelayMs > 0) {
          console.log(`[info] Waiting ${settleDelayMs}ms before OTP fallback...`);
          await sleep(settleDelayMs);
        }
      } else {
        if (isInvalidSessionError(sessionError)) {
          console.log(`[info] Existing session is invalid: ${sessionError.message}`);
          console.log("[info] Falling back to OTP login flow.");
        } else {
          throw new Error(
            `Existing session is not reusable but not marked invalid-session: ${sessionError.message}`
          );
        }
      }
    }

    dashboard.setState({ phase: "otp-send" });
    console.log(withAccountTag(accountLogTag, "[step] Send OTP"));
    let sendOtpResponse = null;
    try {
      sendOtpResponse = await sendOtpWithCheckpointRecovery(
        client,
        selectedEmail,
        accountConfig,
        markCheckpointRefresh
      );
    } catch (error) {
      const otpCheckpointDefer = error && error.code === "SEND_OTP_CHECKPOINT_DEFER";
      if (otpCheckpointDefer || isCheckpointOr429Error(error)) {
        const fallbackRetryAfterSeconds = Math.max(
          60,
          clampToNonNegativeInt(accountConfig.session.browserChallengeRetryAfterSeconds, 120)
        );
        const retryAfterSeconds = Math.max(
          30,
          clampToNonNegativeInt(
            error && error.retryAfterSeconds,
            fallbackRetryAfterSeconds
          )
        );
        const errorMessage = String(error && error.message ? error.message : error || "unknown");

        dashboard.setState({
          phase: "cooldown",
          transfer: "deferred (otp-checkpoint)",
          send: `OTP checkpoint deferred ${retryAfterSeconds}s`,
          cooldown: `${retryAfterSeconds}s`
        });
        console.log(
          withAccountTag(
            accountLogTag,
            `[warn] OTP flow blocked by checkpoint. Defer ${retryAfterSeconds}s. Detail: ${errorMessage}`
          )
        );

        tokens.accounts[account.name] = applyClientStateToTokenProfile(
          accountToken,
          client,
          checkpointRefreshCount,
          lastVercelRefreshAt
        );
        await saveTokensSerial(tokensPath, tokens);

        return {
          success: true,
          account: account.name,
          mode: "otp-checkpoint-deferred",
          deferred: true,
          deferReason: "otp-checkpoint",
          deferRetryAfterSeconds: retryAfterSeconds,
          deferRequiredAmount: null,
          deferAvailableAmount: null,
          sentRecipientLabels: [],
          txCompleted: 0,
          txSkipped: 0
        };
      }

      throw error;
    }
    updateCookieDashboard(client);
    const otpId = sendOtpResponse && sendOtpResponse.data ? sendOtpResponse.data.otpId : null;

    if (!otpId) {
      throw new Error("send-otp did not return otpId");
    }

    console.log(`[info] OTP sent to ${maskEmail(selectedEmail)} | otpId=${maskSecret(otpId, 8, 6)}`);

    const otpCode = await promptOtpCode();

    if (!/^\d{4,8}$/.test(otpCode)) {
      throw new Error("OTP format must be numeric (4 to 8 digits)");
    }

    dashboard.setState({ phase: "otp-verify" });
    console.log(withAccountTag(accountLogTag, "[step] Verify OTP"));
    const verifyResponse = await client.verifyOtp({
      email: selectedEmail,
      otpId,
      otpCode
    });

    const nextStep = verifyResponse && verifyResponse.data ? verifyResponse.data.nextStep : null;
    console.log(`[info] verify-otp nextStep: ${nextStep || "unknown"}`);

    dashboard.setState({ phase: "sync-onboard" });
    console.log(withAccountTag(accountLogTag, "[step] Sync account (onboard referer)"));
    await client.syncAccount(accountConfig.paths.onboard);

    const pendingAfterVerify = await client.getPending(accountConfig.paths.onboard);
    const pendingData = pendingAfterVerify && pendingAfterVerify.data ? pendingAfterVerify.data : {};
    console.log(`[info] Pending after verify: ${Boolean(pendingData.pending)}`);

    if (pendingData.pending) {
      if (pendingData.alreadyActive === true) {
        dashboard.setState({ phase: "finalize-returning" });
        console.log(withAccountTag(accountLogTag, "[step] Finalize returning account"));
        const finalizeResponse = await client.finalizeReturning();
        const username = finalizeResponse && finalizeResponse.data ? finalizeResponse.data.username : pendingData.existingUsername;
        console.log(`[info] Finalized returning user: ${username || "unknown"}`);
      } else {
        throw new Error(
          "Account still in pending state and not marked alreadyActive. This script currently handles returning-account flow."
        );
      }
    }

    dashboard.setState({ phase: "sync-bridge" });
    console.log(withAccountTag(accountLogTag, "[step] Sync account (bridge referer)"));
    await client.syncAccount(accountConfig.paths.bridge);

    dashboard.setState({ phase: "balances" });
    console.log(withAccountTag(accountLogTag, "[step] Get balances"));
    const balancesResponse = await client.getBalances();
    const balance = printBalanceSummary(balancesResponse && balancesResponse.data ? balancesResponse.data : {});
    dashboard.setState({
      balance: `CC=${balance.cc} | USDCx=${balance.usdcx} | CBTC=${balance.cbtc}`
    });

    await refreshThisWeekRewardDashboard(
      client,
      dashboard,
      accountLogTag,
      account.name,
      minScoreThreshold
    );

    buildSendRequestsNow();
    if (buildDeferResult) {
      client.logCookieStatus("after login flow");
      updateCookieDashboard(client, "completed");
      tokens.accounts[account.name] = applyClientStateToTokenProfile(
        accountToken,
        client,
        checkpointRefreshCount,
        lastVercelRefreshAt
      );
      await saveTokensSerial(tokensPath, tokens);
      return buildDeferResult;
    }

    let sendBatchResult = {
      completedTx: 0,
      skippedTx: 0,
      deferred: false,
      deferReason: null,
      deferRetryAfterSeconds: 0,
      completedTransfers: []
    };

    const qualityScore2 = getAccountQualityScore(account.name);
    if (sendRequests.length > 0 && qualityScore2 !== null && qualityScore2 < minScoreThreshold) {
      dashboard.setState({
        transfer: `skipped (score ${qualityScore2}/100)`,
        send: `Skip send: quality ${qualityScore2}/100 < threshold ${minScoreThreshold}`
      });
      console.log(
        withAccountTag(
          accountLogTag,
          `[SKIP] Account quarantined (score ${qualityScore2} < ${minScoreThreshold}) - skipping send`
        )
      );
    } else if (sendRequests.length > 0) {
      sendBatchResult = await executeSendBatch(
        client,
        sendRequests,
        accountConfig,
        dashboard,
        markCheckpointRefresh,
        accountLogTag,
        account.name // senderAccountName for pair tracking
      );

      // Accumulate global and per-account TX stats
      const batchCompleted = clampToNonNegativeInt(sendBatchResult.completedTx, 0);
      const batchFailed = clampToNonNegativeInt(sendBatchResult.skippedTx, 0);
      addGlobalTxStats(batchCompleted, batchFailed);
      addPerAccountTxStats(account.name, batchCompleted, batchFailed);
      saveDailyProgress(tokens);
      await saveTokensSerial(tokensPath, tokens);

      // Update dashboard banner with global totals
      dashboard.setState({
        swapsTotal: globalSwapsTotal,
        swapsOk: globalSwapsOk,
        swapsFail: globalSwapsFail
      });

      if (!deferWalleyRefundsToRoundLevel) {
        await processWalleyRefundsForBatch(
          walleyRefundBridge,
          account,
          sendMode,
          sendBatchResult,
          accountLogTag,
          selectedAccounts,
          accountSnapshots
        );
      } else if (
        walleyRefundBridge &&
        walleyRefundBridge.isActive() &&
        (sendMode === "external" || sendMode === "hybrid")
      ) {
        console.log(
          withAccountTag(
            accountLogTag,
            `[walley-refund] Queued for round-level settlement after account send batch`
          )
        );
      }
    }

    client.logCookieStatus("after login flow");
    updateCookieDashboard(client, "completed");
    if (!client.hasAccountSessionCookie()) {
      console.log(
        "[warn] cantonbridge_session is not present in cookie jar yet. This can happen if runtime does not expose set-cookie headers."
      );
    }

    console.log("[done] Login and balance check completed.");

    tokens.accounts[account.name] = applyClientStateToTokenProfile(
      accountToken,
      client,
      checkpointRefreshCount,
      lastVercelRefreshAt
    );
    await saveTokensSerial(tokensPath, tokens);
    console.log("[info] Session/header/device/security saved to tokens.json");

    return {
      success: true,
      account: account.name,
      mode: "otp-login",
      deferred: Boolean(sendBatchResult.deferred),
      deferReason: sendBatchResult.deferReason || null,
      deferRetryAfterSeconds: clampToNonNegativeInt(
        sendBatchResult.deferRetryAfterSeconds,
        TX_RETRY_INITIAL_DELAY_SECONDS
      ),
      deferRequiredAmount: sendBatchResult.deferRequiredAmount,
      deferAvailableAmount: sendBatchResult.deferAvailableAmount,
      sentRecipientLabels: Array.isArray(sendBatchResult.sentRecipientLabels)
        ? sendBatchResult.sentRecipientLabels
        : [],
      completedTransfers: Array.isArray(sendBatchResult.completedTransfers)
        ? sendBatchResult.completedTransfers
        : [],
      txCompleted: clampToNonNegativeInt(sendBatchResult.completedTx, 0),
      txSkipped: clampToNonNegativeInt(sendBatchResult.skippedTx, 0)
    };
  } finally {
    dashboard.detach();
  }
}

function getNextHourUTC(date = new Date()) {
  return new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    date.getUTCHours() + 1,
    0,
    0,
    0
  ));
}

function formatDuration(ms) {
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}h ${minutes}m ${seconds}s`;
}

function formatUTCTime(date) {
  return date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

async function runStartupBalanceWarmup(context) {
  const selectedAccounts = Array.isArray(context && context.accounts && context.accounts.accounts)
    ? context.accounts.accounts
    : [];
  if (selectedAccounts.length === 0) {
    return;
  }

  const accountSnapshots =
    isObject(context && context.accountSnapshots) ? context.accountSnapshots : {};
  context.accountSnapshots = accountSnapshots;

  console.log(
    `[startup] Warmup started: refreshing balance and rewards for ${selectedAccounts.length} account(s) before hourly cycle execution`
  );

  const warmupArgs = {
    ...(isObject(context && context.args) ? context.args : {})
  };

  for (let index = 0; index < selectedAccounts.length; index += 1) {
    const account = selectedAccounts[index];
    const accountToken = context.tokens.accounts[account.name] || normalizeTokenProfile({});
    context.tokens.accounts[account.name] = accountToken;

    try {
      await processAccount({
        account,
        accountToken,
        config: context.config,
        tokens: context.tokens,
        tokensPath: context.tokensPath,
        sendMode: "balance-only",
        recipientsInfo: context.recipientsInfo,
        args: warmupArgs,
        accountIndex: index,
        totalAccounts: selectedAccounts.length,
        selectedAccounts,
        accountSnapshots,
        telegramReporter: null,
        walleyRefundBridge: null,
        loopRound: 1,
        totalLoopRounds: 1,
        hybridAssignedMode: null,
        deferWalleyRefundsToRoundLevel: true,
        maxLoopTxOverride: null,
        smartFillBlockRecipients: [],
        resumeFromDeferReason: "",
        preferredInternalRecipients: [],
        plannedInternalAmount: null
      });
      console.log(`[startup] Warmup ${index + 1}/${selectedAccounts.length}: ${account.name} ready`);
    } catch (error) {
      console.log(
        `[startup] Warmup ${index + 1}/${selectedAccounts.length}: ${account.name} failed -> ${error.message}`
      );
    }
  }

  console.log("[startup] Warmup completed.\n");
}

async function runDailyCycle(context) {
  const {
    config,
    accounts,
    tokens,
    tokensPath,
    sendMode,
    recipientsInfo,
    args,
    telegramReporter,
    walleyRefundBridge,
    accountSnapshots: persistedAccountSnapshots
  } = context;

  const cycleStartTime = new Date();
  const sessionConfig = isObject(config && config.session)
    ? config.session
    : INTERNAL_API_DEFAULTS.session;
  if (telegramReporter) {
    telegramReporter.scheduleText(
      [
        `${getJakartaTimeStamp()} WIB`,
        "Status: RUNNING",
        `Cycle started: ${formatUTCTime(cycleStartTime)}`,
        `Mode: ${sendMode}`,
        `Accounts: ${accounts.accounts.length}`
      ].join("\n"),
      { immediate: true }
    );
  }
  
  // Reset round-robin offset untuk hourly cycle baru
  resetRoundRobinOffset();
  ensureTxStatsCurrentUtcDay();
  
  // Clean up expired reciprocal cooldown state from previous runs
  cleanupExpiredSendPairs();
  if (sendMode === "internal" || sendMode === "hybrid") {
    await saveInternalPlannerStateSerial();
  }
  
  // Sort accounts for deterministic base order used by rotating offset strategy
  const sortedAccounts = [...accounts.accounts].sort((a, b) => 
    a.name.localeCompare(b.name)
  );
  
  console.log(`\n${"#".repeat(70)}`);
  console.log(`[cycle] Hourly cycle started at ${formatUTCTime(cycleStartTime)}`);
  console.log(`[cycle] Mode: ${sendMode} | Accounts: ${sortedAccounts.length}`);
  if (sendMode === "internal" || sendMode === "hybrid") {
    console.log(`[internal] Strategy: BALANCE CHAIN (largest -> smallest, recipient continues chain)`);
    console.log(`[internal] Goal: every active account sends once per round while re-feeding the lowest balance`);
    console.log(`[internal] Guard: no direct send-back to previous sender for >=10 minutes`);
  }
  if (sendMode === "hybrid") {
    console.log("[hybrid] Strategy: RANDOM PER SEND (internal atau external)");
  }
  console.log(`${"#".repeat(70)}\n`);

  const results = [];
  const totalAccounts = sortedAccounts.length;
  const configuredMaxTransfersPerHour = Math.max(
    1,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(config.send, "maxTransfersPerHour")
        ? config.send.maxTransfersPerHour
        : INTERNAL_API_DEFAULTS.send.maxTransfersPerHour,
      INTERNAL_API_DEFAULTS.send.maxTransfersPerHour
    )
  );
  const totalLoopRounds = sendMode === "balance-only" ? 1 : configuredMaxTransfersPerHour;
  const minAccountDelaySec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "minDelayTxSeconds")
      ? config.send.minDelayTxSeconds
      : config.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.minDelayTxSeconds
  );
  const maxAccountDelaySec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "maxDelayTxSeconds")
      ? config.send.maxDelayTxSeconds
      : config.send.delayTxSeconds,
    INTERNAL_API_DEFAULTS.send.maxDelayTxSeconds
  );
  const accountDelayMinSec = Math.min(minAccountDelaySec, maxAccountDelaySec);
  const accountDelayMaxSec = Math.max(minAccountDelaySec, maxAccountDelaySec);
  
  // Parallel jitter: random delay for each account before starting (staggered start)
  // This prevents all accounts hitting the server at exact same millisecond
  const minParallelJitterSec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "parallelJitterMinSeconds")
      ? config.send.parallelJitterMinSeconds
      : (
          Object.prototype.hasOwnProperty.call(config.send, "minDelayTxSeconds")
            ? config.send.minDelayTxSeconds
            : config.send.delayTxSeconds
        ),
    INTERNAL_API_DEFAULTS.send.minDelayTxSeconds
  );
  const maxParallelJitterSec = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(config.send, "parallelJitterMaxSeconds")
      ? config.send.parallelJitterMaxSeconds
      : (
          Object.prototype.hasOwnProperty.call(config.send, "maxDelayTxSeconds")
            ? config.send.maxDelayTxSeconds
            : config.send.delayTxSeconds
        ),
    INTERNAL_API_DEFAULTS.send.maxDelayTxSeconds
  );
  const parallelJitterMinSec = Math.min(minParallelJitterSec, maxParallelJitterSec);
  const parallelJitterMaxSec = Math.max(minParallelJitterSec, maxParallelJitterSec);
  const workerCount = Math.max(
    1,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(config.send, "workers")
        ? config.send.workers
        : INTERNAL_API_DEFAULTS.send.workers,
      INTERNAL_API_DEFAULTS.send.workers
    )
  );
  const maxDeferredWaitSeconds = Math.max(
    1,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(config.send, "maxDeferredWaitSeconds")
        ? config.send.maxDeferredWaitSeconds
        : INTERNAL_API_DEFAULTS.send.maxDeferredWaitSeconds,
      INTERNAL_API_DEFAULTS.send.maxDeferredWaitSeconds
    )
  );
  const softRestartRetryAfterSeconds = Math.max(
    15,
    clampToNonNegativeInt(
      Object.prototype.hasOwnProperty.call(sessionConfig, "softRestartRetryAfterSeconds")
        ? sessionConfig.softRestartRetryAfterSeconds
        : INTERNAL_API_DEFAULTS.session.softRestartRetryAfterSeconds,
      INTERNAL_API_DEFAULTS.session.softRestartRetryAfterSeconds
    )
  );
  
  // Round delay: fixed delay between rounds
  const delayRoundSec = clampToNonNegativeInt(
    config.send.delayCycleSeconds,
    INTERNAL_API_DEFAULTS.send.delayCycleSeconds
  );
  const forceSequentialAllRounds =
    typeof config.send.sequentialAllRounds === "boolean"
      ? config.send.sequentialAllRounds
      : INTERNAL_API_DEFAULTS.send.sequentialAllRounds;
  
  const accountSnapshots = isObject(persistedAccountSnapshots) ? persistedAccountSnapshots : {};
  context.accountSnapshots = accountSnapshots;
  const roundDeferPollSeconds = TX_RETRY_INITIAL_DELAY_SECONDS;
  const CARRY_OVER_ROUND_DEFER_DEFAULT_SECONDS = 45;
  const carryOverDeferStateByAccount = new Map();

  // Display deterministic account order used as internal roster baseline.
  const ringOrderLabel = sortedAccounts.map((item) => item.name).join(" -> ");
  if (sendMode === "internal" || sendMode === "hybrid") {
    console.log(`[internal] Base account order: ${ringOrderLabel}`);
  }
  console.log(
    `[cycle] Loop rounds: ${totalLoopRounds} (maxTransfersPerHour=${configuredMaxTransfersPerHour})`
  );
  if (forceSequentialAllRounds) {
    console.log("[cycle] Execution mode: sequential all rounds (worker mode disabled)");
  } else {
    if (sendMode === "internal") {
      console.log(
        `[cycle] Worker mode: internal-chain runs dependency-safe sequential ` +
        `(configured workers=${workerCount}; delay between accounts ${accountDelayMinSec}-${accountDelayMaxSec}s)`
      );
    } else {
      console.log(
        `[cycle] Worker mode: workers=${workerCount} ` +
        `(delay between batches ${accountDelayMinSec}-${accountDelayMaxSec}s)`
      );
    }
  }
  console.log(
    `[cycle] Round delay: ${delayRoundSec}s between rounds | max deferred wait: ${maxDeferredWaitSeconds}s | soft restart retry: ${softRestartRetryAfterSeconds}s\n`
  );

  for (let roundIndex = 0; roundIndex < totalLoopRounds; roundIndex += 1) {
    const loopRound = roundIndex + 1;
    
    const maxDeferPassesPerRound = Math.max(3, sortedAccounts.length * 4);
    
    const configuredWorkerCount = forceSequentialAllRounds ? 1 : workerCount;
    const chainDependencyMode = sendMode === "internal";
    const effectiveWorkerCount = chainDependencyMode
      ? 1
      : configuredWorkerCount;
    const executionMode =
      effectiveWorkerCount > 1
        ? `WORKERS x${effectiveWorkerCount}`
        : (chainDependencyMode ? "SEQUENTIAL (chain dependency)" : "SEQUENTIAL");
    
    console.log(`\n[cycle] Round ${loopRound}/${totalLoopRounds} started (${executionMode})`);

    const nowRoundMs = Date.now();
    let pendingEntries = [];
    for (const account of sortedAccounts) {
      const carryOverState = carryOverDeferStateByAccount.get(account.name);
      const carryUntilMs = Number(carryOverState && carryOverState.untilMs ? carryOverState.untilMs : 0);

      if (!args.dryRun && Number.isFinite(carryUntilMs) && carryUntilMs > nowRoundMs) {
        const waitSeconds = Math.max(1, Math.ceil((carryUntilMs - nowRoundMs) / 1000));
        const carryReason = String(carryOverState && carryOverState.reason ? carryOverState.reason : "deferred");
        console.log(
          `[cycle] Round ${loopRound}/${totalLoopRounds} skip ${account.name}: ` +
          `${carryReason} cooldown ${waitSeconds}s remaining`
        );
        continue;
      }

      if (carryOverState) {
        carryOverDeferStateByAccount.delete(account.name);
      }

      if (sendMode !== "balance-only" && hasReachedAccountHourlyTxCap(config, account.name)) {
        const cap = getAccountHourlyTxCap(config);
        const hourlyStats = getPerAccountHourlyTxStats(account.name);
        console.log(
          `[cap] Skip ${account.name}: hourly cap reached ${hourlyStats.total}/${cap}`
        );
        continue;
      }

      if (sendMode !== "balance-only" && hasReachedAccountTierDailyTxCap(config, account.name)) {
        const cap = getAccountTierDailyTxCap(config, account.name);
        const tierKey = getAccountTierKey(account.name);
        const stats = getPerAccountTxStats(account.name);
        console.log(
          `[cap] Skip ${account.name}: daily tier cap reached ${stats.total}/${cap} (${tierKey})`
        );
        continue;
      }

      pendingEntries.push({
        account,
        deferUntilMs: 0,
        deferReason: "",
        debtTurns: 0
      });
    }

    const hybridRoundAssignments =
      sendMode === "hybrid"
        ? buildHybridRoundAssignments(pendingEntries.map((entry) => entry.account))
        : null;
    if (sendMode === "hybrid") {
      const externalNames = Array.from(hybridRoundAssignments.externalNames);
      const internalNames = Array.from(hybridRoundAssignments.internalNames);
      console.log(
        `[hybrid] Round ${loopRound}/${totalLoopRounds} mix: ` +
        `${externalNames.length} external [${externalNames.join(", ")}] | ` +
        `${internalNames.length} internal [${internalNames.join(", ")}]`
      );
    }

    const activeRoundAccounts = pendingEntries.map((entry) => entry.account);
    const activeAccountNames = activeRoundAccounts.map((account) => account.name);
    if (sendMode === "internal" || sendMode === "hybrid") {
      logBalanceDistribution(activeAccountNames, `Round ${loopRound}/${totalLoopRounds}`, accountSnapshots);
    }
    const roundSendPlan =
      sendMode === "internal" || sendMode === "hybrid"
        ? computeRoundSendPlan(activeRoundAccounts, accountSnapshots, config.send, config)
        : new Map();

    if (pendingEntries.length === 0) {
      console.log(
        `[cycle] Round ${loopRound}/${totalLoopRounds} skipped: all accounts already reached hourly or daily caps`
      );
      break;
    }

    let deferPassCount = 0;

    while (pendingEntries.length > 0) {
      deferPassCount += 1;
      const nowMs = Date.now();
      const readyEntries = [];
      const delayedEntries = [];

      for (const entry of pendingEntries) {
        if (!args.dryRun && entry.deferUntilMs > nowMs) {
          delayedEntries.push(entry);
        } else {
          readyEntries.push(entry);
        }
      }

      if (readyEntries.length === 0) {
        const nearestReadyMs = delayedEntries.reduce(
          (minValue, entry) => Math.min(minValue, entry.deferUntilMs || nowMs),
          Number.MAX_SAFE_INTEGER
        );
        const waitMs = Math.max(0, nearestReadyMs - nowMs);
        const waitCeilingSec = Math.max(1, Math.min(
          Math.max(1, maxAccountDelaySec || roundDeferPollSeconds),
          maxDeferredWaitSeconds
        ));
        const waitSeconds = Math.max(1, Math.min(waitCeilingSec, Math.ceil(waitMs / 1000)));
        const waitingNames = delayedEntries.map((entry) => entry.account.name).join(", ");
        const cappedReadyMs = nowMs + (waitSeconds * 1000);
        for (const entry of delayedEntries) {
          if (entry.deferUntilMs > cappedReadyMs) {
            entry.deferUntilMs = cappedReadyMs;
          }
        }
        console.log(
          `[cycle] Round ${loopRound}/${totalLoopRounds} waiting ${waitSeconds}s for deferred accounts: ${waitingNames}`
        );
        if (!args.dryRun) {
          await sleep(waitSeconds * 1000);
        }
        pendingEntries = delayedEntries;
        continue;
      }

      if (deferPassCount > 1) {
        const retryOrder = readyEntries.map((entry) => entry.account.name).join(", ");
        console.log(
          `[cycle] Round ${loopRound}/${totalLoopRounds} deferred retry pass #${deferPassCount} | accounts: ${retryOrder}`
        );
      }

      const executionEntries = readyEntries;
      const flowLabel = effectiveWorkerCount > 1 ? `workers=${effectiveWorkerCount}` : "sequential";
      const roundPlanOrder = Array.from(roundSendPlan.keys());
      const roundPlanOrderMap = new Map(roundPlanOrder.map((name, index) => [name, index]));
      executionEntries.sort((left, right) => {
        const leftRank = roundPlanOrderMap.has(left.account.name)
          ? roundPlanOrderMap.get(left.account.name)
          : Number.MAX_SAFE_INTEGER;
        const rightRank = roundPlanOrderMap.has(right.account.name)
          ? roundPlanOrderMap.get(right.account.name)
          : Number.MAX_SAFE_INTEGER;
        if (leftRank !== rightRank) {
          return leftRank - rightRank;
        }
        return String(left.account.name || "").localeCompare(String(right.account.name || ""));
      });

      let roundResults = [];
      const runOneEntry = async (entry, indexInRound) => {
        const account = entry.account;
        const senderPlan = isObject(roundSendPlan.get(entry.account.name))
          ? roundSendPlan.get(entry.account.name)
          : {};
        const accountToken = tokens.accounts[account.name] || normalizeTokenProfile({});
        tokens.accounts[account.name] = accountToken;
        console.log(`[${flowLabel}] [${indexInRound + 1}/${executionEntries.length}] Processing ${account.name}...`);

        const expectedInboundFrom = String(senderPlan.expectedInboundFrom || "").trim();
        if (
          chainDependencyMode &&
          expectedInboundFrom &&
          !args.dryRun &&
          !String(entry.deferReason || "").trim()
        ) {
          const settleDelaySec = Math.max(1, humanLikeDelay(accountDelayMinSec, accountDelayMaxSec));
          console.log(
            `[internal-chain] Waiting ${settleDelaySec}s for inbound settle ${expectedInboundFrom} -> ${account.name} before send...`
          );
          await sleep(settleDelaySec * 1000);
        }

        try {
          const result = await processAccount({
            account,
            accountToken,
            config,
            tokens,
            tokensPath,
            sendMode,
            recipientsInfo,
            args,
            accountIndex: indexInRound,
            totalAccounts,
            selectedAccounts: activeRoundAccounts,
            accountSnapshots,
            telegramReporter,
            walleyRefundBridge,
            loopRound,
            totalLoopRounds,
            hybridAssignedMode:
              sendMode === "hybrid" && hybridRoundAssignments && hybridRoundAssignments.externalNames.has(account.name)
                ? "external"
                : (sendMode === "hybrid" ? "internal" : null),
            deferWalleyRefundsToRoundLevel: true,
            maxLoopTxOverride: sendMode === "balance-only" ? null : 1,
            smartFillBlockRecipients: [],
            resumeFromDeferReason: entry.deferReason || "",
            preferredInternalRecipients: Array.isArray(senderPlan.preferredRecipients)
              ? senderPlan.preferredRecipients
              : [],
            plannedInternalAmount: senderPlan.plannedAmount || null
          });
          return { entry, result, error: null };
        } catch (error) {
          const isSoftRestart = error && error.isSoftRestart;
          if (isSoftRestart) {
            console.log(
              `[soft-restart] ${account.name} triggered soft restart due to consecutive timeouts. ` +
              `Resetting connection pool and deferring retry for ${softRestartRetryAfterSeconds}s...`
            );
            await resetConnectionPool();
            return {
              entry,
              result: {
                success: false,
                account: account.name,
                deferred: true,
                deferReason: "soft-restart-timeout",
                deferRetryAfterSeconds: softRestartRetryAfterSeconds
              },
              error: null,
              softRestart: true
            };
          }

          console.error(`[error] Round ${loopRound}/${totalLoopRounds} | Account ${account.name}: ${error.message}`);
          return {
            entry,
            result: { success: false, account: account.name },
            error: error.message
          };
        }
      };

      const batches = [];
      for (let startIndex = 0; startIndex < executionEntries.length; startIndex += effectiveWorkerCount) {
        batches.push(executionEntries.slice(startIndex, startIndex + effectiveWorkerCount));
      }

      const readyOrderLabel = executionEntries.map((item) => item.account.name).join(" -> ");
      console.log(
        `[${flowLabel}] Processing ${executionEntries.length} accounts in ${batches.length} batch(es): ${readyOrderLabel}`
      );

      let processedCount = 0;
      for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
        const batch = batches[batchIndex];
        const batchResults = await Promise.all(
          batch.map((entry, indexInBatch) => runOneEntry(entry, processedCount + indexInBatch))
        );
        roundResults.push(...batchResults);
        processedCount += batch.length;

        if (batchIndex < batches.length - 1 && !args.dryRun && accountDelayMaxSec > 0 && !chainDependencyMode) {
          const batchDelaySec = humanLikeDelay(accountDelayMinSec, accountDelayMaxSec);
          console.log(`[${flowLabel}] Waiting ${batchDelaySec}s before next batch...`);
          await sleep(batchDelaySec * 1000);
        }
      }

      await processWalleyRefundsForRoundPass(
        walleyRefundBridge,
        sendMode,
        roundResults,
        loopRound,
        totalLoopRounds,
        sortedAccounts,
        accountSnapshots,
        {
          parallelEnabled: walleyRefundBridge ? walleyRefundBridge.parallelEnabled : true,
          transferConcurrency: walleyRefundBridge ? walleyRefundBridge.maxConcurrency : 1,
          parallelJitterMinMs: walleyRefundBridge ? walleyRefundBridge.parallelJitterMinSeconds * 1000 : 0,
          parallelJitterMaxMs: walleyRefundBridge ? walleyRefundBridge.parallelJitterMaxSeconds * 1000 : 0
        }
      );
      
      // Process results
      let passMadeProgress = false;
      const nextPendingEntries = delayedEntries.slice();
      
      for (const { entry, result, error } of roundResults) {
        if (error) {
          results.push({ success: false, account: entry.account.name, round: loopRound, error });
          continue;
        }
        
        results.push({ ...result, round: loopRound });

        if (result && result.deferred && sendMode !== "balance-only") {
          const deferReason = String(result.deferReason || "temporary");

          if (
            deferReason === "insufficient-balance" ||
            deferReason === "fragmented-balance" ||
            deferReason === "internal-avoid-sendback" ||
            deferReason === "balance-not-available" ||
            deferReason === "session-reuse-transient" ||
            deferReason === "otp-checkpoint"
          ) {
            const requiredLabel = Number.isFinite(Number(result.deferRequiredAmount))
              ? `need=${result.deferRequiredAmount}`
              : "need=n/a";
            const availableLabel = Number.isFinite(Number(result.deferAvailableAmount))
              ? `have=${result.deferAvailableAmount}`
              : "have=n/a";
            const carryOverRetryAfterSeconds = Math.max(
              30,
              clampToNonNegativeInt(
                result.deferRetryAfterSeconds,
                CARRY_OVER_ROUND_DEFER_DEFAULT_SECONDS
              )
            );
            carryOverDeferStateByAccount.set(entry.account.name, {
              untilMs: Date.now() + (carryOverRetryAfterSeconds * 1000),
              reason: deferReason
            });

            console.log(
              `[cycle] ${entry.account.name} carry-over to next round (${deferReason}) ` +
              `${requiredLabel} ${availableLabel} retry=${carryOverRetryAfterSeconds}s`
            );
            continue;
          }

          const retryAfterSeconds = Math.max(
            1,
            clampToNonNegativeInt(result.deferRetryAfterSeconds, roundDeferPollSeconds)
          );
          const deferUntilMs = Date.now() + (retryAfterSeconds * 1000);
          const requiredLabel = Number.isFinite(Number(result.deferRequiredAmount))
            ? `need=${result.deferRequiredAmount}`
            : "need=n/a";
          const availableLabel = Number.isFinite(Number(result.deferAvailableAmount))
            ? `have=${result.deferAvailableAmount}`
            : "have=n/a";
          console.log(
            `[cycle] Deferred ${entry.account.name}: reason=${deferReason} ${requiredLabel} ${availableLabel} retry=${retryAfterSeconds}s`
          );
          nextPendingEntries.push({
            account: entry.account,
            deferUntilMs,
            deferReason,
            debtTurns: (entry.debtTurns || 0) + 1
          });
          carryOverDeferStateByAccount.set(entry.account.name, {
            untilMs: deferUntilMs,
            reason: deferReason
          });
        } else {
          carryOverDeferStateByAccount.delete(entry.account.name);
          passMadeProgress = true;
        }
      }
      
      // No delay between accounts in parallel execution (they already ran simultaneously)

      if (nextPendingEntries.length === 0) {
        pendingEntries = [];
        break;
      }

      nextPendingEntries.sort((left, right) => {
        const debtDiff = (right.debtTurns || 0) - (left.debtTurns || 0);
        if (debtDiff !== 0) {
          return debtDiff;
        }

        const deferDiff = (left.deferUntilMs || 0) - (right.deferUntilMs || 0);
        return deferDiff;
      });

      if (!passMadeProgress) {
        if (deferPassCount >= maxDeferPassesPerRound) {
          const unresolvedNames = nextPendingEntries.map((entry) => entry.account.name).join(", ");
          console.warn(
            `[warn] Round ${loopRound}/${totalLoopRounds} reached defer pass limit (${maxDeferPassesPerRound}). Carry unresolved to next round: ${unresolvedNames}`
          );
          pendingEntries = [];
          break;
        }

        const nowAfterPassMs = Date.now();
        const nearestReadyMs = nextPendingEntries.reduce((minValue, entry) => {
          const candidate = entry.deferUntilMs || (nowAfterPassMs + (roundDeferPollSeconds * 1000));
          return Math.min(minValue, candidate);
        }, Number.MAX_SAFE_INTEGER);
        const waitMs = Math.max(0, nearestReadyMs - nowAfterPassMs);
        const waitSeconds = Math.min(
          maxDeferredWaitSeconds,
          Math.max(1, Math.ceil(waitMs / 1000))
        );
        console.log(
          `[cycle] Round ${loopRound}/${totalLoopRounds} has no send progress. Waiting ${waitSeconds}s before retrying deferred accounts...`
        );
        if (!args.dryRun) {
          await sleep(waitSeconds * 1000);
        }
      }

      pendingEntries = nextPendingEntries;
    }

    // Fixed delay between rounds (delayCycleSeconds)
    if (
      roundIndex < totalLoopRounds - 1 &&
      sendMode !== "balance-only" &&
      delayRoundSec > 0 &&
      !args.dryRun
    ) {
      console.log(
        `[cycle] Round ${loopRound}/${totalLoopRounds} completed. Waiting ${delayRoundSec}s before next round...`
      );
      await sleep(delayRoundSec * 1000);
    }
  }

  const cycleEndTime = new Date();
  const cycleDuration = cycleEndTime - cycleStartTime;
  
  const successful = results.filter((r) => r.success && !r.deferred);
  const failed = results.filter(r => !r.success);

  if (telegramReporter) {
    telegramReporter.scheduleText(
      [
        `${getJakartaTimeStamp()} WIB`,
        "Status: IDLE",
        `Cycle finished: ${formatUTCTime(cycleEndTime)}`,
        `Mode: ${sendMode}`,
        `Accounts: ${accounts.accounts.length}`,
        `Result: ${successful.length} successful | ${failed.length} failed`,
        `Duration: ${formatDuration(cycleDuration)}`
      ].join("\n"),
      { immediate: true }
    );
  }

  return { results, successful, failed, cycleDuration };
}

async function run() {
  if (typeof fetch !== "function") {
    throw new Error("Global fetch is not available. Use Node.js 18+.");
  }

  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const configPath = path.resolve(process.cwd(), args.configFile);
  const accountsPath = path.resolve(process.cwd(), args.accountsFile);
  const tokensPath = path.resolve(process.cwd(), args.tokensFile);
  const internalPlannerStatePath = path.resolve(process.cwd(), DEFAULT_INTERNAL_PLANNER_STATE_FILE);

  const [rawConfig, rawAccounts, rawTokens, rawInternalPlannerState] = await Promise.all([
    readJson(configPath, "config"),
    readJson(accountsPath, "accounts"),
    readOptionalJson(tokensPath, "tokens"),
    readOptionalJson(internalPlannerStatePath, "internal planner state")
  ]);

  const syncedRawConfig = await syncWalleyRefundSenderMap(configPath, rawConfig);
  const normalizedConfig = normalizeConfig(syncedRawConfig);
  const config = {
    ...normalizedConfig,
    session: {
      ...INTERNAL_API_DEFAULTS.session,
      ...(isObject(normalizedConfig.session) ? normalizedConfig.session : {})
    }
  };
  const accounts = normalizeAccounts(rawAccounts);
  const legacyCookies = extractLegacyAccountCookies(rawAccounts);
  const tokens = normalizeTokens(rawTokens, accounts);
  const dailyProgress = loadDailyProgress(tokens);
  hydrateDailyProgressIntoRuntime(dailyProgress);
  configureInternalPlannerPersistence(internalPlannerStatePath, accounts);
  const normalizedInternalPlannerState = applyInternalPlannerState(rawInternalPlannerState);
  const telegramReporter = config.telegram.enabled
    ? new TelegramDashboardReporter({
        ...config.telegram,
        projectName: "RootsFi Bot Dashboard"
      })
    : null;
  const walleyRefundBridge = config.walleyRefund.enabled
    ? new WalleyRefundBridge(config.walleyRefund)
    : null;

  for (const accountEntry of accounts.accounts) {
    const profile = tokens.accounts[accountEntry.name] || normalizeTokenProfile({});
    if (!String(profile.cookie || "").trim() && legacyCookies.has(accountEntry.name)) {
      profile.cookie = legacyCookies.get(accountEntry.name);
    }
    tokens.accounts[accountEntry.name] = profile;
  }

  // Keep generated token file in sync with current accounts and token schema.
  await saveTokensSerial(tokensPath, tokens);

  if (Object.keys(normalizedInternalPlannerState.coverageQueues || {}).length > 0) {
    console.log(
      `[internal] Loaded planner state: ${Object.keys(normalizedInternalPlannerState.coverageQueues).length} sender queue(s) from ${internalPlannerStatePath}`
    );
  } else {
    console.log(`[internal] Planner state ready: ${internalPlannerStatePath}`);
  }
  console.log(
    `[init] Safety: minScoreThreshold=${config.safety.minScoreThreshold}, minHoldBalanceCc=${config.safety.minHoldBalanceCc}`
  );
  await saveInternalPlannerStateSerial();

  // Load recipients
  const recipientsInfo = await loadRecipients(config.recipientFile);
  if (recipientsInfo.missing) {
    console.log(`[warn] Recipient file not found: ${recipientsInfo.absolutePath}`);
  } else {
    console.log(`[init] Recipients loaded: ${recipientsInfo.recipients.length}`);
    if (recipientsInfo.invalidLines.length > 0) {
      console.log(`[warn] Invalid recipient rows: ${recipientsInfo.invalidLines.length}`);
    }
  }

  // Show accounts summary
  console.log(`[init] Total accounts: ${accounts.accounts.length}`);
  for (const acc of accounts.accounts) {
    const tokenProfile = tokens.accounts[acc.name];
    const hasToken = tokenProfile && String(tokenProfile.cookie || "").trim();
    console.log(`  - ${acc.name} (${maskEmail(acc.email)}) [${hasToken ? "has-token" : "no-token"}]`);
  }

  // Prompt for send mode
  const sendMode = await promptSendMode();
  console.log(`\n[init] Selected mode: ${sendMode}`);

  if (
    (sendMode === "external" || sendMode === "hybrid") &&
    (recipientsInfo.missing || recipientsInfo.recipients.length === 0)
  ) {
    throw new Error(
      sendMode === "hybrid"
        ? "Hybrid mode requires recipient.txt with valid recipients"
        : "External mode requires recipient.txt with valid recipients"
    );
  }

  // Validate internal-capable modes - check accounts have addresses
  if (sendMode === "internal" || sendMode === "hybrid") {
    const accountsWithAddress = accounts.accounts.filter(acc => String(acc.address || "").trim());
    if (accountsWithAddress.length < 2) {
      throw new Error(
        sendMode === "hybrid"
          ? "Hybrid mode requires at least 2 accounts with 'address' field in accounts.json. Please fill in the cantonPartyId for each account."
          : "Internal mode requires at least 2 accounts with 'address' field in accounts.json. Please fill in the cantonPartyId for each account."
      );
    }
    console.log(`[init] Accounts with address: ${accountsWithAddress.length}/${accounts.accounts.length}`);
    
    const missingAddress = accounts.accounts.filter(acc => !String(acc.address || "").trim());
    if (missingAddress.length > 0) {
      console.log(`[warn] Accounts without address (will be skipped): ${missingAddress.map(a => a.name).join(", ")}`);
    }
  }

  // Prompt for account selection (for external and balance-only modes)
  // For internal-capable modes, use all accounts with valid addresses
  let selectedAccounts = accounts.accounts;
  if (sendMode === "external" || sendMode === "balance-only") {
    const accountSelection = await promptAccountSelection(accounts.accounts);
    selectedAccounts = accountSelection.selectedAccounts;
    
    const accountNames = selectedAccounts.map(a => a.name).join(", ");
    console.log(`\n[init] Selected accounts (${selectedAccounts.length}): ${accountNames}`);
  } else if (sendMode === "internal" || sendMode === "hybrid") {
    // For internal/hybrid modes, use all accounts with valid addresses
    selectedAccounts = accounts.accounts.filter(acc => String(acc.address || "").trim());
    const modeLabel = sendMode === "hybrid" ? "Hybrid mode" : "Internal mode";
    const strategyLabel =
      sendMode === "hybrid"
        ? "mixed internal/external send"
        : "sequential cross-send";
    console.log(`\n[init] ${modeLabel} - using all ${selectedAccounts.length} accounts with addresses (${strategyLabel})`);
  }

  const cycleContext = {
    config,
    accounts: { ...accounts, accounts: selectedAccounts },
    tokens,
    tokensPath,
    sendMode,
    recipientsInfo,
    args,
    legacyCookies,
    telegramReporter,
    walleyRefundBridge,
    accountSnapshots: {}
  };

  if (!args.dryRun) {
    await runStartupBalanceWarmup(cycleContext);
  }

  // Hourly loop
  let cycleCount = 0;
  const maxConsecutiveErrors = 3;
  let consecutiveErrors = 0;

  while (true) {
    cycleCount++;

    try {
      ensureTxStatsCurrentUtcHour();

      // Reload tokens before each cycle (in case manually edited)
      const freshTokens = await readOptionalJson(tokensPath, "tokens");
      const reloadedTokens = normalizeTokens(freshTokens, cycleContext.accounts);
      
      for (const accountEntry of cycleContext.accounts.accounts) {
        const profile = reloadedTokens.accounts[accountEntry.name] || normalizeTokenProfile({});
        if (!String(profile.cookie || "").trim() && cycleContext.legacyCookies.has(accountEntry.name)) {
          profile.cookie = cycleContext.legacyCookies.get(accountEntry.name);
        }
        cycleContext.tokens.accounts[accountEntry.name] = profile;
      }

      const readyForHourlyCap = getHourlyCapReadyAccounts(
        cycleContext.config,
        cycleContext.accounts.accounts,
        cycleContext.sendMode
      );
      if (!args.dryRun && cycleContext.sendMode !== "balance-only" && readyForHourlyCap.length === 0) {
        const now = new Date();
        const nextCycleTime = getNextHourUTC(now);
        const maxPollMs = Math.max(
          5000,
          clampToNonNegativeInt(
            cycleContext.config.send.hourlyCapPollSeconds,
            INTERNAL_API_DEFAULTS.send.hourlyCapPollSeconds
          ) * 1000
        );
        const waitMs = Math.max(0, Math.min(nextCycleTime - now, maxPollMs));
        console.log(`\n${"=".repeat(70)}`);
        console.log(`[cycle] Hourly caps reached for all ${cycleContext.accounts.accounts.length} account(s).`);
        console.log(`[cycle] Next UTC reset at: ${formatUTCTime(nextCycleTime)}`);
        console.log(`[cycle] Polling again in: ${formatDuration(waitMs)}`);
        console.log(`${"=".repeat(70)}\n`);

        if (telegramReporter) {
          telegramReporter.scheduleText(
            [
              `${getJakartaTimeStamp()} WIB`,
              "Status: HOURLY-CAP",
              `Cycle #: ${cycleCount}`,
              `Ready accounts: 0/${cycleContext.accounts.accounts.length}`,
              `Next UTC reset: ${formatUTCTime(nextCycleTime)}`,
              `Polling again in: ${formatDuration(waitMs)}`
            ].join("\n"),
            { immediate: true }
          );
        }

        await sleep(waitMs);
        cycleCount -= 1;
        continue;
      }

      // Run the hourly cycle
      const cycleResult = await runDailyCycle(cycleContext);
      
      // Reset consecutive errors on success
      consecutiveErrors = 0;

      if (args.dryRun) {
        break;
      }

      // Rolling scheduler: check again after configured cycle delay instead of
      // sleeping until the next UTC hour. Hourly caps are enforced separately.
      const waitMs = Math.max(
        0,
        clampToNonNegativeInt(
          cycleContext.config.send.delayCycleSeconds,
          INTERNAL_API_DEFAULTS.send.delayCycleSeconds
        ) * 1000
      );
      
      if (waitMs > 0) {
        console.log(`\n${"=".repeat(70)}`);
        console.log(`[cycle] Hourly cycle #${cycleCount} completed!`);
        console.log(`[cycle] Results: ${cycleResult.successful.length} successful, ${cycleResult.failed.length} failed`);
        console.log(`[cycle] Duration: ${formatDuration(cycleResult.cycleDuration)}`);
        console.log(`[cycle] Next cycle check in: ${formatDuration(waitMs)}`);
        console.log(`${"=".repeat(70)}\n`);

        if (telegramReporter) {
          telegramReporter.scheduleText(
            [
              `${getJakartaTimeStamp()} WIB`,
              "Status: WAITING",
              `Cycle #: ${cycleCount}`,
              `Result: ${cycleResult.successful.length} successful | ${cycleResult.failed.length} failed`,
              `Next cycle check in: ${formatDuration(waitMs)}`
            ].join("\n"),
            { immediate: true }
          );
        }
        
        await sleep(waitMs);
      }

    } catch (error) {
      consecutiveErrors++;
      console.error(`\n[error] Cycle #${cycleCount} failed: ${error.message}`);
      if (telegramReporter) {
        telegramReporter.scheduleText(
          [
            `${getJakartaTimeStamp()} WIB`,
            "Status: ERROR",
            `Cycle #: ${cycleCount}`,
            `Message: ${error.message}`
          ].join("\n"),
          { immediate: true }
        );
        await telegramReporter.sendEvent(
          `Cycle #${cycleCount} failed.\nError: ${error.message}`,
          { label: "ERROR" }
        );
      }
      
      if (consecutiveErrors >= maxConsecutiveErrors) {
        console.error(`[fatal] ${maxConsecutiveErrors} consecutive errors. Stopping bot.`);
        if (telegramReporter) {
          await telegramReporter.sendEvent(
            `${maxConsecutiveErrors} consecutive errors detected. Bot stopped.`,
            { label: "FATAL" }
          );
          await telegramReporter.close();
        }
        throw error;
      }

      // Wait 5 minutes before retrying on error
      const retryDelayMs = 5 * 60 * 1000;
      console.log(`[loop] Retrying in ${formatDuration(retryDelayMs)}... (${consecutiveErrors}/${maxConsecutiveErrors} errors)`);
      await sleep(retryDelayMs);
    }
  }
}

run().catch((error) => {
  console.error(`[error] ${error && error.message ? error.message : String(error)}`);
  process.exitCode = 1;
});
