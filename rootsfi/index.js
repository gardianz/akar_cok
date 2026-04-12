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
// ADAPTIVE INTERNAL RECIPIENT STRATEGY
// ============================================================================
// Goals:
// - Recipient tidak monoton (rotating offset per round)
// - Hindari kirim balik langsung ke sender sebelumnya (server cooldown 10m)
// - Tetap support fallback recipient saat candidate utama cooldown
// ============================================================================

const SEND_PAIR_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes
const SEND_PAIR_COOLDOWN_BUFFER_SECONDS = 45; // Safety buffer near expiry

// key: "sender=>recipient", value: timestamp (ms) of successful send
const sendPairHistory = new Map();
// key: "sender=>recipient", value: block-until timestamp (ms)
const reciprocalSendCooldowns = new Map();

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
  avoidRecipientNames = []
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

  const primaryOffset = getRotatingOffset(sortedAccounts.length, loopRound);
  const offsetPriority = buildInternalOffsetPriority(sortedAccounts.length, primaryOffset);
  const amount = generateRandomCcAmount(sendPolicy.randomAmount);
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
      source: "internal-rotating",
      offset,
      internalRecipientCandidate: true
    });
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
    console.log(
      `[internal] ${senderName}: no eligible recipient. ` +
      `cooldownRetry=${shortestCooldownSeconds || 0}s avoidBlocked=${skippedByAvoidCount} ` +
      `(retryAfter=${retryAfterSeconds}s reason=${reason})`
    );
    return {
      requests: [],
      reason,
      retryAfterSeconds,
      primaryOffset
    };
  }

  const preview = requests.slice(0, 4).map((entry) => entry.label).join(", ");
  const suffix = requests.length > 4 ? ` (+${requests.length - 4} more)` : "";
  console.log(
    `[internal] ${senderName}: offset=${primaryOffset} candidates=${requests.length}/${offsetPriority.length} ` +
    `primary=${requests[0].label} | pool=[${preview}${suffix}]`
  );

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

// Per-account TX tracking - accumulates totals per account for TX Progress column
const perAccountTxStats = {};

function resetGlobalTxStats() {
  globalSwapsTotal = 0;
  globalSwapsOk = 0;
  globalSwapsFail = 0;
  // Clear per-account stats
  for (const key of Object.keys(perAccountTxStats)) {
    delete perAccountTxStats[key];
  }
}

function addGlobalTxStats(completed, failed) {
  globalSwapsTotal += completed + failed;
  globalSwapsOk += completed;
  globalSwapsFail += failed;
}

function addPerAccountTxStats(accountName, completed, failed) {
  if (!perAccountTxStats[accountName]) {
    perAccountTxStats[accountName] = { total: 0, ok: 0, fail: 0 };
  }
  perAccountTxStats[accountName].total += completed + failed;
  perAccountTxStats[accountName].ok += completed;
  perAccountTxStats[accountName].fail += failed;
}

function getPerAccountTxStats(accountName) {
  return perAccountTxStats[accountName] || { total: 0, ok: 0, fail: 0 };
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
  send: {
    maxLoopTx: 1,
    minDelayTxSeconds: 120,
    maxDelayTxSeconds: 120,
    parallelJitterMinSeconds: 5,
    parallelJitterMaxSeconds: 15,
    delayCycleSeconds: 300,
    sequentialAllRounds: true,
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
    return this.enqueue(async () => {
      const payload = this.buildPayload(text);

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
    if (!this.isActive() || !dashboard || typeof dashboard.getTelegramSnapshot !== "function") {
      return;
    }

    const snapshot = dashboard.getTelegramSnapshot({
      accountLimit: this.accountsPerUpdate,
      logLimit: this.logsPerUpdate
    });
    this.scheduleText(snapshot);
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

  buildRewardSummaryLabel(quality, tier, todayPoints, volume, dailyCheckin) {
    const parts = [];
    const qualityValue = String(quality || "-").trim();
    const tierValue = String(tier || "-").trim();
    const todayPointsValue = String(todayPoints || "-").trim();
    const volumeValue = String(volume || "-").trim();
    const dailyCheckinValue = String(dailyCheckin || "-").trim();

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

  syncSelectedAccountSnapshot() {
    const selected = this.parseSelectedAccountName();
    if (!selected || selected === "-") {
      return;
    }

    const prev = isObject(this.accountSnapshots[selected]) ? this.accountSnapshots[selected] : {};
    const balances = this.parseBalanceFields();
    const currentSend = String(this.state.send || "-").trim();
    const currentReward = String(this.state.reward || "-").trim();
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
        progress: isSelected ? currentProgress : String(snapshot.progress || "-"),
        send: isSelected
          ? (String(this.state.send || "-") !== "-" ? String(this.state.send || "-") : String(snapshot.send || "-"))
          : String(snapshot.send || "-"),
        reward: isSelected
          ? (String(this.state.reward || "-") !== "-" ? String(this.state.reward || "-") : String(snapshot.reward || "-"))
          : String(snapshot.reward || "-"),
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

    const rewardParts = [];
    if (row && row.rewardTier && row.rewardTier !== "-") {
      rewardParts.push(`Tier ${row.rewardTier}`);
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
    const tier = String(this.state.rewardTier || "-").trim();
    const quality = String(this.state.rewardQuality || "-").trim();
    const todayPoints = String(this.state.rewardTodayPoints || "-").trim();
    const volume = String(this.state.rewardVolume || "-").trim();
    const dailyCheckin = String(this.state.rewardDailyCheckin || "-").trim();

    const lines = [];
    const primaryParts = [];
    const secondaryParts = [];

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

    return lines;
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
    const shownAccountCount = Math.min(rows.length, accountLimit);

    const lines = [
      `Time  ${now} WIB`,
      `Run   ${modeLabel} | ${this.state.phase}`,
      `Acct  ${selectedAccount} | ${shownAccountCount}/${rows.length || 0} shown`,
      `TX    ${this.state.swapsTotal} | ok ${this.state.swapsOk} | fail ${this.state.swapsFail} | target ${this.state.targetPerDay}/day`
    ];

    const selectedRewardLines = this.buildTelegramSelectedRewardsLines();
    if (selectedRewardLines.length > 0) {
      lines.push(...selectedRewardLines);
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
      const topBorder = `+${"=".repeat(frameWidth - 2)}+`;
      const midBorder = `+${"-".repeat(frameWidth - 2)}+`;
      const bannerLine = (text) => `| ${this.formatCell(text, contentWidth)} |`;

      const columnCount = 6;
      const separatorWidth = 3 * (columnCount - 1);
      const accountWidth = 14;
      const statusWidth = 9;
      const ccWidth = 10;
      const txProgressWidth = 20;
      const rewardWidth = 52;
      const sendPlanWidth = Math.max(
        20,
        contentWidth - separatorWidth - (accountWidth + statusWidth + ccWidth + txProgressWidth + rewardWidth)
      );
      const tableWidths = [accountWidth, statusWidth, ccWidth, txProgressWidth, sendPlanWidth, rewardWidth];
      const tableRow = (cells) => `| ${cells.map((cell, idx) => this.formatCell(cell, tableWidths[idx])).join(" | ")} |`;
      const tableRule = (char) => `| ${tableWidths.map((width) => char.repeat(width)).join(" | ")} |`;

      const lines = [];
      lines.push(topBorder);
      lines.push(
        bannerLine(
          `RootFiBot Auto-Send V1  |  ${now} WIB  |  ${accountCount} akun  |  Mode: ${modeLabel}`
        )
      );
      lines.push(
        bannerLine(
          `Sends: ${this.state.swapsTotal} total  ${this.state.swapsOk} ok  ${this.state.swapsFail} fail  |  Target: ${this.state.targetPerDay}/day`
        )
      );
      lines.push(
        bannerLine(
          `State: ${this.state.phase}`
        )
      );
      lines.push(midBorder);
      lines.push(tableRow(["Akun", "Status", "CC", "TX Progress", "Send Plan", "Tier / Q / Today / Vol / Check-in"]));
      lines.push(tableRule("-"));

      if (rows.length === 0) {
        lines.push(tableRow(["-", "IDLE", "-", "-", "-", "-"]));
      } else {
        for (const row of rows) {
          const progressLabel = String(row.progress || "-");
          const sendLabel = String(row.send || "-");
          const rewardLabel = String(row.rewardSummary || "-");
          lines.push(tableRow([row.name, row.status, row.cc, progressLabel, sendLabel, rewardLabel]));
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
    accounts: accountMap
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

function cloneRuntimeConfig(config) {
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
    session: { ...config.session },
    send: {
      ...config.send,
      randomAmount: {
        ...(isObject(config.send && config.send.randomAmount) ? config.send.randomAmount : {})
      }
    },
    ui: { ...config.ui }
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

function generateRandomCcAmount(randomAmountConfig) {
  const decimals = clampToNonNegativeInt(randomAmountConfig.decimals, 2);
  const factor = Math.pow(10, decimals);
  const minUnits = Math.ceil(Number(randomAmountConfig.min) * factor);
  const maxUnits = Math.floor(Number(randomAmountConfig.max) * factor);

  if (minUnits <= 0 || maxUnits <= 0 || minUnits > maxUnits) {
    throw new Error("Random amount range is invalid. Check config.send.randomAmount settings.");
  }

  const units = randomIntInclusive(minUnits, maxUnits);
  const amount = (units / factor).toFixed(decimals);
  return normalizeCcAmount(amount);
}

function buildSendRequestsWithRandomRecipients(recipients, sendPolicy) {
  const requests = [];
  const txCount = clampToNonNegativeInt(sendPolicy.maxLoopTx || sendPolicy.maxTx, 1);

  for (let index = 0; index < txCount; index += 1) {
    const amount = generateRandomCcAmount(sendPolicy.randomAmount);
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

function buildSingleExternalRandomRequest(recipients, sendPolicy, source = "external-random") {
  const amount = generateRandomCcAmount(sendPolicy.randomAmount);
  const target = getRandomRecipient(recipients);

  return {
    amount,
    label: target.alias,
    address: target.partyId,
    source
  };
}

function buildHybridExternalRequest(recipients, sendPolicy, refundTargetAccount) {
  const request = buildSingleExternalRandomRequest(recipients, sendPolicy, "hybrid-external-random");
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

function buildSendRequests(target, sendPolicy, fixedAmountInput, idempotencySeed) {
  const requests = [];
  const txCount = clampToNonNegativeInt(sendPolicy.maxLoopTx || sendPolicy.maxTx, 1);

  for (let index = 0; index < txCount; index += 1) {
    const amount = fixedAmountInput
      ? normalizeCcAmount(fixedAmountInput)
      : generateRandomCcAmount(sendPolicy.randomAmount);

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

function selectHybridRefundTarget(sourceAccount, selectedAccounts, accountSnapshots) {
  const sourceName = String(sourceAccount && sourceAccount.name ? sourceAccount.name : "").trim();
  const candidates = Array.isArray(selectedAccounts)
    ? selectedAccounts
        .filter((account) => {
          const name = String(account && account.name ? account.name : "").trim();
          const address = String(account && account.address ? account.address : "").trim();
          return Boolean(name) && Boolean(address) && name !== sourceName;
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
        .filter((account) => String(account && account.address ? account.address : "").trim())
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
  preferredModeInput = null
) {
  const safeRecipients = Array.isArray(recipients) ? recipients : [];
  const internalPlan = buildInternalSendRequests(
    accounts,
    senderName,
    sendPolicy,
    loopRound,
    avoidRecipientNames
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
      requests: [buildSingleExternalRandomRequest(safeRecipients, sendPolicy, "hybrid-external-random")],
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
    requests: [buildSingleExternalRandomRequest(safeRecipients, sendPolicy, "hybrid-external-random")],
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

  const randomAmount = isObject(sendPolicy && sendPolicy.randomAmount)
    ? sendPolicy.randomAmount
    : null;
  const decimals = Math.min(
    8,
    Math.max(
      0,
      clampToNonNegativeInt(
        randomAmount && Object.prototype.hasOwnProperty.call(randomAmount, "decimals")
          ? randomAmount.decimals
          : 3,
        3
      )
    )
  );

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
  const maxLoopTx = clampToNonNegativeInt(
    Object.prototype.hasOwnProperty.call(sendInput, "maxLoopTx")
      ? sendInput.maxLoopTx
      : (
          Object.prototype.hasOwnProperty.call(sendInput, "maxTx")
            ? sendInput.maxTx
            : sendInput.maxTxPerAccount
        ),
    INTERNAL_API_DEFAULTS.send.maxLoopTx
  );
  if (maxLoopTx < 1) {
    throw new Error("config.send.maxLoopTx must be >= 1");
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

  const randomAmount = normalizeRandomAmountConfig(
    sendInput.randomAmount,
    INTERNAL_API_DEFAULTS.send.randomAmount,
    "config.send.randomAmount"
  );

  const sequentialAllRounds =
    typeof sendInput.sequentialAllRounds === "boolean"
      ? sendInput.sequentialAllRounds
      : (
          typeof sendInput.parallelEnabled === "boolean"
            ? !sendInput.parallelEnabled
            : INTERNAL_API_DEFAULTS.send.sequentialAllRounds
        );

  const send = {
    maxLoopTx,
    minDelayTxSeconds,
    maxDelayTxSeconds,
    parallelJitterMinSeconds,
    parallelJitterMaxSeconds,
    delayCycleSeconds,
    sequentialAllRounds,
    randomAmount
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
    walleyRefund
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

  // Step 2: Resolve recipient (skip for external wallets, no retry needed)
  stepLog("[step] Resolve recipient");
  try {
    const resolveResponse = await apiCallWithTimeout(
      () => client.resolveSendRecipient(sendRequest.address),
      "Resolve recipient",
      15000 // 15s timeout
    );
    const resolveData = isObject(resolveResponse.data) ? resolveResponse.data : {};
    const preview = JSON.stringify(resolveData).slice(0, 180);
    console.log(`[info] Resolve response: ${preview || "ok"}`);
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
      () => client.sendCcTransfer(sendRequest.address, sendRequest.amount, idempotencyKey),
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

function buildRewardsSummaryLabel(rewardLabel, qualityLabel, tierLabel) {
  const parts = [];
  const reward = String(rewardLabel || "-").trim();
  const quality = String(qualityLabel || "-").trim();
  const tier = String(tierLabel || "-").trim();

  if (reward && reward !== "-") {
    parts.push(reward);
  }
  if (quality && quality !== "-") {
    parts.push(`Q ${quality}`);
  }
  if (tier && tier !== "-") {
    parts.push(`Tier ${tier}`);
  }

  return parts.length > 0 ? parts.join(" | ") : "-";
}

function extractThisWeekRewardLabelFromResponse(payload) {
  const data = isObject(payload && payload.data) ? payload.data : {};
  const candidates = [];

  candidates.push(data.earnedThisWeekCc, data.thisWeekCc, data.rewardThisWeekCc);

  if (isObject(data.tierProgress)) {
    candidates.push(
      data.tierProgress.earnedThisWeekCc,
      data.tierProgress.thisWeekRewardCc,
      data.tierProgress.rewardThisWeekCc,
      data.tierProgress.thisWeekCc
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

  return { quality, tier, todayPoints, volume, dailyCheckin };
}

async function refreshThisWeekRewardDashboard(client, dashboard, accountLogTag = null) {
  let qualityLabel = "-";
  let tierLabel = "-";
  let todayPointsLabel = "-";
  let volumeLabel = "-";
  let dailyCheckinLabel = "-";

  try {
    const overviewResponse = await client.getRewardsOverview();
    const insights = extractRewardsInsightsFromResponse(overviewResponse);
    qualityLabel = insights.quality;
    tierLabel = insights.tier;
    todayPointsLabel = insights.todayPoints;
    volumeLabel = insights.volume;
    dailyCheckinLabel = insights.dailyCheckin;
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
    } catch (error) {
      if (!isTimeoutError(error) && !isCheckpointOr429Error(error)) {
        console.log(withAccountTag(accountLogTag, `[warn] Rewards page scrape failed: ${error.message}`));
      }
    }
  }

  if (
    qualityLabel !== "-" ||
    tierLabel !== "-" ||
    todayPointsLabel !== "-" ||
    volumeLabel !== "-" ||
    dailyCheckinLabel !== "-"
  ) {
    const summaryLabel = buildRewardsSummaryLabel(
      qualityLabel,
      tierLabel,
      todayPointsLabel,
      volumeLabel,
      dailyCheckinLabel
    );
    dashboard.setState({
      reward: "-",
      rewardQuality: qualityLabel,
      rewardTier: tierLabel,
      rewardTodayPoints: todayPointsLabel,
      rewardVolume: volumeLabel,
      rewardDailyCheckin: dailyCheckinLabel
    });
    console.log(withAccountTag(accountLogTag, `[info] Rewards stats: ${summaryLabel}`));
  }
  // Don't log warning for timeout - just silently skip
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
  const BALANCE_GUARD_MIN_BUFFER_CC = 0.001;
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

    // Delay after every successful transaction, including the last tx in a batch.
    if (delayTxMaxSec > 0) {
      const delayTxSec = randomIntInclusive(delayTxMinSec, delayTxMaxSec);
      const delayTargetLabel = hasMoreTxAfterCurrent ? "next tx" : "balance refresh";
      console.log(`[info] Waiting ${delayTxSec}s after successful tx before ${delayTargetLabel}...`);
      dashboard.setState({
        phase: "cooldown",
        cooldown: `${delayTxSec}s`,
        send: `Post-success cooldown ${delayTxSec}s before ${delayTargetLabel}`
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

  applySessionReuseConcurrencyLimit(config.session.maxConcurrentSessionReuse);

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
    resumeFromDeferReason
  } = context;
  const safeSmartFillBlockRecipients = Array.isArray(smartFillBlockRecipients)
    ? smartFillBlockRecipients
        .map((item) => String(item || "").trim())
        .filter((item) => Boolean(item))
    : [];
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
  const configuredMaxLoopTx = clampToNonNegativeInt(
    accountConfig.send.maxLoopTx || accountConfig.send.maxTx,
    1
  );
  const effectiveMaxLoopTx = Number.isFinite(Number(maxLoopTxOverride))
    ? Math.max(1, clampToNonNegativeInt(maxLoopTxOverride, 1))
    : configuredMaxLoopTx;
  accountConfig.send.maxLoopTx = effectiveMaxLoopTx;

  const cycleLoopRounds = Math.max(
    1,
    clampToNonNegativeInt(totalLoopRounds, configuredMaxLoopTx)
  );
  const accountTargetPerDay =
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
    targetPerDay: String(accountTargetPerDay),
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

    // Build send requests based on mode
    let sendRequests = [];
    if (sendMode === "external") {
      if (recipientsInfo.missing || recipientsInfo.recipients.length === 0) {
        throw new Error("External mode requires recipient.txt with valid recipients");
      }

      if (!sendPolicy.randomAmount.enabled) {
        throw new Error("External mode requires config.send.randomAmount.enabled=true");
      }

      // Build requests with random recipient per TX
      sendRequests = buildSendRequestsWithRandomRecipients(recipientsInfo.recipients, sendPolicy);

      const amountLabel = `${sendPolicy.randomAmount.min}-${sendPolicy.randomAmount.max} (random)`;
      const recipientsList = sendRequests.map(r => r.label).join(", ");
      dashboard.setState({
        send: `${amountLabel} CC x${sendRequests.length} -> random recipients`,
        mode: "external"
      });
      console.log(`[init] Send plan: ${amountLabel} CC x${sendRequests.length} -> [${recipientsList}]`);
    } else if (sendMode === "hybrid") {
      if (recipientsInfo.missing || recipientsInfo.recipients.length === 0) {
        throw new Error("Hybrid mode requires recipient.txt with valid recipients");
      }

      if (!sendPolicy.randomAmount.enabled) {
        throw new Error("Hybrid mode requires config.send.randomAmount.enabled=true");
      }

      const hybridPlan = buildHybridSendRequests(
        selectedAccounts,
        account.name,
        recipientsInfo.recipients,
        sendPolicy,
        currentRound,
        safeSmartFillBlockRecipients,
        hybridAssignedMode
      );

      if (hybridPlan.selectedMode === "internal" && safeSmartFillBlockRecipients.length > 0) {
        console.log(
          `[hybrid] Smart-fill guard for ${account.name}: avoid send-back to [${safeSmartFillBlockRecipients.join(", ")}]`
        );
      }

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

        return {
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
            `${fallbackLabel} | offset=${hybridPlan.primaryOffset}${fallbackSourceLabel}`
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
            `${fallbackSourceLabel} | refund=post-send-lowest-balance-priority`
        );
      }
    } else if (sendMode === "internal") {
      if (!sendPolicy.randomAmount.enabled) {
        throw new Error("Internal mode requires config.send.randomAmount.enabled=true");
      }

      const internalPlan = buildInternalSendRequests(
        selectedAccounts,
        account.name,
        sendPolicy,
        currentRound,
        safeSmartFillBlockRecipients
      );

      if (safeSmartFillBlockRecipients.length > 0) {
        console.log(
          `[internal] Smart-fill guard for ${account.name}: avoid send-back to [${safeSmartFillBlockRecipients.join(", ")}]`
        );
      }

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
          mode: "internal-rotating"
        });

        return {
          success: true,
          account: account.name,
          mode: "internal-rotating-deferred",
          deferred: true,
          deferReason,
          deferRetryAfterSeconds: retryAfterSeconds,
          deferRequiredAmount: null,
          deferAvailableAmount: null,
          txCompleted: 0,
          txSkipped: 0
        };
      }

      sendRequests = internalPlan.requests;
      const primaryRequest = sendRequests[0];
      const fallbackCount = Math.max(0, sendRequests.length - 1);
      const fallbackLabel = fallbackCount > 0 ? ` (+${fallbackCount} fallback)` : "";

      dashboard.setState({
        send: `${primaryRequest.amount} CC -> ${primaryRequest.label}${fallbackLabel}`,
        mode: "internal-rotating"
      });
      console.log(
        `[init] Send plan (internal-rotating): ${primaryRequest.amount} CC -> ${primaryRequest.label}` +
          `${fallbackLabel} | offset=${internalPlan.primaryOffset}`
      );
    } else {
      dashboard.setState({ mode: "balance-only" });
      console.log("[init] Balance check only mode");
    }

    if (args.dryRun) {
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

        await refreshThisWeekRewardDashboard(client, dashboard, accountLogTag);

        let sendBatchResult = {
          completedTx: 0,
          skippedTx: 0,
          deferred: false,
          deferReason: null,
          deferRetryAfterSeconds: 0,
          completedTransfers: []
        };

        if (sendRequests.length > 0) {
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

    await refreshThisWeekRewardDashboard(client, dashboard, accountLogTag);

    let sendBatchResult = {
      completedTx: 0,
      skippedTx: 0,
      deferred: false,
      deferReason: null,
      deferRetryAfterSeconds: 0,
      completedTransfers: []
    };

    if (sendRequests.length > 0) {
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

function getNextMidnightUTC() {
  const now = new Date();
  const tomorrow = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0, 0, 0, 0
  ));
  return tomorrow;
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
    walleyRefundBridge
  } = context;

  const cycleStartTime = new Date();
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
  
  // Reset round-robin offset untuk daily cycle baru
  resetRoundRobinOffset();
  
  // Reset global TX stats untuk daily cycle baru
  resetGlobalTxStats();
  
  // Clean up expired reciprocal cooldown state from previous runs
  cleanupExpiredSendPairs();
  
  // Sort accounts for deterministic base order used by rotating offset strategy
  const sortedAccounts = [...accounts.accounts].sort((a, b) => 
    a.name.localeCompare(b.name)
  );
  
  console.log(`\n${"#".repeat(70)}`);
  console.log(`[cycle] Loop cycle started at ${formatUTCTime(cycleStartTime)}`);
  console.log(`[cycle] Mode: ${sendMode} | Accounts: ${sortedAccounts.length}`);
  if (sendMode === "internal" || sendMode === "hybrid") {
    console.log(`[internal] Strategy: ADAPTIVE ROTATING OFFSETS + COOLDOWN-AWARE FALLBACK`);
    console.log(`[internal] Guard: no direct send-back to previous sender for >=10 minutes`);
  }
  if (sendMode === "hybrid") {
    console.log("[hybrid] Strategy: RANDOM PER SEND (internal atau external)");
  }
  console.log(`${"#".repeat(70)}\n`);

  const results = [];
  const totalAccounts = sortedAccounts.length;
  const configuredMaxLoopTx = clampToNonNegativeInt(config.send.maxLoopTx || config.send.maxTx, 1);
  const totalLoopRounds = sendMode === "balance-only" ? 1 : configuredMaxLoopTx;
  
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
  
  // Round delay: fixed delay between rounds
  const delayRoundSec = clampToNonNegativeInt(
    config.send.delayCycleSeconds,
    INTERNAL_API_DEFAULTS.send.delayCycleSeconds
  );
  const forceSequentialAllRounds =
    typeof config.send.sequentialAllRounds === "boolean"
      ? config.send.sequentialAllRounds
      : INTERNAL_API_DEFAULTS.send.sequentialAllRounds;
  
  const accountSnapshots = {};
  const roundDeferPollSeconds = TX_RETRY_INITIAL_DELAY_SECONDS;
  const SMART_FILL_RETRY_DELAY_SECONDS = 20;
  const SMART_FILL_MAX_ATTEMPTS_PER_ROUND = 2;
  const CARRY_OVER_ROUND_DEFER_DEFAULT_SECONDS = 45;
  const carryOverDeferStateByAccount = new Map();

  // Display deterministic account order used as rotating baseline.
  const ringOrderLabel = sortedAccounts.map((item) => item.name).join(" -> ");
  if (sendMode === "internal" || sendMode === "hybrid") {
    console.log(`[internal] Base account order: ${ringOrderLabel}`);
  }
  console.log(`[cycle] Loop rounds: ${totalLoopRounds} (maxLoopTx=${configuredMaxLoopTx})`);
  if (forceSequentialAllRounds) {
    console.log("[cycle] Execution mode: sequential all rounds (parallel disabled)");
  } else {
    console.log(`[cycle] Parallel jitter: ${parallelJitterMinSec}-${parallelJitterMaxSec}s per account`);
  }
  console.log(`[cycle] Round delay: ${delayRoundSec}s between rounds\n`);

  for (let roundIndex = 0; roundIndex < totalLoopRounds; roundIndex += 1) {
    const loopRound = roundIndex + 1;
    
    // Increment round offset seed used by internal rotating recipient planner.
    incrementRoundRobinOffset();
    
    const maxDeferPassesPerRound = Math.max(3, sortedAccounts.length * 4);
    
    // Sequential mode can be forced for all rounds to reduce server pressure.
    // If disabled, round 1 stays sequential and round 2+ runs in parallel.
    const isSequentialRound = forceSequentialAllRounds || (loopRound === 1);
    const executionMode = isSequentialRound
      ? (forceSequentialAllRounds ? "SEQUENTIAL (all rounds)" : "SEQUENTIAL (auth/OTP)")
      : "PARALLEL";
    
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

      pendingEntries.push({
        account,
        deferUntilMs: 0,
        deferReason: "",
        debtTurns: 0,
        smartFillAttempts: 0,
        smartFillBlockRecipients: [],
        smartFillPriority: 0
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
        const waitSeconds = Math.max(1, Math.ceil(waitMs / 1000));
        const waitingNames = delayedEntries.map((entry) => entry.account.name).join(", ");
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

      // ========================================================================
      // EXECUTION MODE: Sequential for Round 1, Parallel for Round 2+
      // ========================================================================
      
      let roundResults = [];
      
      if (isSequentialRound) {
        // ====================================================================
        // SEQUENTIAL EXECUTION (Round 1): Process accounts one by one
        // This allows proper OTP input without prompts overlapping
        // ====================================================================
        const sequentialAccounts = readyEntries.map((e) => e.account.name).join(" -> ");
        console.log(`[sequential] Processing ${readyEntries.length} accounts one by one: ${sequentialAccounts}`);
        
        for (let i = 0; i < readyEntries.length; i++) {
          const entry = readyEntries[i];
          const account = entry.account;
          const accountToken = tokens.accounts[account.name] || normalizeTokenProfile({});
          tokens.accounts[account.name] = accountToken;

          console.log(`[sequential] [${i + 1}/${readyEntries.length}] Processing ${account.name}...`);

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
              accountIndex: i,
              totalAccounts,
              selectedAccounts: sortedAccounts,
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
              smartFillBlockRecipients: Array.isArray(entry.smartFillBlockRecipients)
                ? entry.smartFillBlockRecipients
                : [],
              resumeFromDeferReason: entry.deferReason || ""
            });
            roundResults.push({ entry, result, error: null });
          } catch (error) {
            // Check if this is a soft restart error (consecutive timeouts)
            const isSoftRestart = error && error.isSoftRestart;
            if (isSoftRestart) {
              console.log(
                `[soft-restart] ${account.name} triggered soft restart due to consecutive timeouts. ` +
                `Resetting connection pool and deferring to next round...`
              );
              
              // Reset connection pool to clear stuck connections
              await resetConnectionPool();
              
              // Defer with longer delay (120s) to allow connection reset to take effect
              roundResults.push({ 
                entry, 
                result: { 
                  success: false, 
                  account: account.name,
                  deferred: true,
                  deferReason: "soft-restart-timeout",
                  deferRetryAfterSeconds: 120 // Retry after 120s (longer for recovery)
                }, 
                error: null,
                softRestart: true
              });
            } else {
              console.error(`[error] Round ${loopRound}/${totalLoopRounds} | Account ${account.name}: ${error.message}`);
              roundResults.push({ 
                entry, 
                result: { success: false, account: account.name }, 
                error: error.message 
              });
            }
          }

          // Small delay between sequential accounts (not the full jitter)
          if (i < readyEntries.length - 1 && !args.dryRun) {
            const seqDelaySec = 2; // 2 seconds between sequential accounts
            console.log(`[sequential] Waiting ${seqDelaySec}s before next account...`);
            await sleep(seqDelaySec * 1000);
          }
        }
      } else {
        // ====================================================================
        // PARALLEL EXECUTION (Round 2+): All accounts send with staggered jitter
        // Sessions should already be established from Round 1
        // ====================================================================
        const parallelAccounts = readyEntries.map((e) => e.account.name).join(", ");
        console.log(`[parallel] Executing ${readyEntries.length} accounts with jitter ${parallelJitterMinSec}-${parallelJitterMaxSec}s: ${parallelAccounts}`);
        
        const accountPromises = readyEntries.map(async (entry, i) => {
          const account = entry.account;
          const accountToken = tokens.accounts[account.name] || normalizeTokenProfile({});
          tokens.accounts[account.name] = accountToken;

          // Apply random jitter before starting this account (staggered parallel)
          if (!args.dryRun && parallelJitterMaxSec > 0) {
            const jitterSec = randomIntInclusive(parallelJitterMinSec, parallelJitterMaxSec);
            if (jitterSec > 0) {
              console.log(`[parallel] ${account.name} waiting ${jitterSec}s jitter before start`);
              await sleep(jitterSec * 1000);
            }
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
              accountIndex: i,
              totalAccounts,
              selectedAccounts: sortedAccounts,
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
              smartFillBlockRecipients: Array.isArray(entry.smartFillBlockRecipients)
                ? entry.smartFillBlockRecipients
                : [],
              resumeFromDeferReason: entry.deferReason || ""
            });
            return { entry, result, error: null };
          } catch (error) {
            // Check if this is a soft restart error (consecutive timeouts)
            const isSoftRestart = error && error.isSoftRestart;
            if (isSoftRestart) {
              console.log(
                `[soft-restart] ${account.name} triggered soft restart due to consecutive timeouts. ` +
                `Resetting connection pool and deferring to next round...`
              );
              
              // Reset connection pool to clear stuck connections
              await resetConnectionPool();
              
              // Defer with longer delay (120s) to allow connection reset to take effect
              return { 
                entry, 
                result: { 
                  success: false, 
                  account: account.name,
                  deferred: true,
                  deferReason: "soft-restart-timeout",
                  deferRetryAfterSeconds: 120 // Retry after 120s (longer for recovery)
                }, 
                error: null,
                softRestart: true
              };
            } else {
              console.error(`[error] Round ${loopRound}/${totalLoopRounds} | Account ${account.name}: ${error.message}`);
              return { 
                entry, 
                result: { success: false, account: account.name }, 
                error: error.message 
              };
            }
          }
        });
        
        // Wait for all parallel executions to complete
        roundResults = await Promise.all(accountPromises);
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
      const inboundSendersByRecipient = new Map();

      for (const { entry, result, error } of roundResults) {
        if (error || !result || !Array.isArray(result.sentRecipientLabels)) {
          continue;
        }

        for (const recipientLabelRaw of result.sentRecipientLabels) {
          const recipientLabel = String(recipientLabelRaw || "").trim();
          if (!recipientLabel) {
            continue;
          }

          if (!inboundSendersByRecipient.has(recipientLabel)) {
            inboundSendersByRecipient.set(recipientLabel, []);
          }
          inboundSendersByRecipient.get(recipientLabel).push(entry.account.name);
        }
      }
      
      for (const { entry, result, error } of roundResults) {
        if (error) {
          results.push({ success: false, account: entry.account.name, round: loopRound, error });
          continue;
        }
        
        results.push({ ...result, round: loopRound });

        if (result && result.deferred && sendMode !== "balance-only") {
          const deferReason = String(result.deferReason || "temporary");

          // Insufficient balance should not block the current parallel round.
          // Let other accounts continue, then retry this account in the next round.
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
            const inboundSenders = inboundSendersByRecipient.get(entry.account.name) || [];
            const smartFillAttempts = Math.max(
              0,
              clampToNonNegativeInt(entry.smartFillAttempts, 0)
            );

            if (
              (sendMode === "internal" || sendMode === "hybrid") &&
              inboundSenders.length > 0 &&
              smartFillAttempts < SMART_FILL_MAX_ATTEMPTS_PER_ROUND
            ) {
              const retryAfterSeconds = SMART_FILL_RETRY_DELAY_SECONDS;
              const inboundSendersLabel = inboundSenders.join(", ");
              console.log(
                `[cycle] Smart-fill ${entry.account.name}: inbound from [${inboundSendersLabel}] detected. ` +
                `Retry in ${retryAfterSeconds}s (attempt ${smartFillAttempts + 1}/${SMART_FILL_MAX_ATTEMPTS_PER_ROUND})`
              );

              nextPendingEntries.push({
                account: entry.account,
                deferUntilMs: Date.now() + (retryAfterSeconds * 1000),
                deferReason: "smart-fill",
                debtTurns: (entry.debtTurns || 0) + 1,
                smartFillAttempts: smartFillAttempts + 1,
                smartFillBlockRecipients: inboundSenders.slice(),
                smartFillPriority: 2
              });
              passMadeProgress = true;
              continue;
            }

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
            debtTurns: (entry.debtTurns || 0) + 1,
            smartFillAttempts: clampToNonNegativeInt(entry.smartFillAttempts, 0),
            smartFillBlockRecipients: Array.isArray(entry.smartFillBlockRecipients)
              ? entry.smartFillBlockRecipients
              : [],
            smartFillPriority: clampToNonNegativeInt(entry.smartFillPriority, 0)
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
        const priorityDiff =
          clampToNonNegativeInt(right.smartFillPriority, 0) -
          clampToNonNegativeInt(left.smartFillPriority, 0);
        if (priorityDiff !== 0) {
          return priorityDiff;
        }

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
        const waitSeconds = Math.max(1, Math.ceil(waitMs / 1000));
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

  const [rawConfig, rawAccounts, rawTokens] = await Promise.all([
    readJson(configPath, "config"),
    readJson(accountsPath, "accounts"),
    readOptionalJson(tokensPath, "tokens")
  ]);

  const syncedRawConfig = await syncWalleyRefundSenderMap(configPath, rawConfig);
  const config = normalizeConfig(syncedRawConfig);
  const accounts = normalizeAccounts(rawAccounts);
  const legacyCookies = extractLegacyAccountCookies(rawAccounts);
  const tokens = normalizeTokens(rawTokens, accounts);
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
    walleyRefundBridge
  };

  // Daily loop
  let cycleCount = 0;
  const maxConsecutiveErrors = 3;
  let consecutiveErrors = 0;

  while (true) {
    cycleCount++;

    try {
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

      // Run the daily cycle
      const cycleResult = await runDailyCycle(cycleContext);
      
      // Reset consecutive errors on success
      consecutiveErrors = 0;

      // Calculate time until next cycle (24 hours from cycle start, or next midnight UTC)
      const now = new Date();
      const nextCycleTime = getNextMidnightUTC();
      const waitMs = Math.max(0, nextCycleTime - now);
      
      if (waitMs > 0 && !args.dryRun) {
        console.log(`\n${"=".repeat(70)}`);
        console.log(`[cycle] Daily cycle #${cycleCount} completed!`);
        console.log(`[cycle] Results: ${cycleResult.successful.length} successful, ${cycleResult.failed.length} failed`);
        console.log(`[cycle] Duration: ${formatDuration(cycleResult.cycleDuration)}`);
        console.log(`[cycle] Next cycle at: ${formatUTCTime(nextCycleTime)}`);
        console.log(`[cycle] Waiting: ${formatDuration(waitMs)}`);
        console.log(`${"=".repeat(70)}\n`);

        if (telegramReporter) {
          telegramReporter.scheduleText(
            [
              `${getJakartaTimeStamp()} WIB`,
              "Status: WAITING",
              `Cycle #: ${cycleCount}`,
              `Result: ${cycleResult.successful.length} successful | ${cycleResult.failed.length} failed`,
              `Next cycle: ${formatUTCTime(nextCycleTime)}`,
              `Waiting: ${formatDuration(waitMs)}`
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
