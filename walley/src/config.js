import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf-8'));
}

function assertArray(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function assertString(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

function optionalNumber(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function optionalBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

function normalizeDelayRange(minValue, maxValue, fallbackMin, fallbackMax) {
  const min = Math.max(0, optionalNumber(minValue, fallbackMin));
  const max = Math.max(0, optionalNumber(maxValue, fallbackMax));
  return {
    min: Math.min(min, max),
    max: Math.max(min, max),
  };
}

export function loadRuntimeConfig(rootDir = process.cwd()) {
  const configPath = resolve(rootDir, 'config.json');
  const accountsPath = resolve(rootDir, 'accounts.json');
  const transfersPath = resolve(rootDir, 'transfers.json');

  for (const requiredPath of [configPath, accountsPath, transfersPath]) {
    if (!existsSync(requiredPath)) {
      throw new Error(`Missing required file: ${requiredPath}`);
    }
  }

  const config = readJson(configPath);
  const sessionMode =
    typeof config.sessionMode === 'string' && config.sessionMode.trim()
      ? config.sessionMode.trim()
      : 'browser-session';
  const accounts = assertArray(readJson(accountsPath), 'accounts.json').map((account, index) => ({
    name:
      typeof account.name === 'string' && account.name.trim()
        ? account.name.trim()
        : `walley-${index + 1}`,
    partyHint: assertString(account.partyHint, `accounts[${index}].partyHint`),
    mnemonic: optionalString(account.mnemonic),
    userDataDir: optionalString(account.userDataDir) || `./profiles/walley-${index + 1}`,
  }));
  const transfers = assertArray(readJson(transfersPath), 'transfers.json').map((transfer, index) => ({
    from: assertString(transfer.from, `transfers[${index}].from`),
    toPartyId: assertString(transfer.toPartyId, `transfers[${index}].toPartyId`),
    amount: assertString(String(transfer.amount), `transfers[${index}].amount`),
    tokenSymbol: optionalString(transfer.tokenSymbol),
    instrumentId: optionalString(transfer.instrumentId),
    instrumentAdminId: optionalString(transfer.instrumentAdminId),
    reason: optionalString(transfer.reason),
  }));

  return {
    apiBaseUrl:
      typeof config.apiBaseUrl === 'string' && config.apiBaseUrl.trim()
        ? config.apiBaseUrl.trim()
        : 'https://api.walley.cc',
    webBaseUrl:
      typeof config.webBaseUrl === 'string' && config.webBaseUrl.trim()
        ? config.webBaseUrl.trim()
        : 'https://walley.cc',
    requestTimeoutMs: optionalNumber(config.requestTimeoutMs, 30000),
    loginConcurrency: optionalNumber(config.loginConcurrency, 3),
    sessionMode,
    transferMode:
      typeof config.transferMode === 'string' && config.transferMode.trim()
        ? config.transferMode.trim()
        : 'manual',
    ensureTransferPreapproval: config.ensureTransferPreapproval === true,
    verifyAfterSubmit: config.verifyAfterSubmit !== false,
    verificationPollIntervalMs: optionalNumber(config.verificationPollIntervalMs, 3000),
    verificationPollAttempts: optionalNumber(config.verificationPollAttempts, 8),
    interTransferDelayMs: optionalNumber(config.interTransferDelayMs, 1000),
    autoAcceptPendingTransfers: optionalBoolean(config.autoAcceptPendingTransfers, true),
    pendingTransferPollIntervalMs: optionalNumber(config.pendingTransferPollIntervalMs, 4000),
    pendingTransferPollAttempts: optionalNumber(config.pendingTransferPollAttempts, 6),
    postAcceptTransferDelayRangeMs: normalizeDelayRange(
      config.postAcceptTransferDelayMinMs,
      config.postAcceptTransferDelayMaxMs,
      3000,
      8000,
    ),
    browserChannel: optionalString(config.browserChannel) || 'chrome',
    browserHeadless: optionalBoolean(config.browserHeadless, false),
    browserNavigationTimeoutMs: optionalNumber(config.browserNavigationTimeoutMs, 45000),
    browserActionTimeoutMs: optionalNumber(config.browserActionTimeoutMs, 15000),
    bootstrapMissingSession: optionalBoolean(config.bootstrapMissingSession, true),
    keepBrowserOpen: optionalBoolean(config.keepBrowserOpen, false),
    accounts,
    transfers,
  };
}
