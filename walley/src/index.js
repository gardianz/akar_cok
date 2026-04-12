import { resolve } from 'path';
import { pathToFileURL } from 'url';
import { loadRuntimeConfig } from './config.js';
import { WalleySession, resolveTokenSelection } from './client.js';
import { WalleyBrowserSession } from './browser.js';

function now() {
  return new Date().toISOString();
}

function log(message) {
  console.log(`[${now()}] ${message}`);
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function randomIntegerBetween(min, max) {
  const safeMin = Math.min(min, max);
  const safeMax = Math.max(min, max);
  return Math.floor(Math.random() * (safeMax - safeMin + 1)) + safeMin;
}

function formatDelaySecondsTag(ms) {
  const seconds = Math.max(1, Math.round(Number(ms) / 1000));
  return `[${seconds}s]`;
}

function buildSessionDelayKey(session) {
  const name = session?.account?.name || '';
  const partyHint = session?.account?.partyHint || '';
  const partyId = session?.partyId || '';
  return `${name}::${partyHint}::${partyId}`;
}

async function applyPostAcceptTransferDelay(logger, label, config) {
  const delayRange = config.postAcceptTransferDelayRangeMs || { min: 0, max: 0 };
  const delayMs = randomIntegerBetween(
    Math.max(0, Number(delayRange.min) || 0),
    Math.max(0, Number(delayRange.max) || 0),
  );
  if (delayMs <= 0) {
    return 0;
  }

  logger(`${label} waiting ${formatDelaySecondsTag(delayMs)} after accept before refund send...`);
  await sleep(delayMs);
  return delayMs;
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  async function run() {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index], index);
    }
  }

  const runners = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    () => run(),
  );
  await Promise.all(runners);
  return results;
}

function normalizeTransferOverrides(transfers) {
  if (!Array.isArray(transfers)) {
    return null;
  }

  return transfers.map((transfer, index) => {
    if (!transfer || typeof transfer !== 'object') {
      throw new Error(`transferOverrides[${index}] must be an object`);
    }

    const normalized = {
      from: String(transfer.from || '').trim(),
      toPartyId: String(transfer.toPartyId || '').trim(),
      amount: String(transfer.amount || '').trim(),
      tokenSymbol: String(transfer.tokenSymbol || 'CC').trim() || 'CC',
      instrumentId: String(transfer.instrumentId || '').trim(),
      instrumentAdminId: String(transfer.instrumentAdminId || '').trim(),
      reason: String(transfer.reason || '').trim(),
    };

    if (!normalized.from) {
      throw new Error(`transferOverrides[${index}].from must be a non-empty string`);
    }
    if (!normalized.toPartyId) {
      throw new Error(`transferOverrides[${index}].toPartyId must be a non-empty string`);
    }
    if (!normalized.amount) {
      throw new Error(`transferOverrides[${index}].amount must be a non-empty string`);
    }

    return normalized;
  });
}

function matchAccountReference(account, reference) {
  const ref = String(reference || '').trim();
  if (!ref) {
    return false;
  }

  if (account.name === ref || account.partyHint === ref) {
    return true;
  }

  if (ref.includes('::')) {
    return account.partyHint === ref.split('::')[0];
  }

  return false;
}

function collectAccountsForTransfers(accounts, transfers) {
  if (!Array.isArray(transfers) || transfers.length === 0) {
    return accounts;
  }

  const selectedAccounts = [];
  const seen = new Set();

  for (const transfer of transfers) {
    const matchedAccount = accounts.find((account) => matchAccountReference(account, transfer.from));
    if (!matchedAccount) {
      continue;
    }

    const key = `${matchedAccount.name}::${matchedAccount.partyHint}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    selectedAccounts.push(matchedAccount);
  }

  return selectedAccounts.length > 0 ? selectedAccounts : accounts;
}

function findSender(sessions, transfer) {
  return sessions.find(
    (session) =>
      session.account.name === transfer.from ||
      session.account.partyHint === transfer.from ||
      session.partyId === transfer.from,
  );
}

function createSession(account, config, rootDir) {
  if (config.sessionMode === 'browser-session') {
    return new WalleyBrowserSession(account, config, rootDir);
  }
  if (config.sessionMode === 'api-mnemonic') {
    if (!account.mnemonic) {
      throw new Error(`Account ${account.name} is missing mnemonic for api-mnemonic mode`);
    }
    return new WalleySession(account, config);
  }
  throw new Error(`Unsupported sessionMode "${config.sessionMode}"`);
}

async function settleIncomingTransfers(session, logger, config, transfer = null) {
  if (!config.autoAcceptPendingTransfers || typeof session.acceptAllPendingTransfers !== 'function') {
    return {
      accepted: [],
      count: 0,
      done: true,
      reason: 'auto-accept-disabled',
    };
  }

  const attempts = Math.max(1, Number(config.pendingTransferPollAttempts) || 1);
  const intervalMs = Math.max(1000, Number(config.pendingTransferPollIntervalMs) || 4000);
  let lastResult = {
    accepted: [],
    count: 0,
    done: true,
    reason: 'no-pending-transfer',
  };

  for (let attempt = 1; attempt <= attempts; attempt++) {
    lastResult = await session.acceptAllPendingTransfers((message) => logger(message));
    if (lastResult.count > 0) {
      logger(`accepted ${lastResult.count} pending transfer(s)`);
    }
    if (lastResult.reason && lastResult.reason !== 'no-pending-transfer' && lastResult.count === 0) {
      logger(`pending transfer handler state: ${lastResult.reason}`);
    }

    const pendingTransfers = await session.listPendingIncomingTransfers().catch(() => []);
    if (!pendingTransfers.length) {
      return {
        ...lastResult,
        done: true,
      };
    }

    if (attempt < attempts) {
      const transferLabel = transfer
        ? `before refund ${transfer.amount} ${transfer.tokenSymbol || 'CC'}`
        : 'before transfer processing';
      logger(
        `pending incoming transfer(s) still present (${pendingTransfers.length}); waiting ${Math.round(intervalMs / 1000)}s ${transferLabel}...`,
      );
      await sleep(intervalMs);
    }
  }

  logger(`pending transfer handler exhausted retries: ${lastResult.reason}`);
  return lastResult;
}

export async function runWalleyTransfers(options = {}) {
  const rootDir = resolve(options.rootDir || process.cwd());
  const logger = typeof options.logger === 'function' ? options.logger : log;
  const config = loadRuntimeConfig(rootDir);
  const transfers = normalizeTransferOverrides(options.transfers) || config.transfers;
  const accountsToLogin = collectAccountsForTransfers(config.accounts, transfers);

  if (config.transferMode !== 'manual') {
    throw new Error(
      `Unsupported transferMode "${config.transferMode}". Initial Walley bot only supports manual mode.`,
    );
  }

  logger(
    `Loaded ${accountsToLogin.length}/${config.accounts.length} Walley account(s); session mode=${config.sessionMode}; transfer mode=${config.transferMode}`,
  );

  const sessions = await mapLimit(
    accountsToLogin,
    config.loginConcurrency,
    async (account) => {
      const label = account.name || account.partyHint;
      const session = createSession(account, config, rootDir);
      try {
        logger(`[${label}] login start`);
        const auth = await session.login((message) => logger(`[${label}] ${message}`));
        logger(
          `[${label}] login ok -> partyId=${auth.partyId} fingerprint=${auth.publicKeyFingerprint}`,
        );
        return session;
      } catch (error) {
        logger(`[${label}] login failed: ${error.message}`);
        if (typeof session.close === 'function') {
          await session.close().catch(() => {});
        }
        return null;
      }
    },
  );

  const activeSessions = sessions.filter(Boolean);
  if (!activeSessions.length) {
    logger('No Walley account logged in successfully');
    return {
      ok: false,
      results: transfers.map((transfer) => ({
        ok: false,
        transfer,
        error: 'No Walley account logged in successfully',
      })),
      successCount: 0,
      failureCount: transfers.length,
    };
  }

  const tokenCatalog = await activeSessions[0].getTokens();
  const pendingPostAcceptDelaySessions = new Set();
  logger(`Loaded ${tokenCatalog.length} token definition(s) from Walley`);

  if (config.autoAcceptPendingTransfers) {
    await mapLimit(activeSessions, config.loginConcurrency, async (session) => {
      const label = session.account.name || session.account.partyHint;
      try {
        const result = await settleIncomingTransfers(
          session,
          (message) => logger(`[${label}] ${message}`),
          config,
        );
        if (result.count > 0) {
          logger(`[${label}] settled ${result.count} pending incoming transfer(s)`);
          pendingPostAcceptDelaySessions.add(buildSessionDelayKey(session));
        }
      } catch (error) {
        logger(`[${label}] failed to settle pending incoming transfers: ${error.message}`);
      }
    });
  }

  if (config.ensureTransferPreapproval) {
    await mapLimit(activeSessions, config.loginConcurrency, async (session) => {
      const label = session.account.name || session.account.partyHint;
      try {
        const result = await session.ensureTransferPreapproval(
          (message) => logger(`[${label}] ${message}`),
        );
        logger(
          `[${label}] transfer preapproval status=${result.status}${result.enabled ? ' (submitted now)' : ''}`,
        );
      } catch (error) {
        logger(`[${label}] failed to ensure transfer preapproval: ${error.message}`);
      }
    });
  }

  if (!transfers.length) {
    logger('No transfers configured; login validation complete');
    return {
      ok: true,
      results: [],
      successCount: 0,
      failureCount: 0,
    };
  }

  let successCount = 0;
  let failureCount = 0;
  const results = [];

  for (const [index, transfer] of transfers.entries()) {
    const label = `transfer #${index + 1}`;
    const sender = findSender(activeSessions, transfer);
    if (!sender) {
      const message = `${label} failed: sender "${transfer.from}" not found in logged-in accounts`;
      failureCount++;
      logger(message);
      results.push({
        ok: false,
        transfer,
        error: message,
      });
      continue;
    }

    try {
      const token = resolveTokenSelection(tokenCatalog, transfer);
      const senderDelayKey = buildSessionDelayKey(sender);
      let shouldDelayAfterAccept = pendingPostAcceptDelaySessions.has(senderDelayKey);
      if (config.autoAcceptPendingTransfers) {
        const settleResult = await settleIncomingTransfers(
          sender,
          (message) => logger(`[${sender.account.name || sender.account.partyHint}] ${message}`),
          config,
          transfer,
        );
        if (settleResult.count > 0) {
          logger(
            `${label} settled ${settleResult.count} pending incoming transfer(s) before refund send`,
          );
          shouldDelayAfterAccept = true;
        }
      }
      if (shouldDelayAfterAccept) {
        pendingPostAcceptDelaySessions.delete(senderDelayKey);
        await applyPostAcceptTransferDelay(logger, label, config);
      }
      const beforeUnlockedBalance = await sender.getUnlockedBalance(token);
      logger(
        `${label} start: ${sender.partyId} -> ${transfer.toPartyId} amount ${transfer.amount} ${token.symbol} (unlocked ${beforeUnlockedBalance})`,
      );

      const result = await sender.sendTransfer({
        receiverPartyId: transfer.toPartyId,
        token,
        amount: transfer.amount,
        reason: transfer.reason,
      });

      let verification = {
        verified: true,
        reason: 'submit-only',
        lastUnlockedBalance: beforeUnlockedBalance,
      };
      if (config.verifyAfterSubmit && !result.verification) {
        verification = await sender.verifyTransfer({
          beforeUnlockedBalance,
          token,
          receiverPartyId: transfer.toPartyId,
          amount: transfer.amount,
          reason: transfer.reason,
          attempts: config.verificationPollAttempts,
          intervalMs: config.verificationPollIntervalMs,
        });
      } else if (result.verification) {
        verification = result.verification;
      }

      successCount++;
      logger(
        `${label} ok: verification=${verification.verified ? verification.reason : 'unconfirmed'} responseKeys=${Object.keys(result.submitted || result.matchedTransaction || {}).join(',') || 'none'}`,
      );
      results.push({
        ok: true,
        transfer,
        senderPartyId: sender.partyId,
        verification,
        result,
      });
    } catch (error) {
      failureCount++;
      logger(`${label} failed: ${error.message}`);
      results.push({
        ok: false,
        transfer,
        senderPartyId: sender.partyId,
        error: error.message,
      });
    }

    if (index < transfers.length - 1 && config.interTransferDelayMs > 0) {
      await sleep(config.interTransferDelayMs);
    }
  }

  logger(`Done: ${successCount} success, ${failureCount} failed`);

  if (!config.keepBrowserOpen) {
    await Promise.all(
      activeSessions.map(async (session) => {
        if (typeof session.close === 'function') {
          await session.close().catch(() => {});
        }
      }),
    );
  }

  return {
    ok: failureCount === 0,
    results,
    successCount,
    failureCount,
  };
}

export async function runWalleyTransfer(options = {}) {
  if (!options.transfer || typeof options.transfer !== 'object') {
    throw new Error('runWalleyTransfer requires a transfer object');
  }

  const result = await runWalleyTransfers({
    rootDir: options.rootDir,
    transfers: [options.transfer],
    logger: options.logger,
  });

  return (
    result.results[0] || {
      ok: false,
      transfer: options.transfer,
      error: 'No Walley transfer result returned',
    }
  );
}

async function main() {
  const rootDir = resolve(process.cwd());
  await runWalleyTransfers({ rootDir, logger: log });
}

const isDirectRun =
  process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  main().catch((error) => {
    console.error(`[${now()}] Fatal: ${error.message}`);
    process.exitCode = 1;
  });
}
