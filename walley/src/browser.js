import { mkdirSync } from 'fs';
import { resolve } from 'path';
import { chromium } from 'playwright';
import { WalleyApiSession } from './client.js';

function splitMnemonicWords(mnemonic) {
  return String(mnemonic || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function serialize(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeForRegexSource(value) {
  return escapeRegExp(value).replace(/\\/g, '\\\\');
}

function normalizeUiText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

export class WalleyBrowserSession extends WalleyApiSession {
  constructor(account, options, rootDir = process.cwd()) {
    super(account, options);
    this.rootDir = rootDir;
    this.webBaseUrl = options.webBaseUrl.replace(/\/+$/, '');
    this.userDataDir = resolve(
      rootDir,
      account.userDataDir || `profiles/${account.name || account.partyHint}`,
    );
    this.context = null;
    this.page = null;
    this.session = null;
  }

  async launchBrowserContext(logger = () => {}) {
    mkdirSync(this.userDataDir, { recursive: true });
    logger(`launching persistent browser profile at ${this.userDataDir}`);

    this.context = await chromium.launchPersistentContext(this.userDataDir, {
      channel: this.options.browserChannel,
      headless: this.options.browserHeadless,
      viewport: {
        width: 1440,
        height: 960,
      },
    });
    this.context.setDefaultTimeout(this.options.browserActionTimeoutMs);

    this.page = (await this.pickBestPage()) || (await this.context.newPage());
  }

  async restartBrowserContext(logger = () => {}) {
    if (this.context) {
      logger('restarting browser context for Walley recovery');
      await this.close().catch(() => {});
    }
    await this.launchBrowserContext(logger);
  }

  async login(logger = () => {}) {
    await this.launchBrowserContext(logger);
    await this.page.goto(this.webBaseUrl, {
      waitUntil: 'domcontentloaded',
      timeout: this.options.browserNavigationTimeoutMs,
    });

    let session = await this.resolveReusableSession(logger);
    if (!session?.partyId) {
      if (!this.options.bootstrapMissingSession) {
        throw new Error(
          `No reusable browser session in ${this.userDataDir}; enable bootstrapMissingSession or login manually once`,
        );
      }
      if (!this.account.mnemonic) {
        throw new Error(
          `No reusable browser session in ${this.userDataDir} and accounts.json has no mnemonic for bootstrap`,
        );
      }

      logger('browser session missing, bootstrapping via /recover');
      await this.bootstrapViaRecoveryPhrase(logger);
      session = await this.resolveReusableSession(logger);
    }

    if (!session?.partyId) {
      throw new Error('Walley browser session was not created');
    }
    if (!session.partyId.startsWith(`${this.account.partyHint}::`)) {
      throw new Error(
        `Browser profile belongs to ${session.partyId}, expected partyHint ${this.account.partyHint}`,
      );
    }

    this.session = session;
    this.partyId = session.partyId;

    logger(`verifying registered party ${this.partyId}`);
    await this.getParty();

    return {
      partyId: session.partyId,
      partyHint: this.account.partyHint,
      publicKeyFingerprint: session.publicKeyFingerprint || '',
      publicKeyBase64: session.publicKeyBase64 || '',
    };
  }

  async readStoredSession() {
    return this.page.evaluate(() => {
      const candidates = [];

      for (let index = 0; index < localStorage.length; index++) {
        const key = localStorage.key(index);
        if (key && key.startsWith('walley-session')) {
          candidates.push({
            key,
            raw: localStorage.getItem(key),
          });
        }
      }

      const parsed = candidates
        .map((entry) => {
          try {
            return {
              key: entry.key,
              value: JSON.parse(entry.raw),
            };
          } catch {
            return null;
          }
        })
        .filter(Boolean);

      if (!parsed.length) {
        return null;
      }

      const exact = parsed.find((entry) => entry.value?.partyId);
      return exact?.value || null;
    });
  }

  async pickBestPage() {
    const pages = this.context.pages();
    if (!pages.length) {
      return null;
    }

    for (const page of pages) {
      const url = page.url();
      if (!url.startsWith(this.webBaseUrl)) {
        continue;
      }

      const bodyText = await page.locator('body').innerText().catch(() => '');
      if (
        /Dashboard/i.test(bodyText) ||
        /Send Transfer/i.test(bodyText) ||
        bodyText.includes(`${this.account.partyHint}::`)
      ) {
        return page;
      }
    }

    return pages.find((page) => page.url().startsWith(this.webBaseUrl)) || pages[0];
  }

  async waitForStoredSession(timeoutMs = 8000, pollMs = 500) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const session = await this.readStoredSession().catch(() => null);
      if (session?.partyId) {
        return session;
      }
      await sleep(pollMs);
    }
    return null;
  }

  async readSessionFromDashboardUi() {
    const pageUrl = this.page.url();
    const bodyText = await this.page.locator('body').innerText().catch(() => '');
    const dashboardVisible =
      /Dashboard/i.test(bodyText) ||
      /Send Transfer/i.test(bodyText) ||
      pageUrl === `${this.webBaseUrl}/` ||
      /\/dashboard(?:\/)?$/i.test(pageUrl);

    if (!dashboardVisible) {
      return null;
    }

    const partyIdPattern = new RegExp(`${escapeRegExp(this.account.partyHint)}::[a-zA-Z0-9]+`);
    const matchedPartyId = bodyText.match(partyIdPattern)?.[0];
    if (!matchedPartyId) {
      return null;
    }

    return {
      partyId: matchedPartyId,
      publicKeyFingerprint: '',
      publicKeyBase64: '',
      source: 'dashboard-ui',
    };
  }

  async readPageSnapshot() {
    const [title, bodyText] = await Promise.all([
      this.page.title().catch(() => ''),
      this.page.locator('body').innerText().catch(() => ''),
    ]);

    return {
      url: this.page.url(),
      title,
      bodyText,
    };
  }

  async resolveReusableSession(logger = () => {}) {
    const deadline = Date.now() + this.options.browserNavigationTimeoutMs;

    while (Date.now() < deadline) {
      const stored = await this.readStoredSession().catch(() => null);
      if (stored?.partyId) {
        return stored;
      }

      const dashboardSession = await this.readSessionFromDashboardUi();
      if (dashboardSession?.partyId) {
        logger(`reusing authenticated dashboard state for ${dashboardSession.partyId}`);
        return dashboardSession;
      }

      await sleep(1000);
    }

    const snapshot = await this.readPageSnapshot();
    logger(
      `reusable session not detected; final page url=${snapshot.url} title=${snapshot.title || '-'}`,
    );
    return null;
  }

  async bootstrapViaRecoveryPhrase(logger = () => {}) {
    const words = splitMnemonicWords(this.account.mnemonic);
    if (words.length !== 24) {
      throw new Error(
        `Expected 24 recovery words for bootstrap, received ${words.length}`,
      );
    }

    await this.page.goto(`${this.webBaseUrl}/recover`, {
      waitUntil: 'domcontentloaded',
      timeout: this.options.browserNavigationTimeoutMs,
    });

    await this.page.waitForFunction(() => {
      const textInputs = Array.from(document.querySelectorAll('input')).filter(
        (node) => node instanceof HTMLInputElement && node.type === 'text',
      ).length;
      const importButtons = Array.from(document.querySelectorAll('button, a')).some((node) =>
        /Import Recovery Phrase/i.test((node.textContent || '').replace(/\s+/g, ' ').trim()),
      );
      return textInputs >= 25 || importButtons;
    }, null, {
      timeout: this.options.browserNavigationTimeoutMs,
    });

    const collectTextInputIndexes = async () =>
      this.page.locator('input').evaluateAll((nodes) =>
        nodes
          .map((node, index) => ({
            index,
            type: node instanceof HTMLInputElement ? node.type : '',
          }))
          .filter((entry) => entry.type === 'text')
          .map((entry) => entry.index),
      );

    let textInputIndexes = await collectTextInputIndexes();
    if (textInputIndexes.length < 25) {
      const importRecoveryButton = this.page.getByRole('button', { name: /Import Recovery Phrase/i });
      const importRecoveryLink = this.page.getByRole('link', { name: /Import Recovery Phrase/i });
      const importButtonEnabled =
        (await importRecoveryButton.count().catch(() => 0)) > 0 &&
        (await importRecoveryButton.first().isEnabled().catch(() => false));
      if (importButtonEnabled) {
        await importRecoveryButton.first().click();
        await this.page.waitForLoadState('domcontentloaded').catch(() => {});
        await sleep(1000);
        textInputIndexes = await collectTextInputIndexes();
      } else if ((await importRecoveryLink.count().catch(() => 0)) > 0) {
        await importRecoveryLink.first().click();
        await this.page.waitForLoadState('domcontentloaded').catch(() => {});
        await sleep(1000);
        textInputIndexes = await collectTextInputIndexes();
      }
    }

    if (textInputIndexes.length < 25) {
      throw new Error('Recover form layout changed: expected party hint + 24 word inputs');
    }

    const allInputs = this.page.locator('input');
    await allInputs.nth(textInputIndexes[0]).fill(this.account.partyHint);
    for (let index = 0; index < words.length; index++) {
      await allInputs.nth(textInputIndexes[index + 1]).fill(words[index]);
    }

    const checkbox = this.page.getByRole('checkbox');
    if (!(await checkbox.isChecked())) {
      await checkbox.check();
    }

    logger('submitting recovery import');
    await this.page.getByRole('button', { name: 'Import Recovery Phrase' }).click();
    const deadline = Date.now() + this.options.browserNavigationTimeoutMs;
    while (Date.now() < deadline) {
      const stored = await this.readStoredSession().catch(() => null);
      if (stored?.partyId) {
        return stored;
      }

      const dashboardSession = await this.readSessionFromDashboardUi().catch(() => null);
      if (dashboardSession?.partyId) {
        return dashboardSession;
      }

      await this.page.waitForLoadState('domcontentloaded', { timeout: 1000 }).catch(() => {});
      await sleep(500);
    }

    const snapshot = await this.readPageSnapshot();
    throw new Error(
      `Recovery import completed but reusable session was not detected (url=${snapshot.url || '-'})`,
    );
  }

  async logoutToLogin(logger = () => {}) {
    const logoutButton = this.page.getByRole('button', { name: 'Logout' });
    if ((await logoutButton.count().catch(() => 0)) > 0) {
      logger('logging out current Walley session before recovery');
      await logoutButton.click();
      await this.page.waitForLoadState('domcontentloaded').catch(() => {});
      await sleep(1000);
      return;
    }

    await this.page.goto(`${this.webBaseUrl}/login`, {
      waitUntil: 'domcontentloaded',
      timeout: this.options.browserNavigationTimeoutMs,
    });
    await sleep(500);
  }

  async clearStoredAuthSession(logger = () => {}) {
    if (!this.page) {
      return;
    }

    logger('clearing stored Walley browser session before recovery import');
    await this.page.goto(this.webBaseUrl, {
      waitUntil: 'domcontentloaded',
      timeout: this.options.browserNavigationTimeoutMs,
    }).catch(() => {});
    await this.context?.clearCookies().catch(() => {});
    await this.page.evaluate(() => {
      try {
        const localKeys = [];
        for (let index = 0; index < localStorage.length; index++) {
          const key = localStorage.key(index);
          if (key && key.startsWith('walley-session')) {
            localKeys.push(key);
          }
        }
        for (const key of localKeys) {
          localStorage.removeItem(key);
        }
      } catch {}

      try {
        sessionStorage.clear();
      } catch {}
    }).catch(() => {});
  }

  async ensureDashboard() {
    const snapshot = await this.readPageSnapshot();
    const dashboardVisible =
      /Dashboard/i.test(snapshot.bodyText || '') ||
      /Pending Transfers/i.test(snapshot.bodyText || '') ||
      /Send Transfer/i.test(snapshot.bodyText || '') ||
      this.page.url() === `${this.webBaseUrl}/` ||
      /\/dashboard(?:\/)?$/i.test(this.page.url());

    if (!dashboardVisible) {
      await this.page.goto(this.webBaseUrl, {
        waitUntil: 'domcontentloaded',
        timeout: this.options.browserNavigationTimeoutMs,
      });
    }

    await this.page.getByRole('button', { name: 'Send Transfer' }).waitFor({
      state: 'visible',
      timeout: this.options.browserActionTimeoutMs,
    });
  }

  async openSendTransferModal() {
    await this.ensureDashboard();
    await this.page.getByRole('button', { name: 'Send Transfer' }).click();

    const modal = this.page.getByRole('alertdialog', { name: 'Send Transfer' });
    await modal.waitFor({
      state: 'visible',
      timeout: this.options.browserActionTimeoutMs,
    });
    return modal;
  }

  async selectToken(modal, tokenSymbol) {
    const tokenButton = modal.getByRole('button').filter({ hasText: 'Available:' }).first();
    const currentSelection = await tokenButton.innerText();
    if (currentSelection.includes(tokenSymbol)) {
      return;
    }

    await tokenButton.click();
    const picker = this.page.getByRole('dialog').last();
    const option = picker
      .getByRole('button')
      .filter({ hasText: new RegExp(`\\b${escapeRegExp(tokenSymbol)}\\b`) })
      .first();

    await option.waitFor({
      state: 'visible',
      timeout: this.options.browserActionTimeoutMs,
    });
    await option.click();
  }

  async ensureTransferPreapproval(logger = () => {}) {
    const current = await this.getTransferPreapproval();
    const status = current?.status || 'UNKNOWN';
    if (status === 'ENABLED') {
      logger('transfer preapproval already enabled');
      return { enabled: false, status };
    }

    throw new Error(
      `Transfer preapproval status is ${status}; enabling it via browser UI is not yet verified in this bot`,
    );
  }

  async waitForGenericConfirmDialog() {
    const dialog = this.page
      .getByRole('alertdialog')
      .filter({ hasText: /Confirm Transaction/i })
      .last();

    await dialog.waitFor({
      state: 'visible',
      timeout: this.options.browserActionTimeoutMs,
    });
    return dialog;
  }

  async getVisibleDialogTexts() {
    return this.page.evaluate(() => {
      const visible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return (
          style.visibility !== 'hidden' &&
          style.display !== 'none' &&
          rect.width > 0 &&
          rect.height > 0
        );
      };

      return Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"]'))
        .filter(visible)
        .map((node) => (node.innerText || '').replace(/\s+/g, ' ').trim());
    });
  }

  async findSigningKeyErrorMessage() {
    const dialogTexts = await this.getVisibleDialogTexts().catch(() => []);
    return dialogTexts.find((text) => /Signing key not found/i.test(text)) || '';
  }

  async recoverMissingSigningKey(logger = () => {}) {
    if (!this.account.mnemonic) {
      throw new Error('Signing key missing and no mnemonic available for recovery');
    }

    logger('signing key missing; restarting session and re-importing recovery phrase');
    await this.restartBrowserContext(logger);
    await this.clearStoredAuthSession(logger);
    await this.bootstrapViaRecoveryPhrase(logger);

    const recoveredSession = await this.resolveReusableSession(logger);
    if (!recoveredSession?.partyId) {
      throw new Error('Walley recovery completed but reusable session was not restored');
    }

    this.session = recoveredSession;
    this.partyId = recoveredSession.partyId;
    logger(`recovery complete for ${this.partyId}`);
    await this.ensureDashboard();
  }

  async waitForPendingTransferRemoval(contractId, attempts, intervalMs) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      await sleep(intervalMs);
      const pendingTransfers = await this.listPendingIncomingTransfers().catch(() => []);
      const stillPending = pendingTransfers.some((transfer) => transfer.contract_id === contractId);
      if (!stillPending) {
        return true;
      }
    }
    return false;
  }

  async clickPendingTransferAction(transfer, actionLabel) {
    const payload = {
      amount: String(transfer?.amount || '').trim(),
      sender: String(transfer?.sender || '').trim(),
      actionLabel: String(actionLabel || '').trim(),
    };

    return this.page.evaluate(({ amount, sender, actionLabel }) => {
      const visible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return (
          style.visibility !== 'hidden' &&
          style.display !== 'none' &&
          rect.width > 0 &&
          rect.height > 0
        );
      };

      const normalize = (value) => String(value || '').replace(/\s+/g, ' ').trim();
      const senderHead = sender ? sender.slice(0, Math.min(sender.length, 18)) : '';
      const cards = Array.from(document.querySelectorAll('button'))
        .filter(visible)
        .filter((button) => normalize(button.innerText) === actionLabel)
        .map((button) => {
          const card = button.closest('[class*="rounded"], [class*="border"], div');
          const text = normalize(card?.innerText || '');
          return { button, text };
        });

      const match = cards.find(({ text }) => {
        const hasAmount = amount ? text.includes(amount) : true;
        const hasSender = senderHead ? text.includes(senderHead) : true;
        return hasAmount && hasSender;
      }) || cards[0];

      if (!match || !match.button) {
        return false;
      }

      match.button.click();
      return true;
    }, payload);
  }

  async acceptNextPendingTransfer(logger = () => {}, options = {}) {
    const allowRecovery =
      typeof options.allowRecovery === 'boolean' ? options.allowRecovery : true;
    const pendingTransfers = await this.listPendingIncomingTransfers();
    if (!pendingTransfers.length) {
      return {
        accepted: false,
        reason: 'no-pending-transfer',
        transfer: null,
      };
    }

    const targetTransfer = pendingTransfers[0];
    await this.ensureDashboard();

    const clicked = await this.clickPendingTransferAction(targetTransfer, 'Accept');
    if (!clicked) {
      return {
        accepted: false,
        reason: 'accept-button-not-found',
        transfer: targetTransfer,
      };
    }

    logger(
      `accepting pending transfer ${targetTransfer.contract_id} amount=${targetTransfer.amount} from ${targetTransfer.sender}`,
    );

    let dialog;
    try {
      dialog = await this.waitForGenericConfirmDialog();
    } catch {
      return {
        accepted: false,
        reason: 'accept-confirm-dialog-not-found',
        transfer: targetTransfer,
      };
    }
    const dialogText = (await dialog.innerText().catch(() => '')).replace(/\s+/g, ' ').trim();
    if (/Accept Transfer/i.test(dialogText)) {
      logger('accept confirmation dialog detected');
    }

    await dialog.getByRole('button', { name: 'Confirm' }).click();
    await sleep(1500);

    const signingKeyMessage = await this.findSigningKeyErrorMessage();
    if (signingKeyMessage) {
      logger(signingKeyMessage);
      if (allowRecovery) {
        await this.recoverMissingSigningKey(logger);
        return this.acceptNextPendingTransfer(logger, { allowRecovery: false });
      }
      return {
        accepted: false,
        reason: 'signing-key-missing',
        transfer: targetTransfer,
      };
    }

    const removed = await this.waitForPendingTransferRemoval(
      targetTransfer.contract_id,
      this.options.pendingTransferPollAttempts,
      this.options.pendingTransferPollIntervalMs,
    );

    return {
      accepted: removed,
      reason: removed ? 'removed-from-pending' : 'still-pending',
      transfer: targetTransfer,
    };
  }

  async acceptAllPendingTransfers(logger = () => {}) {
    const accepted = [];
    const maxTransfers = 25;

    for (let index = 0; index < maxTransfers; index++) {
      const result = await this.acceptNextPendingTransfer(logger);
      if (!result.transfer) {
        return {
          accepted,
          count: accepted.length,
          done: true,
          reason: result.reason,
        };
      }

      if (!result.accepted) {
        logger(`pending transfer accept stopped: ${result.reason}`);
        return {
          accepted,
          count: accepted.length,
          done: false,
          reason: result.reason,
          failedTransfer: result.transfer,
        };
      }

      accepted.push(result.transfer);
    }

    return {
      accepted,
      count: accepted.length,
      done: false,
      reason: 'max-accept-limit-reached',
    };
  }

  async waitForConfirmationSurface({ receiverPartyId, amount, token }) {
    const timeout = this.options.browserNavigationTimeoutMs;
    const payload = {
      receiverPartyId,
      amount: String(amount),
      tokenName: token.name || '',
      tokenSymbol: token.symbol || '',
    };

    await this.page.waitForFunction(
      ({ receiverPartyId, amount, tokenName, tokenSymbol }) => {
        const visible = (node) => {
          if (!node) return false;
          const style = window.getComputedStyle(node);
          const rect = node.getBoundingClientRect();
          return (
            style.visibility !== 'hidden' &&
            style.display !== 'none' &&
            rect.width > 0 &&
            rect.height > 0
          );
        };

        const textMatches = (text) =>
          text.includes(receiverPartyId) ||
          text.includes(amount) ||
          text.includes(tokenName) ||
          text.includes(tokenSymbol);

        const dialogs = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"]'))
          .filter(visible)
          .map((node) => {
            const text = (node.innerText || '').replace(/\s+/g, ' ').trim();
            const buttons = Array.from(node.querySelectorAll('button')).filter(visible);
            return {
              node,
              text,
              buttons,
              hasConfirm: buttons.some((button) =>
                /confirm/i.test((button.innerText || '').replace(/\s+/g, ' ').trim()),
              ),
            };
          });

        return dialogs.some((dialog) => dialog.hasConfirm && textMatches(dialog.text));
      },
      payload,
      {
        timeout,
      },
    );

    return this.page.evaluate(({ receiverPartyId, amount, tokenName, tokenSymbol }) => {
      const visible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return (
          style.visibility !== 'hidden' &&
          style.display !== 'none' &&
          rect.width > 0 &&
          rect.height > 0
        );
      };

      const dialogs = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"]'))
        .filter(visible)
        .map((node, index) => {
          const text = (node.innerText || '').replace(/\s+/g, ' ').trim();
          const buttons = Array.from(node.querySelectorAll('button'))
            .filter(visible)
            .map((button) => (button.innerText || '').replace(/\s+/g, ' ').trim());
          const headings = Array.from(node.querySelectorAll('h1, h2, h3, [role="heading"]'))
            .filter(visible)
            .map((heading) => (heading.innerText || '').replace(/\s+/g, ' ').trim());
          return {
            index,
            role: node.getAttribute('role') || '',
            text,
            buttons,
            headings,
          };
        });

      return (
        dialogs.find(
          (dialog) =>
            dialog.buttons.some((button) => /confirm/i.test(button)) &&
            (dialog.text.includes(receiverPartyId) ||
              dialog.text.includes(amount) ||
              dialog.text.includes(tokenName) ||
              dialog.text.includes(tokenSymbol)),
        ) || null
      );
    }, payload);
  }

  async clickVisibleConfirmButton({ receiverPartyId, amount, token }) {
    const payload = {
      receiverPartyId,
      amount: String(amount),
      tokenName: token.name || '',
      tokenSymbol: token.symbol || '',
    };

    const clicked = await this.page.evaluate(({ receiverPartyId, amount, tokenName, tokenSymbol }) => {
      const visible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return (
          style.visibility !== 'hidden' &&
          style.display !== 'none' &&
          rect.width > 0 &&
          rect.height > 0
        );
      };

      const dialogs = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"]'))
        .filter(visible)
        .map((node) => ({
          node,
          text: (node.innerText || '').replace(/\s+/g, ' ').trim(),
          buttons: Array.from(node.querySelectorAll('button')).filter(visible),
        }));

      const targetDialog = dialogs.find(
        (dialog) =>
          dialog.buttons.some((button) =>
            /confirm/i.test((button.innerText || '').replace(/\s+/g, ' ').trim()),
          ) &&
          (dialog.text.includes(receiverPartyId) ||
            dialog.text.includes(amount) ||
            dialog.text.includes(tokenName) ||
            dialog.text.includes(tokenSymbol)),
      );

      const confirmButton = targetDialog?.buttons.find((button) =>
        /confirm/i.test((button.innerText || '').replace(/\s+/g, ' ').trim()),
      );
      if (!confirmButton) {
        return false;
      }
      confirmButton.click();
      return true;
    }, payload);

    if (!clicked) {
      throw new Error('Could not find a visible Confirm button in the Walley confirmation UI');
    }

    await this.page.waitForFunction(() => {
      const visible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return (
          style.visibility !== 'hidden' &&
          style.display !== 'none' &&
          rect.width > 0 &&
          rect.height > 0
        );
      };

      const dialogs = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"]'))
        .filter(visible);
      return !dialogs.some((node) =>
        Array.from(node.querySelectorAll('button'))
          .filter(visible)
          .some((button) => /confirm/i.test((button.innerText || '').replace(/\s+/g, ' ').trim())),
      );
    }, null, {
      timeout: this.options.browserNavigationTimeoutMs,
    });
  }

  async sendTransfer({ receiverPartyId, token, amount, reason }) {
    const beforeUnlockedBalance = await this.getUnlockedBalance(token);
    const captured = [];
    const responseListener = async (response) => {
      const url = response.url();
      if (
        !url.includes('/v1/transfers/prepare') &&
        !url.includes('/v1/transactions/submit-and-wait')
      ) {
        return;
      }

      const request = response.request();
      captured.push({
        method: request.method(),
        url,
        status: response.status(),
        requestBody: request.postDataJSON?.() || request.postData() || null,
      });
    };

    this.page.on('response', responseListener);
    try {
      const modal = await this.openSendTransferModal();
      await modal.getByRole('textbox', { name: 'Party ID' }).fill(receiverPartyId);
      await this.selectToken(modal, token.symbol);
      await modal.getByRole('textbox', { name: '0.00' }).fill(String(amount));
      if (reason) {
        await modal.getByRole('textbox', { name: 'Payment reason' }).fill(reason);
      }

      await modal.getByRole('button', { name: 'Send' }).click();

      const confirmationSurface = await this.waitForConfirmationSurface({
        receiverPartyId,
        amount,
        token,
      });
      const confirmationText = confirmationSurface?.text || '';
      if (!confirmationText.includes(receiverPartyId)) {
        throw new Error('Confirmation UI did not show the expected receiver');
      }
      if (!confirmationText.includes(String(amount))) {
        throw new Error('Confirmation UI did not show the expected amount');
      }
      if (!confirmationText.includes(token.name) && !confirmationText.includes(token.symbol)) {
        throw new Error('Confirmation UI did not show the expected token');
      }

      await this.clickVisibleConfirmButton({
        receiverPartyId,
        amount,
        token,
      });

      const verification = await this.verifyTransfer({
        beforeUnlockedBalance,
        token,
        receiverPartyId,
        amount,
        reason,
        attempts: this.options.verificationPollAttempts,
        intervalMs: this.options.verificationPollIntervalMs,
      });

      const transactions = await this.listTransactions({ pageSize: 10 });
      const matchedTransaction = transactions.transactions.find((item) => {
        const serialized = serialize(item);
        return (
          serialized.includes(receiverPartyId) &&
          serialized.includes(String(amount)) &&
          (!reason || serialized.includes(reason))
        );
      });

      return {
        confirmationText,
        capturedRequests: captured,
        verification,
        matchedTransaction,
      };
    } finally {
      this.page.off('response', responseListener);
    }
  }

  async close() {
    if (this.context) {
      await this.context.close();
      this.context = null;
      this.page = null;
    }
    this.session = null;
    this.partyId = '';
  }
}
