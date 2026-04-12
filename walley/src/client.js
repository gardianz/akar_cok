import { signPreparedTransactionHash, deriveIdentityFromMnemonic } from './crypto.js';
import { WalleyHttpClient } from './http.js';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function serialize(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function extractTransfers(payload) {
  if (Array.isArray(payload?.transfers)) return payload.transfers;
  if (Array.isArray(payload)) return payload;
  return [];
}

function extractTransactions(payload) {
  if (Array.isArray(payload?.transactions)) return payload.transactions;
  if (Array.isArray(payload)) return payload;
  return [];
}

function isPendingTransferForParty(transfer, partyId) {
  if (!transfer || typeof transfer !== 'object') return false;
  const receiver = String(transfer.receiver || '').trim();
  const sender = String(transfer.sender || '').trim();
  const expired = transfer.is_expired === true;
  return !expired && receiver === partyId && sender !== partyId;
}

export function resolveTokenSelection(tokens, transfer) {
  if (transfer.instrumentId && transfer.instrumentAdminId) {
    const matched = tokens.find(
      (token) =>
        token.id === transfer.instrumentId &&
        token.admin_id === transfer.instrumentAdminId,
    );
    if (!matched) {
      throw new Error(
        `Token ${transfer.instrumentId} / ${transfer.instrumentAdminId} not found in /v1/tokens`,
      );
    }
    return {
      instrumentId: matched.id,
      instrumentAdminId: matched.admin_id,
      symbol: matched.symbol || matched.id,
      name: matched.name || matched.id,
    };
  }

  if (transfer.tokenSymbol) {
    const matched = tokens.filter((token) => token.symbol === transfer.tokenSymbol);
    if (!matched.length) {
      throw new Error(`Token symbol ${transfer.tokenSymbol} not found in /v1/tokens`);
    }
    if (matched.length > 1) {
      throw new Error(
        `Token symbol ${transfer.tokenSymbol} is ambiguous; use instrumentId + instrumentAdminId`,
      );
    }
    return {
      instrumentId: matched[0].id,
      instrumentAdminId: matched[0].admin_id,
      symbol: matched[0].symbol || matched[0].id,
      name: matched[0].name || matched[0].id,
    };
  }

  throw new Error('Transfer must define tokenSymbol or instrumentId + instrumentAdminId');
}

export class WalleyApiSession {
  constructor(account, options) {
    this.account = account;
    this.options = options;
    this.http = new WalleyHttpClient({
      baseUrl: options.apiBaseUrl,
      timeoutMs: options.requestTimeoutMs,
    });
    this.identity = null;
    this.partyId = '';
  }

  async getParty() {
    return this.http.request('/v1/party', {
      query: {
        party_id: this.partyId,
      },
    });
  }

  async getTokens() {
    const response = await this.http.request('/v1/tokens');
    return Array.isArray(response?.tokens) ? response.tokens : [];
  }

  async getBalances() {
    const response = await this.http.request('/v1/balances', {
      query: {
        party_id: this.partyId,
      },
    });
    return Array.isArray(response?.balances) ? response.balances : [];
  }

  async listTransfers() {
    const response = await this.http.request('/v1/transfers', {
      query: {
        party_id: this.partyId,
      },
    });
    return extractTransfers(response);
  }

  async listPendingIncomingTransfers() {
    const transfers = await this.listTransfers();
    return transfers.filter((transfer) => isPendingTransferForParty(transfer, this.partyId));
  }

  async listTransactions({ pageSize = 25, cursor } = {}) {
    const response = await this.http.request('/v1/transactions', {
      query: {
        party_id: this.partyId,
        page_size: pageSize,
        cursor,
      },
    });
    return {
      transactions: extractTransactions(response),
      nextCursor: response?.next_cursor,
      prevCursor: response?.prev_cursor,
      raw: response,
    };
  }

  async getTransferPreapproval() {
    return this.http.request('/v1/transfer-preapproval', {
      query: {
        party_id: this.partyId,
      },
    });
  }

  async getUnlockedBalance(token) {
    const balances = await this.getBalances();
    const matched = balances.find(
      (balance) =>
        balance.instrument_id === token.instrumentId &&
        balance.instrument_admin_id === token.instrumentAdminId,
    );
    return toNumber(matched?.unlocked_balance);
  }

  async prepareTransfer({ receiverPartyId, token, amount, reason }) {
    return this.http.request('/v1/transfers/prepare', {
      method: 'POST',
      body: {
        sender: this.partyId,
        receiver: receiverPartyId,
        instrument_id: token.instrumentId,
        instrument_admin_id: token.instrumentAdminId,
        amount: String(amount),
        ...(reason ? { reason } : {}),
      },
    });
  }

  async prepareAcceptTransfer({ contractId, partyId = this.partyId }) {
    return this.http.request('/v1/transfers/accept/prepare', {
      method: 'POST',
      body: {
        contract_id: contractId,
        party_id: partyId,
      },
    });
  }

  async prepareRejectTransfer({ contractId, partyId = this.partyId }) {
    return this.http.request('/v1/transfers/reject/prepare', {
      method: 'POST',
      body: {
        contract_id: contractId,
        party_id: partyId,
      },
    });
  }

  async prepareEnableTransferPreapproval() {
    return this.http.request('/v1/transfer-preapproval/prepare', {
      method: 'POST',
      body: {
        receiver: this.partyId,
      },
    });
  }

  async submitPreparedTransaction(prepared) {
    if (!this.identity) {
      throw new Error('Identity is not ready; call login() first');
    }
    if (!prepared?.prepared_transaction || !prepared?.prepared_transaction_hash) {
      throw new Error('Invalid prepared transaction payload from Walley API');
    }

    const signature = signPreparedTransactionHash(
      prepared.prepared_transaction_hash,
      this.identity,
    );

    const submitted = await this.http.request('/v1/transactions/submit-and-wait', {
      method: 'POST',
      body: {
        party_id: this.partyId,
        prepared_transaction: prepared.prepared_transaction,
        hashing_scheme_version: prepared.hashing_scheme_version,
        signature,
      },
    });

    return {
      prepared,
      signature,
      submitted,
    };
  }

  async ensureTransferPreapproval(logger = () => {}) {
    const current = await this.getTransferPreapproval();
    const status = current?.status || 'UNKNOWN';
    if (status === 'ENABLED') {
      logger('transfer preapproval already enabled');
      return { enabled: false, status };
    }
    if (status === 'PENDING') {
      logger('transfer preapproval already pending');
      return { enabled: false, status };
    }

    logger('enabling transfer preapproval');
    const prepared = await this.prepareEnableTransferPreapproval();
    const result = await this.submitPreparedTransaction(prepared);
    return { enabled: true, status: 'SUBMITTED', result };
  }

  async sendTransfer({ receiverPartyId, token, amount, reason }) {
    const prepared = await this.prepareTransfer({
      receiverPartyId,
      token,
      amount,
      reason,
    });
    return this.submitPreparedTransaction(prepared);
  }

  async acceptTransfer({ contractId }) {
    const prepared = await this.prepareAcceptTransfer({ contractId });
    return this.submitPreparedTransaction(prepared);
  }

  async rejectTransfer({ contractId }) {
    const prepared = await this.prepareRejectTransfer({ contractId });
    return this.submitPreparedTransaction(prepared);
  }

  async verifyTransfer({
    beforeUnlockedBalance,
    token,
    receiverPartyId,
    amount,
    reason,
    attempts,
    intervalMs,
  }) {
    const expectedAmount = Number(amount);
    let lastUnlockedBalance = beforeUnlockedBalance;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      await sleep(intervalMs);

      try {
        lastUnlockedBalance = await this.getUnlockedBalance(token);
        if (beforeUnlockedBalance - lastUnlockedBalance >= expectedAmount) {
          return {
            verified: true,
            reason: 'balance-drop',
            lastUnlockedBalance,
          };
        }
      } catch {
        // Balance refresh is best-effort.
      }

      try {
        const transfers = await this.listTransfers();
        const serialized = serialize(transfers);
        if (
          serialized.includes(receiverPartyId) &&
          serialized.includes(String(amount)) &&
          (!reason || serialized.includes(reason))
        ) {
          return {
            verified: true,
            reason: 'pending-transfer-match',
            lastUnlockedBalance,
          };
        }
      } catch {
        // Pending transfers are best-effort.
      }

      try {
        const transactions = await this.listTransactions();
        const serialized = serialize(transactions.raw);
        if (
          serialized.includes(receiverPartyId) &&
          serialized.includes(String(amount)) &&
          (!reason || serialized.includes(reason))
        ) {
          return {
            verified: true,
            reason: 'transaction-history-match',
            lastUnlockedBalance,
          };
        }
      } catch {
        // History is best-effort.
      }
    }

    return {
      verified: false,
      reason: 'not-confirmed',
      lastUnlockedBalance,
    };
  }
}

export class WalleySession extends WalleyApiSession {
  async login(logger = () => {}) {
    logger('deriving Ed25519 identity from recovery phrase');
    this.identity = deriveIdentityFromMnemonic({
      partyHint: this.account.partyHint,
      mnemonic: this.account.mnemonic,
    });
    this.partyId = this.identity.partyId;

    logger(`verifying registered party ${this.partyId}`);
    await this.getParty();

    return {
      partyId: this.identity.partyId,
      partyHint: this.identity.partyHint,
      publicKeyFingerprint: this.identity.publicKeyFingerprint,
      publicKeyBase64: this.identity.publicKeyBase64,
    };
  }
}
