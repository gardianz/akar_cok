import { createHash, createPrivateKey, createPublicKey, sign as signDetached } from 'crypto';
import { mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const PRIVATE_KEY_PKCS8_PREFIX = Uint8Array.from([
  48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32,
]);
const MULTICODEC_ED25519_PUBLIC_KEY_PREFIX = Uint8Array.from([0, 0, 0, 12]);

function normalizeMnemonic(mnemonic) {
  return String(mnemonic).trim().normalize('NFKD').replace(/\s+/g, ' ');
}

function base64Encode(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function decodeBase64Flexible(value) {
  const text = String(value).trim();
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function concatBytes(...parts) {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function buildPrivateKeyFromSeed(seedBytes) {
  const der = concatBytes(PRIVATE_KEY_PKCS8_PREFIX, seedBytes);
  return createPrivateKey({
    key: Buffer.from(der),
    format: 'der',
    type: 'pkcs8',
  });
}

function mnemonicEntropyBytes(mnemonic) {
  const normalized = normalizeMnemonic(mnemonic);
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error('Invalid Walley recovery phrase');
  }
  const wordCount = normalized.split(' ').length;
  if (wordCount !== 24) {
    throw new Error(`Walley recovery phrase must contain 24 words, got ${wordCount}`);
  }
  const entropy = mnemonicToEntropy(normalized, wordlist);
  const bytes = typeof entropy === 'string' ? Buffer.from(entropy, 'hex') : Buffer.from(entropy);
  if (bytes.length !== 32) {
    throw new Error(`Walley mnemonic must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

function extractRawPublicKey(publicKeyDer) {
  const bytes = Buffer.from(publicKeyDer);
  return bytes.subarray(bytes.length - 32);
}

function publicKeyFingerprint(rawPublicKey) {
  const digest = createHash('sha256')
    .update(Buffer.from(concatBytes(MULTICODEC_ED25519_PUBLIC_KEY_PREFIX, rawPublicKey)))
    .digest('hex');
  return `1220${digest}`;
}

export function deriveIdentityFromMnemonic({ partyHint, mnemonic }) {
  const normalizedPartyHint = String(partyHint).trim();
  if (!normalizedPartyHint) {
    throw new Error('partyHint must be a non-empty string');
  }

  const privateSeed = mnemonicEntropyBytes(mnemonic);
  const privateKey = buildPrivateKeyFromSeed(privateSeed);
  const publicKeyDer = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  const rawPublicKey = extractRawPublicKey(publicKeyDer);
  const fingerprint = publicKeyFingerprint(rawPublicKey);

  return {
    partyHint: normalizedPartyHint,
    partyId: `${normalizedPartyHint}::${fingerprint}`,
    publicKeyFingerprint: fingerprint,
    publicKeyBase64: base64Encode(publicKeyDer),
    privateKey,
  };
}

export function signPreparedTransactionHash(hashValue, identity) {
  const hashBytes = decodeBase64Flexible(hashValue);
  const signature = signDetached(null, hashBytes, identity.privateKey);
  return {
    format: 'RAW',
    signature: base64Encode(signature),
    signed_by: identity.publicKeyFingerprint,
    signing_algorithm_spec: 'ED25519',
  };
}
