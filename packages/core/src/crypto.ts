// dMail v2 crypto update: deterministic identity derivation + metadata hashing utilities.
import EthCrypto from 'eth-crypto'
import { ed25519, x25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'

import { getEnsTextRecord } from './ens.js'
import { synapseUpload, synapseFetch } from './synapse.js'

const textEncoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null
const textDecoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null

const EMAIL_V2_VERSION = 2
const EMAIL_V2_SCHEME = 'x25519-hkdf-sha256+aes-256-gcm'
const MESSAGE_ID_BYTES = 16
const isBrowser = typeof window !== 'undefined'
const SIGNATURE_DOMAIN = 'dmail-envelope-v1'
const IDENTITY_CHALLENGE_PREFIX = 'dmail-identity-v2'
const IDENTITY_SEED_INFO = 'dmail-identity-seed-v1'
const IDENTITY_SENDER_SYM_INFO = 'dmail-sender-sym-v1'
const IDENTITY_SIGNING_INFO = 'dmail-signing-key-v1'
const DEFAULT_IDENTITY_NETWORK = 'unknown'
const DEFAULT_IDENTITY_DOMAIN = 'localhost'
const identityInfoCache = {
  seed: textEncoder ? textEncoder.encode(IDENTITY_SEED_INFO) : null,
  senderSym: textEncoder ? textEncoder.encode(IDENTITY_SENDER_SYM_INFO) : null,
  signing: textEncoder ? textEncoder.encode(IDENTITY_SIGNING_INFO) : null,
  signingFromIdentity: textEncoder ? textEncoder.encode('dmail-signing-from-identity-v1') : null,
}

function getCrypto() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle && globalThis.crypto?.getRandomValues) {
    return globalThis.crypto
  }
  throw new Error(
    'Web Crypto API unavailable. Please run in a modern browser or Node.js >= 18 (globalThis.crypto).'
  )
}

function toBase64(bytes) {
  if (!bytes) return ''
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(bytes).toString('base64')
  }
  if (typeof btoa !== 'undefined') {
    let binary = ''
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte)
    })
    return btoa(binary)
  }
  throw new Error('Base64 encoding is not supported in this environment')
}

function fromBase64(value) {
  if (!value) return new Uint8Array()
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return new Uint8Array(Buffer.from(value, 'base64'))
  }
  if (typeof atob !== 'undefined') {
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  }
  throw new Error('Base64 decoding is not supported in this environment')
}

function hexToBytes(hex) {
  if (!hex) return new Uint8Array()
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex
  if (normalized.length % 2 !== 0) {
    throw new Error('Invalid hex input')
  }
  const bytes = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes) {
  if (!bytes) return ''
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function getRandomBytes(length) {
  const crypto = getCrypto()
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return array
}

function encodeKeyBytes(bytes, format = 'base64') {
  if (format === 'base64') {
    return toBase64(bytes)
  }
  if (format === 'hex') {
    return bytesToHex(bytes)
  }
  if (format === 'raw') {
    return bytes
  }
  throw new Error(`Unsupported key format: ${format}`)
}

function normalizeKeyInput(key) {
  if (!key) return null
  if (key instanceof Uint8Array) return key
  if (typeof key === 'string') {
    const trimmed = key.trim()
    if (trimmed.startsWith('0x') || /^[0-9a-fA-F]+$/.test(trimmed)) {
      return hexToBytes(trimmed)
    }
    return fromBase64(trimmed)
  }
  throw new Error('Unsupported key input type')
}

function looksLikeLegacySecpKey(publicKey) {
  if (!publicKey || typeof publicKey !== 'string') return false
  const normalized = publicKey.trim().toLowerCase()
  if (normalized.startsWith('0x04') && (normalized.length === 132 || normalized.length === 130)) {
    return true
  }
  return /^[0-9a-f]{128}$/i.test(normalized)
}

function buildAdditionalData({ from, to, timestamp, messageId }) {
  if (!textEncoder) return undefined
  const payload = `${from ?? ''}|${to ?? ''}|${timestamp ?? ''}|${messageId ?? ''}`
  return textEncoder.encode(payload)
}

function sortStringArray(values) {
  if (!values) return []
  const list = Array.isArray(values) ? values : [values]
  return list
    .map((value) => String(value))
    .filter((value) => value.length > 0)
    .sort((a, b) => a.localeCompare(b))
}

function canonicalizeEnvelopeMetadata(metadata = {}) {
  const bodyCid = metadata.bodyCid ?? metadata.cidRecipient ?? metadata.cid ?? null
  const keyEnvelopesCid = metadata.keyEnvelopesCid ?? metadata.cidRecipient ?? metadata.cid ?? null
  if (!bodyCid) {
    throw new Error('computeEnvelopeMetadataHash: bodyCid (or cidRecipient) is required')
  }
  if (!keyEnvelopesCid) {
    throw new Error('computeEnvelopeMetadataHash: keyEnvelopesCid (or cidRecipient) is required')
  }

  const recipientList =
    metadata.toRecipients ?? metadata.recipients ?? (Array.isArray(metadata.to) ? metadata.to : metadata.to ? [metadata.to] : [])
  const ccList =
    metadata.ccRecipients ?? (Array.isArray(metadata.cc) ? metadata.cc : metadata.cc ? [metadata.cc] : [])

  const canonical = {}
  canonical.messageId = metadata.messageId ?? ''
  canonical.bodyCid = String(bodyCid)
  canonical.keyEnvelopesCid = String(keyEnvelopesCid)
  canonical.senderCopyCid = metadata.senderCopyCid ?? metadata.cidSender ?? null
  canonical.from = metadata.from ?? ''
  canonical.to = sortStringArray(recipientList ?? [])
  canonical.cc = sortStringArray(ccList ?? [])
  canonical.timestamp = Number(metadata.timestamp ?? 0)
  canonical.ephemeralPublicKey = metadata.ephemeralPublicKey ?? ''

  return canonical
}

export function computeEnvelopeMetadataHash(metadata, options = {}) {
  if (!textEncoder) {
    throw new Error('computeEnvelopeMetadataHash: TextEncoder unavailable in this environment')
  }
  const canonical = canonicalizeEnvelopeMetadata(metadata)
  const payload = textEncoder.encode(JSON.stringify(canonical))
  const digest = sha256(payload)
  if (options.as === 'bytes') {
    return digest
  }
  if (options.encoding === 'hex') {
    return bytesToHex(digest)
  }
  return toBase64(digest)
}

function normalizeMetadataHashInput(metadataHash) {
  if (!metadataHash) {
    throw new Error('Metadata hash is required')
  }
  if (metadataHash instanceof Uint8Array) {
    if (metadataHash.length !== 32) {
      throw new Error('Metadata hash must be 32 bytes')
    }
    return metadataHash
  }
  if (typeof metadataHash === 'object') {
    return computeEnvelopeMetadataHash(metadataHash, { as: 'bytes' })
  }
  if (typeof metadataHash === 'string') {
    const trimmed = metadataHash.trim()
    if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length === 64) {
      return hexToBytes(trimmed)
    }
    return fromBase64(trimmed)
  }
  throw new Error('Unsupported metadata hash input')
}

export function signEnvelope(arg1, arg2) {
  if (!arg1 || !arg2) {
    throw new Error('signEnvelope: privateKey and metadata hash are required')
  }
  if (typeof arg1 === 'object' && typeof arg2 === 'string') {
    return signEnvelope(arg2, arg1)
  }
  const keyBytes = normalizeKeyInput(arg1)
  if (!keyBytes || keyBytes.length !== 32) {
    throw new Error('signEnvelope: private key must be 32 bytes')
  }
  const digest = normalizeMetadataHashInput(arg2)
  const signature = ed25519.sign(digest, keyBytes)
  return toBase64(signature)
}

export function verifyEnvelopeSignature(arg1, arg2, arg3) {
  if (typeof arg1 === 'object' && typeof arg2 === 'string' && typeof arg3 === 'string') {
    return verifyEnvelopeSignature(arg3, arg2, arg1)
  }
  if (!arg1 || !arg2 || !arg3) {
    return false
  }
  try {
    const signatureBytes = fromBase64(arg2)
    const publicKeyBytes = normalizeKeyInput(arg1)
    if (!publicKeyBytes || publicKeyBytes.length !== 32) {
      return false
    }
    const digest = normalizeMetadataHashInput(arg3)
    return ed25519.verify(signatureBytes, digest, publicKeyBytes)
  } catch (error) {
    console.warn('verifyEnvelopeSignature failed', error)
    return false
  }
}

function deriveSymmetricKey(sharedSecret, saltLabel, messageId) {
  const saltInput = `${saltLabel}:${messageId ?? ''}`
  const salt = textEncoder ? textEncoder.encode(saltInput) : undefined
  return hkdf(sha256, sharedSecret, salt, textEncoder?.encode('dmail-email-v2') ?? undefined, 32)
}

async function aesGcmEncrypt(rawKey, plaintextBytes, additionalData) {
  const crypto = getCrypto()
  const subtle = crypto.subtle
  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = getRandomBytes(12)
  const cipherBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData,
    },
    key,
    plaintextBytes
  )
  return { ciphertext: new Uint8Array(cipherBuffer), iv }
}

async function aesGcmDecrypt(rawKey, ciphertextBytes, iv, additionalData) {
  const crypto = getCrypto()
  const subtle = crypto.subtle
  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt'])
  const plainBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData,
    },
    key,
    ciphertextBytes
  )
  return new Uint8Array(plainBuffer)
}

function generateMessageId() {
  const cryptoApi = typeof globalThis !== 'undefined' ? globalThis.crypto : null
  if (cryptoApi?.randomUUID) {
    return cryptoApi.randomUUID()
  }
  return toBase64(getRandomBytes(MESSAGE_ID_BYTES)).replace(/[^a-z0-9]/gi, '').slice(0, 24)
}

function normaliseHex(input) {
  if (!input) return undefined
  return input.startsWith('0x') ? input.slice(2) : input
}

function ensurePrivateKey(privateKey) {
  const key = normaliseHex(privateKey)
  if (!key) {
    throw new Error('Private key is required for this operation')
  }
  return key
}

export function generateEncryptionKeyPair(options = {}) {
  const format = options.format ?? 'base64'
  const privateKeyBytes = x25519.utils.randomPrivateKey()
  const publicKeyBytes = x25519.getPublicKey(privateKeyBytes)
  return {
    privateKey: encodeKeyBytes(privateKeyBytes, format),
    publicKey: encodeKeyBytes(publicKeyBytes, format),
    format,
  }
}

export function deriveX25519PublicKey(privateKey, options = {}) {
  const keyBytes = normalizeKeyInput(privateKey)
  if (!keyBytes || keyBytes.length !== 32) {
    throw new Error('X25519 private key must be 32 bytes')
  }
  const publicKeyBytes = x25519.getPublicKey(keyBytes)
  return encodeKeyBytes(publicKeyBytes, options.format ?? 'base64')
}

function normalizeIdentityKeyPair(identity) {
  if (!identity) return null
  if (identity.privateKey && identity.publicKey) {
    return {
      privateKey: identity.privateKey,
      publicKey: identity.publicKey,
    }
  }
  if (typeof identity === 'string') {
    return {
      privateKey: identity,
      publicKey: deriveX25519PublicKey(identity),
    }
  }
  return null
}

function normalizeKeyMaterial(input) {
  if (!input) return {}
  if (typeof input === 'string') {
    return {
      identityPrivateKey: input,
      legacyPrivateKey: input,
    }
  }
  if (typeof input === 'object') {
    return { ...input }
  }
  return {}
}

function getEnvValue(name) {
  if (typeof process !== 'undefined' && process?.env?.[name]) {
    return process.env[name]
  }
  if (typeof import.meta !== 'undefined' && import.meta?.env) {
    const direct = import.meta.env[name]
    if (direct) return direct
    const vitePrefixed = import.meta.env[`VITE_${name}`]
    if (vitePrefixed) return vitePrefixed
  }
  if (typeof window !== 'undefined' && window?.__DMAIL_CONFIG__?.[name]) {
    return window.__DMAIL_CONFIG__[name]
  }
  return undefined
}

function resolveAppDomain(domainOverride) {
  if (domainOverride) {
    return String(domainOverride).toLowerCase()
  }
  if (typeof window !== 'undefined' && window?.location?.hostname) {
    return window.location.hostname.toLowerCase()
  }
  const envDomain =
    getEnvValue('DMAIL_APP_DOMAIN') ??
    getEnvValue('APP_DOMAIN') ??
    getEnvValue('DOMAIN') ??
    null
  return (envDomain ? String(envDomain) : DEFAULT_IDENTITY_DOMAIN).toLowerCase()
}

async function resolveNetworkLabel(signer, networkOverride) {
  if (networkOverride) {
    return String(networkOverride).toLowerCase()
  }
  const provider = signer?.provider
  if (provider && typeof provider.getNetwork === 'function') {
    try {
      const network = await provider.getNetwork()
      if (network?.name && network.name !== 'unknown') {
        return String(network.name).toLowerCase()
      }
      if (network?.chainId != null) {
        return `chain-${network.chainId}`
      }
    } catch (error) {
      console.warn('deriveIdentityFromWallet: failed to read provider network', error)
    }
  }
  if (typeof signer?.getChainId === 'function') {
    try {
      const id = await signer.getChainId()
      if (id != null) {
        return `chain-${id}`
      }
    } catch (error) {
      console.warn('deriveIdentityFromWallet: getChainId failed', error)
    }
  }
  const envNetwork =
    getEnvValue('DMAIL_IDENTITY_NETWORK') ??
    getEnvValue('ETH_NETWORK') ??
    getEnvValue('CHAIN_ID') ??
    null
  if (envNetwork) {
    return String(envNetwork).toLowerCase()
  }
  return DEFAULT_IDENTITY_NETWORK
}

function buildIdentityChallengeString(network, domain) {
  const normalizedNetwork = network ?? DEFAULT_IDENTITY_NETWORK
  const normalizedDomain = domain ?? DEFAULT_IDENTITY_DOMAIN
  return `${IDENTITY_CHALLENGE_PREFIX}:${normalizedNetwork}:${normalizedDomain}`
}

function normalizeSignatureBytes(signature) {
  if (!signature) {
    throw new Error('deriveIdentityFromWallet: signer signature missing')
  }
  if (signature instanceof Uint8Array) {
    return signature
  }
  if (typeof signature === 'string') {
    return hexToBytes(signature)
  }
  if (typeof signature === 'object' && typeof signature.hex === 'string') {
    return hexToBytes(signature.hex)
  }
  throw new Error('deriveIdentityFromWallet: unsupported signature format')
}

function clampX25519PrivateKey(bytes) {
  const clamped = new Uint8Array(bytes)
  clamped[0] &= 248
  clamped[31] &= 127
  clamped[31] |= 64
  return clamped
}

function zeroizeBuffers(...buffers) {
  for (const buffer of buffers) {
    if (buffer && typeof buffer.fill === 'function') {
      buffer.fill(0)
    }
  }
}

export async function deriveIdentityFromWallet(signer, options = {}) {
  if (!signer || typeof signer.signMessage !== 'function') {
    throw new Error('deriveIdentityFromWallet: signer with signMessage is required')
  }
  if (
    !textEncoder ||
    !identityInfoCache.seed ||
    !identityInfoCache.senderSym ||
    !identityInfoCache.signing
  ) {
    throw new Error('deriveIdentityFromWallet: TextEncoder unavailable in this environment')
  }

  const domain = resolveAppDomain(options.domain)
  const network = await resolveNetworkLabel(signer, options.network)
  const challenge = options.challenge ?? buildIdentityChallengeString(network, domain)

  const signatureOutput = await signer.signMessage(challenge)
  const signatureBytes = normalizeSignatureBytes(signatureOutput)

  const seedBytes = hkdf(sha256, signatureBytes, options.seedSalt, identityInfoCache.seed, 32)
  const x25519PrivateBytes = clampX25519PrivateKey(seedBytes)
  const x25519PublicBytes = x25519.getPublicKey(x25519PrivateBytes)
  const senderSymBytes = hkdf(sha256, seedBytes, undefined, identityInfoCache.senderSym, 32)
  const signingKeyBytes = hkdf(sha256, seedBytes, undefined, identityInfoCache.signing, 32)
  const signingPublicBytes = ed25519.getPublicKey(signingKeyBytes)

  const result = {
    x25519PrivateBase64: toBase64(x25519PrivateBytes),
    x25519PublicBase64: toBase64(x25519PublicBytes),
    senderStaticSymKeyBase64: toBase64(senderSymBytes),
    signingKeyBase64: toBase64(signingKeyBytes),
    signingPublicKeyBase64: toBase64(signingPublicBytes),
  }

  zeroizeBuffers(signatureBytes, seedBytes, x25519PrivateBytes, senderSymBytes, signingKeyBytes, signingPublicBytes)
  return result
}

export function deriveSigningKeyFromIdentityPrivateKey(identityPrivateKey) {
  if (
    !identityInfoCache.signingFromIdentity ||
    !textEncoder
  ) {
    throw new Error('deriveSigningKeyFromIdentityPrivateKey: TextEncoder unavailable')
  }
  const identityBytes = normalizeKeyInput(identityPrivateKey)
  if (!identityBytes || identityBytes.length !== 32) {
    throw new Error('deriveSigningKeyFromIdentityPrivateKey: identity private key must be 32 bytes')
  }
  const signingKeyBytes = hkdf(
    sha256,
    identityBytes,
    undefined,
    identityInfoCache.signingFromIdentity,
    32
  )
  const signingPublicBytes = ed25519.getPublicKey(signingKeyBytes)
  const result = {
    signingKeyBase64: toBase64(signingKeyBytes),
    signingPublicKeyBase64: toBase64(signingPublicBytes),
  }
  zeroizeBuffers(signingKeyBytes, signingPublicBytes)
  return result
}

export function deriveSigningPublicKey(signingPrivateKey) {
  const keyBytes = normalizeKeyInput(signingPrivateKey)
  if (!keyBytes || keyBytes.length !== 32) {
    throw new Error('deriveSigningPublicKey: signing private key must be 32 bytes')
  }
  const publicBytes = ed25519.getPublicKey(keyBytes)
  const publicKeyBase64 = toBase64(publicBytes)
  zeroizeBuffers(publicBytes)
  return publicKeyBase64
}

export async function derivePublicKeyFromEthAddress(address, options = {}) {
  if (!address) {
    throw new Error('derivePublicKeyFromEthAddress: address is required')
  }

  if (options.privateKey) {
    return EthCrypto.publicKeyByPrivateKey(ensurePrivateKey(options.privateKey))
  }

  if (options.publicKey) {
    return normaliseHex(options.publicKey)
  }

  if (options.provider || options.resolver) {
    const publicKey = await getEnsTextRecord(address, 'dmail:pubkey', options)
    if (publicKey) {
      return normaliseHex(publicKey)
    }
  }

  throw new Error(
    'Unable to derive public key. Provide the recipient public key via options.publicKey, options.privateKey, or ENS text record `dmail:pubkey`.'
  )
}

/**
 * Upload attachments to Synapse SDK and return attachment references
 * @param {Array} attachments - Array of attachment objects with {filename, mimeType, data}
 * @param {string} recipientPublicKey - Public key to encrypt attachment metadata
 * @returns {Promise<Array>} Array of attachment references with {filename, mimeType, cid, pieceCid, providerInfo}
 */
export async function uploadAttachments(attachments, recipientPublicKey, options = {}) {
  if (!Array.isArray(attachments) || attachments.length === 0) {
    return []
  }

  const encryptMetadata =
    !options.skipMetadataEncryption &&
    recipientPublicKey &&
    looksLikeLegacySecpKey(recipientPublicKey)
  const normalizedKey = encryptMetadata ? normaliseHex(recipientPublicKey) : null

  return Promise.all(
    attachments.map(async (attachment) => {
      if (!attachment?.data) {
        throw new Error('uploadAttachments: attachment data is required')
      }

      // Decode base64 data to binary
      const binaryData = decodeBase64Attachment(attachment.data)

      // Upload attachment to Synapse
      const uploadResult = await synapseUpload(binaryData, {
        filename: attachment.filename || 'attachment',
        contentType: attachment.mimeType || 'application/octet-stream',
        metadata: {
          type: 'dmail-attachment',
          filename: attachment.filename || 'attachment',
          mimeType: attachment.mimeType || 'application/octet-stream',
        },
      })

      const entry = {
        cid: uploadResult.cid,
        pieceCid: uploadResult.pieceCid,
        providerInfo: uploadResult.providerInfo,
      }

      const filename = attachment.filename || 'attachment'
      const mimeType = attachment.mimeType || 'application/octet-stream'

      if (encryptMetadata && normalizedKey) {
        entry.encryptedMetadata = await encryptString(
          JSON.stringify({
            filename,
            mimeType,
          }),
          normalizedKey
        )
      } else {
        entry.filename = filename
        entry.mimeType = mimeType
      }

      return entry
    })
  )
}

async function prepareAttachments(attachments, recipientPublicKey, options = {}) {
  if (!Array.isArray(attachments) || attachments.length === 0) {
    return []
  }

  if (options.uploadAttachmentsToSynapse === false) {
    return attachments
  }

  // For v2 encryption we may pass undefined recipient key to skip metadata encryption
  const keyForAttachments = looksLikeLegacySecpKey(recipientPublicKey) ? recipientPublicKey : null
  return await uploadAttachments(attachments, keyForAttachments, {
    skipMetadataEncryption: !keyForAttachments,
  })
}

/**
 * Fetch and decrypt attachment from Synapse SDK
 * @param {Object} attachmentRef - Attachment reference with {cid, pieceCid, providerInfo, encryptedMetadata}
 * @param {string} privateKey - Private key to decrypt attachment metadata
 * @returns {Promise<Object>} Attachment object with {filename, mimeType, data}
 */
export async function fetchAttachment(attachmentRef, privateKey) {
  if (!attachmentRef?.cid || !attachmentRef?.pieceCid) {
    throw new Error('fetchAttachment: attachment reference must include cid and pieceCid')
  }

  let normalizedKey = null
  if (attachmentRef.encryptedMetadata || attachmentRef.data || attachmentRef._inline) {
    normalizedKey = ensurePrivateKey(privateKey)
  }

  // Fetch attachment from Synapse
  const encryptedData = await synapseFetch(attachmentRef.cid, {
    as: 'arrayBuffer',
    pieceCid: attachmentRef.pieceCid,
    providerInfo: attachmentRef.providerInfo,
  })

  // Convert ArrayBuffer to Uint8Array
  const bytes = encryptedData instanceof ArrayBuffer 
    ? new Uint8Array(encryptedData)
    : encryptedData instanceof Uint8Array
    ? encryptedData
    : new Uint8Array(0)

  // Decode to base64 for storage
  const base64Data = encodeAttachmentToBase64(bytes)

  // Decrypt metadata
  let metadata
  if (attachmentRef.encryptedMetadata) {
    const decryptedMetadata = await decryptString(attachmentRef.encryptedMetadata, normalizedKey)
    metadata = JSON.parse(decryptedMetadata)
  } else {
    // Fallback for old format (backward compatibility)
    metadata = {
      filename: attachmentRef.filename || 'attachment',
      mimeType: attachmentRef.mimeType || 'application/octet-stream',
    }
  }

  return {
    filename: metadata.filename || 'attachment',
    mimeType: metadata.mimeType || 'application/octet-stream',
    data: base64Data,
  }
}

export async function encryptEmail(payload, recipientPublicKey, options = {}) {
  if (!recipientPublicKey) {
    throw new Error('encryptEmail: recipientPublicKey is required')
  }
  if (!payload) {
    throw new Error('encryptEmail: payload is required')
  }

  if (options.forceLegacy || looksLikeLegacySecpKey(recipientPublicKey)) {
    return await encryptEmailLegacy(payload, recipientPublicKey, options)
  }

  return await encryptEmailV2(payload, recipientPublicKey, options)
}

async function encryptEmailV2(payload, recipientPublicKey, options = {}) {
  const recipientKeyBytes = normalizeKeyInput(recipientPublicKey)
  if (!recipientKeyBytes || recipientKeyBytes.length !== 32) {
    throw new Error('encryptEmail: recipient public key must be a 32-byte X25519 key (base64 or hex).')
  }

  const encoder = textEncoder ?? new TextEncoder()
  const timestamp = payload.timestamp ?? Date.now()
  const messageId = options.messageId ?? generateMessageId()
  const senderIdentity = normalizeIdentityKeyPair(options.senderIdentity ?? options.identity ?? null)

  const attachments = await prepareAttachments(payload.attachments ?? [], recipientPublicKey, options)

  const messageBody = {
    subject: payload.subject ?? '',
    message: payload.message ?? '',
    attachments,
  }

  const plaintextBytes = encoder.encode(JSON.stringify(messageBody))
  const additionalData = buildAdditionalData({
    from: payload.from,
    to: payload.to,
    timestamp,
    messageId,
  })

  const ephemeralPrivateKey = x25519.utils.randomPrivateKey()
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey)
  const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, recipientKeyBytes)
  const recipientKey = deriveSymmetricKey(sharedSecret, 'recipient', messageId)
  const recipientEncrypted = await aesGcmEncrypt(recipientKey, plaintextBytes, additionalData)

  const recipientEnvelope = {
    version: EMAIL_V2_VERSION,
    scheme: EMAIL_V2_SCHEME,
    messageId,
    fromEns: payload.from,
    toEns: payload.to,
    timestamp,
    ephemeralPublicKey: toBase64(ephemeralPublicKey),
    nonce: toBase64(recipientEncrypted.iv),
    ciphertext: toBase64(recipientEncrypted.ciphertext),
  }

  let senderEnvelope = null
  if (senderIdentity?.privateKey) {
    const senderSecretBytes = normalizeKeyInput(senderIdentity.privateKey)
    if (!senderSecretBytes || senderSecretBytes.length !== 32) {
      console.warn('[encryptEmail] sender identity private key must be 32 bytes (X25519). Sender copy skipped.')
    } else {
      const senderKey = deriveSymmetricKey(senderSecretBytes, 'sender', messageId)
      const senderEncrypted = await aesGcmEncrypt(senderKey, plaintextBytes, additionalData)
      senderEnvelope = {
        version: EMAIL_V2_VERSION,
        scheme: EMAIL_V2_SCHEME,
        messageId,
        fromEns: payload.from,
        toEns: payload.to,
        timestamp,
        nonce: toBase64(senderEncrypted.iv),
        ciphertext: toBase64(senderEncrypted.ciphertext),
      }
    }
  }

  return {
    version: EMAIL_V2_VERSION,
    scheme: EMAIL_V2_SCHEME,
    messageId,
    fromEns: payload.from,
    toEns: payload.to,
    timestamp,
    preview: {
      subject: payload.subject ?? '',
      snippet: (payload.message ?? '').slice(0, 160),
      attachments: attachments.length,
    },
    recipientEnvelope,
    senderEnvelope,
  }
}

export async function decryptEmail(encryptedPayload, keyMaterial, options = {}) {
  if (!encryptedPayload) {
    throw new Error('decryptEmail: encryptedPayload is required')
  }

  const material = normalizeKeyMaterial(keyMaterial)
  
  // Find the v2 envelope
  const candidateEnvelope =
    encryptedPayload?.ciphertext && encryptedPayload?.version
      ? encryptedPayload
      : encryptedPayload?.recipientEnvelope ?? encryptedPayload?.senderEnvelope ?? null

  if (!candidateEnvelope) {
    throw new Error('decryptEmail: No valid v2 envelope found in encrypted payload. Expected structure with recipientEnvelope/senderEnvelope or single envelope with ciphertext and version.')
  }

  // Verify it's a v2 envelope: version >= 2 OR has ephemeralPublicKey (v2-specific field)
  const hasV2Version = candidateEnvelope?.version != null && 
                        Number(candidateEnvelope.version) >= EMAIL_V2_VERSION
  const hasV2Structure = candidateEnvelope?.ephemeralPublicKey != null || 
                         (candidateEnvelope?.ciphertext && !candidateEnvelope?.encryptedSubject)
  const isV2 = (hasV2Version || hasV2Structure) && candidateEnvelope?.ciphertext

  if (!isV2) {
    throw new Error('decryptEmail: Only v2 email format is supported. Expected envelope with version >= 2 and ciphertext.')
  }

  return await decryptEmailV2(candidateEnvelope, material, options)
}

async function decryptEmailV2(encryptedEnvelope, keyMaterial, options = {}) {
  const decoder = textDecoder ?? new TextDecoder()
  const messageId = encryptedEnvelope.messageId ?? encryptedEnvelope.id ?? ''
  const timestamp = encryptedEnvelope.timestamp ?? Date.now()
  const metadata = {
    from: encryptedEnvelope.fromEns ?? encryptedEnvelope.from,
    to: encryptedEnvelope.toEns ?? encryptedEnvelope.to,
    timestamp,
    messageId,
  }
  const additionalData = buildAdditionalData(metadata)

  let plaintextBytes
  if (encryptedEnvelope.ephemeralPublicKey) {
    const identityKey =
      keyMaterial.identityPrivateKey ??
      keyMaterial.recipientPrivateKey ??
      options.identityPrivateKey ??
      options.recipientPrivateKey
    if (!identityKey) {
      throw new Error('decryptEmail: identity private key required for inbox message')
    }
    const identityBytes = normalizeKeyInput(identityKey)
    if (!identityBytes || identityBytes.length !== 32) {
      throw new Error('decryptEmail: identity private key must be a 32-byte X25519 key')
    }
    const ephemeralBytes = fromBase64(encryptedEnvelope.ephemeralPublicKey)
    const sharedSecret = x25519.scalarMult(identityBytes, ephemeralBytes)
    const symmetricKey = deriveSymmetricKey(sharedSecret, 'recipient', messageId)
    plaintextBytes = await aesGcmDecrypt(
      symmetricKey,
      fromBase64(encryptedEnvelope.ciphertext),
      fromBase64(encryptedEnvelope.nonce),
      additionalData
    )
  } else {
    const senderSecret =
      keyMaterial.senderSecret ??
      keyMaterial.identityPrivateKey ??
      options.senderSecret ??
      options.identityPrivateKey
    if (!senderSecret) {
      throw new Error('decryptEmail: sender secret required for sent message copy')
    }
    const senderSecretBytes = normalizeKeyInput(senderSecret)
    if (!senderSecretBytes || senderSecretBytes.length !== 32) {
      throw new Error('decryptEmail: sender secret must be a 32-byte X25519 key')
    }
    const symmetricKey = deriveSymmetricKey(senderSecretBytes, 'sender', messageId)
    plaintextBytes = await aesGcmDecrypt(
      symmetricKey,
      fromBase64(encryptedEnvelope.ciphertext),
      fromBase64(encryptedEnvelope.nonce),
      additionalData
    )
  }

  let body
  try {
    body = JSON.parse(decoder.decode(plaintextBytes))
  } catch (error) {
    throw new Error(`decryptEmail: failed to parse decrypted payload (${error?.message ?? error})`)
  }

  return {
    from: metadata.from,
    to: metadata.to,
    timestamp: metadata.timestamp,
    subject: body.subject ?? '',
    message: body.message ?? '',
    attachments: Array.isArray(body.attachments) ? body.attachments : [],
  }
}

async function encryptEmailLegacy(payload, recipientPublicKey, options = {}) {
  if (!recipientPublicKey) {
    throw new Error('encryptEmail: recipientPublicKey is required')
  }
  if (!payload) {
    throw new Error('encryptEmail: payload is required')
  }

  const normalizedKey = normaliseHex(recipientPublicKey)
  if (!normalizedKey) {
    throw new Error('encryptEmail: recipientPublicKey must be a hex string (legacy mode)')
  }

  const timestamp = payload.timestamp ?? Date.now()

  const encryptedSubject = await encryptString(payload.subject ?? '', normalizedKey)
  const encryptedMessage = await encryptString(payload.message ?? '', normalizedKey)

  // Handle attachments: either upload to Synapse (new way) or encrypt inline (old way for backward compatibility)
  let encryptedAttachments = []
  if (Array.isArray(payload.attachments) && payload.attachments.length > 0) {
    if (options.uploadAttachmentsToSynapse !== false) {
      // New way: upload attachments to Synapse and store references
      const attachmentRefs = await uploadAttachments(payload.attachments, recipientPublicKey)
      encryptedAttachments = attachmentRefs
    } else {
      // Old way: encrypt attachments inline (for backward compatibility)
      encryptedAttachments = await Promise.all(
        payload.attachments.map(async (attachment) => {
          const data = attachment?.data ?? ''
          return {
            filename: attachment?.filename ?? 'attachment',
            mimeType: attachment?.mimeType ?? 'application/octet-stream',
            data: await encryptString(data, normalizedKey),
            _inline: true, // Flag to indicate inline encrypted data
          }
        })
      )
    }
  }

  return {
    fromEns: payload.from,
    toEns: payload.to,
    timestamp,
    encryptedSubject,
    encryptedMessage,
    encryptedAttachments,
  }
}

async function decryptEmailLegacy(encryptedPayload, privateKey, options = {}) {
  if (!encryptedPayload) {
    throw new Error('decryptEmail: encryptedPayload is required')
  }
  const normalizedKey = ensurePrivateKey(privateKey)

  const subject = await decryptString(encryptedPayload.encryptedSubject ?? '', normalizedKey)
  const message = await decryptString(encryptedPayload.encryptedMessage ?? '', normalizedKey)

  // Handle attachments: either fetch from Synapse (new way) or decrypt inline (old way)
  let attachments = []
  if (Array.isArray(encryptedPayload.encryptedAttachments) && encryptedPayload.encryptedAttachments.length > 0) {
    attachments = await Promise.all(
      encryptedPayload.encryptedAttachments.map(async (attachment) => {
        // Check if this is an inline encrypted attachment (old format)
        if (attachment._inline || attachment.data) {
          // Old format: decrypt inline encrypted data
          return {
            filename: attachment.filename || 'attachment',
            mimeType: attachment.mimeType || 'application/octet-stream',
            data: await decryptString(attachment.data ?? '', normalizedKey),
          }
        } else if (attachment.cid && attachment.pieceCid) {
          // New format: fetch from Synapse
          if (options.fetchAttachmentsFromSynapse !== false) {
            return await fetchAttachment(attachment, privateKey)
          } else {
            // Return metadata only if fetching is disabled
            return {
              filename: 'attachment',
              mimeType: 'application/octet-stream',
              data: '', // Will be fetched on demand
              cid: attachment.cid,
              pieceCid: attachment.pieceCid,
              providerInfo: attachment.providerInfo,
              _needsFetch: true,
            }
          }
        } else {
          // Fallback: return what we have
          return {
            filename: attachment.filename || 'attachment',
            mimeType: attachment.mimeType || 'application/octet-stream',
            data: '',
          }
        }
      })
    )
  }

  return {
    from: encryptedPayload.fromEns ?? encryptedPayload.from,
    to: encryptedPayload.toEns ?? encryptedPayload.to,
    timestamp: encryptedPayload.timestamp,
    subject,
    message,
    attachments,
  }
}

async function encryptString(value, publicKey) {
  let stringValue
  if (typeof value === 'string') {
    stringValue = value
  } else if (value instanceof Uint8Array) {
    stringValue = encodeAttachmentToBase64(value)
  } else if (typeof value === 'object') {
    stringValue = JSON.stringify(value)
  } else {
    stringValue = String(value ?? '')
  }

  const cipherObject = await EthCrypto.encryptWithPublicKey(publicKey, stringValue)
  return EthCrypto.cipher.stringify(cipherObject)
}

async function decryptString(value, privateKey) {
  if (!value) return ''
  const cipherObject = EthCrypto.cipher.parse(value)
  const decrypted = await EthCrypto.decryptWithPrivateKey(privateKey, cipherObject)
  return decrypted
}

export function encodeAttachmentToBase64(bytes) {
  if (!bytes) return ''
  if (typeof bytes === 'string') return bytes

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(bytes)) {
    return bytes.toString('base64')
  }

  if (bytes instanceof Uint8Array) {
    if (typeof btoa !== 'undefined') {
      let binary = ''
      bytes.forEach((byte) => {
        binary += String.fromCharCode(byte)
      })
      return btoa(binary)
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(bytes).toString('base64')
    }
  }

  throw new Error('Unsupported attachment input for base64 encoding')
}

export function decodeBase64Attachment(encoded) {
  if (!encoded) return new Uint8Array()
  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(encoded, 'base64'))
  }
  if (typeof atob !== 'undefined') {
    const binary = atob(encoded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  }
  throw new Error('Base64 decoding is not supported in this environment')
}
