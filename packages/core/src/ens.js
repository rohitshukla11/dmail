import { BrowserProvider, JsonRpcProvider, Wallet, Contract, namehash } from 'ethers'
import { normalizeServiceUrl, getStorageServiceUrl } from './synapse.js'

const MAILBOX_KEY = 'dmail:mailbox'
const MAILBOX_SENT_KEY = 'dmail:mailbox:sent'
const CALENDAR_KEY = 'dmail:calendar'
const PUBKEY_KEY = 'dmail:pubkey'

const isBrowser = typeof window !== 'undefined'

function getEnv(name) {
  if (typeof process !== 'undefined' && process?.env?.[name]) {
    return process.env[name]
  }
  if (typeof import.meta !== 'undefined' && import.meta?.env) {
    const direct = import.meta.env[name]
    if (direct) return direct
    const vitePrefixed = import.meta.env[`VITE_${name}`]
    if (vitePrefixed) return vitePrefixed
  }
  if (isBrowser && window?.__DMAIL_CONFIG__?.[name]) {
    return window.__DMAIL_CONFIG__[name]
  }
  return undefined
}

export function createDefaultProvider(providerOverride) {
  if (providerOverride) {
    return providerOverride
  }

  if (isBrowser && window?.ethereum) {
    return new BrowserProvider(window.ethereum)
  }

  const rpcUrl = getEnv('ETH_RPC_URL')
  if (!rpcUrl) {
    throw new Error('ETH_RPC_URL is not configured. Set it in the environment to resolve ENS.')
  }
  return new JsonRpcProvider(rpcUrl)
}

export async function getMailboxUploadResult(ensName, options = {}) {
  if (!ensName) {
    throw new Error('getMailboxUploadResult: ensName is required')
  }
  const provider = options.provider ?? createDefaultProvider()
  const resolver = await provider.getResolver(ensName)
  if (!resolver) return null
  const value = await resolver.getText(MAILBOX_KEY)
  if (!value) return null

  try {
    return JSON.parse(value)
  } catch {
    return { cid: value }
  }
}

// Get full mailbox root with both inbox and sent pointers from ENS.
// Supports both the legacy (single pointer) format and the new JSON root format.
export async function getMailboxRootFromEns(ensName, options = {}) {
  if (!ensName) {
    throw new Error('getMailboxRootFromEns: ensName is required')
  }
  const provider = options.provider ?? createDefaultProvider()
  const resolver = await provider.getResolver(ensName)
  if (!resolver) return null

  const primaryValue = await resolver.getText(MAILBOX_KEY)
  if (!primaryValue) return null

  const parsePointer = (value) => {
    if (!value) return null
    if (typeof value === 'object') {
      return value
    }
    try {
      return JSON.parse(value)
    } catch {
      return { cid: value }
    }
  }

  let parsedRoot = null
  try {
    parsedRoot = JSON.parse(primaryValue)
  } catch {
    parsedRoot = null
  }

  if (parsedRoot && (parsedRoot.inbox || parsedRoot.sent)) {
    return {
      owner: parsedRoot.owner ?? ensName,
      version: parsedRoot.version ?? 2,
      inbox: parsePointer(parsedRoot.inbox),
      sent: parsePointer(parsedRoot.sent),
    }
  }

  // Legacy format: mailbox key stored only inbox pointer string; sent pointer (if any) lives in MAILBOX_SENT_KEY.
  const legacyInbox = parsePointer(primaryValue)
  const legacySentValue = await resolver.getText(MAILBOX_SENT_KEY)
  const legacySent = parsePointer(legacySentValue)

  return {
    owner: ensName,
    version: 2,
    inbox: legacyInbox,
    sent: legacySent,
  }
}

// Backward compatibility alias
export async function getMailboxCid(ensName, options = {}) {
  const result = await getMailboxUploadResult(ensName, options)
  return result?.cid ?? null
}

export async function getCalendarUploadResult(ensName, options = {}) {
  if (!ensName) {
    throw new Error('getCalendarUploadResult: ensName is required')
  }
  const provider = options.provider ?? createDefaultProvider()
  const resolver = await provider.getResolver(ensName)
  if (!resolver) return null
  const value = await resolver.getText(CALENDAR_KEY)
  if (!value) return null

  try {
    return JSON.parse(value)
  } catch {
    return { cid: value }
  }
}

export async function setMailboxUploadResult(ensName, uploadResult, options = {}) {
  if (!ensName) {
    throw new Error('setMailboxUploadResult: ensName is required')
  }
  if (!uploadResult || !uploadResult.cid) {
    throw new Error('setMailboxUploadResult: uploadResult with cid is required')
  }
  if (!uploadResult.pieceCid) {
    throw new Error('setMailboxUploadResult: uploadResult must include pieceCid')
  }
  if (!uploadResult.providerInfo) {
    throw new Error('setMailboxUploadResult: uploadResult must include providerInfo')
  }

  const provider = options.provider ?? createDefaultProvider(options.providerOverride)
  const signer = await resolveSigner(provider, options.signer, options.privateKey)

  const resolver = await provider.getResolver(ensName)
  if (!resolver) {
    throw new Error(`setMailboxUploadResult: Resolver not configured for ${ensName}`)
  }

  // Store upload result as JSON string in ENS text record
  // Includes: cid, pieceCid, providerId, providerAddress, serviceURL
  const storageInfo = {
    cid: uploadResult.cid,
    pieceCid: uploadResult.pieceCid,
    providerId: uploadResult.providerInfo?.id,
    providerAddress: uploadResult.providerInfo?.address,
    serviceURL: normalizeServiceUrl(getStorageServiceUrl(uploadResult.providerInfo)),
  }
  const value = JSON.stringify(storageInfo)

  const resolverAddress = resolver?.address ?? resolver?.target
  if (!resolverAddress) {
    throw new Error('setMailboxUploadResult: Resolver address unavailable')
  }

  const resolverContract = new Contract(
    resolverAddress,
    ['function setText(bytes32 node, string key, string value) external'],
    signer
  )
  const tx = await resolverContract.setText(namehash(ensName), MAILBOX_KEY, value)
  if (options.wait !== false) {
    await tx.wait()
  }
  return tx.hash ?? tx
}

// Backward compatibility alias
export async function setMailboxCid(ensName, cid, options = {}) {
  // Legacy: if only CID provided, we can't use it with Synapse-only retrieval
  // This will fail if used, but kept for API compatibility
  throw new Error('setMailboxCid is deprecated. Use setMailboxUploadResult with full upload result including provider info.')
}

// Set full mailbox root with both inbox and sent pointers to ENS
export async function setMailboxRootToEns(ensName, mailboxRoot, options = {}) {
  if (!ensName) {
    throw new Error('setMailboxRootToEns: ensName is required')
  }
  if (!mailboxRoot) {
    throw new Error('setMailboxRootToEns: mailboxRoot is required')
  }

  const provider = options.provider ?? createDefaultProvider(options.providerOverride)
  const signer = await resolveSigner(provider, options.signer, options.privateKey)

  const resolver = await provider.getResolver(ensName)
  if (!resolver) {
    throw new Error(`setMailboxRootToEns: Resolver not configured for ${ensName}`)
  }

  const resolverAddress = resolver?.address ?? resolver?.target
  if (!resolverAddress) {
    throw new Error('setMailboxRootToEns: Resolver address unavailable')
  }

  const resolverContract = new Contract(
    resolverAddress,
    ['function setText(bytes32 node, string key, string value) external'],
    signer
  )

  const serializePointer = (pointer) => {
    if (!pointer) return null
    return {
      cid: pointer.cid,
      pieceCid: pointer.pieceCid,
      providerId: pointer.providerInfo?.id,
      providerAddress: pointer.providerInfo?.address,
      serviceURL: normalizeServiceUrl(getStorageServiceUrl(pointer.providerInfo)),
    }
  }

  const payload = JSON.stringify({
    owner: mailboxRoot.owner ?? ensName,
    version: mailboxRoot.version ?? 2,
    inbox: serializePointer(mailboxRoot.inbox),
    sent: serializePointer(mailboxRoot.sent),
  })

  const tx = await resolverContract.setText(namehash(ensName), MAILBOX_KEY, payload)
  if (options.wait !== false) {
    await tx.wait()
  }

  return tx.hash ?? tx
}

export async function setCalendarUploadResult(ensName, uploadResult, options = {}) {
  if (!ensName) {
    throw new Error('setCalendarUploadResult: ensName is required')
  }
  if (!uploadResult || !uploadResult.cid) {
    throw new Error('setCalendarUploadResult: uploadResult with cid is required')
  }
  if (!uploadResult.pieceCid) {
    throw new Error('setCalendarUploadResult: uploadResult must include pieceCid')
  }
  if (!uploadResult.providerInfo) {
    throw new Error('setCalendarUploadResult: uploadResult must include providerInfo')
  }

  const provider = options.provider ?? createDefaultProvider(options.providerOverride)
  const signer = await resolveSigner(provider, options.signer, options.privateKey)

  const resolver = await provider.getResolver(ensName)
  if (!resolver) {
    throw new Error(`setCalendarUploadResult: Resolver not configured for ${ensName}`)
  }

  const storageInfo = {
    cid: uploadResult.cid,
    pieceCid: uploadResult.pieceCid,
    providerId: uploadResult.providerInfo?.id,
    providerAddress: uploadResult.providerInfo?.address,
    serviceURL: normalizeServiceUrl(getStorageServiceUrl(uploadResult.providerInfo)),
  }
  const value = JSON.stringify(storageInfo)

  const resolverAddress = resolver?.address ?? resolver?.target
  if (!resolverAddress) {
    throw new Error('setCalendarUploadResult: Resolver address unavailable')
  }

  const resolverContract = new Contract(
    resolverAddress,
    ['function setText(bytes32 node, string key, string value) external'],
    signer
  )
  const tx = await resolverContract.setText(namehash(ensName), CALENDAR_KEY, value)
  if (options.wait !== false) {
    await tx.wait()
  }
  return tx.hash ?? tx
}

export async function getEnsTextRecord(ensNameOrAddress, key, options = {}) {
  if (!ensNameOrAddress) {
    throw new Error('getEnsTextRecord: ENS name or address is required')
  }
  const provider = options.provider ?? createDefaultProvider(options.providerOverride)

  const target =
    ensNameOrAddress.includes('.') || ensNameOrAddress.endsWith('.eth')
      ? ensNameOrAddress
      : await provider.lookupAddress(ensNameOrAddress)

  if (!target) {
    return null
  }

  const resolver = await provider.getResolver(target)
  if (!resolver) return null
  const value = await resolver.getText(key)
  return value ?? null
}

export async function setEnsTextRecord(ensName, key, value, options = {}) {
  if (!ensName) {
    throw new Error('setEnsTextRecord: ensName is required')
  }
  if (!key) {
    throw new Error('setEnsTextRecord: key is required')
  }

  const provider = options.provider ?? createDefaultProvider(options.providerOverride)
  const signer = await resolveSigner(provider, options.signer, options.privateKey)

  const resolver = await provider.getResolver(ensName)
  if (!resolver) {
    throw new Error(`setEnsTextRecord: Resolver not configured for ${ensName}`)
  }

  const connectedResolver = resolver.connect(signer)
  const tx = await connectedResolver.setText(key, value ?? '')
  if (options.wait !== false) {
    await tx.wait()
  }
  return tx.hash ?? tx
}

async function resolveSigner(provider, signerOverride, privateKey) {
  if (signerOverride) {
    return signerOverride
  }
  if (privateKey) {
    return new Wallet(privateKey, provider)
  }
  if (provider instanceof BrowserProvider) {
    return provider.getSigner()
  }
  if (typeof provider.getSigner === 'function') {
    const signer = await provider.getSigner()
    if (signer) {
      return signer
    }
  }
  throw new Error('Unable to resolve signer. Provide options.signer or options.privateKey.')
}

export async function publishPublicKeyToEns(ensName, publicKey, options = {}) {
  if (!publicKey) {
    throw new Error('Public key is required to publish to ENS')
  }
  return setEnsTextRecord(ensName, PUBKEY_KEY, publicKey, options)
}

export async function fetchPublicKeyFromEns(ensName, options = {}) {
  return getEnsTextRecord(ensName, PUBKEY_KEY, options)
}
