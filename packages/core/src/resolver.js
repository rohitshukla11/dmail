import { fetchPublicKeyFromEns, getMailboxRootFromEns } from './ens.js'

const isBrowser = typeof window !== 'undefined'
const MISSING_PROFILE = Symbol('resolver-profile-missing')
const profileCache = new Map()

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

function getResolverBaseUrl() {
  return (
    getEnv('DMAIL_API_URL') ??
    getEnv('RESOLVER_API_URL') ??
    getEnv('RESOLVER_URL') ??
    getEnv('OFFCHAIN_RESOLVER_URL') ??
    getEnv('VITE_DMAIL_API_URL') ??
    getEnv('VITE_RESOLVER_API_URL') ??
    getEnv('VITE_RESOLVER_URL') ??
    null
  )
}

function buildResolverUrl(path) {
  const baseUrl = getResolverBaseUrl()
  if (!baseUrl) {
    return null
  }
  const normalizedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return `${normalizedBase}${normalizedPath}`
}

async function resolverRequest(path, { method = 'GET', body, signal, headers = {} } = {}) {
  const url = buildResolverUrl(path)
  if (!url) {
    return null
  }

  const init = {
    method,
    headers: {
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    signal,
  }

  if (body) {
    init.body = typeof body === 'string' ? body : JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(url, init)
  } catch (error) {
    console.warn('[resolver] request failed', error)
    return null
  }

  if (response.status === 404) {
    return null
  }

  if (!response.ok) {
    const text = await safeReadBody(response)
    console.warn(`[resolver] ${method} ${url} failed: ${response.status} ${text}`)
    return null
  }

  try {
    return await response.json()
  } catch (error) {
    console.warn('[resolver] failed to parse response', error)
    return null
  }
}

async function fetchIdentityRecord(identifier, options = {}) {
  const normalized = normalizeIdentifierInput(identifier)
  if (!normalized) return null
  return await resolverRequest(`/v1/identity/${encodeURIComponent(normalized)}`, {
    signal: options.signal,
  })
}

export async function appendRemoteMailboxEntry(entry, options = {}) {
  return await resolverRequest('/v1/mailbox/append', {
    method: 'POST',
    body: entry,
    signal: options.signal,
  })
}

export async function fetchRemoteMailboxIndex(owner, folder, options = {}) {
  const normalizedOwner = normalizeIdentifierInput(owner)
  if (!normalizedOwner) return null
  if (!folder) return null
  const query = new URLSearchParams({
    owner: normalizedOwner,
    folder,
  })
  return await resolverRequest(`/v1/mailbox/index?${query.toString()}`, {
    signal: options.signal,
  })
}

async function safeReadBody(response) {
  try {
    return await response.text()
  } catch (error) {
    return `<unreadable: ${error?.message ?? String(error)}>`
  }
}

function normalizeIdentifierInput(identifier) {
  if (!identifier) return null
  if (typeof identifier !== 'string') {
    return String(identifier)
  }
  return identifier.trim()
}

function buildProfileCacheKeys(identifier, options = {}) {
  const keys = new Set()
  const normalizedId = normalizeIdentifierInput(identifier)
  if (normalizedId) keys.add(normalizedId.toLowerCase())
  if (options.address) keys.add(String(options.address).toLowerCase())
  if (options.ensName) keys.add(String(options.ensName).toLowerCase())
  if (options.ens) keys.add(String(options.ens).toLowerCase())
  return Array.from(keys)
}

function getCachedProfile(identifier, options) {
  const keys = buildProfileCacheKeys(identifier, options)
  for (const key of keys) {
    if (profileCache.has(key)) {
      const value = profileCache.get(key)
      return value === MISSING_PROFILE ? null : value
    }
  }
  return undefined
}

function setCachedProfile(identifier, options, profile) {
  const keys = buildProfileCacheKeys(identifier, options)
  const value = profile ?? MISSING_PROFILE
  for (const key of keys) {
    profileCache.set(key, value)
  }
}

export async function fetchResolverProfile(identifier, options = {}) {
  const id = normalizeIdentifierInput(identifier ?? options.ensName ?? options.address)
  const cached = getCachedProfile(id, options)
  if (cached !== undefined) {
    return cached
  }
  const query = new URLSearchParams()
  if (id) {
    query.set('id', id)
  }
  if (options.address) {
    query.set('address', options.address)
  }
  if (options.ensName) {
    query.set('ens', options.ensName)
  }

  const path = query.toString() ? `/profiles/lookup?${query.toString()}` : '/profiles/lookup'
  const profile = await resolverRequest(path, { signal: options.signal })
  setCachedProfile(id, options, profile ?? null)
  return profile
}

export async function registerResolverProfile(profile, options = {}) {
  if (!profile || !profile.encryptionPublicKey) {
    throw new Error('registerResolverProfile: encryptionPublicKey is required')
  }
  if (!profile.address && !profile.ensName) {
    throw new Error('registerResolverProfile: address or ensName is required')
  }
  return await resolverRequest('/profiles', {
    method: 'POST',
    body: {
      address: profile.address,
      ens: profile.ensName ?? profile.ens,
      encryptionPublicKey: profile.encryptionPublicKey,
      mailboxRoot: profile.mailboxRoot ?? null,
      metadata: profile.metadata ?? {},
    },
    signal: options.signal,
  })
}

export async function resolvePublicKey(identifier, options = {}) {
  const offchainIdentity = await fetchIdentityRecord(identifier, options)
  if (offchainIdentity?.x25519PublicKey) {
    return offchainIdentity.x25519PublicKey
  }
  const profile = await fetchResolverProfile(identifier, options)
  if (profile?.encryptionPublicKey) {
    return profile.encryptionPublicKey
  }
  if (options.disableEnsFallback) {
    return null
  }
  return await fetchPublicKeyFromEns(identifier, options)
}

export async function resolveMailboxRoot(identifier, options = {}) {
  const profile = await fetchResolverProfile(identifier, options)
  if (profile?.mailboxRoot) {
    return profile.mailboxRoot
  }
  if (options.disableEnsFallback) {
    return null
  }
  // Fallback to ENS - now fetches both inbox AND sent pointers
  return await getMailboxRootFromEns(identifier, options)
}

export async function updateResolverMailboxRoot(identifier, mailboxRoot, options = {}) {
  if (!mailboxRoot) {
    throw new Error('updateResolverMailboxRoot: mailboxRoot is required')
  }
  const id = normalizeIdentifierInput(identifier ?? mailboxRoot?.owner)
  if (!id) {
    throw new Error('updateResolverMailboxRoot: identifier required')
  }
  const response = await resolverRequest('/profiles/mailbox', {
    method: 'POST',
    body: {
      id,
      mailboxRoot,
    },
    signal: options.signal,
  })
  setCachedProfile(id, options, {
    ...(typeof mailboxRoot === 'object' ? mailboxRoot : {}),
    mailboxRoot,
  })
  return response
}

export async function ensureResolverProfile({ address, ensName, encryptionPublicKey }, options = {}) {
  if (!address && !ensName) {
    throw new Error('ensureResolverProfile: address or ensName is required')
  }
  if (!encryptionPublicKey) {
    throw new Error('ensureResolverProfile: encryptionPublicKey is required')
  }

  const identifier = address ?? ensName
  const existing = await fetchResolverProfile(identifier, {
    address,
    ensName,
  })
  if (existing?.encryptionPublicKey) {
    if (existing.encryptionPublicKey === encryptionPublicKey) {
      return existing
    }
    console.warn('[resolver] updating encryption key for profile due to mismatch')
  }
  const created = await registerResolverProfile(
    {
      address,
      ensName,
      encryptionPublicKey,
    },
    options
  )
  if (identifier) {
    setCachedProfile(identifier, { address, ensName }, created ?? { encryptionPublicKey })
  }
  return created
}

function getNetworkLabel() {
  return (
    getEnv('DMAIL_NETWORK') ??
    getEnv('NETWORK') ??
    getEnv('ETH_NETWORK') ??
    'unknown'
  )
}

export async function ensureRegisteredIdentity(ensName, publicKeyBase64, signer, options = {}) {
  if (!ensName) {
    throw new Error('ensureRegisteredIdentity: ensName is required')
  }
  if (!publicKeyBase64) {
    throw new Error('ensureRegisteredIdentity: publicKeyBase64 is required')
  }
  const profile = await fetchResolverProfile(ensName, options)
  const existingKey = profile?.identity?.publicKey ?? profile?.encryptionPublicKey ?? null
  if (existingKey && existingKey === publicKeyBase64) {
    return { registered: false, profile }
  }
  if (!signer || typeof signer.getAddress !== 'function' || typeof signer.signMessage !== 'function') {
    throw new Error('ensureRegisteredIdentity: signer with getAddress & signMessage is required')
  }
  const payload = {
    ens: ensName,
    publicKey: publicKeyBase64,
    signingPublicKey: options.signingPublicKey,
    network: getNetworkLabel(),
    timestamp: new Date().toISOString(),
    purpose: 'dmail-identity-registration-v1',
  }
  const sortedKeys = Object.keys(payload).sort()
  const canonical = {}
  for (const key of sortedKeys) {
    canonical[key] = payload[key]
  }
  const payloadString = JSON.stringify(canonical)
  const signature = await signer.signMessage(payloadString)
  const address = await signer.getAddress()

  const body = {
    payload,
    signature,
    address,
  }

  const offchainResponse = await resolverRequest('/v1/identity/register', {
    method: 'POST',
    body,
    signal: options.signal,
  })
  if (offchainResponse) {
    return { registered: true, resolverResponse: offchainResponse }
  }

  const response = await resolverRequest('/identity/register', {
    method: 'POST',
    body,
    signal: options.signal,
  })
  return { registered: true, resolverResponse: response }
}


