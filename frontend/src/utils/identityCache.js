import { deriveIdentityFromWallet } from '@dmail/core'

const IDENTITY_STORAGE_KEY_PREFIX = 'dmail_identity_v2'
const identityInflightPromises = new Map()

function hasLocalStorage() {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

function getIdentityStorageKey(account, domain) {
  const safeAccount = account ? account.toLowerCase() : 'unknown'
  const safeDomain = domain || 'unknown'
  return `${IDENTITY_STORAGE_KEY_PREFIX}:${safeDomain}:${safeAccount}`
}

export function readIdentityFromStorage(account, domain) {
  if (!hasLocalStorage()) return null
  const key = getIdentityStorageKey(account, domain)
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return null
    return JSON.parse(raw)
  } catch (error) {
    console.warn('Failed to parse cached identity', error)
    window.localStorage.removeItem(key)
    return null
  }
}

export function writeIdentityToStorage(account, domain, identityObj) {
  if (!hasLocalStorage()) return
  const key = getIdentityStorageKey(account, domain)
  try {
    window.localStorage.setItem(key, JSON.stringify(identityObj))
  } catch (error) {
    console.warn('Failed to persist identity to localStorage', error)
  }
}

export function clearIdentityCache(account, domain) {
  if (!hasLocalStorage()) return
  const storage = window.localStorage
  if (account || domain) {
    const key = getIdentityStorageKey(account, domain)
    storage.removeItem(key)
    identityInflightPromises.delete(key)
    return
  }
  for (let i = storage.length - 1; i >= 0; i -= 1) {
    const key = storage.key(i)
    if (key && key.startsWith(IDENTITY_STORAGE_KEY_PREFIX)) {
      storage.removeItem(key)
      identityInflightPromises.delete(key)
    }
  }
}

export async function getOrCreateIdentityCached({ signer, account, domain }) {
  if (!signer) {
    throw new Error('Signer is required to derive identity')
  }
  const key = getIdentityStorageKey(account, domain)
  const cached = readIdentityFromStorage(account, domain)
  if (cached) {
    return cached
  }
  if (identityInflightPromises.has(key)) {
    return identityInflightPromises.get(key)
  }
  const promise = deriveIdentityFromWallet(signer, { domain })
    .then((identity) => {
      writeIdentityToStorage(account, domain, identity)
      identityInflightPromises.delete(key)
      return identity
    })
    .catch((error) => {
      identityInflightPromises.delete(key)
      throw error
    })
  identityInflightPromises.set(key, promise)
  return promise
}

