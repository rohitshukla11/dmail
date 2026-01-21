import { deriveIdentityFromWallet } from '@dmail/core'
import type { Signer } from 'ethers'

export interface IdentityMaterial {
  x25519PrivateBase64: string
  x25519PublicBase64: string
  senderStaticSymKeyBase64: string
  signingKeyBase64: string
  signingPublicKeyBase64: string
}

const IDENTITY_STORAGE_KEY_PREFIX = 'dmail_identity_v2'
const identityInflightPromises = new Map<string, Promise<IdentityMaterial>>()

function hasLocalStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

function getIdentityStorageKey(account: string | null | undefined, domain: string | null | undefined): string {
  const safeAccount = account ? account.toLowerCase() : 'unknown'
  const safeDomain = domain || 'unknown'
  return `${IDENTITY_STORAGE_KEY_PREFIX}:${safeDomain}:${safeAccount}`
}

export function readIdentityFromStorage(
  account: string | null | undefined,
  domain: string | null | undefined
): IdentityMaterial | null {
  if (!hasLocalStorage()) return null
  const key = getIdentityStorageKey(account, domain)
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return null
    return JSON.parse(raw) as IdentityMaterial
  } catch (error) {
    console.warn('Failed to parse cached identity', error)
    window.localStorage.removeItem(key)
    return null
  }
}

export function writeIdentityToStorage(
  account: string | null | undefined,
  domain: string | null | undefined,
  identityObj: IdentityMaterial
): void {
  if (!hasLocalStorage()) return
  const key = getIdentityStorageKey(account, domain)
  try {
    window.localStorage.setItem(key, JSON.stringify(identityObj))
  } catch (error) {
    console.warn('Failed to persist identity to localStorage', error)
  }
}

export function clearIdentityCache(
  account?: string | null | undefined,
  domain?: string | null | undefined
): void {
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

export interface GetOrCreateIdentityOptions {
  signer: Signer
  account: string | null | undefined
  domain?: string | null | undefined
}

export async function getOrCreateIdentityCached({
  signer,
  account,
  domain,
}: GetOrCreateIdentityOptions): Promise<IdentityMaterial> {
  if (!signer) {
    throw new Error('Signer is required to derive identity')
  }
  const key = getIdentityStorageKey(account, domain)
  const cached = readIdentityFromStorage(account, domain)
  if (cached) {
    return cached
  }
  if (identityInflightPromises.has(key)) {
    return identityInflightPromises.get(key)!
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

