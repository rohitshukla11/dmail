// dMail v2 update: extend mailbox helpers with append-only index utilities.
import { synapseFetch, synapseUpload, normalizeServiceUrl, getStorageServiceUrl, setStorageServiceUrl } from './synapse.js'
import {
  resolveMailboxRoot as resolveMailboxRootFromResolver,
  updateResolverMailboxRoot,
} from './resolver.js'

let synapseFetchImpl = synapseFetch
let synapseUploadImpl = synapseUpload
let resolveMailboxRootImpl = resolveMailboxRootFromResolver
let updateResolverMailboxRootImpl = updateResolverMailboxRoot

export function __setMailboxTestOverrides(overrides = {}) {
  if (Object.prototype.hasOwnProperty.call(overrides, 'synapseFetch')) {
    synapseFetchImpl = overrides.synapseFetch ?? synapseFetch
  }
  if (Object.prototype.hasOwnProperty.call(overrides, 'synapseUpload')) {
    synapseUploadImpl = overrides.synapseUpload ?? synapseUpload
  }
  if (Object.prototype.hasOwnProperty.call(overrides, 'resolveMailboxRoot')) {
    resolveMailboxRootImpl = overrides.resolveMailboxRoot ?? resolveMailboxRootFromResolver
  }
  if (Object.prototype.hasOwnProperty.call(overrides, 'updateResolverMailboxRoot')) {
    updateResolverMailboxRootImpl = overrides.updateResolverMailboxRoot ?? updateResolverMailboxRoot
  }
}

function normalizeRecipientArray(value) {
  if (!value) return []
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter((item) => item.length > 0)
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
  }
  return [String(value).trim()].filter((item) => item.length > 0)
}

export function createEmptyMailbox(ownerEns, type = 'inbox') {
  return {
    owner: ownerEns ?? null,
    type,
    version: 2,
    updatedAt: new Date().toISOString(),
    entries: [],
    emails: [],
  }
}

function normalizeUploadResult(uploadResult) {
  if (!uploadResult) return null
  if (typeof uploadResult === 'string') {
    return { cid: uploadResult }
  }
  return uploadResult
}

function ensureProviderInfo(uploadResult) {
  if (!uploadResult) return null
  if (uploadResult.providerInfo) {
    return uploadResult.providerInfo
  }
  if (uploadResult.serviceURL) {
    const baseInfo = {
      id: uploadResult.providerId,
      address: uploadResult.providerAddress,
      products: {},
    }
    // Use first available product key from Synapse SDK
    const productKey = 'STORAGE'
    baseInfo.products[productKey] = {
      data: {
        serviceURL: normalizeServiceUrl(uploadResult.serviceURL),
      },
    }
    return baseInfo
  }
  return null
}

export function appendEmailEntry(mailbox, uploads, metadata = {}) {
  if (!mailbox) {
    throw new Error('appendEmailEntry: mailbox is required')
  }

  const recipientUpload =
    uploads?.recipient ??
    uploads?.recipientUpload ??
    (uploads?.cid ? uploads : metadata.recipientUpload ?? null)
  const senderUpload =
    uploads?.sender ?? uploads?.senderUpload ?? metadata.senderUpload ?? null

  if (!recipientUpload?.cid) {
    throw new Error('appendEmailEntry: recipient upload result with cid is required')
  }
  if (!recipientUpload?.pieceCid) {
    throw new Error('appendEmailEntry: recipient upload result must include pieceCid')
  }
  if (!ensureProviderInfo(recipientUpload)) {
    throw new Error('appendEmailEntry: recipient upload result missing provider info/service URL')
  }

  const timestamp = metadata.timestamp ?? Date.now()
  const toRecipients = normalizeRecipientArray(
    metadata.toRecipients ?? metadata.recipients ?? metadata.to
  )
  const ccRecipients = normalizeRecipientArray(metadata.cc ?? metadata.ccRecipients)
  const bodyCid =
    metadata.bodyCid ?? metadata.cidRecipient ?? metadata.cid ?? recipientUpload?.cid ?? null
  const keyEnvelopesCid =
    metadata.keyEnvelopesCid ?? metadata.cidRecipient ?? metadata.cid ?? recipientUpload?.cid ?? null
  const senderCopyCid =
    metadata.senderCopyCid ?? metadata.cidSender ?? senderUpload?.cid ?? null

  const entry = {
    messageId: metadata.messageId ?? null,
    folder: metadata.folder ?? 'inbox',
    cid: recipientUpload.cid,
    pieceCid: recipientUpload.pieceCid,
    providerId: recipientUpload.providerInfo?.id ?? recipientUpload.providerId ?? null,
    providerAddress: recipientUpload.providerInfo?.address ?? recipientUpload.providerAddress ?? null,
    serviceURL: normalizeServiceUrl(
      getStorageServiceUrl(recipientUpload.providerInfo) ?? recipientUpload.serviceURL ?? null
    ),
    cidRecipient: recipientUpload.cid,
    recipientPieceCid: recipientUpload.pieceCid,
    cidSender: senderUpload?.cid ?? null,
    senderPieceCid: senderUpload?.pieceCid ?? null,
    senderProviderId: senderUpload?.providerInfo?.id ?? senderUpload?.providerId ?? null,
    senderProviderAddress:
      senderUpload?.providerInfo?.address ?? senderUpload?.providerAddress ?? null,
    senderServiceURL: normalizeServiceUrl(
      getStorageServiceUrl(senderUpload?.providerInfo) ?? senderUpload?.serviceURL ?? null
    ),
    timestamp,
    from: metadata.from ?? null,
    to: metadata.to ?? (toRecipients[0] ?? null),
    toRecipients,
    cc: ccRecipients,
    subjectPreview: metadata.subjectPreview ?? null,
    ephemeralPublicKey: metadata.ephemeralPublicKey ?? null,
    signature: metadata.signature ?? null,
    signerPublicKey: metadata.signerPublicKey ?? null,
    attachments: Array.isArray(metadata.attachments) ? metadata.attachments : [],
    bodyCid,
    keyEnvelopesCid,
    senderCopyCid,
  }

  const existing = Array.isArray(mailbox.entries)
    ? [...mailbox.entries]
    : Array.isArray(mailbox.emails)
    ? [...mailbox.emails]
    : []
  existing.push(entry)

  return {
    ...mailbox,
    updatedAt: new Date().toISOString(),
    entries: existing,
    emails: existing,
  }
}

export async function loadMailboxFromCid(mailboxUploadResult, options = {}) {
  if (!mailboxUploadResult || !mailboxUploadResult.cid) {
    if (options.optional) return null
    throw new Error('loadMailboxFromCid: mailboxUploadResult with cid is required')
  }
  
  if (!mailboxUploadResult.pieceCid) {
    if (options.optional) return null
    throw new Error('loadMailboxFromCid: mailboxUploadResult must include pieceCid for Synapse retrieval')
  }
  
  // Reconstruct providerInfo if not present but we have the components
  let providerInfo = mailboxUploadResult.providerInfo
  if (!providerInfo && mailboxUploadResult.serviceURL) {
    const baseInfo = {
      id: mailboxUploadResult.providerId,
      address: mailboxUploadResult.providerAddress,
      products: {},
    }
    const productKey = 'STORAGE'
    baseInfo.products[productKey] = {
      data: {
        serviceURL: normalizeServiceUrl(mailboxUploadResult.serviceURL)
      }
    }
    providerInfo = baseInfo
  }
  
  if (!providerInfo) {
    if (options.optional) return null
    throw new Error('loadMailboxFromCid: mailboxUploadResult must include providerInfo (or serviceURL) for Synapse retrieval')
  }

  // Normalize provider info URLs (old entries may have outdated URL formats)
  const serviceUrl = getStorageServiceUrl(providerInfo)
  if (serviceUrl) {
    providerInfo = setStorageServiceUrl(providerInfo, normalizeServiceUrl(serviceUrl))
  }

  try {
    const mailbox = await synapseFetchImpl(mailboxUploadResult.cid, {
      as: 'json',
      pieceCid: mailboxUploadResult.pieceCid,
      providerInfo,
      ...options,
    })
    if (!mailbox || typeof mailbox !== 'object') {
      throw new Error('Mailbox payload is not a valid object')
    }
    const list = Array.isArray(mailbox.entries)
      ? mailbox.entries
      : Array.isArray(mailbox.emails)
      ? mailbox.emails
      : []
    mailbox.entries = list
    mailbox.emails = list
    return mailbox
  } catch (error) {
    if (options.optional) {
      return null
    }
    throw error
  }
}

export async function ensureMailbox(ensName, currentMailboxUploadResult, options = {}) {
  const type = options.type ?? 'inbox'
  const existingMailbox = currentMailboxUploadResult
    ? await loadMailboxFromCid(currentMailboxUploadResult, { ...options, optional: true })
    : null

  if (existingMailbox) {
    return { mailbox: existingMailbox, uploadResult: currentMailboxUploadResult }
  }

  const mailbox = createEmptyMailbox(ensName, type)
  const uploadResult = await persistMailbox(mailbox, { ...options, type })
  return { mailbox, uploadResult }
}

export async function persistMailbox(mailbox, options = {}) {
  if (!mailbox) {
    throw new Error('persistMailbox: mailbox is required')
  }
  const payload = JSON.stringify(mailbox, null, 2)
  const uploadResult = await synapseUploadImpl(payload, {
    filename: options.filename ?? `${mailbox.type ?? options.type ?? 'mailbox'}.json`,
    metadata: {
      type: options.metadataType ?? `mailbox-${mailbox.type ?? 'index'}`,
      owner: mailbox.owner ?? options.owner ?? 'unknown',
    },
    ...options.uploadOptions,
  })
  return uploadResult
}

export function normalizeMailboxRoot(rawRoot, { owner } = {}) {
  if (!rawRoot) {
    return null
  }

  if (typeof rawRoot === 'string') {
    return {
      owner: owner ?? null,
      version: 1,
      inbox: normalizeUploadResult(rawRoot),
      sent: null,
    }
  }

  if (rawRoot.version >= 2 || rawRoot.inbox || rawRoot.sent) {
    const inboxPointer = rawRoot.inbox ?? (rawRoot.cid ? rawRoot : null)
    const sentPointer = rawRoot.sent ?? null
    return {
      owner: rawRoot.owner ?? owner ?? null,
      version: rawRoot.version ?? 2,
      inbox: normalizeUploadResult(inboxPointer),
      sent: normalizeUploadResult(sentPointer),
    }
  }

  if (rawRoot.cid || rawRoot.pieceCid) {
    return {
      owner: rawRoot.owner ?? owner ?? null,
      version: rawRoot.version ?? 1,
      inbox: normalizeUploadResult(rawRoot),
      sent: null,
    }
  }

  return {
    owner: rawRoot.owner ?? owner ?? null,
    version: rawRoot.version ?? 2,
    inbox: normalizeUploadResult(rawRoot.inbox ?? null),
    sent: normalizeUploadResult(rawRoot.sent ?? null),
  }
}

export function getMailboxIndexPointer(root, type = 'inbox') {
  if (!root) return null
  if (root.version >= 2 || root.inbox || root.sent) {
    return normalizeUploadResult(root[type])
  }
  // Legacy structure: treat entire object as inbox pointer
  if (type === 'inbox') {
    return normalizeUploadResult(root)
  }
  return null
}

export function mergeMailboxRoot(currentRoot, type, uploadResult, { owner } = {}) {
  const normalized = normalizeMailboxRoot(currentRoot, { owner })
  const next = {
    owner: normalized?.owner ?? owner ?? null,
    version: 2,
    inbox: normalized?.inbox ?? null,
    sent: normalized?.sent ?? null,
  }
  next[type] = uploadResult
  return next
}

export function getMailboxEntries(mailbox) {
  if (!mailbox) return []
  if (Array.isArray(mailbox.entries)) return mailbox.entries
  if (Array.isArray(mailbox.emails)) return mailbox.emails
  return []
}

export async function fetchMailboxIndex(ownerEns, mailboxRoot, type = 'inbox', options = {}) {
  const pointer = getMailboxIndexPointer(mailboxRoot, type)
  const loadOptions = options.loadOptions ?? {}

  if (options.mailbox) {
    return {
      mailbox: options.mailbox,
      pointer,
      isNew: !pointer,
    }
  }

  if (pointer?.cid) {
    const mailbox = await loadMailboxFromCid(pointer, { optional: true, ...loadOptions })
    if (mailbox) {
      return {
        mailbox,
        pointer,
        isNew: false,
      }
    }
  }

  return {
    mailbox: createEmptyMailbox(ownerEns, type),
    pointer: null,
    isNew: true,
  }
}

export async function appendMailboxIndexEntry({
  ownerEns,
  mailboxRoot,
  uploads,
  metadata = {},
  type = 'inbox',
  loadOptions,
  persistOptions,
}) {
  if (!ownerEns) {
    throw new Error('appendMailboxIndexEntry: ownerEns is required')
  }
  const { mailbox } = await fetchMailboxIndex(ownerEns, mailboxRoot, type, {
    loadOptions,
  })
  const entryMetadata = {
    ...metadata,
    folder: metadata.folder ?? type,
  }
  const nextMailbox = appendEmailEntry(mailbox, uploads, entryMetadata)
  const uploadResult = await persistMailbox(nextMailbox, {
    owner: ownerEns,
    type,
    ...(persistOptions ?? {}),
  })
  const nextRoot = mergeMailboxRoot(mailboxRoot, type, uploadResult, { owner: ownerEns })
  const entries = getMailboxEntries(nextMailbox)
  const appendedEntry = entries[entries.length - 1] ?? null

  return {
    mailbox: nextMailbox,
    uploadResult,
    mailboxRoot: nextRoot,
    entry: appendedEntry,
  }
}

async function resolveMailboxRootForOwner(ownerEns, mailboxRoot, resolveOptions) {
  if (mailboxRoot) {
    return normalizeMailboxRoot(mailboxRoot, { owner: ownerEns })
  }
  const resolved = await resolveMailboxRootImpl(ownerEns, resolveOptions)
  return normalizeMailboxRoot(resolved, { owner: ownerEns })
}

async function appendMailboxEntryAndSyncResolver({
  ownerEns,
  mailboxRoot,
  uploads,
  metadata = {},
  type = 'inbox',
  loadOptions,
  persistOptions,
  resolveOptions,
  resolverOptions,
  skipResolverUpdate = false,
}) {
  const baselineRoot = await resolveMailboxRootForOwner(ownerEns, mailboxRoot, resolveOptions)
  const result = await appendMailboxIndexEntry({
    ownerEns,
    mailboxRoot: baselineRoot,
    uploads,
    metadata,
    type,
    loadOptions,
    persistOptions,
  })
  if (!skipResolverUpdate) {
    await updateResolverMailboxRootImpl(ownerEns, result.mailboxRoot, resolverOptions)
  }
  return result
}

export async function appendInboxEntry(options) {
  return appendMailboxEntryAndSyncResolver({ ...options, type: 'inbox' })
}

export async function appendSentEntry(options) {
  return appendMailboxEntryAndSyncResolver({ ...options, type: 'sent' })
}

