// dMail v2 update: extend mailbox helpers with append-only index utilities.
import {
  synapseFetch,
  synapseUpload,
  normalizeServiceUrl,
  getStorageServiceUrl,
  setStorageServiceUrl,
} from './synapse.js'
import {
  resolveMailboxRoot as resolveMailboxRootFromResolver,
  updateResolverMailboxRoot,
} from './resolver.js'

const MAILBOX_ROOT_VERSION = 3
const MAX_SEGMENT_ENTRIES = 50
const SEGMENT_FILENAME_PREFIX = 'mailbox-segment'
const ROOT_FILENAME = 'mailbox-root'

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

function sanitizeForJson(value) {
  if (typeof value === 'bigint') {
    return value.toString()
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeForJson(item))
  }
  if (value && typeof value === 'object') {
    const next = {}
    for (const [key, val] of Object.entries(value)) {
      if (typeof val === 'undefined') continue
      next[key] = sanitizeForJson(val)
    }
    return next
  }
  return value
}

function cloneUploadResult(uploadResult) {
  if (!uploadResult) return null
  const serialized = JSON.stringify(uploadResult, (_, val) =>
    typeof val === 'bigint' ? val.toString() : val
  )
  return JSON.parse(serialized)
}

function ensureArray(value) {
  return Array.isArray(value) ? value : []
}

function getSegmentsKey(type) {
  return type === 'sent' ? 'sentSegments' : 'inboxSegments'
}

function createEmptyMailboxRootDocument(ownerEns) {
  return {
    owner: ownerEns ?? null,
    version: MAILBOX_ROOT_VERSION,
    inboxSegments: [],
    sentSegments: [],
    updatedAt: new Date().toISOString(),
  }
}

function generateSegmentId(type) {
  const suffix = Math.floor(Math.random() * 1e9)
  return `${type}-segment-${Date.now()}-${suffix}`
}

function createSegmentDocument({ owner, type, segmentId, entries = [] }) {
  return {
    owner: owner ?? null,
    type,
    version: 1,
    segmentId: segmentId ?? generateSegmentId(type),
    entries: ensureArray(entries),
    updatedAt: new Date().toISOString(),
  }
}

function getSegmentEntries(segmentDoc) {
  if (!segmentDoc) return []
  return Array.isArray(segmentDoc.entries) ? segmentDoc.entries : []
}

function buildSegmentPointerFromUpload(uploadResult, segmentDoc) {
  if (!uploadResult?.cid) {
    throw new Error('Segment upload result with cid is required')
  }
  if (!uploadResult?.pieceCid) {
    throw new Error('Segment upload result must include pieceCid')
  }
  return {
    id: segmentDoc.segmentId,
    cid: uploadResult.cid,
    pieceCid: uploadResult.pieceCid,
    providerInfo: sanitizeForJson(ensureProviderInfo(uploadResult)),
    entryCount: getSegmentEntries(segmentDoc).length,
    updatedAt: new Date().toISOString(),
  }
}

function normalizeSegmentPointer(pointer) {
  if (!pointer) return null
  if (!pointer.id) {
    return {
      ...pointer,
      id: generateSegmentId(pointer.type ?? 'segment'),
    }
  }
  return pointer
}

function getRootPointerFromMailboxRoot(mailboxRoot) {
  if (!mailboxRoot) return null
  const pointer = mailboxRoot.inbox ?? mailboxRoot.sent ?? null
  return normalizeUploadResult(pointer)
}

function isSegmentedRoot(mailboxRoot) {
  return mailboxRoot?.version >= MAILBOX_ROOT_VERSION
}

function chunkEntries(entries, chunkSize = MAX_SEGMENT_ENTRIES) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return []
  }
  const chunks = []
  for (let i = 0; i < entries.length; i += chunkSize) {
    chunks.push(entries.slice(i, i + chunkSize))
  }
  return chunks
}

async function loadMailboxRootDocument(pointer, options = {}) {
  if (!pointer?.cid) {
    return createEmptyMailboxRootDocument(options.owner)
  }
  const providerInfo = pointer.providerInfo ?? ensureProviderInfo(pointer)
  const normalizedProvider = providerInfo
    ? setStorageServiceUrl(providerInfo, normalizeServiceUrl(getStorageServiceUrl(providerInfo)))
    : null
  const rootDoc = await synapseFetchImpl(pointer.cid, {
    as: 'json',
    pieceCid: pointer.pieceCid,
    providerInfo: normalizedProvider ?? undefined,
    ...options,
  })
  if (!rootDoc || typeof rootDoc !== 'object') {
    throw new Error('Mailbox root payload is not a valid object')
  }
  rootDoc.inboxSegments = ensureArray(rootDoc.inboxSegments)
  rootDoc.sentSegments = ensureArray(rootDoc.sentSegments)
  rootDoc.version = MAILBOX_ROOT_VERSION
  return rootDoc
}

async function persistMailboxRootDocument(rootDoc, options = {}) {
  const payload = JSON.stringify(sanitizeForJson(rootDoc), null, 2)
  return synapseUploadImpl(payload, {
    filename: `${ROOT_FILENAME}.json`,
    metadata: {
      type: 'dmail-mailbox-root',
      owner: rootDoc.owner ?? options.owner ?? 'unknown',
    },
    ...(options.uploadOptions ?? {}),
  })
}

async function loadMailboxSegment(segmentPointer, options = {}) {
  if (!segmentPointer?.cid) return null
  const providerInfo =
    segmentPointer.providerInfo ??
    ensureProviderInfo({
      providerInfo: segmentPointer.providerInfo,
      serviceURL: segmentPointer.serviceURL,
      providerId: segmentPointer.providerId,
      providerAddress: segmentPointer.providerAddress,
    })
  const normalizedProvider = providerInfo
    ? setStorageServiceUrl(providerInfo, normalizeServiceUrl(getStorageServiceUrl(providerInfo)))
    : null
  const segment = await synapseFetchImpl(segmentPointer.cid, {
    as: 'json',
    pieceCid: segmentPointer.pieceCid,
    providerInfo: normalizedProvider ?? undefined,
    ...options,
  })
  if (!segment) {
    return null
  }
  segment.entries = ensureArray(segment.entries)
  if (!segment.segmentId) {
    segment.segmentId = segmentPointer.id ?? generateSegmentId(segment.type ?? 'inbox')
  }
  return segment
}

async function persistMailboxSegment(segmentDoc, options = {}) {
  const payload = JSON.stringify(sanitizeForJson(segmentDoc), null, 2)
  return synapseUploadImpl(payload, {
    filename: `${SEGMENT_FILENAME_PREFIX}-${segmentDoc.type}-${segmentDoc.segmentId}.json`,
    metadata: {
      type: `dmail-mailbox-segment-${segmentDoc.type}`,
      owner: segmentDoc.owner ?? options.owner ?? 'unknown',
      segmentId: segmentDoc.segmentId,
    },
    ...(options.uploadOptions ?? {}),
  })
}

async function convertLegacyMailboxToSegmented({
  ownerEns,
  mailboxRoot,
  loadOptions,
  persistOptions,
}) {
  const normalizedRoot = normalizeMailboxRoot(mailboxRoot, { owner: ownerEns })
  const rootDoc = createEmptyMailboxRootDocument(ownerEns)
  let hasLegacyData = false

  for (const folder of ['inbox', 'sent']) {
    const pointer = getMailboxIndexPointer(normalizedRoot, folder)
    if (!pointer?.cid) continue
    const mailbox = await loadMailboxFromCid(pointer, { optional: true, ...(loadOptions ?? {}) })
    const entries = getMailboxEntries(mailbox)
    if (!entries.length) continue
    hasLegacyData = true
    const chunks = chunkEntries(entries, MAX_SEGMENT_ENTRIES)
    for (const chunk of chunks) {
      const segmentDoc = createSegmentDocument({
        owner: ownerEns,
        type: folder,
        entries: chunk,
        segmentId: generateSegmentId(folder),
      })
      const uploadResult = await persistMailboxSegment(segmentDoc, {
        owner: ownerEns,
        type: folder,
        ...(persistOptions ?? {}),
      })
      rootDoc[getSegmentsKey(folder)].push(buildSegmentPointerFromUpload(uploadResult, segmentDoc))
    }
  }

  let nextRoot = {
    owner: ownerEns ?? null,
    version: MAILBOX_ROOT_VERSION,
    inbox: null,
    sent: null,
  }

  if (hasLegacyData) {
    const rootUpload = await persistMailboxRootDocument(rootDoc, { owner: ownerEns })
    const pointer = normalizeUploadResult(rootUpload)
    nextRoot = {
      owner: ownerEns ?? null,
      version: MAILBOX_ROOT_VERSION,
      inbox: pointer ? cloneUploadResult(pointer) : null,
      sent: pointer ? cloneUploadResult(pointer) : null,
    }
  }

  return { mailboxRoot: nextRoot, rootDoc }
}

async function ensureSegmentedRootDocument({
  ownerEns,
  mailboxRoot,
  loadOptions,
  persistOptions,
}) {
  if (!mailboxRoot || !isSegmentedRoot(mailboxRoot)) {
    return convertLegacyMailboxToSegmented({
      ownerEns,
      mailboxRoot,
      loadOptions,
      persistOptions,
    })
  }

  const pointer = getRootPointerFromMailboxRoot(mailboxRoot)
  if (pointer?.cid) {
    const rootDoc = await loadMailboxRootDocument(pointer, {
      ...(loadOptions ?? {}),
      owner: ownerEns,
    })
    return {
      mailboxRoot,
      rootDoc,
    }
  }

  return {
    mailboxRoot,
    rootDoc: createEmptyMailboxRootDocument(ownerEns),
  }
}

async function appendEntriesToSegments({
  ownerEns,
  rootDoc,
  type,
  items,
  persistOptions,
  loadOptions,
}) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error('appendEntriesToSegments: items array is required')
  }

  const segmentsKey = getSegmentsKey(type)
  if (!Array.isArray(rootDoc[segmentsKey])) {
    rootDoc[segmentsKey] = []
  }
  const segments = rootDoc[segmentsKey]
  const dirtySegments = new Map()
  const segmentCache = new Map()
  let activeSegmentState = null

  async function getWritableSegmentState() {
    if (activeSegmentState) {
      const currentCount = getSegmentEntries(activeSegmentState.doc).length
      if (currentCount < MAX_SEGMENT_ENTRIES) {
        return activeSegmentState
      }
      dirtySegments.set(activeSegmentState.doc.segmentId, activeSegmentState)
      activeSegmentState = null
    }

    const lastIndex = segments.length - 1
    const lastPointer = lastIndex >= 0 ? segments[lastIndex] : null
    if (lastPointer && !lastPointer.pending) {
      const cacheKey = lastPointer.id ?? `segment-${lastIndex}`
      if (!segmentCache.has(cacheKey)) {
        const doc = await loadMailboxSegment(lastPointer, {
          optional: true,
          ...(loadOptions ?? {}),
        })
        if (doc) {
          segmentCache.set(cacheKey, { doc, pointerIndex: lastIndex, pointer: lastPointer })
        }
      }
      const cachedState = segmentCache.get(cacheKey)
      if (cachedState && getSegmentEntries(cachedState.doc).length < MAX_SEGMENT_ENTRIES) {
        activeSegmentState = cachedState
        return cachedState
      }
    }

    const newDoc = createSegmentDocument({
      owner: ownerEns,
      type,
      segmentId: generateSegmentId(type),
    })
    const placeholderPointer = {
      id: newDoc.segmentId,
      cid: null,
      pieceCid: null,
      providerInfo: null,
      entryCount: 0,
      pending: true,
    }
    segments.push(placeholderPointer)
    const newState = {
      doc: newDoc,
      pointerIndex: segments.length - 1,
      pointer: placeholderPointer,
    }
    segmentCache.set(newDoc.segmentId, newState)
    activeSegmentState = newState
    return newState
  }

  const appendedEntries = []

  for (const item of items) {
    let segmentState = await getWritableSegmentState()
    if (!segmentState) {
      throw new Error('Failed to allocate mailbox segment for append operation')
    }
    const segmentEntries = [...getSegmentEntries(segmentState.doc)]
    const entryMetadata = {
      ...item.metadata,
      folder: item.metadata?.folder ?? type,
    }
    const nextSegmentMailbox = appendEmailEntry({ entries: segmentEntries }, item.uploads, entryMetadata)
    segmentState.doc.entries = nextSegmentMailbox.entries
    segmentState.doc.updatedAt = new Date().toISOString()
    const appendedEntry = nextSegmentMailbox.entries[nextSegmentMailbox.entries.length - 1] ?? null
    appendedEntries.push({
      entry: appendedEntry,
      itemId: item.id ?? null,
    })
    dirtySegments.set(segmentState.doc.segmentId, segmentState)
    const currentCount = getSegmentEntries(segmentState.doc).length
    if (currentCount >= MAX_SEGMENT_ENTRIES) {
      activeSegmentState = null
    }
  }

  const dirtyStates = Array.from(dirtySegments.values())
  const segmentUploadResults = await Promise.all(
    dirtyStates.map(async (state) => {
      const uploadResult = await persistMailboxSegment(state.doc, {
        owner: ownerEns,
        type,
        ...(persistOptions ?? {}),
      })
      return { state, uploadResult }
    })
  )

  const segmentUploads = []
  for (const { state, uploadResult } of segmentUploadResults) {
    const pointer = segments[state.pointerIndex]
    pointer.cid = uploadResult.cid
    pointer.pieceCid = uploadResult.pieceCid
    pointer.providerInfo = ensureProviderInfo(uploadResult)
    pointer.entryCount = getSegmentEntries(state.doc).length
    delete pointer.pending
    segmentUploads.push({
      pointer,
      uploadResult,
    })
  }

  rootDoc.updatedAt = new Date().toISOString()

  return {
    appendedEntries,
    segmentUploads,
  }
}

export async function appendMailboxEntriesBatch({
  ownerEns,
  mailboxRoot,
  items,
  type = 'inbox',
  loadOptions,
  persistOptions,
}) {
  if (!ownerEns) {
    throw new Error('appendMailboxEntriesBatch: ownerEns is required')
  }
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error('appendMailboxEntriesBatch: items array is required')
  }

  const { mailboxRoot: baselineRoot, rootDoc } = await ensureSegmentedRootDocument({
    ownerEns,
    mailboxRoot,
    loadOptions,
    persistOptions,
  })

  const appendResult = await appendEntriesToSegments({
    ownerEns,
    rootDoc,
    type,
    items,
    persistOptions,
    loadOptions,
  })

  const rootUpload = await persistMailboxRootDocument(rootDoc, {
    owner: ownerEns,
    ...(persistOptions ?? {}),
  })
  const normalizedPointer = normalizeUploadResult(rootUpload)
  const inboxPointer = normalizedPointer ? cloneUploadResult(normalizedPointer) : null
  const sentPointer = normalizedPointer ? cloneUploadResult(normalizedPointer) : null
  const nextRoot = {
    owner: baselineRoot?.owner ?? ownerEns ?? null,
    version: MAILBOX_ROOT_VERSION,
    inbox: inboxPointer,
    sent: sentPointer,
  }

  return {
    entries: appendResult.appendedEntries.map((item) => item.entry),
    mailboxRoot: nextRoot,
    rootUploadResult: rootUpload,
    segmentUploads: appendResult.segmentUploads.map((segment) => segment.uploadResult),
  }
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
  const normalizedRoot = normalizeMailboxRoot(mailboxRoot, { owner: ownerEns })
  const loadOptions = options.loadOptions ?? {}

  if (options.mailbox) {
    return {
      mailbox: options.mailbox,
      pointer: getMailboxIndexPointer(normalizedRoot, type),
      isNew: !getMailboxIndexPointer(normalizedRoot, type),
    }
  }

  if (isSegmentedRoot(normalizedRoot)) {
    const rootPointer = getRootPointerFromMailboxRoot(normalizedRoot)
    if (rootPointer?.cid) {
      const rootDoc = await loadMailboxRootDocument(rootPointer, {
        ...loadOptions,
        owner: ownerEns,
      })
      const segmentsKey = getSegmentsKey(type)
      const segmentPointers = ensureArray(rootDoc[segmentsKey])
      const entries = []
      for (const segmentPointer of segmentPointers) {
        const segmentDoc = await loadMailboxSegment(segmentPointer, {
          optional: true,
          ...loadOptions,
        })
        if (segmentDoc) {
          entries.push(...getSegmentEntries(segmentDoc))
        }
      }
      return {
        mailbox: {
          owner: ownerEns ?? rootDoc.owner ?? null,
          type,
          version: rootDoc.version ?? MAILBOX_ROOT_VERSION,
          entries,
        },
        pointer: rootPointer,
        isNew: segmentPointers.length === 0,
      }
    }
    return {
      mailbox: createEmptyMailbox(ownerEns, type),
      pointer: rootPointer,
      isNew: true,
    }
  }

  const legacyPointer = getMailboxIndexPointer(normalizedRoot, type)
  if (legacyPointer?.cid) {
    const mailbox = await loadMailboxFromCid(legacyPointer, { optional: true, ...loadOptions })
    if (mailbox) {
      return {
        mailbox,
        pointer: legacyPointer,
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
  const batchResult = await appendMailboxEntriesBatch({
    ownerEns,
    mailboxRoot,
    items: [{ uploads, metadata }],
    type,
    loadOptions,
    persistOptions,
  })
  return {
    mailbox: null,
    uploadResult: batchResult.segmentUploads[batchResult.segmentUploads.length - 1] ?? null,
    mailboxRoot: batchResult.mailboxRoot,
    entry: batchResult.entries[batchResult.entries.length - 1] ?? null,
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

async function appendMailboxEntriesBatchAndSyncResolver({
  ownerEns,
  mailboxRoot,
  items,
  type = 'inbox',
  loadOptions,
  persistOptions,
  resolveOptions,
  resolverOptions,
  skipResolverUpdate = false,
}) {
  const baselineRoot = await resolveMailboxRootForOwner(ownerEns, mailboxRoot, resolveOptions)
  const result = await appendMailboxEntriesBatch({
    ownerEns,
    mailboxRoot: baselineRoot,
    items,
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

export async function appendInboxEntriesBatch(options) {
  return appendMailboxEntriesBatchAndSyncResolver({ ...options, type: 'inbox' })
}

export async function appendSentEntriesBatch(options) {
  return appendMailboxEntriesBatchAndSyncResolver({ ...options, type: 'sent' })
}

