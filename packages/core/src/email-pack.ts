const EMAIL_PACK_VERSION = 1
const EMAIL_PACK_METADATA_TYPE = 'dmail-email-pack-v1'

function normalizeStringArray(value) {
  if (!value) return []
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter(Boolean)
  }
  return [String(value).trim()].filter(Boolean)
}

function normalizeFolderHints(hints) {
  const allowed = new Set(['inbox', 'sent'])
  const normalized = normalizeStringArray(hints).filter((hint) => allowed.has(hint))
  if (normalized.length === 0) {
    return undefined
  }
  return Array.from(new Set(normalized))
}

function normalizeAttachment(entry) {
  if (!entry || typeof entry !== 'object') return null
  const normalized = {
    cid: entry.cid ?? entry.pieceCid ?? undefined,
    name: entry.name ?? entry.filename ?? null,
    size:
      typeof entry.size === 'number'
        ? entry.size
        : typeof entry.size === 'string'
          ? Number.parseInt(entry.size, 10) || undefined
          : undefined,
    contentType: entry.contentType ?? entry.mimeType ?? undefined,
  }
  if (!normalized.name && !normalized.cid && !normalized.contentType) {
    return null
  }
  return normalized
}

export function normalizeEmailPack(pack) {
  if (!pack || typeof pack !== 'object') {
    throw new Error('normalizeEmailPack: pack must be an object')
  }
  const indexEntry = pack.indexEntry ?? {}
  const normalizedPack = {
    ...pack,
    version: pack.version ?? EMAIL_PACK_VERSION,
    to: normalizeStringArray(pack.to),
    cc: normalizeStringArray(pack.cc),
    attachments: Array.isArray(pack.attachments)
      ? pack.attachments.map((item) => normalizeAttachment(item)).filter(Boolean)
      : undefined,
    indexEntry: {
      ...indexEntry,
      subjectPreview: indexEntry.subjectPreview ?? '',
      from: indexEntry.from ?? pack.from ?? '',
      to: normalizeStringArray(indexEntry.to ?? pack.to),
      timestamp: indexEntry.timestamp ?? pack.timestamp ?? Date.now(),
      messageId: indexEntry.messageId ?? pack.messageId ?? '',
      folderHints: normalizeFolderHints(indexEntry.folderHints),
    },
  }
  if (!normalizedPack.indexEntry.folderHints) {
    normalizedPack.indexEntry.folderHints = ['sent']
  }
  if (!normalizedPack.indexEntry.to.length && normalizedPack.to.length) {
    normalizedPack.indexEntry.to = [...normalizedPack.to]
  }
  if (!normalizedPack.indexEntry.messageId) {
    normalizedPack.indexEntry.messageId = normalizedPack.messageId ?? ''
  }
  if (!normalizedPack.indexEntry.timestamp) {
    normalizedPack.indexEntry.timestamp = normalizedPack.timestamp ?? Date.now()
  }
  return normalizedPack
}

export function normalizeEmailPackIndexEntry(entry) {
  if (!entry || typeof entry !== 'object') {
    return null
  }
  if (!entry.cid || !entry.pieceCid) {
    return null
  }
  const normalizedIndexEntry = {
    ...(entry.indexEntry ?? {}),
    folderHints: normalizeFolderHints(entry.indexEntry?.folderHints) ?? ['sent'],
    to: normalizeStringArray(entry.indexEntry?.to),
    subjectPreview: entry.indexEntry?.subjectPreview ?? '(No subject)',
    from: entry.indexEntry?.from ?? 'unknown',
    timestamp:
      typeof entry.indexEntry?.timestamp === 'number'
        ? entry.indexEntry.timestamp
        : Number.parseInt(entry.indexEntry?.timestamp ?? '', 10) || Date.now(),
    messageId: entry.indexEntry?.messageId ?? entry.messageId ?? entry.cid,
  }
  return {
    messageId: entry.messageId ?? normalizedIndexEntry.messageId,
    cid: entry.cid,
    pieceCid: entry.pieceCid,
    providerInfo: entry.providerInfo ?? null,
    indexEntry: normalizedIndexEntry,
  }
}

export { EMAIL_PACK_METADATA_TYPE, EMAIL_PACK_VERSION }

