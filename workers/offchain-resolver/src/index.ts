import { verifyMessage } from 'ethers'

type Env = {
  DB: D1Database
  CORS_ALLOW_ORIGIN?: string
}

type IdentityRow = {
  identifier: string
  wallet: string
  x25519PublicKey: string
  signingPublicKey: string
  updatedAt: number
}

type MailboxRow = {
  owner: string
  messageId: string
  cid: string
  pieceCid: string
  providerInfo: string
  folder: string
  timestamp: number
  subjectPreview: string | null
  recipients: string | null
  sender: string | null
}

const allowedFolders = new Set(['inbox', 'sent'])

const corsHeaders = (env: Env, extra: HeadersInit = {}) => {
  const headers = new Headers(extra)
  headers.set('Access-Control-Allow-Origin', env.CORS_ALLOW_ORIGIN ?? '*')
  headers.set('Access-Control-Allow-Headers', 'content-type, authorization')
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  headers.set('Access-Control-Max-Age', '86400')
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  return headers
}

const jsonResponse = (env: Env, data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: corsHeaders(env, init.headers),
  })

const noContent = (env: Env, init: ResponseInit = {}) =>
  new Response(null, {
    ...init,
    headers: corsHeaders(env, init.headers),
  })

async function readJson<T>(request: Request): Promise<T | null> {
  try {
    const text = await request.text()
    if (!text) return null
    return JSON.parse(text)
  } catch (error) {
    console.warn('[worker] failed to parse JSON body', error)
    return null
  }
}

const canonicalizePayload = (value: Record<string, unknown>) => {
  const sortedKeys = Object.keys(value).sort()
  const canonical: Record<string, unknown> = {}
  for (const key of sortedKeys) {
    canonical[key] = value[key]
  }
  return JSON.stringify(canonical)
}

const normalizeIdentifier = (input?: string | null) =>
  input ? input.trim().toLowerCase() : null

async function handleIdentityRegister(request: Request, env: Env) {
  const body = await readJson<any>(request)
  if (!body?.payload || !body?.signature || !body?.address) {
    return jsonResponse(env, { error: 'payload, signature, and address required' }, { status: 400 })
  }

  const payload = body.payload as Record<string, unknown>
  const canonical = canonicalizePayload(payload)

  let recovered: string
  try {
    recovered = verifyMessage(canonical, body.signature)
  } catch (error) {
    console.warn('[worker] failed to verify signature', error)
    return jsonResponse(env, { error: 'invalid signature' }, { status: 400 })
  }

  if (recovered.toLowerCase() !== String(body.address).toLowerCase()) {
    return jsonResponse(env, { error: 'signature mismatch' }, { status: 401 })
  }

  const identifier =
    normalizeIdentifier((payload.ens as string | undefined) ?? (payload.identifier as string | undefined)) ??
    normalizeIdentifier(body.address)
  if (!identifier) {
    return jsonResponse(env, { error: 'identifier missing' }, { status: 400 })
  }

  const x25519 = (payload.publicKey || payload.x25519PublicKey) as string | undefined
  const signing = (payload.signingPublicKey || payload.signingKey) as string | undefined
  if (!x25519 || !signing) {
    return jsonResponse(env, { error: 'x25519PublicKey and signingPublicKey required' }, { status: 400 })
  }

  const wallet = normalizeIdentifier(body.address)
  const updatedAt = Date.now()

  await env.DB.prepare(
    `INSERT INTO identities (identifier, wallet, x25519PublicKey, signingPublicKey, updatedAt)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(identifier)
     DO UPDATE SET wallet=?2, x25519PublicKey=?3, signingPublicKey=?4, updatedAt=?5`
  )
    .bind(identifier, wallet, x25519, signing, updatedAt)
    .run()

  return jsonResponse(env, {
    ok: true,
    identifier,
    wallet,
    updatedAt,
  })
}

async function handleIdentityGet(identifier: string, env: Env) {
  const normalized = normalizeIdentifier(identifier)
  if (!normalized) {
    return jsonResponse(env, { error: 'identifier required' }, { status: 400 })
  }
  const row = (await env.DB.prepare('SELECT * FROM identities WHERE identifier = ?1').bind(normalized).first()) as
    | IdentityRow
    | null
  if (!row) {
    return jsonResponse(env, { found: false, identifier: normalized })
  }
  return jsonResponse(env, {
    found: true,
    identifier: row.identifier,
    wallet: row.wallet,
    x25519PublicKey: row.x25519PublicKey,
    signingPublicKey: row.signingPublicKey,
    updatedAt: row.updatedAt,
  })
}

const normalizeFolders = (hints: unknown): string[] => {
  if (Array.isArray(hints)) {
    const folders = hints
      .map((value) => String(value).toLowerCase())
      .filter((value) => allowedFolders.has(value))
    if (folders.length > 0) {
      return folders
    }
  }
  return ['sent']
}

async function handleMailboxAppend(request: Request, env: Env) {
  const body = await readJson<any>(request)
  if (!body?.owner || !body?.cid || !body?.pieceCid || !body?.messageId) {
    return jsonResponse(env, { error: 'owner, messageId, cid, pieceCid required' }, { status: 400 })
  }
  const owner = normalizeIdentifier(body.owner)
  if (!owner) {
    return jsonResponse(env, { error: 'owner invalid' }, { status: 400 })
  }

  const folders = normalizeFolders(body.folderHints)
  const providerInfo = body.providerInfo ? JSON.stringify(body.providerInfo) : '{}'
  const recipients = Array.isArray(body.to) ? JSON.stringify(body.to) : '[]'
  const sender = body.from ?? null
  const timestamp = Number(body.timestamp ?? Date.now())
  const subjectPreview = body.subjectPreview ?? null

  const stmt = env.DB.prepare(
    `INSERT INTO mailbox_index
      (owner, messageId, cid, pieceCid, providerInfo, folder, timestamp, subjectPreview, recipients, sender)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
     ON CONFLICT(owner, messageId, folder)
     DO UPDATE SET cid=?3, pieceCid=?4, providerInfo=?5, timestamp=?7, subjectPreview=?8, recipients=?9, sender=?10`
  )

  for (const folder of folders) {
    await stmt.bind(owner, body.messageId, body.cid, body.pieceCid, providerInfo, folder, timestamp, subjectPreview, recipients, sender).run()
  }

  return jsonResponse(env, { ok: true, folders })
}

async function handleMailboxIndex(url: URL, env: Env) {
  const ownerParam = url.searchParams.get('owner')
  const folderParam = url.searchParams.get('folder')
  const owner = normalizeIdentifier(ownerParam)
  const folder = folderParam ? folderParam.toLowerCase() : null
  if (!owner || !folder || !allowedFolders.has(folder)) {
    return jsonResponse(env, { error: 'owner and valid folder required' }, { status: 400 })
  }

  const rows = (await env.DB.prepare(
    `SELECT * FROM mailbox_index WHERE owner = ?1 AND folder = ?2 ORDER BY timestamp DESC LIMIT 500`
  )
    .bind(owner, folder)
    .all()) as { results: MailboxRow[] }

  const entries = (rows?.results ?? []).map((row) => ({
    owner: row.owner,
    messageId: row.messageId,
    cid: row.cid,
    pieceCid: row.pieceCid,
    providerInfo: safeJsonParse(row.providerInfo, {}),
    folder: row.folder,
    timestamp: row.timestamp,
    subjectPreview: row.subjectPreview,
    to: safeJsonParse(row.recipients, []),
    from: row.sender,
  }))

  return jsonResponse(env, entries)
}

async function handleEnsWellKnown(name: string, env: Env) {
  const identifier = decodeURIComponent(name).toLowerCase()
  const identityResp = await env.DB.prepare('SELECT * FROM identities WHERE identifier = ?1').bind(identifier).first()
  const mailboxResp = (await env.DB.prepare(
    `SELECT * FROM mailbox_index WHERE owner = ?1 ORDER BY timestamp DESC LIMIT 100`
  )
    .bind(identifier)
    .all()) as { results: MailboxRow[] }

  return jsonResponse(env, {
    identifier,
    publicKey: (identityResp as IdentityRow | null)?.x25519PublicKey ?? null,
    signingPublicKey: (identityResp as IdentityRow | null)?.signingPublicKey ?? null,
    mailbox: (mailboxResp?.results ?? []).map((row) => ({
      messageId: row.messageId,
      folder: row.folder,
      timestamp: row.timestamp,
      cid: row.cid,
      pieceCid: row.pieceCid,
      providerInfo: safeJsonParse(row.providerInfo, {}),
      subjectPreview: row.subjectPreview,
      to: safeJsonParse(row.recipients, []),
      from: row.sender,
    })),
  })
}

async function handleLegacyProfileLookup(url: URL, env: Env) {
  const params = url.searchParams
  const identifier =
    normalizeIdentifier(params.get('id')) ??
    normalizeIdentifier(params.get('ens')) ??
    normalizeIdentifier(params.get('address'))
  if (!identifier) {
    return jsonResponse(env, {})
  }
  const identity = (await env.DB.prepare('SELECT * FROM identities WHERE identifier = ?1').bind(identifier).first()) as
    | IdentityRow
    | null
  if (!identity) {
    return jsonResponse(env, {})
  }
  return jsonResponse(env, {
    id: identity.identifier,
    ens: identity.identifier.endsWith('.eth') ? identity.identifier : null,
    address: identity.wallet,
    encryptionPublicKey: identity.x25519PublicKey,
    signingPublicKey: identity.signingPublicKey,
    identity: {
      publicKey: identity.x25519PublicKey,
      signingPublicKey: identity.signingPublicKey,
      updatedAt: identity.updatedAt,
    },
    mailboxRoot: null,
    metadata: {},
  })
}

const safeJsonParse = <T>(input: string | null | undefined, fallback: T): T => {
  if (!input) return fallback
  try {
    return JSON.parse(input)
  } catch {
    return fallback
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url)
      const { pathname } = url

      if (request.method === 'OPTIONS') {
        return noContent(env, { status: 204 })
      }

      if (pathname === '/v1/identity/register' && request.method === 'POST') {
        return handleIdentityRegister(request, env)
      }

      if (pathname.startsWith('/v1/identity/') && request.method === 'GET') {
        const identifier = pathname.replace('/v1/identity/', '')
        return handleIdentityGet(identifier, env)
      }

      if (pathname === '/v1/mailbox/append' && request.method === 'POST') {
        return handleMailboxAppend(request, env)
      }

      if (pathname === '/v1/mailbox/index' && request.method === 'GET') {
        return handleMailboxIndex(url, env)
      }

      if (pathname.startsWith('/.well-known/ens/') && request.method === 'GET') {
        const ensName = pathname.replace('/.well-known/ens/', '')
        return handleEnsWellKnown(ensName, env)
      }

      if (pathname.startsWith('/profiles/lookup') && request.method === 'GET') {
        return handleLegacyProfileLookup(url, env)
      }

      return jsonResponse(env, { error: 'not found' }, { status: 404 })
    } catch (error) {
      console.error('[worker] unhandled error', error)
      return jsonResponse(
        env,
        {
          error: 'internal_error',
          message: error instanceof Error ? error.message : String(error),
        },
        { status: 500 }
      )
    }
  },
}

