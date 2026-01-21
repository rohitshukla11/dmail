import pino from 'pino'
import { Synapse } from '@filoz/synapse-sdk'
import { EMAIL_PACK_METADATA_TYPE } from './email-pack.js'

const textEncoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null
const textDecoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null
const DEFAULT_RPC_URL = 'https://api.calibration.node.glif.io/rpc/v1'
const isBrowser = typeof window !== 'undefined'

let synapsePromise = null
let storageContextPromise = null
let loggerInstance = null

function getLogger() {
  if (!loggerInstance) {
    loggerInstance = pino({
      level: getEnv('FILECOIN_LOG_LEVEL') ?? 'info',
      browser: { asObject: true },
    })
  }
  return loggerInstance
}

function getEnv(name) {
  if (typeof process !== 'undefined' && process?.env?.[name]) {
    return process.env[name]
  }
  if (typeof import.meta !== 'undefined' && import.meta?.env) {
    const direct = import.meta.env[name]
    if (direct) return direct
    const prefixed = import.meta.env[`VITE_${name}`]
    if (prefixed) return prefixed
  }
  if (isBrowser && window?.__DMAIL_CONFIG__?.[name]) {
    return window.__DMAIL_CONFIG__[name]
  }
  return undefined
}

function parseBoolean(value) {
  if (value == null) return undefined
  const normalized = String(value).trim().toLowerCase()
  if (['true', '1', 'yes', 'y'].includes(normalized)) return true
  if (['false', '0', 'no', 'n'].includes(normalized)) return false
  return undefined
}

function parseInteger(value) {
  if (value == null || value === '') return undefined
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) ? parsed : undefined
}

async function toUint8Array(data) {
  if (data == null) throw new Error('synapseUpload: data is required')
  if (data instanceof Uint8Array) return data
  if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) return new Uint8Array(data)
  if (typeof Blob !== 'undefined' && data instanceof Blob) return new Uint8Array(await data.arrayBuffer())
  if (typeof data === 'string') {
    if (!textEncoder) throw new Error('synapseUpload: TextEncoder unavailable')
    return textEncoder.encode(data)
  }
  if (typeof data === 'object') {
    if (!textEncoder) throw new Error('synapseUpload: TextEncoder unavailable')
    return textEncoder.encode(JSON.stringify(data))
  }
  throw new Error(`synapseUpload: Unsupported data type ${typeof data}`)
}

function resolveSynapseOptions() {
  const rpcURL = getEnv('FILECOIN_RPC_URL') ?? DEFAULT_RPC_URL
  const warmStorageAddress = getEnv('FILECOIN_WARM_STORAGE_ADDRESS')
  const privateKey = getEnv('FILECOIN_PRIVATE_KEY') ?? getEnv('VITE_FILECOIN_PRIVATE_KEY')
  const sessionKey =
    getEnv('FILECOIN_SESSION_KEY') ?? getEnv('VITE_FILECOIN_SESSION_KEY') ?? getEnv('VITE_SESSION_KEY')

  if (privateKey) {
    return { privateKey, rpcURL, warmStorageAddress }
  }

  if (sessionKey) {
    return { privateKey: sessionKey, rpcURL, warmStorageAddress }
  }

  throw new Error('Synapse authentication missing. Provide FILECOIN_PRIVATE_KEY or FILECOIN_SESSION_KEY.')
}

function resolveStorageOptions() {
  const options = {}

  const providerId = parseInteger(getEnv('FILECOIN_PROVIDER_ID'))
  if (providerId) options.providerId = providerId

  const providerAddress = getEnv('FILECOIN_PROVIDER_ADDRESS')
  if (providerAddress) options.providerAddress = providerAddress

  const datasetId = parseInteger(getEnv('FILECOIN_DATASET_ID'))
  if (datasetId) options.dataSetId = datasetId

  const forceCreate = parseBoolean(getEnv('FILECOIN_DATASET_CREATE_NEW'))
  if (forceCreate) {
    options.forceCreateDataSet = true
  }

  // CDN configuration
  const withCdnEnv =
    parseBoolean(getEnv('FILECOIN_WITH_CDN')) ??
    parseBoolean(getEnv('VITE_FILECOIN_WITH_CDN'))
  
  const requireCdn =
    parseBoolean(getEnv('FILECOIN_REQUIRE_CDN')) ??
    parseBoolean(getEnv('VITE_FILECOIN_REQUIRE_CDN'))
  
  // Default to CDN-enabled when creating new datasets (unless explicitly disabled)
  // If no dataset ID provided, auto-create a CDN-enabled dataset
  if (!datasetId) {
    options.forceCreateDataSet = true
    // Default to CDN unless explicitly set to false
    if (withCdnEnv === false) {
      options.withCDN = false
    } else {
      options.withCDN = true
    }
  } else if (options.forceCreateDataSet && withCdnEnv == null && !requireCdn) {
    // Creating new dataset with existing ID - default to CDN
    options.withCDN = true
  } else if (withCdnEnv != null) {
    options.withCDN = withCdnEnv
  } else if (requireCdn) {
    options.withCDN = true
    if (!datasetId) {
      options.forceCreateDataSet = true
    }
  }

  const metadata = {}
  const owner = getEnv('FILECOIN_DATASET_OWNER')
  if (owner) metadata.owner = owner
  const namespace = getEnv('FILECOIN_DATASET_NAMESPACE')
  if (namespace) metadata.namespace = namespace

  if (Object.keys(metadata).length > 0) {
    options.metadata = metadata
  }

  return options
}

async function getSynapse() {
  if (!synapsePromise) {
    const options = resolveSynapseOptions()
    synapsePromise = Synapse.create({
      privateKey: options.privateKey,
      rpcURL: options.rpcURL,
      warmStorageAddress: options.warmStorageAddress,
      telemetry: {
        sentrySetTags: {
          appName: getEnv('FILECOIN_APP_NAME') ?? 'dmail-app',
        },
      },
    })
  }
  return synapsePromise
}

async function getStorageContext() {
  if (!storageContextPromise) {
    const synapse = await getSynapse()
    const storageOptions = resolveStorageOptions()
    
    // Log dataset configuration
    const requestedDatasetId = storageOptions.dataSetId
    const isCreatingNew = storageOptions.forceCreateDataSet
    const withCdn = storageOptions.withCDN ?? false
    
    if (requestedDatasetId) {
      console.log(`[Synapse] Using dataset ID: ${requestedDatasetId} (CDN: ${withCdn ? 'enabled' : 'disabled'})`)
    } else if (isCreatingNew) {
      console.log(`[Synapse] Creating new dataset (CDN: ${withCdn ? 'enabled' : 'disabled'})`)
    } else {
      console.log(`[Synapse] Auto-selecting dataset (CDN: ${withCdn ? 'enabled' : 'disabled'})`)
    }
    
    storageContextPromise = synapse.storage.createContext(storageOptions).then((context) => {
      const actualDatasetId = context.dataSetId
      const actualCdn = context.withCDN
      
      if (requestedDatasetId && actualDatasetId !== requestedDatasetId) {
        console.warn(
          `[Synapse] Dataset ID mismatch: requested ${requestedDatasetId}, but using ${actualDatasetId}. ` +
          `This may indicate the requested dataset doesn't exist or doesn't match CDN requirements.`
        )
      } else if (!requestedDatasetId && actualDatasetId) {
        console.log(`[Synapse] Created/selected dataset ID: ${actualDatasetId} (CDN: ${actualCdn ? 'enabled' : 'disabled'})`)
      }
      
      console.log(`[Synapse] Active dataset: ${actualDatasetId} (CDN: ${actualCdn ? 'enabled' : 'disabled'})`)
      
      const requireCdn =
        parseBoolean(getEnv('FILECOIN_REQUIRE_CDN')) ??
        parseBoolean(getEnv('VITE_FILECOIN_REQUIRE_CDN'))
      if (requireCdn && !context.withCDN) {
        throw new Error(
          'Synapse storage context is not CDN-enabled. Set FILECOIN_WITH_CDN=1 and provision a CDN-backed dataset.'
        )
      }
      return context
    })
  }
  return storageContextPromise
}

function normalizeMetadata(metadata = {}) {
  const normalized = {}
  for (const [key, value] of Object.entries(metadata)) {
    if (value == null) continue
    normalized[key] = String(value)
  }
  return normalized
}

export async function synapseUploadMany(payloads = [], globalOptions = {}) {
  if (!Array.isArray(payloads) || payloads.length === 0) {
    return []
  }

  const normalizedPayloads = payloads
    .map((payload, index) => {
      if (!payload || payload.data == null) {
        return null
      }
      return {
        data: payload.data,
        filename: payload.filename ?? globalOptions.filename ?? `dmail-${Date.now()}-${index}.json`,
        contentType: payload.contentType ?? globalOptions.contentType ?? 'application/json',
        metadata: payload.metadata ?? globalOptions.metadata ?? {},
        label: payload.label ?? null,
      }
    })
    .filter(Boolean)

  if (normalizedPayloads.length === 0) {
    return []
  }

  const context = await getStorageContext()
  const datasetId = context.dataSetId
  const withCdn = context.withCDN

  if (datasetId) {
    console.log(
      `[Synapse] Bulk uploading ${normalizedPayloads.length} piece(s) to dataset ID: ${datasetId} (CDN: ${
        withCdn ? 'enabled' : 'disabled'
      })`
    )
  } else {
    console.log(
      `[Synapse] Bulk uploading ${normalizedPayloads.length} piece(s) with auto-selected dataset (CDN: ${
        withCdn ? 'enabled' : 'disabled'
      })`
    )
  }

  const finalDatasetIdBefore = context.dataSetId

  const uploadResults = await Promise.all(
    normalizedPayloads.map(async (payload) => {
      const bytes = await toUint8Array(payload.data)
      const metadata = normalizeMetadata({
        filename: payload.filename,
        contentType: payload.contentType,
        ...payload.metadata,
      })
      const result = await context.upload(bytes, {
        metadata,
      })
      const normalizedProviderInfo = normalizeProviderInfo(context.provider)
      return {
        cid: result.pieceCid.toString(),
        pieceCid: result.pieceCid.toString(),
        providerInfo: normalizedProviderInfo,
        dataSetId: context.dataSetId ?? finalDatasetIdBefore ?? null,
        result,
        label: payload.label,
      }
    })
  )

  const finalDatasetId = context.dataSetId ?? finalDatasetIdBefore
  if (finalDatasetId && finalDatasetId !== finalDatasetIdBefore) {
    console.log(
      `[Synapse] Bulk upload complete. Dataset ID: ${finalDatasetId} (CDN: ${context.withCDN ? 'enabled' : 'disabled'})`
    )
  }

  return uploadResults
}

export async function synapseUpload(data, options = {}) {
  const [result] = await synapseUploadMany(
    [
      {
        data,
        filename: options.filename,
        contentType: options.contentType,
        metadata: options.metadata,
      },
    ],
    options
  )
  if (!result) {
    throw new Error('synapseUpload: Upload failed or no data provided')
  }
  return result
}

export async function synapseUploadEmailPack(emailPack, options = {}) {
  if (!emailPack || typeof emailPack !== 'object') {
    throw new Error('synapseUploadEmailPack: emailPack must be an object')
  }

  const filename =
    options?.filename ??
    `email-pack-${emailPack.messageId ?? Date.now().toString(36)}.json`

  const metadata = normalizeMetadata({
    type: EMAIL_PACK_METADATA_TYPE,
    owner: emailPack.from ?? options?.metadata?.owner ?? 'unknown',
    messageId: emailPack.messageId ?? '',
    ...(options?.metadata ?? {}),
  })

  return synapseUpload(emailPack, {
    ...options,
    filename,
    contentType: options.contentType ?? 'application/json',
    metadata,
  })
}

function normalizeServiceUrl(url) {
  if (!url) return null
  let normalized = url.trim()
  
  // Remove query params
  if (normalized.includes('?')) {
    normalized = normalized.split('?')[0]
  }
  
  // Remove trailing slashes and path segments
  normalized = normalized.replace(/\/$/, '')
  
  // Remove any existing /piece path
  if (normalized.endsWith('/piece')) {
    normalized = normalized.slice(0, -6)
  }
  
  // Ensure ends with /piece for CDN retrieval
  return normalized + '/piece'
}

function getStorageServiceUrl(providerInfo) {
  if (!providerInfo) return null
  // Access storage product serviceURL from provider info
  const products = providerInfo.products || {}
  const storageProduct = products[Object.keys(products)[0]] || {}
  return storageProduct?.data?.serviceURL ?? providerInfo?.serviceURL ?? providerInfo?.url ?? null
}

function setStorageServiceUrl(providerInfo, normalizedUrl) {
  if (!providerInfo) return providerInfo
  const products = providerInfo.products || {}
  const productKey = Object.keys(products)[0]
  if (!productKey) return providerInfo
  
  return {
    ...providerInfo,
    products: {
      ...products,
      [productKey]: {
        ...products[productKey],
        data: {
          ...products[productKey].data,
          serviceURL: normalizedUrl,
        },
      },
    },
  }
}

function normalizeProviderInfo(providerInfo) {
  if (!providerInfo) return providerInfo
  
  const serviceURL = getStorageServiceUrl(providerInfo)
  if (!serviceURL) return providerInfo
  
  return setStorageServiceUrl(providerInfo, normalizeServiceUrl(serviceURL))
}

function resolveProviderUrl(providerInfo) {
  if (!providerInfo) return null
  const rawUrl = getStorageServiceUrl(providerInfo)
  return normalizeServiceUrl(rawUrl)
}

function buildPieceUrl(providerUrl, pieceCid) {
  if (!providerUrl) return null
  let base = providerUrl.trim()
  if (!base) return null

  console.log(`[buildPieceUrl] Input: ${base}`)

  // Remove query parameters
  if (base.includes('?')) {
    base = base.split('?')[0]
  }

  // Handle template placeholders
  if (base.includes('{pieceCid}')) {
    const result = base.replace('{pieceCid}', pieceCid)
    console.log(`[buildPieceUrl] Template result: ${result}`)
    return result
  }
  if (base.includes('{piece}')) {
    const result = base.replace('{piece}', pieceCid)
    console.log(`[buildPieceUrl] Template result: ${result}`)
    return result
  }

  // Remove trailing slashes
  base = base.replace(/\/$/, '')

  // Ensure /piece path and append CID
  if (base.endsWith('/piece')) {
    const result = `${base}/${pieceCid}`
    console.log(`[buildPieceUrl] Result: ${result}`)
    return result
  }

  const result = `${base}/piece/${pieceCid}`
  console.log(`[buildPieceUrl] Result: ${result}`)
  return result
}

export async function synapseFetch(pieceCid, options = {}) {
  if (!pieceCid) throw new Error('synapseFetch: pieceCid is required')

  const providerInfo = options.providerInfo
  const providerUrl = resolveProviderUrl(providerInfo)
  if (!providerUrl) {
    throw new Error('synapseFetch: providerInfo with serviceURL is required')
  }

  const piece = options.pieceCid ?? pieceCid
  const resolvedUrl = buildPieceUrl(providerUrl, piece)
  if (!resolvedUrl) {
    throw new Error('synapseFetch: unable to construct retrieval URL from provider info')
  }

  console.log(`[Synapse] Fetching piece:`)
  console.log(`  Original URL: ${providerUrl}`)
  console.log(`  Resolved URL: ${resolvedUrl}`)
  console.log(`  Piece CID: ${piece}`)

  const response = await fetch(resolvedUrl)

  if (!response.ok) {
    const text = await safeReadText(response)
    throw new Error(`Synapse fetch failed (${response.status} ${response.statusText}): ${text}`)
  }

  return await parseResponse(response, options.as)
}

async function parseResponse(response, responseType = 'json') {
  if (responseType === 'arrayBuffer') {
    return await response.arrayBuffer()
  }
  if (responseType === 'text') {
    return await response.text()
  }
  try {
    return await response.json()
  } catch (error) {
    if (responseType === 'json') {
      throw new Error(
        `Synapse fetch expected JSON but parsing failed: ${error instanceof Error ? error.message : String(error)}`
      )
    }
    throw error
  }
}

async function safeReadText(response) {
  try {
    return await response.text()
  } catch (error) {
    return `<unable to read body: ${error instanceof Error ? error.message : String(error)}>`
  }
}

export function decodeBytesToString(bytes) {
  if (!bytes) return ''
  if (typeof bytes === 'string') return bytes
  if (bytes instanceof Uint8Array) {
    if (!textDecoder) throw new Error('TextDecoder not available to decode data')
    return textDecoder.decode(bytes)
  }
  if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
    if (!textDecoder) throw new Error('TextDecoder not available to decode data')
    return textDecoder.decode(new Uint8Array(bytes))
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(bytes)) {
    return bytes.toString('utf8')
  }
  throw new Error('Unsupported byte-like input for decodeBytesToString')
}

export { normalizeServiceUrl, getStorageServiceUrl, setStorageServiceUrl }
