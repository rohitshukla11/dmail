// Type definitions for @dmail/core package
import type { Signer } from 'ethers'

export interface IdentityMaterial {
  x25519PrivateBase64: string
  x25519PublicBase64: string
  senderStaticSymKeyBase64: string
  signingKeyBase64: string
  signingPublicKeyBase64: string
}

export interface EmailAttachment {
  filename: string
  mimeType: string
  data: string // Base64 encoded
}

export interface EmailPayload {
  from: string
  to: string
  timestamp?: number
  subject: string
  message: string
  attachments?: EmailAttachment[]
}

export interface EncryptedEmail {
  version: string
  scheme: string
  messageId: string
  fromEns: string
  toEns: string
  timestamp: number
  recipientEnvelope?: EncryptedEnvelope
  senderEnvelope?: EncryptedEnvelope | null
  preview?: {
    subject: string
    snippet: string
    attachments: number
  }
}

export interface EncryptedEnvelope {
  version: string
  scheme: string
  messageId: string
  fromEns?: string
  toEns?: string
  timestamp: number
  ephemeralPublicKey?: string
  nonce: string
  ciphertext: string
}

export interface DecryptedEmail {
  from: string
  to: string
  timestamp: number
  subject: string
  message: string
  attachments: EmailAttachment[]
}

export interface MailboxEntry {
  cid?: string
  timestamp: number
  from: string
  to?: string
  subjectPreview?: string | null
  folder?: 'inbox' | 'sent'
  messageId?: string
  attachments?: Array<{
    filename?: string
    name?: string
    mimeType?: string
    contentType?: string
    cid?: string
    pieceCid?: string
    providerInfo?: unknown
    encryptedMetadata?: string
    _needsFetch?: boolean
  }>
}

export interface MailboxIndex {
  owner: string
  version: number
  updatedAt: number
  entries: MailboxEntry[]
}

export interface SynapseUploadResult {
  cid: string
  pieceCid?: string
  providerInfo?: unknown
}

export interface CalendarEvent {
  id: string
  title: string
  description?: string
  location?: string
  startTime: string
  endTime: string
  attendees?: string[]
  timezone?: string
}

export interface Calendar {
  version: number
  events: CalendarEvent[]
  updatedAt: number
}

export interface EncryptEmailOptions {
  senderIdentity?: IdentityMaterial | { privateKey: string; publicKey: string } | string | null
  identity?: IdentityMaterial | { privateKey: string; publicKey: string } | string | null
  messageId?: string
  forceLegacy?: boolean
  uploadAttachmentsToSynapse?: boolean
}

export interface DecryptEmailOptions {
  identityPrivateKey?: string
  recipientPrivateKey?: string
  senderSecret?: string
  fetchAttachmentsFromSynapse?: boolean
}

export interface AttachmentRef {
  cid: string
  pieceCid?: string
  providerInfo?: unknown
  encryptedMetadata?: string
  filename?: string
  mimeType?: string
}

export interface DeriveIdentityOptions {
  domain?: string
  network?: string
  challenge?: string
  seedSalt?: Uint8Array
}

export interface ResolverOptions {
  apiUrl?: string
  signal?: AbortSignal
}

export interface SynapseOptions {
  privateKey?: string
  sessionKey?: string
  rpcUrl?: string
  gateway?: string
  providerId?: string
  datasetId?: string
  withCDN?: boolean
  requireCDN?: boolean
}
