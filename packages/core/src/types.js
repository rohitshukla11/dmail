export const EMAIL_ATTACHMENT_SCHEMA = {
  filename: 'string',
  mimeType: 'string',
  data: 'base64-string',
}

export const ENCRYPTED_EMAIL_SCHEMA = {
  fromEns: 'string',
  toEns: 'string',
  timestamp: 'number',
  encryptedSubject: 'string',
  encryptedMessage: 'string',
  encryptedAttachments: [EMAIL_ATTACHMENT_SCHEMA],
}

export const MAILBOX_SCHEMA = {
  owner: 'string',
  version: 'number',
  updatedAt: 'string',
  emails: [
    {
      cid: 'string',
      timestamp: 'number',
      from: 'string',
      to: 'string',
      subjectPreview: 'string|null',
    },
  ],
}
/**
 * @typedef {Object} EmailAttachment
 * @property {string} filename
 * @property {string} mimeType
 * @property {string} data Base64 encoded payload
 */

/**
 * @typedef {Object} EmailPayload
 * @property {string} from
 * @property {string} to
 * @property {number} timestamp Unix epoch in ms
 * @property {string} subject
 * @property {string} message
 * @property {EmailAttachment[]} attachments
 */

/**
 * @typedef {Object} EncryptedEmail
 * @property {string} version
 * @property {string} cipherText
 * @property {string} mac
 * @property {string} iv
 * @property {string} ephemPublicKey
 */

/**
 * @typedef {Object} MailboxEntry
 * @property {string} cid
 * @property {number} timestamp
 * @property {string} from
 * @property {string} [subject]
 */

/**
 * @typedef {Object} MailboxFile
 * @property {string} owner Ens name or address
 * @property {number} updatedAt Unix epoch in ms
 * @property {MailboxEntry[]} emails
 */

export {}

