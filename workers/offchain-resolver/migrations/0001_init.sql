CREATE TABLE IF NOT EXISTS identities (
  identifier TEXT PRIMARY KEY,
  wallet TEXT NOT NULL,
  x25519PublicKey TEXT NOT NULL,
  signingPublicKey TEXT NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mailbox_index (
  owner TEXT NOT NULL,
  messageId TEXT NOT NULL,
  cid TEXT NOT NULL,
  pieceCid TEXT NOT NULL,
  providerInfo TEXT NOT NULL,
  folder TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  subjectPreview TEXT,
  recipients TEXT,
  sender TEXT,
  PRIMARY KEY (owner, messageId, folder)
);

