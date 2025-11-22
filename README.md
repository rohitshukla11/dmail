# dMail v2 — Filecoin + ENS mail client

dMail v2 is a purely client-side mail experience:

- React + Vite frontend for inbox, compose, attachments and calendar events.
- `@dmail/core` shared helpers for Synapse uploads, mailbox management, resolver integration and deterministic identities.
- No more CLI demos, Hardhat scripts, or legacy private-key flows — just the pieces required to run the v2 UI.

## Repository Layout

```
frontend/        Vite + React app (connect wallet, read inbox, compose, calendar)
packages/core/   Shared helpers consumed by the frontend (`@dmail/core`)
```

## Prerequisites

- Node.js 18+ / npm 10+
- MetaMask (or another EIP-1193 wallet)
- Filecoin Onchain Cloud credentials (private key or session key for Synapse uploads)
- ENS test name(s) on Sepolia or another supported network

## Install

```bash
npm install
```

This installs `frontend` and `packages/core` via npm workspaces.

## Configure Environment

Create `frontend/.env.local` (or `.env`) with the values needed by Synapse + resolver helpers:

```env
# Ethereum / ENS
VITE_ETH_RPC_URL=https://sepolia.infura.io/v3/<id>
VITE_SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com   # optional fallback

# Filecoin Onchain Cloud (choose private key OR session key)
VITE_FILECOIN_PRIVATE_KEY=0x...
# VITE_FILECOIN_SESSION_KEY=0x...
VITE_FILECOIN_RPC_URL=https://api.calibration.node.glif.io/rpc/v1
VITE_FILECOIN_GATEWAY=https://w3s.link/ipfs

# Resolver API (stores identity pubkeys + mailbox roots)
VITE_RESOLVER_API_URL=https://resolver.example/api

# Optional fallback recipient key when ENS/resolver lookup fails
VITE_RECIPIENT_PUBLIC_KEY=
```

`packages/core/src/synapse.js` documents every supported `FILECOIN_*` variable if you need provider IDs, datasets, or warm storage overrides.

## Run the Frontend

```bash
npm run dev
```

Vite serves the UI at `http://localhost:5173`.

## Using the UI

1. **Connect wallet** — click 🔌, approve MetaMask, and the ENS name (or address) appears in the header.
2. **Identity bootstrap** — the app derives an X25519 + Ed25519 keypair via `deriveIdentityFromWallet`, registers the public key with your resolver (if needed), and caches the result in `localStorage`. You can clear it via the ♻️ Regenerate button.
3. **Inbox** — press 🔄 or “Refresh” to fetch mailbox entries from Filecoin storage (using Synapse fetch + resolver pointers). Signature badges show whether the sender envelope verified.
4. **Compose** — enter an ENS name, the app resolves the recipient public key via resolver → ENS fallback, encrypts the payload and uploads envelopes + mailbox roots via Synapse.
5. **Attachments & calendar** — attachments stream through Synapse; calendar events render in the sidebar with ICS export.

## Identity & Resolver Notes

- Identities are deterministic per wallet: the same wallet always recreates the exact X25519/Ed25519 material client-side.
- The derived bundle lives only in `localStorage:dmail_identity_v2:<domain>:<account>` until you regenerate or clear storage.
- Resolver registration only occurs when the stored public key differs from the derived one, preventing redundant MetaMask prompts.

## Synapse Requirements

`@dmail/core` talks directly to Filecoin Onchain Cloud via the Synapse SDK:

- Provide `VITE_FILECOIN_PRIVATE_KEY` **or** `VITE_FILECOIN_SESSION_KEY`.
- Optional overrides: `VITE_FILECOIN_PROVIDER_ID`, `VITE_FILECOIN_DATASET_ID`, `VITE_FILECOIN_DATASET_CREATE_NEW`, `VITE_FILECOIN_WITH_CDN`, etc.
- Upload metadata is tagged (`type=dmail-email`, `from`, `to`, etc.) so you can inspect jobs in the Synapse UI.

### CDN-enabled datasets

1. In the Synapse dashboard (or via SDK) create a dataset with **With CDN = Yes**. Note the dataset ID/provider ID.
2. Set the following env vars:
   - `FILECOIN_WITH_CDN=1` (or `VITE_FILECOIN_WITH_CDN=1` for frontend-only uploads) to request CDN-backed storage.
   - `FILECOIN_REQUIRE_CDN=1` if you want the app to throw when the resolved dataset isn’t CDN-enabled.
   - `FILECOIN_DATASET_ID=<new id>` (optional) to pin uploads to that dataset. If omitted and `FILECOIN_REQUIRE_CDN=1`, the app will auto-create a CDN dataset.
3. Restart `npm run dev`. The storage context now verifies `context.withCDN`; uploads fail fast if the provider doesn't support CDN.

## Package Scripts

```bash
npm run dev      # start Vite in the frontend workspace
npm run build    # production build
npm run preview  # preview production build
npm run lint     # eslint across the repo
npm run format   # prettier
```

## Troubleshooting

- **Repeated MetaMask prompts** – identity derivation is cached per account + domain. If you still see prompts, clear `localStorage` or click ♻️ Regenerate.
- **Resolver lookup fails** – ensure `VITE_RESOLVER_API_URL` points to a running resolver service; the app falls back to ENS text records when available.
- **Synapse auth errors** – double-check the Filecoin private key or session key plus RPC URL. Missing credentials throw `Synapse authentication missing`.

---

dMail v2 focuses exclusively on the modern client experience. Legacy CLI scripts, Hardhat configs, and documentation bundles were removed to keep the repo lean. Only the frontend and the shared `@dmail/core` helpers remain. Happy hacking!

