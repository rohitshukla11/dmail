# dMail — Decentralized Email on Filecoin + ENS

dMail is a fully decentralized email client built on Filecoin storage and ENS identity:

- **React + Vite frontend** for inbox, compose, attachments, and calendar
- **`@dmail/core`** shared helpers for Synapse uploads, mailbox management, resolver integration, and deterministic identities
- **Cloudflare Worker backend** for off-chain identity and mailbox index storage
- **Two modes**: Traditional segmented mailbox or experimental "1 upload per email" MVP mode

## Repository Layout

```
frontend/                 Vite + React app (connect wallet, read inbox, compose, calendar)
packages/core/            Shared helpers consumed by the frontend (`@dmail/core`)
workers/offchain-resolver Cloudflare Worker + D1 DB for identity + mailbox metadata
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

# Off-chain API (Cloudflare Worker for identities + mailbox index)
VITE_DMAIL_API_URL=https://your-worker.workers.dev

# Optional: Enable "1 upload per email" MVP mode
# VITE_DMAIL_ONE_UPLOAD_PER_EMAIL=true

# Optional fallback recipient key when ENS/resolver lookup fails
VITE_RECIPIENT_PUBLIC_KEY=
```

`packages/core/src/synapse.js` documents every supported `FILECOIN_*` variable if you need provider IDs, datasets, or warm storage overrides.

## Off-chain Resolver Worker

The Cloudflare Worker stores identity records and mailbox indexes for cross-device syncing and faster resolution.

### Local Development

```bash
cd workers/offchain-resolver
npm install
npx wrangler d1 migrations apply offchain_resolver_db --local
npm run dev
```

Set `VITE_DMAIL_API_URL` to the worker URL (e.g. `http://127.0.0.1:8787`) while developing locally.

### Production Deployment

1. **Login to Cloudflare:**
   ```bash
   cd workers/offchain-resolver
   npx wrangler login
   ```

2. **Create D1 Database:**
   ```bash
   npx wrangler d1 create offchain_resolver_db
   ```
   Copy the `database_id` from the output.

3. **Update `wrangler.toml`:**
   Paste the `database_id` into the `[[d1_databases]]` section.

4. **Run Migrations:**
   ```bash
   npm run migrate
   ```

5. **Deploy:**
   ```bash
   npm run deploy
   ```

6. **Update Frontend Config:**
   Set `VITE_DMAIL_API_URL` in `frontend/.env.local` to your deployed worker URL (e.g. `https://dmail-resolver-xxx.workers.dev`).

## Run the Frontend

```bash
npm run dev
```

Vite serves the UI at `http://localhost:5173`.

## Using the UI

1. **Connect wallet** — Click 🔌, approve MetaMask, and your ENS name (or address) appears in the header.
2. **Identity bootstrap** — The app derives an X25519 + Ed25519 keypair via `deriveIdentityFromWallet`, registers the public key with the resolver (if needed), and caches the result in `localStorage`. You can clear it via the ♻️ Regenerate button.
3. **Inbox** — Press 🔄 or "Refresh" to fetch mailbox entries. In default mode, entries come from Filecoin storage via resolver pointers. In "1 upload per email" mode, entries come from the off-chain resolver backend.
4. **Compose** — Enter an ENS name, the app resolves the recipient public key via resolver → ENS fallback, encrypts the payload and uploads to Filecoin via Synapse.
5. **Calendar** — View events in the sidebar or switch to full-page calendar view. Create events, share via ICS export.
6. **Attachments** — Attachments stream through Synapse storage.

## Features

### Email Modes

**Default Mode (Segmented Mailbox):**
- Traditional segmented mailbox structure
- Separate uploads for envelopes, mailbox segments, and roots
- Full ENS integration with mailbox root pointers

**1 Upload Per Email Mode (MVP):**
- Enable with `VITE_DMAIL_ONE_UPLOAD_PER_EMAIL=true`
- Each email results in exactly one Synapse upload (EmailPack format)
- Mailbox index stored in off-chain resolver backend
- Faster UX, cross-device sync via backend
- Local fallback to `localStorage` if backend unavailable

### Calendar

- **Sidebar View**: Quick access to upcoming events
- **Full Page View**: Monthly grid calendar (click 📅 Calendar in sidebar)
- **Event Management**: Create, view, and share events
- **ICS Export**: Export calendar events as `.ics` files

### Identity & Resolver

- Identities are deterministic per wallet: the same wallet always recreates the exact X25519/Ed25519 material client-side.
- The derived bundle lives only in `localStorage:dmail_identity:<domain>:<account>` until you regenerate or clear storage.
- Resolver registration only occurs when the stored public key differs from the derived one, preventing redundant MetaMask prompts.
- Off-chain resolver provides fast, gas-free identity and mailbox lookups with ENS compatibility.

## Synapse Requirements

`@dmail/core` talks directly to Filecoin Onchain Cloud via the Synapse SDK:

- Provide `VITE_FILECOIN_PRIVATE_KEY` **or** `VITE_FILECOIN_SESSION_KEY`.
- Optional overrides: `VITE_FILECOIN_PROVIDER_ID`, `VITE_FILECOIN_DATASET_ID`, `VITE_FILECOIN_DATASET_CREATE_NEW`, `VITE_FILECOIN_WITH_CDN`, etc.
- Upload metadata is tagged (`type=dmail-email-pack-v1`, `from`, `to`, etc.) so you can inspect jobs in the Synapse UI.

### CDN-enabled datasets

1. In the Synapse dashboard (or via SDK) create a dataset with **With CDN = Yes**. Note the dataset ID/provider ID.
2. Set the following env vars:
   - `FILECOIN_WITH_CDN=1` (or `VITE_FILECOIN_WITH_CDN=1` for frontend-only uploads) to request CDN-backed storage.
   - `FILECOIN_REQUIRE_CDN=1` if you want the app to throw when the resolved dataset isn't CDN-enabled.
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

## Deploy to Vercel

The repository ships with a `vercel.json` so Vercel knows how to build the Vite frontend from the monorepo root.

1. **Install the Vercel CLI (optional):**
   ```bash
   npm install -g vercel
   vercel login
   ```
2. **Create a project** (via dashboard or CLI) that points to this repository.
3. **Configure build settings** (already provided by `vercel.json`):
   - Install Command: `npm install`
   - Build Command: `npm run build --workspace frontend`
   - Output Directory: `frontend/dist`
4. **Set environment variables** in the project settings (or `vercel env`):
   - All `VITE_*` variables you use locally, e.g.
     - `VITE_ETH_RPC_URL`
     - `VITE_SEPOLIA_RPC_URL`
     - `VITE_FILECOIN_PRIVATE_KEY` or `VITE_FILECOIN_SESSION_KEY`
     - `VITE_FILECOIN_RPC_URL`
     - `VITE_FILECOIN_GATEWAY`
     - `VITE_DMAIL_API_URL`
     - `VITE_DMAIL_ONE_UPLOAD_PER_EMAIL` (optional)
     - `VITE_RECIPIENT_PUBLIC_KEY` (optional fallback)
5. **Deploy:**
   ```bash
   vercel --prod
   ```

The SPA rewrite in `vercel.json` ensures every route serves `index.html`. The frontend still expects the off-chain resolver backend to be reachable at `VITE_DMAIL_API_URL`, so make sure the Cloudflare Worker is deployed before directing users to the Vercel-hosted UI.

## Troubleshooting

- **Repeated MetaMask prompts** – Identity derivation is cached per account + domain. If you still see prompts, clear `localStorage` or click ♻️ Regenerate.
- **Resolver lookup fails** – Ensure `VITE_DMAIL_API_URL` points to a running off-chain resolver service; the app falls back to ENS text records when available.
- **Synapse auth errors** – Double-check the Filecoin private key or session key plus RPC URL. Missing credentials throw `Synapse authentication missing`.
- **CORS errors** – Make sure your Cloudflare Worker is deployed and `VITE_DMAIL_API_URL` points to the correct worker URL.
- **Database errors** – Ensure D1 migrations have been applied to your remote database (`npm run migrate` in `workers/offchain-resolver`).

---

dMail is a fully client-side decentralized email experience. All encryption, identity derivation, and mailbox management happens in the browser. Happy hacking!
