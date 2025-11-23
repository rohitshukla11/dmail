# dMail Off-Chain Resolver

Cloudflare Worker + D1 database that stores dMail identity metadata and mailbox indexes.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/identity/register` | Register/update identity keys (verifies wallet signature) |
| `GET` | `/v1/identity/:identifier` | Fetch identity (identifier = ENS name or address) |
| `POST` | `/v1/mailbox/append` | Append mailbox pointer metadata (EmailPack pointer) |
| `GET` | `/v1/mailbox/index?owner=<ensOrAddr>&folder=<inbox|sent>` | Fetch mailbox index entries |
| `GET` | `/.well-known/ens/:name` | ENS off-chain JSON resolver output |

## Local Development

```bash
cd workers/offchain-resolver
npm install
wrangler d1 migrations apply offchain_resolver_db --local
npm run dev
```

Set `RESOLVER_API_URL` / `VITE_RESOLVER_API_URL` in the frontend to the dev server URL (e.g. `http://127.0.0.1:8787`).

## Deployment

1. Create a Cloudflare D1 database and copy its ID into `wrangler.toml`.
2. Run migrations: `npm run migrate`
3. Deploy: `npm run deploy`

