# Constrava

## Durable production storage

Constrava stores accounts, sessions, encrypted email provider tokens, website connections, CRM records, analytics, sync cursors, and identity data in one workspace store. Local development defaults to `data/store.json`.

The preferred production configuration is Neon Postgres:

1. Copy the pooled Neon connection string.
2. Add it to Render as the secret environment variable `DATABASE_URL`.
3. Keep `EMAIL_TOKEN_ENCRYPTION_KEY` unchanged across deploys.
4. Redeploy. Constrava creates `public.constrava_app_store_v2` automatically without altering existing Neon tables.
5. If `data/store.json` exists on the first database-backed start, Constrava imports it once.

The existing file store remains available as a fallback. On a paid Render service, attach a persistent disk at `/var/data` and set `DATA_DIR=/var/data`. `DATA_FILE` can be used instead when an explicit full path is preferred.

`/api/health` reports `dataStore: "postgres"`, `postgresStoreConfigured: true`, and `databaseStatus: "ready"` when Neon is active. If Neon is unavailable, the public site and sign-in page stay online, health reports a safe error code, and account APIs return `503` instead of silently writing to Render's temporary filesystem.

### Relational migration safety

Deployment 1 adds migration safeguards without changing the current data layout. `public.constrava_app_store_v2` remains the only application data source, and `DATA_STORAGE_MODE` defaults to `legacy` even when omitted. The deployment creates only two safety tables:

- `public.constrava_schema_migrations` records migration identifiers, checksums, status, and safe error codes.
- `public.constrava_store_snapshots` can hold idempotent copies of the primary legacy JSONB row before a future migration.

Migration operations use a Postgres advisory lock and transactions so concurrent service instances cannot apply the same migration simultaneously. `/api/health` exposes the active storage mode and migration-safety status without exposing database credentials or stored account data. The values `shadow` and `relational` are reserved for later deployments and are not activated by Deployment 1.

### Relational identity and project foundation

Deployment 2 creates normalized tables for users, hashed sessions, CRM projects, project memberships, invitations, user-owned external accounts, and project-to-account links. Before creating the schema it saves an idempotent copy of the current primary JSONB row in `public.constrava_store_snapshots`.

This deployment is schema-only. It does not backfill rows, dual-write application changes, or serve reads from the new tables. `public.constrava_app_store_v2` remains the only source of truth and `/api/health` reports both `relationalBackfillEnabled: false` and `relationalDualWriteEnabled: false`.

### Identity and project baseline backfill

Deployment 3 takes a locked snapshot of the primary JSONB store and copies its users, CRM projects, project memberships, invitations, sessions, user-owned Google/Microsoft accounts, and project-to-account links into the normalized tables in one transaction. It is an idempotent, one-time baseline: a completed migration is recorded with count-only details and is not rerun after restarts.

Raw session cookies are never copied. Their relational token values are SHA-256 hashes and their row identifiers are independently derived from those hashes. OAuth credential blobs remain in their existing encrypted form and are written only to `credentials_ciphertext`; transient OAuth state is excluded. External accounts require an explicit valid user owner, and project links are created only when that owner can access the project.

This deployment still does not read from or continuously write to the normalized tables. `public.constrava_app_store_v2` remains the sole live source of truth, `DATA_STORAGE_MODE` stays `legacy`, and `/api/health` reports the backfill result and counts while keeping `relationalDualWriteEnabled: false`.

## Developer handoff email

Website Tracker developer handoffs are sent through Resend. In Render, set `RESEND_API_KEY` and `DEVELOPER_HANDOFF_FROM`; the sender must use a domain verified in Resend. `DEVELOPER_HANDOFF_REPLY_TO` is optional. When it is omitted, replies go to the signed-in user's email address.

The handoff email includes the user's message, requester and CRM project context, website and platform details, selected tracking items, deadline, installation steps, and that project's exact tracking snippet. Constrava stores a delivery audit record, but not a second copy of the full email body.

Constrava is an AI-assisted business command center for turning messy activity into structured records, priorities, analytics, and next actions.

## Run locally

```powershell
cd C:\Users\jerne\Documents\Codex\2026-07-09\ca\constrava-backend
$env:OPENAI_API_KEY="your_key_here"
node src/server.js
```

Then open `http://localhost:3000`.

The app runs without an OpenAI key using a deterministic local planner. When `OPENAI_API_KEY` is set, `/api/records/plan`, `/api/search/natural`, and `/api/reports/generate` use OpenAI structured JSON responses and fall back safely if the provider is unavailable.

## Important routes

- `POST /api/records/plan` turns raw notes, form submissions, uploads, or emails into a validated action plan.
- `POST /api/records/commit` writes an accepted plan as connected records.
- `GET /api/records` lists searchable and sortable records.
- `PATCH /api/records/:id` updates a record manually.
- `POST /api/sources/form` receives website form submissions and plans records from them.
- `POST /api/uploads/import` imports CSV/text and returns AI plans.
- `POST /api/analytics/events` stores tracking events.
- `GET /api/dashboard/summary` returns dashboard metrics and recommended actions.
- `POST /api/search/natural` converts a plain-English search into safe filters.
- `POST /api/reports/generate` creates factual reports with AI interpretation.

## Current scope

This is a complete first build in one Node process with Neon/Postgres persistence in production and file-based persistence in `data/store.json` for local development.
