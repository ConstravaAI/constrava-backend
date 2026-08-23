import crypto from "node:crypto";

export const RELATIONAL_FOUNDATION_MIGRATION_ID = "0002_relational_foundation";
export const RELATIONAL_FOUNDATION_SNAPSHOT_KEY = "before-0002-relational-foundation";

const RELATIONAL_FOUNDATION_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS public.constrava_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    auth_provider TEXT NOT NULL DEFAULT 'password',
    password_salt TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS constrava_users_email_unique
    ON public.constrava_users (LOWER(email))`,
  `CREATE TABLE IF NOT EXISTS public.constrava_workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id TEXT REFERENCES public.constrava_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`,
  `CREATE INDEX IF NOT EXISTS constrava_workspaces_owner_idx
    ON public.constrava_workspaces (owner_user_id)`,
  `CREATE TABLE IF NOT EXISTS public.constrava_workspace_memberships (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES public.constrava_workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.constrava_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'active',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_opened_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (workspace_id, user_id)
  )`,
  `CREATE INDEX IF NOT EXISTS constrava_memberships_user_idx
    ON public.constrava_workspace_memberships (user_id, status)`,
  `CREATE TABLE IF NOT EXISTS public.constrava_workspace_invitations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES public.constrava_workspaces(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    invited_user_id TEXT REFERENCES public.constrava_users(id) ON DELETE SET NULL,
    invited_by_user_id TEXT REFERENCES public.constrava_users(id) ON DELETE SET NULL,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'pending',
    token_hash TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`,
  `CREATE INDEX IF NOT EXISTS constrava_invitations_email_idx
    ON public.constrava_workspace_invitations (LOWER(email), status)`,
  `CREATE TABLE IF NOT EXISTS public.constrava_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES public.constrava_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`,
  `CREATE INDEX IF NOT EXISTS constrava_sessions_user_expiry_idx
    ON public.constrava_sessions (user_id, expires_at)`,
  `CREATE TABLE IF NOT EXISTS public.constrava_external_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES public.constrava_users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    authorization_status TEXT NOT NULL DEFAULT 'ready',
    credentials_ciphertext TEXT NOT NULL DEFAULT '',
    granted_scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    selected_apps TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS constrava_external_provider_subject_unique
    ON public.constrava_external_accounts (user_id, provider, provider_subject)
    WHERE provider_subject <> ''`,
  `CREATE INDEX IF NOT EXISTS constrava_external_accounts_user_idx
    ON public.constrava_external_accounts (user_id, provider, status)`,
  `CREATE TABLE IF NOT EXISTS public.constrava_workspace_external_accounts (
    workspace_id TEXT NOT NULL REFERENCES public.constrava_workspaces(id) ON DELETE CASCADE,
    external_account_id TEXT NOT NULL REFERENCES public.constrava_external_accounts(id) ON DELETE CASCADE,
    linked_by_user_id TEXT REFERENCES public.constrava_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (workspace_id, external_account_id)
  )`,
  `CREATE INDEX IF NOT EXISTS constrava_workspace_external_account_idx
    ON public.constrava_workspace_external_accounts (external_account_id)`
];

const relationalFoundationChecksum = `sha256:${crypto
  .createHash("sha256")
  .update(RELATIONAL_FOUNDATION_STATEMENTS.join(";\n"))
  .digest("hex")}`;

export const RELATIONAL_FOUNDATION_MIGRATION = Object.freeze({
  id: RELATIONAL_FOUNDATION_MIGRATION_ID,
  name: "Relational identity and project foundation",
  checksum: relationalFoundationChecksum,
  snapshotKey: RELATIONAL_FOUNDATION_SNAPSHOT_KEY,
  snapshotLabel: "Before relational identity and project foundation",
  async up(client) {
    for (const statement of RELATIONAL_FOUNDATION_STATEMENTS) await client.query(statement);
  }
});

function safeErrorCode(error) {
  return String(error?.code || "relational_foundation_failed")
    .replace(/[^a-z0-9_-]/gi, "")
    .slice(0, 64) || "relational_foundation_failed";
}

export function createRelationalFoundation({ migrationSafety } = {}) {
  let readyPromise = null;
  let status = migrationSafety ? "checking" : "not_configured";
  let errorCode = "";
  let checkedAt = "";

  async function ensure() {
    if (!migrationSafety) return;
    if (!readyPromise) {
      status = "checking";
      readyPromise = migrationSafety.runMigration(RELATIONAL_FOUNDATION_MIGRATION)
        .then((result) => {
          status = "ready";
          errorCode = "";
          checkedAt = new Date().toISOString();
          return result;
        })
        .catch((error) => {
          status = "unavailable";
          errorCode = safeErrorCode(error);
          checkedAt = new Date().toISOString();
          readyPromise = null;
          throw error;
        });
    }
    return readyPromise;
  }

  function health() {
    return {
      relationalSchemaStatus: status,
      relationalSchemaVersion: RELATIONAL_FOUNDATION_MIGRATION_ID,
      relationalSchemaErrorCode: errorCode,
      relationalSchemaCheckedAt: checkedAt,
      relationalBackfillEnabled: false,
      relationalDualWriteEnabled: false
    };
  }

  return { ensure, health };
}
