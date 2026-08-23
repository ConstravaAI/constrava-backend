import crypto from "node:crypto";
import { buildIdentityBackfill, syncIdentityBackfill } from "./postgres-identity-backfill.js";

export const RELATIONAL_SHADOW_SYNC_MIGRATION_ID = "0004_relational_shadow_sync";
export const RELATIONAL_SHADOW_SYNC_SNAPSHOT_KEY = "before-0004-relational-shadow-sync";

const LEGACY_STORE_TABLE = "public.constrava_app_store_v2";
const SHADOW_STATE_TABLE = "public.constrava_relational_shadow_state";
const SHADOW_STATE_ID = "identity_project";
const SHADOW_VERIFY_INTERVAL_MS = 5 * 60 * 1000;
const SHADOW_STATE_STATEMENT = `CREATE TABLE IF NOT EXISTS ${SHADOW_STATE_TABLE} (
  id TEXT PRIMARY KEY,
  source_store_version BIGINT NOT NULL DEFAULT 0,
  source_checksum TEXT NOT NULL DEFAULT '',
  relational_checksum TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  last_error_code TEXT NOT NULL DEFAULT '',
  counts JSONB NOT NULL DEFAULT '{}'::jsonb,
  synced_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`;

const shadowMigrationChecksum = `sha256:${crypto.createHash("sha256").update(SHADOW_STATE_STATEMENT).digest("hex")}`;

function text(value) {
  return String(value ?? "");
}

function iso(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function jsonObject(value) {
  if (!value) return {};
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { return {}; }
  }
  return typeof value === "object" ? value : {};
}

function stableValue(value) {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, stableValue(value[key])]));
  }
  return value === undefined ? null : value;
}

function fingerprint(value) {
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex")}`;
}

function sortRows(rows, key = (row) => row.id) {
  return [...rows].sort((left, right) => text(key(left)).localeCompare(text(key(right))));
}

function canonicalBackfill(backfill) {
  return {
    users: sortRows(backfill.users).map((row) => ({
      id: row.id, email: row.email, name: row.name, role: row.role, authProvider: row.authProvider,
      passwordSalt: row.passwordSalt, passwordHash: row.passwordHash, emailVerifiedAt: iso(row.emailVerifiedAt),
      createdAt: iso(row.createdAt), updatedAt: iso(row.updatedAt), metadata: jsonObject(row.metadata)
    })),
    workspaces: sortRows(backfill.workspaces).map((row) => ({
      id: row.id, name: row.name, ownerUserId: row.ownerUserId, createdAt: iso(row.createdAt),
      updatedAt: iso(row.updatedAt), metadata: jsonObject(row.metadata)
    })),
    memberships: sortRows(backfill.memberships).map((row) => ({
      id: row.id, workspaceId: row.workspaceId, userId: row.userId, role: row.role, status: row.status,
      joinedAt: iso(row.joinedAt), lastOpenedAt: iso(row.lastOpenedAt), createdAt: iso(row.createdAt),
      updatedAt: iso(row.updatedAt), metadata: jsonObject(row.metadata)
    })),
    invitations: sortRows(backfill.invitations).map((row) => ({
      id: row.id, workspaceId: row.workspaceId, email: row.email, invitedUserId: row.invitedUserId,
      invitedByUserId: row.invitedByUserId, role: row.role, status: row.status, tokenHash: row.tokenHash,
      expiresAt: iso(row.expiresAt), acceptedAt: iso(row.acceptedAt), createdAt: iso(row.createdAt),
      updatedAt: iso(row.updatedAt), metadata: jsonObject(row.metadata)
    })),
    sessions: sortRows(backfill.sessions).map((row) => ({
      id: row.id, userId: row.userId, tokenHash: row.tokenHash, createdAt: iso(row.createdAt),
      expiresAt: iso(row.expiresAt), lastSeenAt: iso(row.lastSeenAt), revokedAt: null, metadata: jsonObject(row.metadata)
    })),
    externalAccounts: sortRows(backfill.externalAccounts).map((row) => ({
      id: row.id, userId: row.userId, provider: row.provider, providerSubject: row.providerSubject,
      email: row.email, displayName: row.displayName, status: row.status, authorizationStatus: row.authorizationStatus,
      credentialsCiphertext: row.credentialsCiphertext, grantedScopes: row.grantedScopes,
      selectedApps: row.selectedApps, settings: jsonObject(row.settings), createdAt: iso(row.createdAt),
      updatedAt: iso(row.updatedAt), lastSyncedAt: iso(row.lastSyncedAt)
    })),
    externalAccountLinks: sortRows(backfill.externalAccountLinks, (row) => `${row.workspaceId}\u001f${row.externalAccountId}`).map((row) => ({
      workspaceId: row.workspaceId, externalAccountId: row.externalAccountId,
      linkedByUserId: row.linkedByUserId, settings: jsonObject(row.settings)
    }))
  };
}

async function readCanonicalShadow(client) {
  const users = await client.query(`SELECT id, email, name, role, auth_provider, password_salt, password_hash, email_verified_at, created_at, updated_at, metadata FROM public.constrava_users ORDER BY id`);
  const workspaces = await client.query(`SELECT id, name, owner_user_id, created_at, updated_at, metadata FROM public.constrava_workspaces ORDER BY id`);
  const memberships = await client.query(`SELECT id, workspace_id, user_id, role, status, joined_at, last_opened_at, created_at, updated_at, metadata FROM public.constrava_workspace_memberships ORDER BY id`);
  const invitations = await client.query(`SELECT id, workspace_id, email, invited_user_id, invited_by_user_id, role, status, token_hash, expires_at, accepted_at, created_at, updated_at, metadata FROM public.constrava_workspace_invitations ORDER BY id`);
  const sessions = await client.query(`SELECT id, user_id, token_hash, created_at, expires_at, last_seen_at, revoked_at, metadata FROM public.constrava_sessions ORDER BY id`);
  const externalAccounts = await client.query(`SELECT id, user_id, provider, provider_subject, email, display_name, status, authorization_status, credentials_ciphertext, granted_scopes, selected_apps, settings, created_at, updated_at, last_synced_at FROM public.constrava_external_accounts ORDER BY id`);
  const externalAccountLinks = await client.query(`SELECT workspace_id, external_account_id, linked_by_user_id, settings FROM public.constrava_workspace_external_accounts ORDER BY workspace_id, external_account_id`);
  return {
    users: users.rows.map((row) => ({
      id: row.id, email: row.email, name: row.name, role: row.role, authProvider: row.auth_provider,
      passwordSalt: row.password_salt, passwordHash: row.password_hash, emailVerifiedAt: iso(row.email_verified_at),
      createdAt: iso(row.created_at), updatedAt: iso(row.updated_at), metadata: jsonObject(row.metadata)
    })),
    workspaces: workspaces.rows.map((row) => ({
      id: row.id, name: row.name, ownerUserId: row.owner_user_id, createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at), metadata: jsonObject(row.metadata)
    })),
    memberships: memberships.rows.map((row) => ({
      id: row.id, workspaceId: row.workspace_id, userId: row.user_id, role: row.role, status: row.status,
      joinedAt: iso(row.joined_at), lastOpenedAt: iso(row.last_opened_at), createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at), metadata: jsonObject(row.metadata)
    })),
    invitations: invitations.rows.map((row) => ({
      id: row.id, workspaceId: row.workspace_id, email: row.email, invitedUserId: row.invited_user_id,
      invitedByUserId: row.invited_by_user_id, role: row.role, status: row.status, tokenHash: row.token_hash,
      expiresAt: iso(row.expires_at), acceptedAt: iso(row.accepted_at), createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at), metadata: jsonObject(row.metadata)
    })),
    sessions: sessions.rows.map((row) => ({
      id: row.id, userId: row.user_id, tokenHash: row.token_hash, createdAt: iso(row.created_at),
      expiresAt: iso(row.expires_at), lastSeenAt: iso(row.last_seen_at), revokedAt: iso(row.revoked_at),
      metadata: jsonObject(row.metadata)
    })),
    externalAccounts: externalAccounts.rows.map((row) => ({
      id: row.id, userId: row.user_id, provider: row.provider, providerSubject: row.provider_subject,
      email: row.email, displayName: row.display_name, status: row.status, authorizationStatus: row.authorization_status,
      credentialsCiphertext: row.credentials_ciphertext, grantedScopes: row.granted_scopes || [],
      selectedApps: row.selected_apps || [], settings: jsonObject(row.settings), createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at), lastSyncedAt: iso(row.last_synced_at)
    })),
    externalAccountLinks: externalAccountLinks.rows.map((row) => ({
      workspaceId: row.workspace_id, externalAccountId: row.external_account_id,
      linkedByUserId: row.linked_by_user_id, settings: jsonObject(row.settings)
    }))
  };
}

export async function verifyIdentityShadow(client, backfill) {
  const expectedChecksum = fingerprint(canonicalBackfill(backfill));
  const relationalChecksum = fingerprint(await readCanonicalShadow(client));
  return { matches: expectedChecksum === relationalChecksum, expectedChecksum, relationalChecksum };
}

function safeCounts(backfill) {
  return {
    users: backfill.users.length,
    workspaces: backfill.workspaces.length,
    memberships: backfill.memberships.length,
    invitations: backfill.invitations.length,
    sessions: backfill.sessions.length,
    externalAccounts: backfill.externalAccounts.length,
    externalAccountLinks: backfill.externalAccountLinks.length,
    skippedSessions: backfill.skippedSessions,
    skippedExternalAccounts: backfill.skippedExternalAccounts,
    skippedExternalAccountLinks: backfill.skippedExternalAccountLinks
  };
}

function parseLegacyRow(row) {
  if (!row) {
    const error = new Error("The primary legacy store is missing.");
    error.code = "LEGACY_STORE_MISSING";
    throw error;
  }
  if (typeof row.data === "string") {
    try { return JSON.parse(row.data); } catch {
      const error = new Error("The primary legacy store is invalid.");
      error.code = "LEGACY_STORE_INVALID";
      throw error;
    }
  }
  return row.data;
}

function safeErrorCode(error) {
  return text(error?.shadowErrorCode || error?.code || "relational_shadow_sync_failed")
    .replace(/[^a-z0-9_-]/gi, "")
    .slice(0, 64) || "relational_shadow_sync_failed";
}

function publicShadowError(error) {
  if (error?.status === 409) return error;
  const shadowErrorCode = safeErrorCode(error);
  return Object.assign(new Error("Account data could not be saved safely. Please try again."), {
    status: 503,
    code: "RELATIONAL_SHADOW_SYNC_FAILED",
    shadowErrorCode,
    cause: error
  });
}

async function writeShadowState(client, version, verification, counts, { synchronized = true } = {}) {
  const synchronizedAt = synchronized ? new Date().toISOString() : null;
  await client.query(
    `INSERT INTO ${SHADOW_STATE_TABLE} AS shadow_state (id, source_store_version, source_checksum, relational_checksum, status, last_error_code, counts, synced_at, verified_at, updated_at)
     VALUES ($1,$2,$3,$4,'in_sync','',$5::jsonb,$6,NOW(),NOW())
     ON CONFLICT (id) DO UPDATE SET source_store_version=EXCLUDED.source_store_version, source_checksum=EXCLUDED.source_checksum,
       relational_checksum=EXCLUDED.relational_checksum, status='in_sync', last_error_code='', counts=EXCLUDED.counts,
       synced_at=COALESCE(EXCLUDED.synced_at, shadow_state.synced_at), verified_at=NOW(), updated_at=NOW()`,
    [SHADOW_STATE_ID, Number(version || 0), verification.expectedChecksum, verification.relationalChecksum, JSON.stringify(counts), synchronizedAt]
  );
}

async function advanceShadowState(client, version, counts) {
  await client.query(
    `UPDATE ${SHADOW_STATE_TABLE}
     SET source_store_version=$2, counts=$3::jsonb, updated_at=NOW()
     WHERE id=$1 AND status='in_sync'`,
    [SHADOW_STATE_ID, Number(version || 0), JSON.stringify(counts)]
  );
}

async function synchronize(client, storeData, version) {
  const backfill = buildIdentityBackfill(storeData, version);
  await syncIdentityBackfill(client, backfill, { prune: true });
  const verification = await verifyIdentityShadow(client, backfill);
  if (!verification.matches) {
    const error = new Error("The relational shadow did not match the legacy source after synchronization.");
    error.code = "RELATIONAL_SHADOW_DRIFT";
    throw error;
  }
  const counts = safeCounts(backfill);
  await writeShadowState(client, version, verification, counts);
  return { version: Number(version || 0), counts, synchronized: true };
}

async function synchronizeIfNeeded(client, storeData, version) {
  const backfill = buildIdentityBackfill(storeData, version);
  const counts = safeCounts(backfill);
  const expectedChecksum = fingerprint(canonicalBackfill(backfill));
  const state = await client.query(
    `SELECT source_checksum, status, verified_at FROM ${SHADOW_STATE_TABLE} WHERE id=$1 FOR UPDATE`,
    [SHADOW_STATE_ID]
  );
  const current = state.rows[0];
  if (current?.status === "in_sync" && current.source_checksum === expectedChecksum) {
    const verifiedAt = new Date(current.verified_at || 0).getTime();
    if (Number.isFinite(verifiedAt) && Date.now() - verifiedAt < SHADOW_VERIFY_INTERVAL_MS) {
      await advanceShadowState(client, version, counts);
      return { version: Number(version || 0), counts, synchronized: false };
    }
    const verification = await verifyIdentityShadow(client, backfill);
    if (verification.matches) {
      await writeShadowState(client, version, verification, counts, { synchronized: false });
      return { version: Number(version || 0), counts, synchronized: false };
    }
  }
  await syncIdentityBackfill(client, backfill, { prune: true });
  const verification = await verifyIdentityShadow(client, backfill);
  if (!verification.matches) {
    const error = new Error("The relational shadow did not match the legacy source after synchronization.");
    error.code = "RELATIONAL_SHADOW_DRIFT";
    throw error;
  }
  await writeShadowState(client, version, verification, counts);
  return { version: Number(version || 0), counts, synchronized: true };
}

export const RELATIONAL_SHADOW_SYNC_MIGRATION = Object.freeze({
  id: RELATIONAL_SHADOW_SYNC_MIGRATION_ID,
  name: "Relational shadow synchronization state",
  checksum: shadowMigrationChecksum,
  snapshotKey: RELATIONAL_SHADOW_SYNC_SNAPSHOT_KEY,
  snapshotLabel: "Before relational shadow synchronization",
  async up(client) {
    await client.query(SHADOW_STATE_STATEMENT);
  }
});

export function createRelationalShadowSync({ pool, migrationSafety, enabled = false } = {}) {
  const configured = Boolean(pool && migrationSafety);
  const shadowEnabled = configured && enabled === true;
  let readyPromise = null;
  let status = configured ? "checking" : "not_configured";
  let errorCode = "";
  let checkedAt = "";
  let syncedAt = "";
  let sourceVersion = 0;
  let counts = {};
  let driftDetected = false;

  function succeeded(result, { synced = true } = {}) {
    status = shadowEnabled ? "ready" : "disabled";
    errorCode = "";
    checkedAt = new Date().toISOString();
    if (synced) syncedAt = checkedAt;
    sourceVersion = Number(result?.version || sourceVersion || 0);
    counts = result?.counts || counts;
    driftDetected = false;
    return result;
  }

  function failed(error) {
    status = "unavailable";
    errorCode = safeErrorCode(error);
    checkedAt = new Date().toISOString();
    driftDetected = errorCode === "RELATIONAL_SHADOW_DRIFT";
  }

  async function withTransaction(operation) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try { await client.query("ROLLBACK"); } catch {}
      throw error;
    } finally {
      client.release();
    }
  }

  async function reconcileExisting() {
    return withTransaction(async (client) => {
      const legacy = await client.query(`SELECT data, version FROM ${LEGACY_STORE_TABLE} WHERE id = 'primary' FOR UPDATE`);
      const row = legacy.rows[0];
      return synchronize(client, parseLegacyRow(row), row?.version);
    });
  }

  async function ensure() {
    if (!configured) return;
    if (!readyPromise) {
      status = "checking";
      readyPromise = migrationSafety.runMigration(RELATIONAL_SHADOW_SYNC_MIGRATION)
        .then(async () => shadowEnabled ? reconcileExisting() : { version: 0, counts: {} })
        .then((result) => succeeded(result, { synced: shadowEnabled }))
        .catch((error) => {
          failed(error);
          readyPromise = null;
          throw publicShadowError(error);
        });
    }
    return readyPromise;
  }

  async function save({ serialized, storeData, expectedVersion }) {
    if (!configured) throw publicShadowError(Object.assign(new Error("Relational shadow storage is not configured."), { code: "RELATIONAL_SHADOW_NOT_CONFIGURED" }));
    await ensure();
    try {
      const result = await withTransaction(async (client) => {
        const updated = await client.query(
          `UPDATE ${LEGACY_STORE_TABLE}
           SET data = $1::jsonb, version = version + 1, updated_at = NOW()
           WHERE id = $2 AND version = $3
           RETURNING version`,
          [serialized, "primary", Number(expectedVersion || 0)]
        );
        if (!updated.rows.length) {
          throw Object.assign(new Error("Workspace data changed during this request. Please retry."), { status: 409, code: "STORE_VERSION_CONFLICT" });
        }
        const version = Number(updated.rows[0].version || 0);
        if (!shadowEnabled) return { version, counts: {}, synchronized: false };
        return synchronizeIfNeeded(client, storeData, version);
      });
      succeeded(result, { synced: shadowEnabled && result.synchronized !== false });
      return { rows: [{ version: result.version }] };
    } catch (error) {
      if (error?.status !== 409) failed(error);
      throw publicShadowError(error);
    }
  }

  function health() {
    return {
      relationalShadowSyncEnabled: shadowEnabled,
      relationalShadowSyncStatus: status,
      relationalShadowSyncVersion: RELATIONAL_SHADOW_SYNC_MIGRATION_ID,
      relationalShadowSyncErrorCode: errorCode,
      relationalShadowSyncCheckedAt: checkedAt,
      relationalShadowSyncLastSyncedAt: syncedAt,
      relationalShadowSyncSourceVersion: sourceVersion,
      relationalShadowSyncCounts: counts,
      relationalShadowDriftDetected: driftDetected,
      relationalDualWriteEnabled: shadowEnabled,
      relationalReadsEnabled: false
    };
  }

  return { ensure, save, health };
}
