import assert from "node:assert/strict";
import {
  createRelationalShadowSync,
  RELATIONAL_SHADOW_SYNC_MIGRATION_ID,
  RELATIONAL_SHADOW_SYNC_SNAPSHOT_KEY
} from "../src/postgres-relational-shadow-sync.js";
import { buildIdentityBackfill } from "../src/postgres-identity-backfill.js";

const fixture = {
  users: [{
    id: "user_one", email: "one@example.com", name: "User One", role: "user", authProvider: "password",
    passwordSalt: "password-salt", passwordHash: "password-hash", emailVerifiedAt: "2026-08-01T10:00:00.000Z",
    createdAt: "2026-08-01T09:00:00.000Z", updatedAt: "2026-08-01T10:00:00.000Z"
  }],
  workspaces: [{ id: "workspace_one", name: "CRM One", ownerUserId: "user_one", createdAt: "2026-08-02T10:00:00.000Z", updatedAt: "2026-08-02T10:00:00.000Z" }],
  workspaceMembers: [{ id: "member_one", workspaceId: "workspace_one", userId: "user_one", role: "owner", status: "active", joinedAt: "2026-08-02T10:00:00.000Z", createdAt: "2026-08-02T10:00:00.000Z", updatedAt: "2026-08-02T10:00:00.000Z" }],
  workspaceInvitations: [],
  sessions: [{ id: "raw_session_cookie_value", userId: "user_one", activeWorkspaceId: "workspace_one", createdAt: "2026-08-03T10:00:00.000Z", expiresAt: "2026-11-03T10:00:00.000Z", lastSeenAt: "2026-08-04T10:00:00.000Z" }],
  googleAccounts: [{
    id: "google_one", accountUserId: "user_one", linkedWorkspaceIds: ["workspace_one"], googleSubject: "google-subject",
    email: "one@gmail.com", displayName: "User One", status: "active", authorizationStatus: "authorized",
    oauthTokens: "encrypted-google-credentials", grantedScopes: ["calendar.readonly"], selectedApps: ["calendar"],
    createdAt: "2026-08-05T10:00:00.000Z", updatedAt: "2026-08-05T10:00:00.000Z"
  }],
  microsoftAccounts: []
};

function rowsFor(data, version) {
  const backfill = buildIdentityBackfill(data, version);
  return {
    users: backfill.users.map((row) => ({ id: row.id, email: row.email, name: row.name, role: row.role, auth_provider: row.authProvider, password_salt: row.passwordSalt, password_hash: row.passwordHash, email_verified_at: row.emailVerifiedAt, created_at: row.createdAt, updated_at: row.updatedAt, metadata: row.metadata })),
    workspaces: backfill.workspaces.map((row) => ({ id: row.id, name: row.name, owner_user_id: row.ownerUserId, created_at: row.createdAt, updated_at: row.updatedAt, metadata: row.metadata })),
    memberships: backfill.memberships.map((row) => ({ id: row.id, workspace_id: row.workspaceId, user_id: row.userId, role: row.role, status: row.status, joined_at: row.joinedAt, last_opened_at: row.lastOpenedAt, created_at: row.createdAt, updated_at: row.updatedAt, metadata: row.metadata })),
    invitations: backfill.invitations.map((row) => ({ id: row.id, workspace_id: row.workspaceId, email: row.email, invited_user_id: row.invitedUserId, invited_by_user_id: row.invitedByUserId, role: row.role, status: row.status, token_hash: row.tokenHash, expires_at: row.expiresAt, accepted_at: row.acceptedAt, created_at: row.createdAt, updated_at: row.updatedAt, metadata: row.metadata })),
    sessions: backfill.sessions.map((row) => ({ id: row.id, user_id: row.userId, token_hash: row.tokenHash, created_at: row.createdAt, expires_at: row.expiresAt, last_seen_at: row.lastSeenAt, revoked_at: null, metadata: row.metadata })),
    externalAccounts: backfill.externalAccounts.map((row) => ({ id: row.id, user_id: row.userId, provider: row.provider, provider_subject: row.providerSubject, email: row.email, display_name: row.displayName, status: row.status, authorization_status: row.authorizationStatus, credentials_ciphertext: row.credentialsCiphertext, granted_scopes: row.grantedScopes, selected_apps: row.selectedApps, settings: row.settings, created_at: row.createdAt, updated_at: row.updatedAt, last_synced_at: row.lastSyncedAt })),
    externalAccountLinks: backfill.externalAccountLinks.map((row) => ({ workspace_id: row.workspaceId, external_account_id: row.externalAccountId, linked_by_user_id: row.linkedByUserId, settings: row.settings }))
  };
}

function clone(value) {
  return structuredClone(value);
}

class ShadowClient {
  constructor(data = fixture, version = 16891) {
    this.legacyData = clone(data);
    this.legacyVersion = version;
    this.rows = rowsFor(data, version);
    this.shadowState = null;
    this.queries = [];
    this.transactionSnapshot = null;
    this.forceDrift = false;
  }

  release() {}

  async query(text, parameters = []) {
    const sql = String(text).replace(/\s+/g, " ").trim();
    this.queries.push({ sql, parameters });
    if (sql === "BEGIN") {
      this.transactionSnapshot = { legacyData: clone(this.legacyData), legacyVersion: this.legacyVersion, rows: clone(this.rows), shadowState: clone(this.shadowState) };
      return { rows: [] };
    }
    if (sql === "COMMIT") {
      this.transactionSnapshot = null;
      return { rows: [] };
    }
    if (sql === "ROLLBACK") {
      if (this.transactionSnapshot) {
        this.legacyData = this.transactionSnapshot.legacyData;
        this.legacyVersion = this.transactionSnapshot.legacyVersion;
        this.rows = this.transactionSnapshot.rows;
        this.shadowState = this.transactionSnapshot.shadowState;
      }
      this.transactionSnapshot = null;
      return { rows: [] };
    }
    if (sql.includes("SELECT data, version FROM public.constrava_app_store_v2")) return { rows: [{ data: clone(this.legacyData), version: this.legacyVersion }] };
    if (sql.includes("UPDATE public.constrava_app_store_v2")) {
      if (Number(parameters[2]) !== this.legacyVersion) return { rows: [] };
      this.legacyData = JSON.parse(parameters[0]);
      this.legacyVersion += 1;
      return { rows: [{ version: this.legacyVersion }] };
    }
    if (sql.startsWith("SELECT source_checksum, status, verified_at FROM public.constrava_relational_shadow_state")) {
      return { rows: this.shadowState ? [clone(this.shadowState)] : [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_relational_shadow_state AS shadow_state")) {
      this.shadowState = {
        source_store_version: Number(parameters[1]),
        source_checksum: parameters[2],
        relational_checksum: parameters[3],
        status: "in_sync",
        counts: JSON.parse(parameters[4]),
        synced_at: parameters[5] || this.shadowState?.synced_at || null,
        verified_at: new Date().toISOString()
      };
      return { rows: [] };
    }
    if (sql.startsWith("UPDATE public.constrava_relational_shadow_state SET source_store_version=")) {
      if (this.shadowState) {
        this.shadowState.source_store_version = Number(parameters[1]);
        this.shadowState.counts = JSON.parse(parameters[2]);
      }
      return { rows: [] };
    }
    if (sql.startsWith("DELETE FROM public.constrava_workspace_external_accounts")) {
      const allowed = new Set(parameters[0]);
      this.rows.externalAccountLinks = this.rows.externalAccountLinks.filter((row) => allowed.has(`${row.workspace_id}\u001f${row.external_account_id}`));
      return { rows: [] };
    }
    if (sql.startsWith("DELETE FROM public.constrava_")) {
      const tableMap = {
        constrava_sessions: "sessions",
        constrava_workspace_invitations: "invitations",
        constrava_workspace_memberships: "memberships",
        constrava_external_accounts: "externalAccounts",
        constrava_workspaces: "workspaces",
        constrava_users: "users"
      };
      const table = Object.keys(tableMap).find((name) => sql.includes(`public.${name} `));
      if (table) {
        const allowed = new Set(parameters[0]);
        this.rows[tableMap[table]] = this.rows[tableMap[table]].filter((row) => allowed.has(row.id));
      }
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_users")) {
      const row = { id: parameters[0], email: parameters[1], name: parameters[2], role: parameters[3], auth_provider: parameters[4], password_salt: parameters[5], password_hash: parameters[6], email_verified_at: parameters[7], created_at: parameters[8], updated_at: parameters[9], metadata: JSON.parse(parameters[10]) };
      this.upsert("users", row);
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_workspaces ")) {
      this.upsert("workspaces", { id: parameters[0], name: parameters[1], owner_user_id: parameters[2], created_at: parameters[3], updated_at: parameters[4], metadata: JSON.parse(parameters[5]) });
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_workspace_memberships")) {
      this.upsert("memberships", { id: parameters[0], workspace_id: parameters[1], user_id: parameters[2], role: parameters[3], status: parameters[4], joined_at: parameters[5], last_opened_at: parameters[6], created_at: parameters[7], updated_at: parameters[8], metadata: JSON.parse(parameters[9]) });
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_workspace_invitations")) {
      this.upsert("invitations", { id: parameters[0], workspace_id: parameters[1], email: parameters[2], invited_user_id: parameters[3], invited_by_user_id: parameters[4], role: parameters[5], status: parameters[6], token_hash: parameters[7], expires_at: parameters[8], accepted_at: parameters[9], created_at: parameters[10], updated_at: parameters[11], metadata: JSON.parse(parameters[12]) });
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_sessions")) {
      this.upsert("sessions", { id: parameters[0], user_id: parameters[1], token_hash: parameters[2], created_at: parameters[3], expires_at: parameters[4], last_seen_at: parameters[5], revoked_at: null, metadata: JSON.parse(parameters[6]) });
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_external_accounts")) {
      this.upsert("externalAccounts", { id: parameters[0], user_id: parameters[1], provider: parameters[2], provider_subject: parameters[3], email: parameters[4], display_name: parameters[5], status: parameters[6], authorization_status: parameters[7], credentials_ciphertext: parameters[8], granted_scopes: parameters[9], selected_apps: parameters[10], settings: JSON.parse(parameters[11]), created_at: parameters[12], updated_at: parameters[13], last_synced_at: parameters[14] });
      return { rows: [] };
    }
    if (sql.startsWith("INSERT INTO public.constrava_workspace_external_accounts")) {
      const row = { workspace_id: parameters[0], external_account_id: parameters[1], linked_by_user_id: parameters[2], settings: JSON.parse(parameters[3]) };
      const index = this.rows.externalAccountLinks.findIndex((entry) => entry.workspace_id === row.workspace_id && entry.external_account_id === row.external_account_id);
      if (index >= 0) this.rows.externalAccountLinks[index] = row; else this.rows.externalAccountLinks.push(row);
      return { rows: [] };
    }
    if (sql.includes("FROM public.constrava_users ORDER BY id")) {
      const rows = clone(this.rows.users);
      if (this.forceDrift && rows[0]) rows[0].name = "Tampered relational name";
      return { rows };
    }
    if (sql.includes("FROM public.constrava_workspaces ORDER BY id")) return { rows: clone(this.rows.workspaces) };
    if (sql.includes("FROM public.constrava_workspace_memberships ORDER BY id")) return { rows: clone(this.rows.memberships) };
    if (sql.includes("FROM public.constrava_workspace_invitations ORDER BY id")) return { rows: clone(this.rows.invitations) };
    if (sql.includes("FROM public.constrava_sessions ORDER BY id")) return { rows: clone(this.rows.sessions) };
    if (sql.includes("FROM public.constrava_external_accounts ORDER BY id")) return { rows: clone(this.rows.externalAccounts) };
    if (sql.includes("FROM public.constrava_workspace_external_accounts ORDER BY")) return { rows: clone(this.rows.externalAccountLinks) };
    return { rows: [] };
  }

  upsert(collection, row) {
    const index = this.rows[collection].findIndex((entry) => entry.id === row.id);
    if (index >= 0) this.rows[collection][index] = row; else this.rows[collection].push(row);
  }
}

class ShadowPool {
  constructor(client = new ShadowClient()) {
    this.client = client;
    this.connectCount = 0;
  }

  async connect() {
    this.connectCount += 1;
    return this.client;
  }
}

function migrationSafetyFor(client) {
  let runs = 0;
  return {
    get runs() { return runs; },
    async runMigration(migration) {
      runs += 1;
      assert.equal(migration.id, RELATIONAL_SHADOW_SYNC_MIGRATION_ID);
      assert.equal(migration.snapshotKey, RELATIONAL_SHADOW_SYNC_SNAPSHOT_KEY);
      await migration.up(client);
      return { id: migration.id, applied: runs === 1 };
    }
  };
}

const unconfigured = createRelationalShadowSync();
assert.equal(unconfigured.health().relationalShadowSyncStatus, "not_configured");
assert.equal(unconfigured.health().relationalDualWriteEnabled, false);
assert.equal(unconfigured.health().relationalReadsEnabled, false);

const client = new ShadowClient();
const pool = new ShadowPool(client);
const migrationSafety = migrationSafetyFor(client);
const shadow = createRelationalShadowSync({ pool, migrationSafety, enabled: true });
await Promise.all([shadow.ensure(), shadow.ensure()]);
assert.equal(migrationSafety.runs, 1, "concurrent startup checks must share one migration/reconciliation promise");
assert.equal(shadow.health().relationalShadowSyncStatus, "ready");
assert.equal(shadow.health().relationalDualWriteEnabled, true);
assert.equal(shadow.health().relationalReadsEnabled, false, "Deployment 4 must keep all application reads on legacy JSONB");
assert.equal(shadow.health().relationalShadowDriftDetected, false);
assert.equal(shadow.health().relationalShadowSyncSourceVersion, 16891);
assert.equal(shadow.health().relationalShadowSyncCounts.users, 1);
assert(client.queries.some(({ sql }) => sql.includes("FOR UPDATE")), "startup reconciliation must lock the legacy source row");
assert(client.queries.some(({ sql }) => sql.startsWith("DELETE FROM public.constrava_users")), "shadow reconciliation must prune rows that no longer exist in legacy JSONB");

const updatedStore = clone(fixture);
updatedStore.users[0].name = "Updated User One";
updatedStore.users[0].updatedAt = "2026-08-23T14:00:00.000Z";
const saveResult = await shadow.save({ serialized: JSON.stringify(updatedStore), storeData: updatedStore, expectedVersion: 16891 });
assert.deepEqual(saveResult, { rows: [{ version: 16892 }] });
assert.equal(client.legacyData.users[0].name, "Updated User One");
assert.equal(client.rows.users[0].name, "Updated User One");
assert.equal(shadow.health().relationalShadowSyncSourceVersion, 16892);
assert.equal(shadow.health().relationalShadowDriftDetected, false);
assert(!JSON.stringify(client.rows).includes("raw_session_cookie_value"), "the relational shadow must never store raw session cookie values");
assert.equal(client.rows.externalAccounts[0].credentials_ciphertext, "encrypted-google-credentials");

const identityWriteCount = client.queries.filter(({ sql }) => sql.startsWith("INSERT INTO public.constrava_users")).length;
await shadow.save({ serialized: JSON.stringify(updatedStore), storeData: updatedStore, expectedVersion: 16892 });
assert.equal(client.legacyVersion, 16893);
assert.equal(
  client.queries.filter(({ sql }) => sql.startsWith("INSERT INTO public.constrava_users")).length,
  identityWriteCount,
  "a CRM-only save with an unchanged identity checksum must not rewrite every relational identity row"
);

const beforeConflict = clone(client.legacyData);
await assert.rejects(
  shadow.save({ serialized: JSON.stringify(updatedStore), storeData: updatedStore, expectedVersion: 1 }),
  (error) => error.status === 409 && error.code === "STORE_VERSION_CONFLICT"
);
assert.deepEqual(client.legacyData, beforeConflict, "an optimistic concurrency conflict must not change either store");

const beforeDriftVersion = client.legacyVersion;
const beforeDriftData = clone(client.legacyData);
client.forceDrift = true;
client.shadowState.verified_at = "2026-08-23T00:00:00.000Z";
await assert.rejects(
  shadow.save({ serialized: JSON.stringify(updatedStore), storeData: updatedStore, expectedVersion: beforeDriftVersion }),
  (error) => error.status === 503 && error.code === "RELATIONAL_SHADOW_SYNC_FAILED" && error.shadowErrorCode === "RELATIONAL_SHADOW_DRIFT"
);
assert.equal(client.legacyVersion, beforeDriftVersion, "a failed shadow verification must roll back the legacy update");
assert.deepEqual(client.legacyData, beforeDriftData, "a failed shadow verification must leave the legacy source untouched");
assert.equal(shadow.health().relationalShadowSyncStatus, "unavailable");
assert.equal(shadow.health().relationalShadowDriftDetected, true);

const disabledClient = new ShadowClient();
const disabledPool = new ShadowPool(disabledClient);
const disabledSafety = migrationSafetyFor(disabledClient);
const disabled = createRelationalShadowSync({ pool: disabledPool, migrationSafety: disabledSafety, enabled: false });
await disabled.ensure();
assert.equal(disabled.health().relationalShadowSyncStatus, "disabled");
assert.equal(disabled.health().relationalDualWriteEnabled, false);
const originalRelationalName = disabledClient.rows.users[0].name;
const legacyOnly = clone(fixture);
legacyOnly.users[0].name = "Legacy only change";
await disabled.save({ serialized: JSON.stringify(legacyOnly), storeData: legacyOnly, expectedVersion: 16891 });
assert.equal(disabledClient.legacyData.users[0].name, "Legacy only change");
assert.equal(disabledClient.rows.users[0].name, originalRelationalName, "the off switch must preserve legacy writes without touching relational rows");

console.log("Relational shadow synchronization tests passed.");
