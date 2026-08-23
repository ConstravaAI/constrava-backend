import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  buildIdentityBackfill,
  createIdentityBackfill,
  IDENTITY_BACKFILL_MIGRATION_ID,
  IDENTITY_BACKFILL_SNAPSHOT_KEY
} from "../src/postgres-identity-backfill.js";

const fixture = {
  users: [
    {
      id: "user_owner",
      email: "Owner@Example.com",
      name: "Owner",
      role: "user",
      authProvider: "password",
      passwordSalt: "stored-password-salt",
      passwordHash: "stored-password-hash",
      createdAt: "2026-08-01T10:00:00.000Z",
      emailVerificationTokenHash: "already-hashed-verification-token"
    },
    {
      id: "user_member",
      email: "member@example.com",
      name: "Member",
      authProvider: "google",
      googleSubject: "google-user-subject",
      createdAt: "2026-08-02T10:00:00.000Z"
    }
  ],
  workspaces: [
    { id: "workspace_shared", name: "Shared CRM", ownerUserId: "user_owner", createdAt: "2026-08-03T10:00:00.000Z" },
    { id: "workspace_other", name: "Other CRM", ownerUserId: "user_owner", createdAt: "2026-08-03T11:00:00.000Z" }
  ],
  workspaceMembers: [
    { id: "member_owner", workspaceId: "workspace_shared", userId: "user_owner", role: "owner", status: "active", joinedAt: "2026-08-03T10:00:00.000Z" },
    { id: "member_shared", workspaceId: "workspace_shared", userId: "user_member", role: "member", status: "active", joinedAt: "2026-08-04T10:00:00.000Z" },
    { id: "member_other_owner", workspaceId: "workspace_other", userId: "user_owner", role: "owner", status: "active", joinedAt: "2026-08-03T11:00:00.000Z" }
  ],
  workspaceInvitations: [
    { id: "invite_one", workspaceId: "workspace_shared", email: "invitee@example.com", role: "member", status: "pending", invitedByUserId: "user_owner", createdAt: "2026-08-05T10:00:00.000Z" }
  ],
  sessions: [
    { id: "session_super_secret_cookie", userId: "user_owner", activeWorkspaceId: "workspace_shared", createdAt: "2026-08-06T10:00:00.000Z", expiresAt: "2026-11-06T10:00:00.000Z" },
    { id: "orphan_session_cookie", userId: "missing_user", createdAt: "2026-08-06T10:00:00.000Z" }
  ],
  googleAccounts: [
    {
      id: "google_owner_account",
      accountUserId: "user_owner",
      linkedWorkspaceIds: ["workspace_shared"],
      email: "owner@gmail.com",
      displayName: "Owner Google",
      googleSubject: "google-subject-owner",
      status: "active",
      authorizationStatus: "authorized",
      oauthTokens: "encrypted-google-token-blob",
      oauthStateHash: "hashed-oauth-state",
      oauthStateExpiresAt: "2026-08-23T12:00:00.000Z",
      grantedScopes: ["calendar.readonly"],
      selectedApps: ["calendar"],
      appScan: { status: "complete", apps: ["calendar"] },
      createdAt: "2026-08-07T10:00:00.000Z"
    },
    {
      id: "google_member_account",
      accountUserId: "user_member",
      linkedWorkspaceIds: ["workspace_shared", "workspace_other"],
      email: "member@gmail.com",
      status: "active",
      authorizationStatus: "authorized",
      oauthTokens: "encrypted-member-google-token-blob",
      createdAt: "2026-08-08T10:00:00.000Z"
    },
    {
      id: "google_ownerless_account",
      workspaceId: "workspace_shared",
      email: "unknown@gmail.com",
      oauthTokens: "encrypted-ownerless-token"
    }
  ],
  microsoftAccounts: []
};

const backfill = buildIdentityBackfill(fixture, 16857);
assert.equal(backfill.legacyStoreVersion, 16857);
assert.equal(backfill.users.length, 2);
assert.equal(backfill.workspaces.length, 2);
assert.equal(backfill.memberships.length, 3);
assert.equal(backfill.invitations.length, 1);
assert.equal(backfill.sessions.length, 1);
assert.equal(backfill.skippedSessions, 1);
assert.equal(backfill.externalAccounts.length, 2);
assert.equal(backfill.skippedExternalAccounts, 1, "an account without an explicit valid owner must not be reassigned to a project member");
assert.equal(backfill.externalAccountLinks.length, 2);
assert.equal(backfill.skippedExternalAccountLinks, 1, "a member-owned provider account must not be linked to a project that member cannot access");

const expectedSessionDigest = crypto.createHash("sha256").update("session_super_secret_cookie").digest("hex");
assert.equal(backfill.sessions[0].tokenHash, `sha256:${expectedSessionDigest}`);
assert.equal(backfill.sessions[0].id, `session_row_${expectedSessionDigest.slice(0, 32)}`);
assert(!JSON.stringify(backfill).includes("session_super_secret_cookie"), "raw session cookies must not be copied anywhere in the relational backfill");
assert.equal(backfill.externalAccounts.find((entry) => entry.id === "google_owner_account")?.userId, "user_owner");
assert.equal(backfill.externalAccounts.find((entry) => entry.id === "google_member_account")?.userId, "user_member");
assert.deepEqual(
  backfill.externalAccountLinks.map((entry) => [entry.externalAccountId, entry.workspaceId, entry.linkedByUserId]).sort(),
  [
    ["google_member_account", "workspace_shared", "user_member"],
    ["google_owner_account", "workspace_shared", "user_owner"]
  ]
);

const ownerAccount = backfill.externalAccounts.find((entry) => entry.id === "google_owner_account");
assert.equal(ownerAccount.credentialsCiphertext, "encrypted-google-token-blob", "the already-encrypted OAuth blob must remain encrypted and isolated in its credential column");
const safeSettings = JSON.stringify(ownerAccount.settings);
assert(!safeSettings.includes("encrypted-google-token-blob"));
assert(!safeSettings.includes("hashed-oauth-state"));
assert(!safeSettings.includes("oauthTokens"));
assert(!safeSettings.includes("oauthStateHash"));

await assert.rejects(
  async () => buildIdentityBackfill({ ...fixture, workspaceMembers: [...fixture.workspaceMembers, { id: "dangling", workspaceId: "missing_workspace", userId: "user_owner" }] }),
  (error) => error.code === "BACKFILL_DANGLING_MEMBERSHIP"
);

class BackfillClient {
  constructor() {
    this.queries = [];
  }

  async query(text, parameters = []) {
    const sql = String(text).replace(/\s+/g, " ").trim();
    this.queries.push({ sql, parameters });
    if (sql.includes("SELECT data, version FROM public.constrava_app_store_v2")) {
      assert(sql.includes("FOR UPDATE"), "the backfill must lock the exact legacy row it reads");
      return { rows: [{ data: fixture, version: 16857 }] };
    }
    return { rows: [] };
  }
}

const client = new BackfillClient();
let migrationRuns = 0;
const migrationSafety = {
  async runMigration(migration) {
    migrationRuns += 1;
    assert.equal(migration.id, IDENTITY_BACKFILL_MIGRATION_ID);
    assert.equal(migration.snapshotKey, IDENTITY_BACKFILL_SNAPSHOT_KEY);
    return { id: migration.id, applied: true, details: await migration.up(client) };
  }
};
const controller = createIdentityBackfill({ migrationSafety });
const [firstEnsure, secondEnsure] = await Promise.all([controller.ensure(), controller.ensure()]);
assert.deepEqual(firstEnsure, secondEnsure);
assert.equal(migrationRuns, 1, "concurrent startup checks must share one backfill promise");
assert.equal(firstEnsure.details.users, 2);
assert.equal(firstEnsure.details.sessions, 1);
assert.equal(firstEnsure.details.externalAccounts, 2);
assert.equal(firstEnsure.details.skippedExternalAccounts, 1);
assert.equal(firstEnsure.details.skippedExternalAccountLinks, 1);
assert.equal(controller.health().relationalBackfillStatus, "ready");
assert.equal(controller.health().relationalBackfillVersion, IDENTITY_BACKFILL_MIGRATION_ID);
assert.equal(controller.health().relationalBackfillCompleted, true);
assert.equal(controller.health().relationalDualWriteEnabled, false, "Deployment 3 must not activate relational writes");
assert.deepEqual(controller.health().relationalBackfillCounts, firstEnsure.details);

const insertedSession = client.queries.find(({ sql }) => sql.includes("INSERT INTO public.constrava_sessions"));
assert(insertedSession, "the migration must insert hashed session rows");
assert(!insertedSession.parameters.includes("session_super_secret_cookie"));
const insertedProvider = client.queries.find(({ sql }) => sql.includes("INSERT INTO public.constrava_external_accounts") && sql.includes("credentials_ciphertext"));
assert(insertedProvider, "the migration must insert user-owned external accounts");
assert(insertedProvider.parameters.includes("encrypted-google-token-blob"));
assert(!insertedProvider.parameters.some((value) => typeof value === "string" && value.includes("hashed-oauth-state")));

const unavailable = createIdentityBackfill({ migrationSafety: { runMigration: async () => { const error = new Error("do not expose this database message"); error.code = "XX-unsafe code!"; throw error; } } });
await assert.rejects(unavailable.ensure());
assert.equal(unavailable.health().relationalBackfillStatus, "unavailable");
assert.equal(unavailable.health().relationalBackfillErrorCode, "XX-unsafecode");

console.log("Identity and project backfill tests passed.");
