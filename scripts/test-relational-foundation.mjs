import assert from "node:assert/strict";
import {
  createRelationalFoundation,
  RELATIONAL_FOUNDATION_MIGRATION,
  RELATIONAL_FOUNDATION_MIGRATION_ID,
  RELATIONAL_FOUNDATION_SNAPSHOT_KEY
} from "../src/postgres-relational-foundation.js";

const queries = [];
let migrationCalls = 0;
let capturedMigration = null;
const migrationSafety = {
  async runMigration(migration) {
    migrationCalls += 1;
    capturedMigration = migration;
    await migration.up({ query: async (sql) => { queries.push(String(sql).replace(/\s+/g, " ").trim()); return { rows: [] }; } });
    return { id: migration.id, applied: true };
  }
};

const foundation = createRelationalFoundation({ migrationSafety });
const [first, second] = await Promise.all([foundation.ensure(), foundation.ensure()]);
assert.deepEqual(first, { id: RELATIONAL_FOUNDATION_MIGRATION_ID, applied: true });
assert.deepEqual(second, first);
assert.equal(migrationCalls, 1, "concurrent foundation checks must share one migration promise");
assert.equal(capturedMigration.id, "0002_relational_foundation");
assert.equal(capturedMigration.snapshotKey, RELATIONAL_FOUNDATION_SNAPSHOT_KEY);
assert.match(capturedMigration.checksum, /^sha256:[a-f0-9]{64}$/);

const schema = queries.join("\n");
for (const table of [
  "constrava_users",
  "constrava_workspaces",
  "constrava_workspace_memberships",
  "constrava_workspace_invitations",
  "constrava_sessions",
  "constrava_external_accounts",
  "constrava_workspace_external_accounts"
]) {
  assert(schema.includes(`CREATE TABLE IF NOT EXISTS public.${table}`), `missing ${table}`);
}
assert(schema.includes("token_hash TEXT NOT NULL UNIQUE"), "sessions must store token hashes instead of raw tokens");
assert(schema.includes("credentials_ciphertext TEXT NOT NULL"), "provider credentials must have an encrypted storage column");
assert(schema.includes("UNIQUE (workspace_id, user_id)"), "project membership must be unique per user");
assert.equal(foundation.health().relationalSchemaStatus, "ready");
assert.equal(foundation.health().relationalBackfillEnabled, false);
assert.equal(foundation.health().relationalDualWriteEnabled, false);

const unavailable = createRelationalFoundation({ migrationSafety: { runMigration: async () => { throw Object.assign(new Error("boom"), { code: "TEST_FAILURE" }); } } });
await assert.rejects(unavailable.ensure(), (error) => error.code === "TEST_FAILURE");
assert.equal(unavailable.health().relationalSchemaStatus, "unavailable");
assert.equal(unavailable.health().relationalSchemaErrorCode, "TEST_FAILURE");

assert.equal(RELATIONAL_FOUNDATION_MIGRATION.id, RELATIONAL_FOUNDATION_MIGRATION_ID);
console.log("Relational foundation tests passed.");
