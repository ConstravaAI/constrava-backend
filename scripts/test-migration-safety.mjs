import assert from "node:assert/strict";
import { createMigrationSafety, normalizeStorageMode } from "../src/postgres-migration-safety.js";
import { createRelationalFoundation, RELATIONAL_FOUNDATION_MIGRATION_ID, RELATIONAL_FOUNDATION_SNAPSHOT_KEY } from "../src/postgres-relational-foundation.js";

class FakeClient {
  constructor({ bootstrapChecksum = "", legacyStorePresent = true } = {}) {
    this.bootstrapChecksum = bootstrapChecksum;
    this.legacyStorePresent = legacyStorePresent;
    this.snapshots = new Set();
    this.migrations = new Map();
    this.queries = [];
    this.released = false;
  }

  async query(text, parameters = []) {
    const sql = String(text).replace(/\s+/g, " ").trim();
    this.queries.push({ sql, parameters });
    if (sql.includes("SELECT checksum FROM public.constrava_schema_migrations")) {
      return { rows: this.bootstrapChecksum ? [{ checksum: this.bootstrapChecksum }] : [] };
    }
    if (sql.includes("INSERT INTO public.constrava_schema_migrations") && parameters[0] === "0001_migration_safety") {
      this.bootstrapChecksum = parameters[2];
      return { rows: [] };
    }
    if (sql.includes("SELECT checksum, status FROM public.constrava_schema_migrations")) {
      const migration = this.migrations.get(parameters[0]);
      return { rows: migration ? [migration] : [] };
    }
    if (sql.includes("INSERT INTO public.constrava_store_snapshots")) {
      if (!this.legacyStorePresent || this.snapshots.has(parameters[0])) return { rows: [] };
      this.snapshots.add(parameters[0]);
      return { rows: [{ snapshot_key: parameters[0] }] };
    }
    if (sql.includes("SELECT snapshot_key FROM public.constrava_store_snapshots")) {
      return { rows: this.snapshots.has(parameters[0]) ? [{ snapshot_key: parameters[0] }] : [] };
    }
    if (sql.includes("INSERT INTO public.constrava_schema_migrations") && parameters[0]) {
      this.migrations.set(parameters[0], { checksum: parameters[2], status: sql.includes("'failed'") ? "failed" : "running" });
      return { rows: [] };
    }
    if (sql.includes("UPDATE public.constrava_schema_migrations SET status = 'completed'")) {
      const migration = this.migrations.get(parameters[0]);
      if (migration) migration.status = "completed";
      return { rows: [] };
    }
    return { rows: [] };
  }

  release() {
    this.released = true;
  }
}

class FakePool {
  constructor(options) {
    this.client = new FakeClient(options);
    this.connectCount = 0;
  }

  async connect() {
    this.connectCount += 1;
    return this.client;
  }
}

assert.equal(normalizeStorageMode(""), "legacy");
assert.equal(normalizeStorageMode("SHADOW"), "shadow");
assert.equal(normalizeStorageMode("unsupported"), "legacy");

const noDatabase = createMigrationSafety();
assert.deepEqual(noDatabase.health(), {
  storageMode: "legacy",
  requestedStorageMode: "legacy",
  storageModeRequestStatus: "active",
  relationalMigrationEnabled: false,
  migrationSafetyStatus: "not_configured",
  migrationSafetyVersion: "0001_migration_safety",
  migrationSafetyErrorCode: "",
  migrationSafetyCheckedAt: ""
});

const pool = new FakePool();
const safety = createMigrationSafety({ pool, requestedStorageMode: "relational" });
await Promise.all([safety.ensure(), safety.ensure()]);
assert.equal(pool.connectCount, 1, "concurrent bootstrap calls should share one promise");
assert.equal(safety.health().storageMode, "legacy", "Deployment 1 must never activate relational reads");
assert.equal(safety.health().requestedStorageMode, "relational");
assert.equal(safety.health().storageModeRequestStatus, "reserved_not_active");
assert.equal(safety.health().migrationSafetyStatus, "ready");
assert(pool.client.queries.some(({ sql }) => sql.includes("pg_advisory_lock")), "bootstrap must acquire the advisory lock");
assert(pool.client.queries.some(({ sql }) => sql.includes("CREATE TABLE IF NOT EXISTS public.constrava_store_snapshots")), "bootstrap must create snapshot infrastructure");
assert(pool.client.released, "bootstrap must release its database client");

const snapshot = await safety.createSnapshot({ key: "before-test-migration", label: "Test snapshot" });
assert.deepEqual(snapshot, { snapshotKey: "before-test-migration", created: true });
const duplicateSnapshot = await safety.createSnapshot({ key: "before-test-migration", label: "Test snapshot" });
assert.deepEqual(duplicateSnapshot, { snapshotKey: "before-test-migration", created: false }, "snapshot creation must be idempotent");

let migrationApplied = 0;
const migration = { id: "0002_test", name: "Test migration", checksum: "sha256:test", snapshotKey: "before-0002", up: async (client) => { migrationApplied += 1; await client.query("SELECT 1"); } };
assert.deepEqual(await safety.runMigration(migration), { id: "0002_test", applied: true });
assert.deepEqual(await safety.runMigration(migration), { id: "0002_test", applied: false });
assert.equal(migrationApplied, 1, "completed migrations must not run twice");
await assert.rejects(
  safety.runMigration({ ...migration, checksum: "sha256:changed" }),
  (error) => error.code === "MIGRATION_CHECKSUM_MISMATCH"
);
assert.equal(pool.client.migrations.get("0002_test").status, "completed", "a checksum mismatch must not alter completed migration history");

const foundation = createRelationalFoundation({ migrationSafety: safety });
assert.deepEqual(await foundation.ensure(), { id: RELATIONAL_FOUNDATION_MIGRATION_ID, applied: true });
assert(pool.client.snapshots.has(RELATIONAL_FOUNDATION_SNAPSHOT_KEY), "Deployment 2 must snapshot the legacy store before creating relational tables");
assert.equal(pool.client.migrations.get(RELATIONAL_FOUNDATION_MIGRATION_ID)?.status, "completed");
const restartedFoundation = createRelationalFoundation({ migrationSafety: safety });
assert.deepEqual(await restartedFoundation.ensure(), { id: RELATIONAL_FOUNDATION_MIGRATION_ID, applied: false }, "the Deployment 2 migration must be restart-safe");

const mismatchedPool = new FakePool({ bootstrapChecksum: "sha256:wrong" });
const mismatchedSafety = createMigrationSafety({ pool: mismatchedPool });
await assert.rejects(mismatchedSafety.ensure(), (error) => error.code === "MIGRATION_CHECKSUM_MISMATCH");
assert.equal(mismatchedSafety.health().migrationSafetyStatus, "unavailable");
assert.equal(mismatchedSafety.health().migrationSafetyErrorCode, "MIGRATION_CHECKSUM_MISMATCH");

console.log("Migration safety tests passed.");
