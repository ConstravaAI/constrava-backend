const MIGRATION_LOCK_KEY = 1_934_827_116;
const BOOTSTRAP_MIGRATION_ID = "0001_migration_safety";
const BOOTSTRAP_MIGRATION_CHECKSUM = "sha256:71b35f509629af367c905c6fa6e5b4afca03ec13b145a2891233e87cb0706601";
const MIGRATION_TABLE = "public.constrava_schema_migrations";
const SNAPSHOT_TABLE = "public.constrava_store_snapshots";
const LEGACY_STORE_TABLE = "public.constrava_app_store_v2";

function safeErrorCode(error) {
  return String(error?.code || "migration_safety_failed")
    .replace(/[^a-z0-9_-]/gi, "")
    .slice(0, 64) || "migration_safety_failed";
}

function migrationIdentity(value, label) {
  const normalized = String(value || "").trim();
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/i.test(normalized)) {
    const error = new Error(`${label} must contain only letters, numbers, periods, colons, underscores, or hyphens.`);
    error.code = "INVALID_MIGRATION_IDENTITY";
    throw error;
  }
  return normalized;
}

export function normalizeStorageMode(value) {
  const requested = String(value || "legacy").trim().toLowerCase();
  return ["legacy", "shadow", "relational"].includes(requested) ? requested : "legacy";
}

export function createMigrationSafety({ pool, requestedStorageMode = "legacy" } = {}) {
  const requestedMode = normalizeStorageMode(requestedStorageMode);
  const activeMode = "legacy";
  let readyPromise = null;
  let status = pool ? "checking" : "not_configured";
  let errorCode = "";
  let checkedAt = "";

  async function withAdvisoryLock(task) {
    const client = await pool.connect();
    let locked = false;
    try {
      await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
      locked = true;
      return await task(client);
    } finally {
      if (locked) {
        try { await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY]); } catch {}
      }
      client.release();
    }
  }

  async function createSafetyTables(client) {
    await client.query(`
      CREATE TABLE IF NOT EXISTS ${MIGRATION_TABLE} (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
        details JSONB NOT NULL DEFAULT '{}'::jsonb,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finished_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS ${SNAPSHOT_TABLE} (
        snapshot_key TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        store_id TEXT NOT NULL,
        store_version BIGINT NOT NULL,
        data JSONB NOT NULL,
        source_created_at TIMESTAMPTZ,
        source_updated_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
  }

  async function ensure() {
    if (!pool) return;
    if (!readyPromise) {
      status = "checking";
      readyPromise = withAdvisoryLock(async (client) => {
        await client.query("BEGIN");
        try {
          await createSafetyTables(client);
          const existing = await client.query(`SELECT checksum FROM ${MIGRATION_TABLE} WHERE id = $1`, [BOOTSTRAP_MIGRATION_ID]);
          if (existing.rows.length && existing.rows[0].checksum !== BOOTSTRAP_MIGRATION_CHECKSUM) {
            const error = new Error("The migration safety bootstrap checksum does not match the recorded migration.");
            error.code = "MIGRATION_CHECKSUM_MISMATCH";
            throw error;
          }
          if (!existing.rows.length) {
            await client.query(
              `INSERT INTO ${MIGRATION_TABLE} (id, name, checksum, status, details, finished_at)
               VALUES ($1, $2, $3, 'completed', $4::jsonb, NOW())`,
              [BOOTSTRAP_MIGRATION_ID, "Migration safety infrastructure", BOOTSTRAP_MIGRATION_CHECKSUM, JSON.stringify({ activeStorageMode: activeMode, changesApplicationDataLayout: false })]
            );
          }
          await client.query("COMMIT");
        } catch (error) {
          try { await client.query("ROLLBACK"); } catch {}
          throw error;
        }
      }).then(() => {
        status = "ready";
        errorCode = "";
        checkedAt = new Date().toISOString();
      }).catch((error) => {
        status = "unavailable";
        errorCode = safeErrorCode(error);
        checkedAt = new Date().toISOString();
        readyPromise = null;
        throw error;
      });
    }
    return readyPromise;
  }

  async function insertSnapshot(client, snapshotKey, label) {
    const inserted = await client.query(
      `INSERT INTO ${SNAPSHOT_TABLE} (snapshot_key, label, store_id, store_version, data, source_created_at, source_updated_at)
       SELECT $1, $2, id, version, data, created_at, updated_at
       FROM ${LEGACY_STORE_TABLE}
       WHERE id = 'primary'
       ON CONFLICT (snapshot_key) DO NOTHING
       RETURNING snapshot_key`,
      [snapshotKey, label]
    );
    if (inserted.rows.length) return { snapshotKey, created: true };
    const existing = await client.query(`SELECT snapshot_key FROM ${SNAPSHOT_TABLE} WHERE snapshot_key = $1`, [snapshotKey]);
    if (existing.rows.length) return { snapshotKey, created: false };
    const error = new Error("The primary legacy store is missing; a migration snapshot could not be created.");
    error.code = "LEGACY_STORE_MISSING";
    throw error;
  }

  async function createSnapshot({ key, label = "Pre-migration snapshot" } = {}) {
    if (!pool) {
      const error = new Error("Postgres is not configured; a migration snapshot cannot be created.");
      error.code = "POSTGRES_NOT_CONFIGURED";
      throw error;
    }
    await ensure();
    const snapshotKey = migrationIdentity(key, "Snapshot key");
    const snapshotLabel = String(label || "Pre-migration snapshot").trim().slice(0, 160);
    return withAdvisoryLock(async (client) => {
      await client.query("BEGIN");
      try {
        const result = await insertSnapshot(client, snapshotKey, snapshotLabel);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch {}
        throw error;
      }
    });
  }

  async function runMigration({ id, name, checksum, snapshotKey = "", snapshotLabel = "", up } = {}) {
    if (!pool) {
      const error = new Error("Postgres is not configured; migrations cannot run.");
      error.code = "POSTGRES_NOT_CONFIGURED";
      throw error;
    }
    if (typeof up !== "function") throw new TypeError("A migration must provide an up(client) function.");
    await ensure();
    const migrationId = migrationIdentity(id, "Migration ID");
    const migrationChecksum = migrationIdentity(checksum, "Migration checksum");
    const migrationName = String(name || migrationId).trim().slice(0, 160);
    const normalizedSnapshotKey = snapshotKey ? migrationIdentity(snapshotKey, "Snapshot key") : "";
    return withAdvisoryLock(async (client) => {
      await client.query("BEGIN");
      try {
        const existing = await client.query(`SELECT checksum, status FROM ${MIGRATION_TABLE} WHERE id = $1`, [migrationId]);
        if (existing.rows.length) {
          if (existing.rows[0].checksum !== migrationChecksum) {
            const error = new Error(`Migration ${migrationId} has already been recorded with a different checksum.`);
            error.code = "MIGRATION_CHECKSUM_MISMATCH";
            throw error;
          }
          if (existing.rows[0].status === "completed") {
            await client.query("COMMIT");
            return { id: migrationId, applied: false };
          }
        }
        if (normalizedSnapshotKey) await insertSnapshot(client, normalizedSnapshotKey, String(snapshotLabel || migrationName).trim().slice(0, 160));
        await client.query(
          `INSERT INTO ${MIGRATION_TABLE} (id, name, checksum, status, details, started_at, finished_at, updated_at)
           VALUES ($1, $2, $3, 'running', '{}'::jsonb, NOW(), NULL, NOW())
           ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = 'running', details = '{}'::jsonb, started_at = NOW(), finished_at = NULL, updated_at = NOW()`,
          [migrationId, migrationName, migrationChecksum]
        );
        await up(client);
        await client.query(
          `UPDATE ${MIGRATION_TABLE} SET status = 'completed', finished_at = NOW(), updated_at = NOW() WHERE id = $1`,
          [migrationId]
        );
        await client.query("COMMIT");
        return { id: migrationId, applied: true };
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch {}
        if (error?.code !== "MIGRATION_CHECKSUM_MISMATCH") {
          try {
            await client.query(
              `INSERT INTO ${MIGRATION_TABLE} (id, name, checksum, status, details, finished_at, updated_at)
               VALUES ($1, $2, $3, 'failed', $4::jsonb, NOW(), NOW())
               ON CONFLICT (id) DO UPDATE SET status = 'failed', details = EXCLUDED.details, finished_at = NOW(), updated_at = NOW()`,
              [migrationId, migrationName, migrationChecksum, JSON.stringify({ errorCode: safeErrorCode(error) })]
            );
          } catch {}
        }
        throw error;
      }
    });
  }

  function health() {
    return {
      storageMode: activeMode,
      requestedStorageMode: requestedMode,
      storageModeRequestStatus: requestedMode === activeMode ? "active" : "reserved_not_active",
      relationalMigrationEnabled: false,
      migrationSafetyStatus: status,
      migrationSafetyVersion: BOOTSTRAP_MIGRATION_ID,
      migrationSafetyErrorCode: errorCode,
      migrationSafetyCheckedAt: checkedAt
    };
  }

  return { ensure, createSnapshot, runMigration, health };
}
