import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimePath = path.join(here, ".server.generated.js");
const runtimeMarker = "migration-safety-runtime-v4";

let source = await fs.readFile(runtimePath, "utf8");

if (!source.includes(runtimeMarker)) {
  const replacements = [
    {
      needle: 'import readXlsxFile from "read-excel-file/node";',
      value: 'import readXlsxFile from "read-excel-file/node";\nimport { createMigrationSafety } from "./postgres-migration-safety.js";\nimport { createRelationalFoundation } from "./postgres-relational-foundation.js";\nimport { createIdentityBackfill } from "./postgres-identity-backfill.js";\nimport { createRelationalShadowSync } from "./postgres-relational-shadow-sync.js";'
    },
    {
      needle: 'const POSTGRES_STORE_TABLE = "public.constrava_app_store_v2";',
      value: 'const POSTGRES_STORE_TABLE = "public.constrava_app_store_v2";\n// migration-safety-runtime-v4\nconst migrationSafety = createMigrationSafety({ pool: postgresPool, requestedStorageMode: process.env.DATA_STORAGE_MODE });\nconst relationalFoundation = createRelationalFoundation({ migrationSafety: postgresPool ? migrationSafety : null });\nconst identityBackfill = createIdentityBackfill({ migrationSafety: postgresPool ? migrationSafety : null });\nconst relationalShadowSync = createRelationalShadowSync({ pool: postgresPool, migrationSafety: postgresPool ? migrationSafety : null, enabled: /^(1|true|yes|on)$/i.test(process.env.RELATIONAL_DUAL_WRITE_ENABLED || "") });'
    },
    {
      needle: '      `);\n      postgresStatus = "ready";',
      value: '      `);\n      await migrationSafety.ensure();\n      await relationalFoundation.ensure();\n      await identityBackfill.ensure();\n      await relationalShadowSync.ensure();\n      postgresStatus = "ready";'
    },
    {
      needle: '    return { postgresStoreConfigured: false, databaseStatus: "not_configured", databaseErrorCode: "", databaseCheckedAt: "" };',
      value: '    return { postgresStoreConfigured: false, databaseStatus: "not_configured", databaseErrorCode: "", databaseCheckedAt: "", ...migrationSafety.health(), ...relationalFoundation.health(), ...identityBackfill.health(), ...relationalShadowSync.health() };'
    },
    {
      needle: '    databaseErrorCode: postgresLastErrorCode,\n    databaseCheckedAt: postgresLastCheckedAt\n  };',
      value: '    databaseErrorCode: postgresLastErrorCode,\n    databaseCheckedAt: postgresLastCheckedAt,\n    ...migrationSafety.health(),\n    ...relationalFoundation.health(),\n    ...identityBackfill.health(),\n    ...relationalShadowSync.health()\n  };'
    },
    {
      needle: '      const result = await postgresQuery(\n        `UPDATE ${POSTGRES_STORE_TABLE}\n         SET data = $1::jsonb, version = version + 1, updated_at = NOW()\n         WHERE id = $2 AND version = $3\n         RETURNING version`,\n        [serialized, "primary", expectedVersion]\n      );',
      value: '      const result = await relationalShadowSync.save({ serialized, storeData, expectedVersion });'
    }
  ];

  for (const replacement of replacements) {
    if (!source.includes(replacement.needle)) {
      throw new Error(`Could not install migration safety runtime replacement: ${replacement.needle.slice(0, 72)}`);
    }
    source = source.replace(replacement.needle, replacement.value);
  }

  await fs.writeFile(runtimePath, source);
}

export { runtimeMarker };
