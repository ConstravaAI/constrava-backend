import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimePath = path.join(here, ".server.generated.js");
const runtimeMarker = "migration-safety-runtime-v1";

let source = await fs.readFile(runtimePath, "utf8");

if (!source.includes(runtimeMarker)) {
  const replacements = [
    {
      needle: 'import readXlsxFile from "read-excel-file/node";',
      value: 'import readXlsxFile from "read-excel-file/node";\nimport { createMigrationSafety } from "./postgres-migration-safety.js";'
    },
    {
      needle: 'const POSTGRES_STORE_TABLE = "public.constrava_app_store_v2";',
      value: 'const POSTGRES_STORE_TABLE = "public.constrava_app_store_v2";\n// migration-safety-runtime-v1\nconst migrationSafety = createMigrationSafety({ pool: postgresPool, requestedStorageMode: process.env.DATA_STORAGE_MODE });'
    },
    {
      needle: '      `);\n      postgresStatus = "ready";',
      value: '      `);\n      await migrationSafety.ensure();\n      postgresStatus = "ready";'
    },
    {
      needle: '    return { postgresStoreConfigured: false, databaseStatus: "not_configured", databaseErrorCode: "", databaseCheckedAt: "" };',
      value: '    return { postgresStoreConfigured: false, databaseStatus: "not_configured", databaseErrorCode: "", databaseCheckedAt: "", ...migrationSafety.health() };'
    },
    {
      needle: '    databaseErrorCode: postgresLastErrorCode,\n    databaseCheckedAt: postgresLastCheckedAt\n  };',
      value: '    databaseErrorCode: postgresLastErrorCode,\n    databaseCheckedAt: postgresLastCheckedAt,\n    ...migrationSafety.health()\n  };'
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
