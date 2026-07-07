import { randomBytes, pbkdf2Sync, createHash } from "crypto";
import { Pool } from "pg";

const email = "constrava@constravaai.com";
const displayName = "Constrava Admin";
const secret = process.env.DEV_LOGIN_KEY || "";
const databaseUrl = process.env.DATABASE_URL || "";

function userIdFor(value) {
  return "usr_" + createHash("sha256").update(String(value).toLowerCase()).digest("hex").slice(0, 24);
}

function passwordHash(value) {
  const salt = randomBytes(16).toString("hex");
  const iterations = 120000;
  const digest = pbkdf2Sync(String(value), salt, iterations, 32, "sha256").toString("hex");
  return `pbkdf2_sha256$${iterations}$${salt}$${digest}`;
}

async function main() {
  if (!secret) {
    console.log("Account bootstrap skipped: DEV_LOGIN_KEY is not set.");
    return;
  }
  if (!databaseUrl) {
    console.log("Account bootstrap skipped: DATABASE_URL is not set.");
    return;
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
  });

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(
      `INSERT INTO app_users (id, email, name, password_hash, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (email)
       DO UPDATE SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, updated_at = NOW()`,
      [userIdFor(email), email, displayName, passwordHash(secret)]
    );

    console.log("Constrava admin account ready.");
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Account bootstrap failed:", err.message);
  process.exit(0);
});
