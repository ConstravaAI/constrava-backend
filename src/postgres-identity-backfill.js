import crypto from "node:crypto";

export const IDENTITY_BACKFILL_MIGRATION_ID = "0003_identity_project_backfill";
export const IDENTITY_BACKFILL_SNAPSHOT_KEY = "before-0003-identity-project-backfill";

const BACKFILL_SPEC = [
  "users:id,email,name,role,authProvider,passwordSalt,passwordHash,emailVerifiedAt,metadata",
  "workspaces:id,name,ownerUserId,timestamps,metadata",
  "memberships:id,workspaceId,userId,role,status,timestamps,metadata",
  "invitations:id,workspaceId,email,userId,invitedByUserId,role,status,tokenHash,timestamps,metadata",
  "sessions:derivedRowId,userId,sha256Token,createdAt,expiresAt,lastSeenAt,activeWorkspaceMetadata",
  "externalAccounts:id,userOwner,provider,subject,email,displayName,status,encryptedCredentials,scopes,apps,settings,timestamps",
  "workspaceExternalAccounts:workspaceId,externalAccountId,linkedByUserId,settings"
].join("\n");

const identityBackfillChecksum = `sha256:${crypto.createHash("sha256").update(BACKFILL_SPEC).digest("hex")}`;
const DAY_MS = 24 * 60 * 60 * 1000;

function text(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

function iso(value, fallback = null) {
  if (!value) return fallback;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed.toISOString();
}

function json(value) {
  return JSON.stringify(value && typeof value === "object" ? value : {});
}

function without(source, omitted) {
  if (!source || typeof source !== "object") return {};
  const result = {};
  for (const [key, value] of Object.entries(source)) {
    if (!omitted.has(key) && value !== undefined) result[key] = value;
  }
  return result;
}

function hashToken(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function backfillError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function parseLegacyData(row) {
  if (!row) throw backfillError("LEGACY_STORE_MISSING", "The primary legacy store is missing.");
  if (typeof row.data === "string") {
    try { return JSON.parse(row.data); } catch { throw backfillError("LEGACY_STORE_INVALID", "The primary legacy store is not valid JSON."); }
  }
  if (!row.data || typeof row.data !== "object") throw backfillError("LEGACY_STORE_INVALID", "The primary legacy store does not contain an object.");
  return row.data;
}

function uniqueBy(items, key, code) {
  const seen = new Set();
  for (const item of items) {
    const value = key(item);
    if (!value || seen.has(value)) throw backfillError(code, `Legacy data contains a missing or duplicate identity: ${value || "(empty)"}.`);
    seen.add(value);
  }
}

function accountOwnerId(account, usersById) {
  const direct = text(account?.accountUserId);
  return usersById.has(direct) ? direct : "";
}

export function buildIdentityBackfill(storeData, legacyStoreVersion = 0) {
  const now = new Date().toISOString();
  const users = array(storeData?.users).filter((entry) => text(entry?.id) && text(entry?.email)).map((entry) => ({
    id: text(entry.id),
    email: text(entry.email).toLowerCase(),
    name: text(entry.name),
    role: text(entry.role || "user"),
    authProvider: text(entry.authProvider || "password"),
    passwordSalt: text(entry.passwordSalt),
    passwordHash: text(entry.passwordHash),
    emailVerifiedAt: iso(entry.emailVerifiedAt),
    createdAt: iso(entry.createdAt, now),
    updatedAt: iso(entry.updatedAt, iso(entry.createdAt, now)),
    metadata: without(entry, new Set(["id", "email", "name", "role", "authProvider", "passwordSalt", "passwordHash", "emailVerifiedAt", "createdAt", "updatedAt"]))
  }));
  uniqueBy(users, (entry) => entry.id, "BACKFILL_DUPLICATE_USER_ID");
  uniqueBy(users, (entry) => entry.email, "BACKFILL_DUPLICATE_USER_EMAIL");
  const usersById = new Map(users.map((entry) => [entry.id, entry]));

  const workspaces = array(storeData?.workspaces).filter((entry) => text(entry?.id)).map((entry) => ({
    id: text(entry.id),
    name: text(entry.name || "Untitled CRM project"),
    ownerUserId: usersById.has(text(entry.ownerUserId)) ? text(entry.ownerUserId) : null,
    createdAt: iso(entry.createdAt, now),
    updatedAt: iso(entry.updatedAt, iso(entry.createdAt, now)),
    metadata: without(entry, new Set(["id", "name", "ownerUserId", "createdAt", "updatedAt"]))
  }));
  uniqueBy(workspaces, (entry) => entry.id, "BACKFILL_DUPLICATE_WORKSPACE_ID");
  const workspacesById = new Map(workspaces.map((entry) => [entry.id, entry]));

  const memberships = array(storeData?.workspaceMembers).filter((entry) => text(entry?.id)).map((entry) => {
    const workspaceId = text(entry.workspaceId), userId = text(entry.userId);
    if (!workspacesById.has(workspaceId) || !usersById.has(userId)) throw backfillError("BACKFILL_DANGLING_MEMBERSHIP", `Membership ${text(entry.id)} does not have a valid user and project.`);
    return {
      id: text(entry.id), workspaceId, userId,
      role: text(entry.role || "member"), status: text(entry.status || "active"),
      joinedAt: iso(entry.joinedAt, now), lastOpenedAt: iso(entry.lastOpenedAt),
      createdAt: iso(entry.createdAt, iso(entry.joinedAt, now)), updatedAt: iso(entry.updatedAt, iso(entry.joinedAt, now)),
      metadata: without(entry, new Set(["id", "workspaceId", "userId", "role", "status", "joinedAt", "lastOpenedAt", "createdAt", "updatedAt"]))
    };
  });
  uniqueBy(memberships, (entry) => entry.id, "BACKFILL_DUPLICATE_MEMBERSHIP_ID");
  uniqueBy(memberships, (entry) => `${entry.workspaceId}:${entry.userId}`, "BACKFILL_DUPLICATE_MEMBERSHIP");
  const membersByWorkspace = new Map();
  for (const membership of memberships.filter((entry) => entry.status === "active")) {
    membersByWorkspace.set(membership.workspaceId, [...(membersByWorkspace.get(membership.workspaceId) || []), membership.userId]);
  }

  const invitations = array(storeData?.workspaceInvitations).filter((entry) => text(entry?.id)).map((entry) => {
    const workspaceId = text(entry.workspaceId);
    if (!workspacesById.has(workspaceId)) throw backfillError("BACKFILL_DANGLING_INVITATION", `Invitation ${text(entry.id)} does not have a valid project.`);
    const invitedUserId = usersById.has(text(entry.userId)) ? text(entry.userId) : null;
    const invitedByUserId = usersById.has(text(entry.invitedByUserId)) ? text(entry.invitedByUserId) : null;
    return {
      id: text(entry.id), workspaceId, email: text(entry.email).toLowerCase(), invitedUserId, invitedByUserId,
      role: text(entry.role || "member"), status: text(entry.status || "pending"), tokenHash: text(entry.tokenHash),
      expiresAt: iso(entry.expiresAt), acceptedAt: iso(entry.acceptedAt), createdAt: iso(entry.createdAt, now),
      updatedAt: iso(entry.updatedAt, iso(entry.createdAt, now)),
      metadata: without(entry, new Set(["id", "workspaceId", "email", "userId", "invitedByUserId", "role", "status", "tokenHash", "expiresAt", "acceptedAt", "createdAt", "updatedAt"]))
    };
  });
  uniqueBy(invitations, (entry) => entry.id, "BACKFILL_DUPLICATE_INVITATION_ID");

  let skippedSessions = 0;
  const sessions = [];
  for (const entry of array(storeData?.sessions)) {
    const rawId = String(entry?.id || ""), userId = text(entry?.userId);
    if (!rawId || !usersById.has(userId)) { skippedSessions += 1; continue; }
    const tokenDigest = hashToken(rawId);
    const createdAt = iso(entry.createdAt, now);
    sessions.push({
      id: `session_row_${tokenDigest.slice(0, 32)}`,
      userId,
      tokenHash: `sha256:${tokenDigest}`,
      createdAt,
      expiresAt: iso(entry.expiresAt, new Date(new Date(createdAt).getTime() + 30 * DAY_MS).toISOString()),
      lastSeenAt: iso(entry.lastSeenAt),
      metadata: without(entry, new Set(["id", "userId", "createdAt", "expiresAt", "lastSeenAt"]))
    });
  }
  uniqueBy(sessions, (entry) => entry.id, "BACKFILL_DUPLICATE_SESSION_ID");

  let skippedExternalAccounts = 0;
  let skippedExternalAccountLinks = 0;
  const externalAccounts = [];
  const externalAccountLinks = [];
  const sensitiveAccountKeys = new Set(["id", "accountUserId", "workspaceId", "linkedWorkspaceIds", "email", "displayName", "name", "status", "authorizationStatus", "oauthTokens", "oauthStateHash", "oauthStateExpiresAt", "oauthRequestedScopes", "pendingApps", "selectedApps", "grantedScopes", "providerSubject", "subject", "googleSubject", "createdAt", "updatedAt", "lastSyncAt"]);
  for (const [provider, entries] of [["google", array(storeData?.googleAccounts)], ["microsoft", array(storeData?.microsoftAccounts)]]) {
    for (const entry of entries) {
      const id = text(entry?.id), userId = accountOwnerId(entry, usersById);
      if (!id || !userId) { skippedExternalAccounts += 1; continue; }
      const requestedWorkspaceIds = [...new Set([
        ...array(entry.linkedWorkspaceIds).map(text),
        text(entry.workspaceId)
      ].filter(Boolean))];
      const linkedWorkspaceIds = requestedWorkspaceIds.filter((workspaceId) => {
        const workspace = workspacesById.get(workspaceId);
        return workspace && (workspace.ownerUserId === userId || (membersByWorkspace.get(workspaceId) || []).includes(userId));
      });
      skippedExternalAccountLinks += requestedWorkspaceIds.length - linkedWorkspaceIds.length;
      externalAccounts.push({
        id, userId, provider,
        providerSubject: text(entry.providerSubject || entry.subject || entry.googleSubject),
        email: text(entry.email).toLowerCase(), displayName: text(entry.displayName || entry.name),
        status: text(entry.status || "draft"), authorizationStatus: text(entry.authorizationStatus || "ready"),
        credentialsCiphertext: String(entry.oauthTokens || ""),
        grantedScopes: [...new Set(array(entry.grantedScopes).map(text).filter(Boolean))],
        selectedApps: [...new Set(array(entry.selectedApps).map(text).filter(Boolean))],
        settings: without(entry, sensitiveAccountKeys),
        createdAt: iso(entry.createdAt, now), updatedAt: iso(entry.updatedAt, iso(entry.createdAt, now)),
        lastSyncedAt: iso(entry.lastSyncAt || entry.appScan?.scannedAt)
      });
      for (const workspaceId of linkedWorkspaceIds) {
        externalAccountLinks.push({ workspaceId, externalAccountId: id, linkedByUserId: userId, settings: { provider } });
      }
    }
  }
  uniqueBy(externalAccounts, (entry) => entry.id, "BACKFILL_DUPLICATE_EXTERNAL_ACCOUNT_ID");
  uniqueBy(externalAccountLinks, (entry) => `${entry.workspaceId}:${entry.externalAccountId}`, "BACKFILL_DUPLICATE_EXTERNAL_ACCOUNT_LINK");

  return {
    legacyStoreVersion: Number(legacyStoreVersion || 0), users, workspaces, memberships, invitations, sessions,
    externalAccounts, externalAccountLinks, skippedSessions, skippedExternalAccounts, skippedExternalAccountLinks
  };
}

export async function syncIdentityBackfill(client, backfill, { prune = false } = {}) {
  if (prune) {
    const linkKeys = backfill.externalAccountLinks.map((row) => `${row.workspaceId}\u001f${row.externalAccountId}`);
    await client.query(
      `DELETE FROM public.constrava_workspace_external_accounts
       WHERE NOT ((workspace_id || CHR(31) || external_account_id) = ANY($1::text[]))`,
      [linkKeys]
    );
    for (const [table, ids] of [
      ["constrava_sessions", backfill.sessions.map((row) => row.id)],
      ["constrava_workspace_invitations", backfill.invitations.map((row) => row.id)],
      ["constrava_workspace_memberships", backfill.memberships.map((row) => row.id)],
      ["constrava_external_accounts", backfill.externalAccounts.map((row) => row.id)],
      ["constrava_workspaces", backfill.workspaces.map((row) => row.id)],
      ["constrava_users", backfill.users.map((row) => row.id)]
    ]) {
      await client.query(`DELETE FROM public.${table} WHERE NOT (id = ANY($1::text[]))`, [ids]);
    }
  }
  for (const row of backfill.users) await client.query(
    `INSERT INTO public.constrava_users (id, email, name, role, auth_provider, password_salt, password_hash, email_verified_at, created_at, updated_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
     ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email, name=EXCLUDED.name, role=EXCLUDED.role, auth_provider=EXCLUDED.auth_provider, password_salt=EXCLUDED.password_salt, password_hash=EXCLUDED.password_hash, email_verified_at=EXCLUDED.email_verified_at, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, metadata=EXCLUDED.metadata`,
    [row.id, row.email, row.name, row.role, row.authProvider, row.passwordSalt, row.passwordHash, row.emailVerifiedAt, row.createdAt, row.updatedAt, json(row.metadata)]
  );
  for (const row of backfill.workspaces) await client.query(
    `INSERT INTO public.constrava_workspaces (id, name, owner_user_id, created_at, updated_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, owner_user_id=EXCLUDED.owner_user_id, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, metadata=EXCLUDED.metadata`,
    [row.id, row.name, row.ownerUserId, row.createdAt, row.updatedAt, json(row.metadata)]
  );
  for (const row of backfill.memberships) await client.query(
    `INSERT INTO public.constrava_workspace_memberships (id, workspace_id, user_id, role, status, joined_at, last_opened_at, created_at, updated_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
     ON CONFLICT (workspace_id, user_id) DO UPDATE SET role=EXCLUDED.role, status=EXCLUDED.status, joined_at=EXCLUDED.joined_at, last_opened_at=EXCLUDED.last_opened_at, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, metadata=EXCLUDED.metadata`,
    [row.id, row.workspaceId, row.userId, row.role, row.status, row.joinedAt, row.lastOpenedAt, row.createdAt, row.updatedAt, json(row.metadata)]
  );
  for (const row of backfill.invitations) await client.query(
    `INSERT INTO public.constrava_workspace_invitations (id, workspace_id, email, invited_user_id, invited_by_user_id, role, status, token_hash, expires_at, accepted_at, created_at, updated_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
     ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email, invited_user_id=EXCLUDED.invited_user_id, invited_by_user_id=EXCLUDED.invited_by_user_id, role=EXCLUDED.role, status=EXCLUDED.status, token_hash=EXCLUDED.token_hash, expires_at=EXCLUDED.expires_at, accepted_at=EXCLUDED.accepted_at, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, metadata=EXCLUDED.metadata`,
    [row.id, row.workspaceId, row.email, row.invitedUserId, row.invitedByUserId, row.role, row.status, row.tokenHash, row.expiresAt, row.acceptedAt, row.createdAt, row.updatedAt, json(row.metadata)]
  );
  for (const row of backfill.sessions) await client.query(
    `INSERT INTO public.constrava_sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
     ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id, token_hash=EXCLUDED.token_hash, created_at=EXCLUDED.created_at, expires_at=EXCLUDED.expires_at, last_seen_at=EXCLUDED.last_seen_at, metadata=EXCLUDED.metadata`,
    [row.id, row.userId, row.tokenHash, row.createdAt, row.expiresAt, row.lastSeenAt, json(row.metadata)]
  );
  for (const row of backfill.externalAccounts) await client.query(
    `INSERT INTO public.constrava_external_accounts (id, user_id, provider, provider_subject, email, display_name, status, authorization_status, credentials_ciphertext, granted_scopes, selected_apps, settings, created_at, updated_at, last_synced_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text[],$11::text[],$12::jsonb,$13,$14,$15)
     ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id, provider=EXCLUDED.provider, provider_subject=EXCLUDED.provider_subject, email=EXCLUDED.email, display_name=EXCLUDED.display_name, status=EXCLUDED.status, authorization_status=EXCLUDED.authorization_status, credentials_ciphertext=EXCLUDED.credentials_ciphertext, granted_scopes=EXCLUDED.granted_scopes, selected_apps=EXCLUDED.selected_apps, settings=EXCLUDED.settings, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, last_synced_at=EXCLUDED.last_synced_at`,
    [row.id, row.userId, row.provider, row.providerSubject, row.email, row.displayName, row.status, row.authorizationStatus, row.credentialsCiphertext, row.grantedScopes, row.selectedApps, json(row.settings), row.createdAt, row.updatedAt, row.lastSyncedAt]
  );
  for (const row of backfill.externalAccountLinks) await client.query(
    `INSERT INTO public.constrava_workspace_external_accounts (workspace_id, external_account_id, linked_by_user_id, settings)
     VALUES ($1,$2,$3,$4::jsonb)
     ON CONFLICT (workspace_id, external_account_id) DO UPDATE SET linked_by_user_id=EXCLUDED.linked_by_user_id, settings=EXCLUDED.settings`,
    [row.workspaceId, row.externalAccountId, row.linkedByUserId, json(row.settings)]
  );
}

export const IDENTITY_BACKFILL_MIGRATION = Object.freeze({
  id: IDENTITY_BACKFILL_MIGRATION_ID,
  name: "Identity and project data backfill",
  checksum: identityBackfillChecksum,
  snapshotKey: IDENTITY_BACKFILL_SNAPSHOT_KEY,
  snapshotLabel: "Before identity and project data backfill",
  async up(client) {
    const legacy = await client.query("SELECT data, version FROM public.constrava_app_store_v2 WHERE id = 'primary' FOR UPDATE");
    const backfill = buildIdentityBackfill(parseLegacyData(legacy.rows[0]), legacy.rows[0]?.version);
    await syncIdentityBackfill(client, backfill);
    return {
      legacyStoreVersion: backfill.legacyStoreVersion,
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
});

function safeErrorCode(error) {
  return String(error?.code || "identity_backfill_failed").replace(/[^a-z0-9_-]/gi, "").slice(0, 64) || "identity_backfill_failed";
}

export function createIdentityBackfill({ migrationSafety } = {}) {
  let readyPromise = null, status = migrationSafety ? "checking" : "not_configured", errorCode = "", checkedAt = "", counts = {};
  async function ensure() {
    if (!migrationSafety) return;
    if (!readyPromise) {
      status = "checking";
      readyPromise = migrationSafety.runMigration(IDENTITY_BACKFILL_MIGRATION).then((result) => {
        status = "ready"; errorCode = ""; checkedAt = new Date().toISOString(); counts = result.details || {}; return result;
      }).catch((error) => {
        status = "unavailable"; errorCode = safeErrorCode(error); checkedAt = new Date().toISOString(); readyPromise = null; throw error;
      });
    }
    return readyPromise;
  }
  function health() {
    return {
      relationalBackfillStatus: status,
      relationalBackfillVersion: IDENTITY_BACKFILL_MIGRATION_ID,
      relationalBackfillErrorCode: errorCode,
      relationalBackfillCheckedAt: checkedAt,
      relationalBackfillCompleted: status === "ready",
      relationalBackfillCounts: counts,
      relationalDualWriteEnabled: false
    };
  }
  return { ensure, health };
}
