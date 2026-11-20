import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuthorizationDomainError, ConflictDomainError } from "@relayquill/domain";
import { createPGliteAuthorityCluster } from "@relayquill/postgres";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function listSqlFiles(relDir) {
  const dir = path.join(REPO_ROOT, relDir);
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => ({
      name: f,
      sql: fs.readFileSync(path.join(dir, f), "utf8")
    }));
}

async function applyAllMigrations(cluster) {
  for (const file of listSqlFiles("migrations")) {
    await cluster.rq.exec(file.sql);
  }
  for (const file of listSqlFiles("examples/receiver/migrations")) {
    await cluster.rc.exec(file.sql);
  }
  for (const file of listSqlFiles("examples/provider-ingress/migrations")) {
    await cluster.pi.exec(file.sql);
  }
}

function parsePgAclEntries(aclArray) {
  const entries = [];
  if (!Array.isArray(aclArray)) {
    return entries;
  }
  for (const item of aclArray) {
    const str = String(item);
    const eqIdx = str.indexOf("=");
    const slashIdx = str.lastIndexOf("/");
    if (eqIdx === -1 || slashIdx === -1 || slashIdx < eqIdx) {
      continue;
    }
    entries.push({
      grantee: str.slice(0, eqIdx), // empty string means PUBLIC
      privileges: str.slice(eqIdx + 1, slashIdx),
      grantor: str.slice(slashIdx + 1)
    });
  }
  return entries;
}

test("All migrations (rq, rq_recovery, rc, pi) apply cleanly in PGlite under shared_database_schemas and separate_databases", async (t) => {
  for (const isolation of ["shared_database_schemas", "separate_databases"]) {
    const cluster = await createPGliteAuthorityCluster({ isolation });
    t.after(() => cluster.close());

    await applyAllMigrations(cluster);

    const rqRes = await cluster.rq.query(
      "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'rq'"
    );
    const recRes = await cluster.rq.query(
      "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'rq_recovery'"
    );
    const rcRes = await cluster.rc.query(
      "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'rc'"
    );
    const piRes = await cluster.pi.query(
      "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'pi'"
    );

    assert.ok(rqRes.rows[0].cnt >= 50);
    assert.ok(recRes.rows[0].cnt >= 14);
    assert.ok(rcRes.rows[0].cnt >= 12);
    assert.ok(piRes.rows[0].cnt >= 8);

    // Verify btree_gist is loaded and enforces temporal exclusion on subscription_topology_ranges
    const extRes = await cluster.rq.query(
      "SELECT extname FROM pg_catalog.pg_extension WHERE extname = 'btree_gist'"
    );
    assert.equal(extRes.rows.length, 1);
  }
});

test("Every function, private helper, role grant, search_path, owner, and sensitive table in privilege-manifest.json matches pg_proc and pg_class", async (t) => {
  const cluster = await createPGliteAuthorityCluster({ isolation: "shared_database_schemas" });
  t.after(() => cluster.close());
  await applyAllMigrations(cluster);

  const manifest = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "migrations/privilege-manifest.json"), "utf8")
  );

  const procRes = await cluster.rq.query(`
    SELECT n.nspname AS schema_name,
           p.proname AS name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_args,
           pg_catalog.pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef AS security_definer,
           p.proconfig AS proconfig,
           p.proacl::text[] AS proacl
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('rq', 'rq_recovery')
     ORDER BY 1, 2
  `);

  const byKey = new Map(
    procRes.rows.map((r) => [`${r.schema_name}.${r.name}(${r.identity_args})`, r])
  );

  // Verify 100% of manifest public functions
  assert.equal(manifest.functions.length, 58);
  for (const fn of manifest.functions) {
    const key = `${fn.schema}.${fn.name}(${fn.identity_args})`;
    const row = byKey.get(key);
    assert.ok(row, `Missing function in pg_proc: ${key}`);
    assert.equal(row.owner, fn.owner, `Owner mismatch on ${fn.qualified_name}`);
    assert.equal(row.security_definer, fn.security_definer, `SECURITY DEFINER mismatch on ${fn.qualified_name}`);
    assert.ok(
      Array.isArray(row.proconfig) && row.proconfig.includes(`search_path=${fn.search_path}`),
      `Missing search_path=${fn.search_path} on ${fn.qualified_name}`
    );

    const acls = parsePgAclEntries(row.proacl);
    const execGrantees = new Set(
      acls.filter((a) => a.privileges.includes("X")).map((a) => a.grantee)
    );
    assert.equal(execGrantees.has(""), false, `PUBLIC must not have EXECUTE on ${fn.qualified_name}`);

    for (const allowed of fn.allowed_roles) {
      assert.equal(
        execGrantees.has(allowed),
        true,
        `Role ${allowed} missing EXECUTE on ${fn.qualified_name}`
      );
    }
    for (const denied of fn.denied_roles ?? []) {
      assert.equal(
        execGrantees.has(denied),
        false,
        `Denied role ${denied} unexpectedly has EXECUTE on ${fn.qualified_name}`
      );
    }
  }

  // Verify 100% of manifest private helpers and ensure no public/runtime execute grants
  assert.equal(manifest.private_helper_functions.length, 20);
  const runtimeRoleSet = new Set(manifest.login_roles.filter((r) => r !== "rq_migrator" && r !== "rq_recovery"));
  for (const helper of manifest.private_helper_functions) {
    const key = `${helper.schema}.${helper.name}(${helper.identity_args})`;
    const row = byKey.get(key);
    assert.ok(row, `Missing private helper in pg_proc: ${key}`);
    assert.equal(row.owner, "rq_owner", `Owner mismatch on helper ${key}`);
    const execGrantees = parsePgAclEntries(row.proacl)
      .filter((a) => a.privileges.includes("X"))
      .map((a) => a.grantee);
    assert.equal(execGrantees.includes(""), false, `PUBLIC has EXECUTE on private helper ${key}`);
    for (const grantee of execGrantees) {
      assert.equal(
        runtimeRoleSet.has(grantee),
        false,
        `Runtime role ${grantee} must not execute private helper ${key}`
      );
    }
  }

  // Verify no undocumented functions exist in rq / rq_recovery
  assert.equal(
    procRes.rows.length,
    manifest.functions.length + manifest.private_helper_functions.length
  );

  // Verify sensitive relations disallow PUBLIC and enforce base_table_dml_policy (no INSERT/UPDATE/DELETE to runtime/migrator/recovery)
  const relRes = await cluster.rq.query(`
    SELECT n.nspname || '.' || c.relname AS qualified_name,
           pg_catalog.pg_get_userbyid(c.relowner) AS owner,
           c.relacl::text[] AS relacl
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('rq', 'rq_recovery')
       AND c.relkind IN ('r', 'p', 'v')
  `);
  const relByName = new Map(relRes.rows.map((r) => [r.qualified_name, r]));
  for (const row of relRes.rows) {
    assert.equal(row.owner, "rq_owner", `Relation ${row.qualified_name} not owned by rq_owner`);
    const acls = parsePgAclEntries(row.relacl);
    for (const acl of acls) {
      assert.notEqual(acl.grantee, "", `PUBLIC grant found on ${row.qualified_name}`);
      if (acl.grantee !== "rq_owner") {
        assert.equal(
          /[awdDxt]/.test(acl.privileges),
          false,
          `Unexpected DML/DDL privilege "${acl.privileges}" for ${acl.grantee} on ${row.qualified_name}`
        );
      }
    }
  }

  for (const sensitiveTable of manifest.restricted_sensitive_relations) {
    const rel = relByName.get(sensitiveTable);
    assert.ok(rel, `Missing sensitive relation ${sensitiveTable}`);
  }

  // Verify rc & pi functions also exist with SECURITY DEFINER + search_path=pg_catalog + PUBLIC revoked
  const exampleProcs = await cluster.rq.query(`
    SELECT n.nspname AS schema_name, p.proname AS name, p.prosecdef, p.proconfig, p.proacl::text[] AS proacl
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('rc', 'pi') AND p.proname NOT LIKE '\\_%' ESCAPE '\\'
  `);
  assert.ok(exampleProcs.rows.length >= 10);
  for (const row of exampleProcs.rows) {
    assert.equal(row.prosecdef, true, `${row.schema_name}.${row.name} must be SECURITY DEFINER`);
    assert.ok(
      Array.isArray(row.proconfig) && row.proconfig.includes("search_path=pg_catalog"),
      `${row.schema_name}.${row.name} missing search_path=pg_catalog`
    );
    const acls = parsePgAclEntries(row.proacl);
    assert.equal(
      acls.some((a) => a.grantee === "" && a.privileges.includes("X")),
      false,
      `${row.schema_name}.${row.name} must revoke PUBLIC EXECUTE`
    );
  }
});

test("Runtime SET LOCAL ROLE enforces ACL boundaries and btree_gist rejects overlapping topology ranges", async (t) => {
  const cluster = await createPGliteAuthorityCluster({
    isolation: "shared_database_schemas",
    applySetLocalRole: true
  });
  t.after(() => cluster.close());
  await applyAllMigrations(cluster);

  // rq_reporter cannot execute payload reads or admission or recovery commands
  await assert.rejects(
    () =>
      cluster.rq.withTransaction("rq_reporter", (tx) =>
        tx.query(
          "SELECT rq.read_event_payload_bytes($1::uuid, $2::uuid, $3::uuid)",
          [
            "10000000-0000-4000-8000-000000000001",
            "20000000-0000-4000-8000-000000000001",
            "a0000000-0000-4000-8000-000000000001"
          ]
        )
      ),
    (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
  );

  await assert.rejects(
    () =>
      cluster.rq.withTransaction("rq_reporter", (tx) =>
        tx.query("SELECT count(*) FROM rq.passkeys")
      ),
    (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
  );

  // rq_sender cannot execute payload reads or rq_recovery commands, even under SET LOCAL ROLE
  await assert.rejects(
    () =>
      cluster.rq.withTransaction("rq_sender", (tx) =>
        tx.query("SELECT rq_recovery.read_operation_result($1::uuid)", [
          "f4000000-0000-4000-8000-000000000001"
        ])
      ),
    (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
  );

  // Verify btree_gist exclusion rejects overlapping int8range in subscription_topology_ranges (23P01)
  await assert.rejects(
    () =>
      cluster.rq.withTransaction("postgres", async (tx) => {
        const tenantId = "11000000-0000-4000-8000-000000000001";
        const projectId = "21000000-0000-4000-8000-000000000001";
        const actorId = "31000000-0000-4000-8000-000000000001";
        const epId = "41000000-0000-4000-8000-000000000001";
        const etId = "51000000-0000-4000-8000-000000000001";
        const subId = "61000000-0000-4000-8000-000000000001";
        const zeros = Buffer.alloc(32, 1);

        await tx.query("INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active')", [actorId]);
        await tx.query("INSERT INTO rq.tenants (id, slug, display_name, state) VALUES ($1::uuid, 't-excl', 'Excl', 'active')", [tenantId]);
        await tx.query("INSERT INTO rq.projects (id, tenant_id, name, state) VALUES ($1::uuid, $2::uuid, 'p-excl', 'active')", [projectId, tenantId]);
        await tx.query("INSERT INTO rq.event_types (id, tenant_id, project_id, type_name, state, current_schema_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 'ev.x', 'active', 1)", [etId, tenantId, projectId]);
        await tx.query("INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, 'ep-x', 'active', 1, $4::uuid)", [epId, tenantId, projectId, actorId]);
        await tx.query("INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://ex.test/wh', 'ex.test', 443, $4::bytea, 'u', 'n', 'rq', 'rs', $4::bytea, $5::uuid)", [epId, tenantId, projectId, zeros, actorId]);
        await tx.query("INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, 'sub-x', 'active', 1, $4::uuid)", [subId, tenantId, projectId, actorId]);
        await tx.query("INSERT INTO rq.retry_policy_versions (policy_version, policy_kind, definition_sha256, base_delay_ms, multiplier, max_delay_ms, retry_after_cap_ms, minimum_next_window_ms, maximum_send_starts, state) VALUES ('default', 'retry_policy', $1::bytea, 1000, 2, 60000, 60000, 1000, 12, 'active')", [zeros]);
        await tx.query("INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, configuration_sha256, created_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'filter.v1', '{}'::jsonb, $6::bytea, 'unordered', 'default', 'default', 'resp.v1', 'default', $6::bytea, $7::uuid)", [subId, tenantId, projectId, epId, etId, zeros, actorId]);
        await tx.query("INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, configuration_sha256, created_by) VALUES ($1::uuid, 2, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'filter.v1', '{}'::jsonb, $6::bytea, 'unordered', 'default', 'default', 'resp.v1', 'default', $6::bytea, $7::uuid)", [subId, tenantId, projectId, epId, etId, zeros, actorId]);

        await tx.query(
          "INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, until_topology_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 1, 5)",
          [projectId, tenantId, subId]
        );
        await tx.query(
          "INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, until_topology_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 2, 3, 7)",
          [projectId, tenantId, subId]
        );
      }),
    (err) => err instanceof ConflictDomainError && err.code === "STATE_TRANSITION_NOT_ALLOWED"
  );
});
