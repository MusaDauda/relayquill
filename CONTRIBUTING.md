# Contributing to Relayquill

Thank you for contributing to Relayquill. This guide defines the workspace dependency layer rules, multi-tier verification gates, and atomic commit standards enforced across the repository.

---

## 1. Prerequisites

- **Node.js**: `>= 24.16.0 < 27` (`.node-version` pins `24.16.0`)
- **npm**: `11.13.0`
- **Go**: `1.27.1` (for `tools/broker-launcher`)
- **Docker & Docker Compose v2+** (optional locally; used for `infra/compose.dev.yaml`, `infra/compose.prod.yaml`, and container image verification)

Install workspace dependencies cleanly from the lockfile:

```bash
npm ci
```

All unit, tooling, migration, and E2E tests execute offline in zero-daemon mode using `@electric-sql/pglite` and `InMemoryJetStreamBroker`. See [docs/dev-setup.md](./docs/dev-setup.md) for containerized and optional `.env` remote development workflows.

---

## 2. Workspace Dependency Layer Rules (`npm run boundaries`)

Relayquill organizes its 22 workspaces into strict architectural tiers enforced mechanically by `tools/verify-import-boundaries.mjs` (`npm run boundaries`). The verifier checks `package.json` dependency declarations, `tsconfig.json` project references, TypeScript/JavaScript AST module specifiers (`import`, `export`, dynamic `import()`, `require()`, `process.getBuiltinModule`), relative path containment, package `exports` subpaths, dependency cycles, and SDK `esbuild` bundle metafiles (`build/metafile.json`).

### Architectural Tiers & Allowed Internal Dependencies

| Tier | Workspace | Path | Allowed `@relayquill/*` Dependencies | Key Restrictions |
|---|---|---|---|---|
| **1 — Core Domain & Contracts** | `@relayquill/domain` | `packages/domain` | *(none)* | **Zero Node built-ins** (`node:*` forbidden); pure ES2023 types, UUID brands, errors, and state machines. |
| **1 — Core Domain & Contracts** | `@relayquill/contracts` | `packages/contracts` | `domain` | **Zero Node built-ins**; HTTP envelopes, capabilities, cursors, SSE watch frames, RFC 8785 canonical commands, webhook & broker wire contracts. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/runtime` | `packages/runtime` | `domain`, `contracts` | Config/env loader, Win32 DACL & POSIX `0600` IPC, secret custody, deadlines, lifecycle, OpenTelemetry. No DB, broker, HTTP server, or UI libs. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/event-schema` | `packages/event-schema` | `domain`, `contracts`, `runtime` | `lossless-json` parser, 128-digit decimals, bounded JSON Schema 2020-12 (`relayquill.event-schema.v1`), `worker_threads` pool, filter AST, ordering extractor, v2 projections. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/egress` | `packages/egress` | `domain`, `contracts`, `runtime` | WHATWG HTTPS URL policy, offline IANA CIDR deny list (`ipaddr.js`), isolated DNS resolver, pinned single-use HTTPS connector. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/signing` | `packages/signing` | `domain`, `contracts`, `runtime` | 25-field `rq.webhook-signature.v1` HMAC-SHA256 signer/verifier, single-occurrence raw-header parser, key rotation, `204` endpoint proof, `receiver_local_commit_v1` receipts. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/broker` | `packages/broker` | `domain`, `contracts`, `runtime` | `@nats-io/transport-node` + `@nats-io/jetstream` TLS/NKey/creds adapter, `RELAYQUILL_EVENTS_V1`/`RELAYQUILL_FANOUT_V1` topology contract, `InMemoryJetStreamBroker`. |
| **1 — Runtime & Boundary Libraries** | `@relayquill/auth` | `packages/auth` | `domain`, `contracts`, `runtime` | WebAuthn passkeys (`@simplewebauthn/server`), challenges, enrollment intents, `__Host-rq_session`, derived CSRF, step-up proofs, `rq_p1` credentials, RBAC & data grants. |
| **1 — Application & Persistence** | `@relayquill/application` | `packages/application` | `domain`, `contracts`, `auth`, `event-schema`, `signing`, `egress`, `broker`, `runtime` | **Forbids `@relayquill/postgres`, `pg`, `@electric-sql/*`, `fastify`, and UI libraries.** Defines pure port interfaces and orchestrates all core use cases. |
| **1 — Application & Persistence** | `@relayquill/postgres` | `packages/postgres` | `domain`, `contracts`, `application`, `auth`, `runtime` | Standard `pg` pool + `@electric-sql/pglite` adapter, custom OID `1184`/`1114`/`20` parsers, ranked `READ COMMITTED` transactions with jittered contention retries, `rq` repositories. |
| **2 — Public SDKs** | `@relayquill/producer-sdk` | `packages/producer-sdk` | `domain`, `contracts` | **Zero Node built-ins** (100% portable Web Crypto + `fetch` ESM); self-contained `esbuild` bundle inlining internal contracts with zero private `@relayquill/*` runtime dependencies. |
| **2 — Public SDKs** | `@relayquill/receiver-sdk` | `packages/receiver-sdk` | `domain`, `contracts`, `signing` | Self-contained ESM bundle for webhook signature verification, `204` endpoint proofs, signed receipts, and idempotent/ordered consumer persistence. |
| **3 — Server Applications** | `@relayquill/api` | `apps/api` | `domain`, `contracts`, `runtime`, `auth`, `application`, `postgres`, `event-schema`, `signing` | Fastify HTTP control/admission API & SSE watch server. Forbids `@relayquill/broker`, `@relayquill/egress`, and cross-app imports. |
| **3 — Server Applications** | `@relayquill/relay` | `apps/relay` | `domain`, `contracts`, `runtime`, `application`, `postgres`, `broker` | Outbox lease claim -> JetStream publisher worker. Forbids `fastify`, `egress`, `signing`, `auth`. |
| **3 — Server Applications** | `@relayquill/fanout` | `apps/fanout` | `domain`, `contracts`, `runtime`, `application`, `postgres`, `broker`, `event-schema` | JetStream pull consumer -> ordered subscription matcher. Forbids `fastify`, `egress`, `signing`, `auth`. |
| **3 — Server Applications** | `@relayquill/sender` | `apps/sender` | `domain`, `contracts`, `runtime`, `application`, `postgres`, `egress`, `signing` | WDRR rate-governed, DNS-pinned HTTPS webhook delivery worker. Forbids `fastify`, `broker`, `auth`. |
| **3 — Server Applications** | `@relayquill/coordinator` | `apps/coordinator` | `domain`, `contracts`, `runtime`, `application`, `postgres`, `broker` | Reaper, eligibility promoter, publication recovery, retention, and projection compaction worker. Forbids `fastify`, `egress`, `auth`. |
| **3 — Server Applications** | `@relayquill/admin` | `apps/admin` | `domain`, `contracts`, `runtime`, `auth`, `application`, `postgres`, `broker`, `signing` | Protected operator CLI (`db migrate`, `broker ensure`, `provider serve`, `diagnostics`, `recovery`). Forbids `fastify` and UI libs. |
| **3 — Independent Examples** | `@relayquill/example-receiver` | `examples/receiver` | `domain`, `contracts`, `receiver-sdk`, `runtime` | Independent webhook receiver (`rc` authority). Forbids all private server libraries (`postgres`, `application`, `auth`, `egress`, `broker`, `signing`). |
| **3 — Independent Examples** | `@relayquill/example-provider-ingress` | `examples/provider-ingress` | `domain`, `contracts`, `producer-sdk`, `runtime` | Stripe/Paystack callback verifier & forwarder (`pi` authority). Forbids all private server libraries. |
| **3 — Independent Examples** | `@relayquill/example-producer` | `examples/producer` | `domain`, `contracts`, `producer-sdk` | Reference producer client. Forbids all private server libraries, DB drivers, and `@relayquill/runtime`. |
| **4 — Browser Console** | `@relayquill/console` | `apps/console` | `domain`, `contracts`, `producer-sdk` | **Zero Node built-ins**; React 19 + Vite WCAG AA operator console. Forbids all server/DB/broker packages and `@simplewebauthn/server`. |

### Boundary Rules to Keep in Mind

1. **No Relative Escapes or Private Subpaths**: Never import across workspace boundaries via `../../packages/...` or deep subpaths not declared in the target package's `exports` map.
2. **Declare What You Import**: Every `@relayquill/*` import in `src/` must be declared in the importing workspace's `package.json` and allowed by `WORKSPACE_POLICIES` in `tools/verify-import-boundaries.mjs`.
3. **Topological Build Order**: `tools/build-workspaces.mjs` and `tools/typecheck-workspaces.mjs` sort workspaces topologically according to `REVIEWED_WORKSPACE_ORDER`. Cyclic workspace dependencies fail immediately.

---

## 3. Multi-Tier Verification

Every change must pass all applicable verification gates before opening or merging a pull request.

### Tier 1 — Repository Hygiene & Import Boundaries

```bash
npm run hygiene
npm run boundaries
```

- `npm run hygiene` (`tools/check-hygiene.mjs`) scans all tracked and untracked non-ignored files plus git commit history (`git log --all`) to enforce:
  - `.gitignore` and `.dockerignore` exclusion rules.
  - Zero external specification numbering, forbidden specification artifact nouns, or third-party automated tooling attribution trailers in source files, comments, documentation, or commit messages.
  - Zero raw secret JSON keys (`*password`, `*secret`, `*private_key`, `*nkey_seed`, `*creds`, `*api_key`, `*signing_key`, `*token`), PEM headers, `rq_p1.` credential literals, credential-bearing PostgreSQL URLs, machine-specific user paths, or hardcoded `.sock` paths inside `config/`.
- `npm run boundaries` (`tools/verify-import-boundaries.mjs`) validates all 22 workspaces, AST imports, and SDK bundle metafiles.

### Tier 2 — TypeScript Typechecking, Linting & Topological Build

```bash
npm run typecheck
npm run lint
npm run build
```

- `tsconfig.base.json` enforces `strict: true`, `noUncheckedIndexedAccess: true`, `exactOptionalPropertyTypes: true`, `verbatimModuleSyntax: true`, and `isolatedModules: true`.
- `eslint.config.mjs` enforces `typescript-eslint` `recommendedTypeChecked` with `--max-warnings 0`, `@typescript-eslint/no-explicit-any: "error"`, `@typescript-eslint/consistent-type-imports`, and `no-eval` / `no-new-func`.
- To target a single workspace during iteration:
  ```bash
  node tools/typecheck-workspaces.mjs --workspace @relayquill/<name>
  node tools/build-workspaces.mjs --workspace @relayquill/<name>
  npm run lint --workspace @relayquill/<name>
  ```

### Tier 3 — Unit, Tooling & PGlite SQL Contract Tests

```bash
npm test
node --test tests/contracts
```

- `npm test` runs `node --test tests/tooling` (hygiene scanner, import boundary verifier, workspace topological sorter, and `config/*.json` schema validation) followed by `npm run test --workspaces --if-present`.
- `node --test tests/contracts` executes all 14 SQL migrations (`migrations/0001..0009`, `examples/receiver/migrations/0001..0002`, `examples/provider-ingress/migrations/0001..0003`) inside `@electric-sql/pglite` (`btree_gist` enabled) and verifies 1-to-1 parity between `migrations/privilege-manifest.json` and `pg_proc` (`SECURITY DEFINER`, `search_path = pg_catalog`, owner, argument signatures, role EXECUTE grants, and direct-table DML denials).

### Tier 4 — Standalone SDK Packing & Isolated Consumer Check

```bash
node tools/pack-sdks.mjs
```

- Bundles `@relayquill/producer-sdk` and `@relayquill/receiver-sdk` with `esbuild`, rolls up public `.d.ts` declarations via `@microsoft/api-extractor`, packs publishable `.tgz` tarballs with zero private `@relayquill/*` dependencies, and installs them into an isolated temporary consumer directory to execute runtime smoke checks.

### Tier 5 — Embedded Go Broker Launcher Verification

```bash
cd tools/broker-launcher
go vet ./...
go test -race -count=1 ./...
```

- Exercises `tools/broker-launcher` (`cmd/relayquill-broker`, `internal/broker`, `internal/custody`, `internal/topology`), including handshake-first client TLS, 3-node cluster route mTLS peer SAN verification, and scoped NKey principal ACLs (`relay`, `fanout`, `broker_admin`). Never commit compiled `relayquill-broker` or `.exe` binaries.

### Tier 6 — Compose & Kubernetes Manifest Validation

```bash
docker compose -f infra/compose.dev.yaml config --quiet
docker compose -f infra/compose.prod.yaml config --quiet
node tools/cluster/validate-rendered.mjs
```

- Validates Docker Compose topologies and rendered Kubernetes manifests (`infra/kubernetes/base`, `infra/kubernetes/overlays/selfhosted`, `infra/kubernetes/overlays/eks`) for non-root execution, read-only root filesystems, dropped capabilities, network segmentation, and absence of embedded secrets or development trust flags.

### Tier 7 — Playwright & PGlite End-to-End Suite

```bash
node tests/e2e/run.mjs --suite harness
node tests/e2e/run.mjs
```

- Runs the multi-tier E2E suite (`tests/e2e/run.mjs`) across in-memory PGlite authorities (`rq`, `rc`, `pi`), `InMemoryJetStreamBroker` / embedded Go broker, local TLS webhook receiver doubles, dual-platform protected IPC probes, and headless Chromium Playwright console specs with virtual WebAuthn authenticators and WCAG AA assertions.

---

## 4. Atomic Commit Standards

1. **Conventional Commit Format**:
   Use concise, imperative subject lines scoped to the affected subsystem:
   ```text
   <type>(<scope>): <imperative summary>
   ```
   Allowed `<type>` values: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `ci`.
   Examples:
   - `feat(signing,egress): implement 25-field webhook HMAC and DNS-pinned connector`
   - `fix(migrations): align obligation inventory state filter with accepted event state`
   - `test(e2e): verify two-person replay approval and strict per-key ordering`
2. **One Logical Slice Per Commit**:
   Stage only the files belonging to a verified logical change. Never mix unrelated workspace refactors, untracked build outputs (`dist/`, `build/`, `*.tsbuildinfo`, `*.tgz`), or temporary debug files into a commit.
3. **Strict Commit Message Hygiene**:
   `npm run hygiene` inspects every commit author, committer, and message body in `git log --all`. Commit messages must contain **zero** external specification numbering, forbidden specification nouns, or automated attribution trailers.
4. **No Secrets or Environment Files**:
   Never stage `.env`, `*.pem`, `*.key`, `*.crt`, `*.seed`, `*.creds`, `*.tfvars`, or `infra/secrets/`. Always run `npm run hygiene` immediately before and after committing.
