# FileGuard — Internal Brain

Extractive, audited agentic access-control for **enterprise knowledge across
platforms** (Confluence, Jira, Slack, Google Drive — all simulated), plus the
original uploaded-documents store as a fifth source.
 
The agent never reads raw content. Discovery is `search` (references only,
permission-filtered, reason-asserted); retrieval is `get_content`, which runs
a live access check, a freshness gate, Gatekeeper span selection and a
grounding check before anything is delivered — with every allow and deny
recorded in a tamper-evident audit log.

```
 User ─► Web UI (FastAPI + htmx: / chat, /audit console, /upload)
           │
           ▼
     AssistantHarness (agent loop; forced first search)
           │  (HMAC-signed grant + permission epoch, never in model context)
           ▼
     Audit Gateway (/v1/request)
       1. Log request (hash-chained, append-only)
       2. Auth Checker (clearance + group AND-gating + stale-epoch gate)
       3. Abuse Guard (rate/volume/pattern caps, per-turn + per-session)
       4. Route:
          ├─ search      → unified index (FTS5), ACL pre-filter,
          │               references only + search_id + hidden_counts
          └─ get_content → live access check (connector, current ACL)
                          → freshness gate (version check, re-fetch)
                          → link expansion (one hop, deterministic, re-checked)
                          → Gatekeeper LLM (joint span selection, refs only)
                          → Span Extractor (verbatim, hash-pinned to version)
                          → confirmation gate (secret/top-secret)
                          → grounding check → answer + citations
                          → signed delivery receipt (Ed25519)
       5. Log response + checkpoint (Ed25519 + RFC 3161 anchor)
           ▲
           │ sync (change feeds, ACL snapshots)
     Sync Engine ─► Unified Index (items, units, versions, ACLs)
           ▲
     Connectors ─► Platform Simulators (Confluence · Jira · Slack · Drive)
                └► Uploads (the original encrypted file store)
```

**Trust boundaries:** the gateway, connectors, index, extractor and audit log
are trusted code. The Gatekeeper and answering model are untrusted LLMs with
narrow channels. All platform content is untrusted data (injection attempts
in it are part of the test suite).

## Key Features

- **Five connectors, one contract** — Confluence, Jira, Slack, Drive and
  Uploads all implement the same `Connector` interface (change feed, fetch,
  current version, live ACL fetch, `can_access`, identity resolution) and
  pass the same contract tests. Native permission semantics are not
  flattened: space+page restrictions, project roles + issue security,
  channel membership, and file/folder sharing are each evaluated by
  unit-tested evaluator functions shared between simulator and adapter.
- **Two-stage tool model** — `search` returns references only (no snippets;
  forbidden and non-existent items are indistinguishable). `get_content`
  runs the full retrieval pipeline and is the only path by which content
  reaches the agent.
- **Two-stage access control** — a cheap ACL pre-filter on indexed
  snapshots, then an authoritative live check against the source's current
  ACL on the top candidates. A permission epoch invalidates grants the
  moment memberships change (stale epoch = hard reject).
- **Freshness gate** — every cited item is version-checked against its
  source at query time and re-fetched on mismatch; answers carry
  "verified current at" / "last synced" stamps.
- **Extractive-only design** — the Gatekeeper can only call `submit_spans`
  with validated references. It cannot compose, summarize, or request more
  text. The answering model must cite span ids.
- **Grounded delivery shapes** — every delivered passage is verbatim and
  hash-pinned, classified as an **excerpt** (one continuous passage) or
  **stitched** (multiple passages in document order, gaps marked `(...)`);
  composed answers are checked sentence-by-sentence and unproven sentences
  are never shipped; a generic no-evidence message (identical whether
  nothing exists or nothing you may see) is the honest empty result.
- **Tamper-evident audit trail** — append-only hash-chained SQLite logs
  (triggers make `UPDATE`/`DELETE` physically impossible), reconciled
  against the harness-local log; signed receipts and checkpoints anchored
  via RFC 3161 timestamps.
- **Restricted audit fields** — raw user input, search terms and answers
  are stored as salted-hash commitments in the chain; plaintext lives in a
  purge-able side table. Purge keeps the chain verifiable.
- **Bell-LaPadula-style session high-water mark**, replay-proof
  single-use nonces for top-secret access (grant re-minted on approval),
  and dual, non-interchangeable token families (chat vs audit console).
- **Abuse guard** — deterministic rate, volume and pattern caps: broad
  search, empty-result floods, denied-item floods, near-duplicate
  refinements, thin reasons, per-turn retrieval budgets.

## Reason-Driven Discovery (Need-to-Know Applied to AI Retrieval)

The agent's knowledge of the corpus is exactly what RBAC permits and what
the user's reason justifies — nothing more. No catalog, summary or item
name is pre-loaded into any model's context; a restricted item and a
non-existent one produce byte-identical responses.

1. **User asks** a question
2. **Agent calls `search`** with a recorded reason and a `desired_clearance`
   ceiling (plus an optional `desired_group`). Requesting a ceiling above the
   user's `max_clearance` is rejected outright (`OVERCLEARANCE` — logged as a
   violation), so the effective ceiling is always ≤ the user's max. The
   gateway fans out per connector over the ACL-prefiltered index and returns
   references (item id, title, platform, container, label) at or below that
   ceiling — items the user passes natively but that sit above the requested
   ceiling appear only as per-label `hidden_counts`, never by name
3. **Agent calls `get_content`** on specific items, with a reason and the
   same `desired_clearance` / `desired_group` mechanics
4. **Pipeline**: live ACL check → freshness gate → (deterministic) link
   expansion → **Gatekeeper LLM** selects spans → verbatim, hash-pinned
   extraction → confirmation gate where required → grounding check
5. **Agent answers** from the delivered spans, citing span ids

## RBAC: Native Permission AND Clearance AND Group

Access requires all of these to pass independently:

1. **Native platform permission** — evaluated against each platform's own
   permission model, live at query time for top candidates. The
   `desired_clearance` never reaches the platform; it is an
   overlay-only concept (see below):

   | Connector | Native permission means |
   |---|---|
   | Confluence | view permission on the space AND the page's view restrictions AND every ancestor page's restrictions |
   | Jira | Browse permission on the project (via a project role) AND, if the issue has a security level, membership of that level |
   | Slack | public channel → full member (guests only see channels they were explicitly added to); private/shared → membership; DM → participant; replies inherit the channel |
   | Drive | the user appears in the file's permission list or a parent folder's, or a link/domain-sharing rule applies; removed shares and trashed files grant nothing |

2. **Clearance ceiling** — every request carries an agent-chosen
   `desired_clearance`; requesting above the user's `max_clearance` is
   rejected (`OVERCLEARANCE`). Container labels
   (`open < confidential < secret < top_secret`, overlay policy in
   `demo-seed/company_a/containers.yaml`) must be at or below the requested
   ceiling. `hidden_counts` covers only items the user passes natively but
   that the ceiling withholds.
3. **Group membership** — restricted containers additionally require group
   overlap (with the requested `desired_group`, or all the user's groups by
   default). Groups restrict; they never elevate. Clearance never bypasses
   groups.

The combined decision is `native_permission AND label ≤ desired_clearance
AND group_overlap` — the overlay can only narrow what the platform already
permits, never elevate it. Askers map to platform identities through the
directory (Company A personas are their own identity; the closed-network-corpus chat cast
is bridged to a persona of the same clearance ceiling in
`fileguard/connectors/factory.py`).

## Quickstart

### Prerequisites

- Python 3.10+
- An Anthropic API key for live Gatekeeper mode, or use test mode (below)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Reset the demo state

Seeds users, tokens, the uploads file registry, ~12 business days of
curated audit history for both casts, and the Company A storyline audit
seed (including planted violations). Safe to re-run anytime.

```bash
python3 demo-seed/reset-demo.py
```

### Start the simulators and sync the index

```bash
python3 scripts/sync_demo.py
```

This starts (or restarts) the four platform simulators on
`localhost:8101–8104` (ports in `fileguard/connectors/factory.py`), reseeds
them from `demo-seed/company_a`, and pulls everything into the unified
index. To start one simulator by hand:
`python3 scripts/sim_server.py confluence` (also: `jira`, `slack`, `drive`).

### Start the server

```bash
uvicorn ui.web:app --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000`.

> **Single-worker only.** The chat harness state is in-process. Do not use
> `--workers` > 1. If you reset the demo, restart uvicorn afterward.

### Run in Docker (recommended for non-Linux hosts)

One container runs everything: the 4 platform simulators, the index sync
and the web app. State is regenerated fresh on every start.

```bash
docker compose up --build
```

Pass your LLM credentials through the environment (compose forwards
`ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL` from the
host shell — on Windows cmd, remember `set VAR=value` takes NO quotes).
Then open `http://localhost:8000`. To persist the audit log across
restarts, uncomment the `volumes:` block in `docker-compose.yml`.

### Test mode (no API key needed)

Uses the offline deterministic Gatekeeper/answering stubs
(`fileguard/stub_models.py`) instead of calling Claude:

```bash
FILEGUARD_GATEKEEPER_MODE=test uvicorn ui.web:app --port 8000
```

## Demo Tokens

Chat tokens (at `/`):

| Who | Token | Clearance | Groups |
|---|---|---|---|
| Maya Chen (Backend Eng, payments) | `token-maya` | confidential | eng, payments |
| Lena Okafor (Security Lead) | `token-lena` | top_secret | eng, security |
| Sam Alvarez (Eng Manager) | `token-sam` | secret | eng, payments, leads |
| Raj Patel (SRE, on-call) | `token-raj` | confidential | eng, sre, payments |
| Tom Becker (External contractor) | `token-tom` | open | contractors |
| Jo Park (Junior Engineer) | `token-jo` | confidential | eng |
| John Doe (Senior Payments Eng) | `token-jdoe` | confidential | eng, payments |
| Closed-network corpus (upload-store demo): Alice / Bob / Carol / Dave | `token-alice` / `token-bob` / `token-carol` / `token-dave` | top_secret / confidential / secret / open | HR+finance / finance / R&D / — |

The four closed-network-corpus chat users are bridged to Company A platform identities of
the same clearance ceiling (`DEMO_IDENTITY_BRIDGE` in
`fileguard/connectors/factory.py`); Company A personas map to themselves.

Audit-console tokens (at `/audit`, separate family — never interchangeable
with chat tokens):

| Token | Tier |
|---|---|
| `audit-priya` (Priya Nair, compliance officer) | standard — redacted |
| `audit-lena` (Lena Okafor, security lead) | top_secret — full, incl. restricted fields |
| `audit-token-standard` | standard — redacted |
| `audit-token-topsecret` | top_secret — full |

## Demo Flows (golden questions from the storyline)

Full walkthrough with expected outputs: **`docs/DEMO-OUTLINE.md`** — the
flows below are its short version.

Sign in as **token-maya** and ask:

> What was the root cause of the payment outage last quarter, and what
> follow-up tickets were created?

The agent searches, pulls the Confluence postmortem and the Slack incident
thread (not the March decoy, not the wrong draft), answers with citations —
every span verbatim and hash-verified.

More, in order:

1. **Freshness** — `python3 scripts/demo_story.py runbook-v8` (publishes
   CF-RUNBOOK v8), then ask **token-raj**: *"What's the latest runbook for
   the payment-service incident?"* — step 6 arrives, stamped verified-current.
2. **Revocation** — `python3 scripts/demo_story.py revoke-raj`, ask Raj
   again about the on-call note: gone, with no hint it ever existed.
3. **Existence leak** — as **token-jo** (no security role), ask *"Show me
   all security vulnerabilities."*: the generic no-evidence message,
   byte-identical to a genuinely missing item — then as **token-lena**
   (security lead), the same question returns the secret-tier inventory.
4. **Audit inquiry** — log into `/audit` as `audit-priya`, filter user
   `jdoe`, platform confluence, container PAYGW, last 30 days: exactly the
   8 seeded accesses. Compare `audit-lena` for the unredacted view.
5. Upload-store demo (closed-network corpus): as `token-alice`, ask *"what is
   the board of director's average salary?"* — `board_compensation.xlsx`
   triggers the one-click replay-proof confirmation, then answers from
   signed, hash-verified spans via the uploads connector.

## Project Structure

```
fileguard/              Core security gateway
  gateway.py              Central FastAPI interceptor — all requests flow through it
  connector.py            Connector protocol + normalised Item/Unit/ACL model
  connectors/             Adapters: confluence, jira, slack, drive, uploads (+factory)
  sync_engine.py          Incremental sync (cursors, tombstones, per-connector lag)
  identity.py             Directory, permission epoch, clearance overlay
  search.py               FTS5 unified search — ACL pre-filter, references only
  pipeline.py             get_content pipeline: live check → freshness → links
                          → Gatekeeper → extraction → grounding
  gatekeeper.py           LLM span selector (constrained to submit_spans refs)
  stub_models.py          Deterministic Gatekeeper + answering stubs (CI)
  grounding.py            Grounding check + delivery-shape classification
                          (excerpt / stitched / none)
  freshness.py            Version gate: verified-current / stale stamps
  auth_checker.py         Clearance ceiling + group AND-gating + epoch gate
  abuse_guard.py          Deterministic rate/volume/pattern abuse caps
  security.py             HMAC grants, AES-256-GCM encryption, Ed25519 receipts
  store.py                Encrypted, content-addressed uploads store
  parsers.py / span_extractor.py   Verbatim extraction, hash-pinned
  db.py                   SQLite with append-only triggers + hash-chained logs
  session_service.py      Sessions, single-use nonces, message budgets
  audit_restricted.py     Salted-hash commitments + purge-able side table
  audit_query.py          Structured audit query API (filters, export)
  audit_view.py           Tiered audit viewer (standard vs top-secret)
  checkpoint.py           Signed checkpoints anchored via RFC 3161
  config.py               Environment-driven configuration

simulators/             Stateful platform simulators (one HTTP server each)
  confluence.py jira.py slack.py drive.py common.py evaluators.py

harness/                Agent loop + local audit log
  agent_loop.py           Tool-use loop (search/get_content), parked confirmations
  audit_chat.py           Audit-chat harness (redact-then-LLM, read-only)
  local_log.py            Harness-side tamper-evident log (monthly reconciliation)

ui/                     Web UI (presentation only)
  web.py                  FastAPI app — chat, upload, sources, audit console
  templates/ static/      Jinja2 + htmx

demo-seed/              Curated demo state
  build_seed.py           Builds demo-seed/seed/ (registry DB + encrypted objects)
  reset-demo.py           Reset button — restores clean demo state
  company_a/              Company A generator (story.py) + containers.yaml
  seed/                   Static assets: registry DB + encrypted objects
  seed_story.py           Old-cast audit story for the closed-network corpus (still run by reset-demo)

scripts/
  sim_server.py           Run one platform simulator (reseeds on start)
  sync_demo.py            Start/restart sims + sync the unified index
  demo_story.py           Storyline events: runbook-v8, revoke-raj,
                          restrict-vendor, unshare-tom, clock, reset
  reconcile.py            Local-vs-central log reconciliation
  verify_receipt.py       Standalone delivery receipt verification
  tamper_demo.py          Demonstrate tamper detection
  seed.py                 User seeding — both casts (all current tokens)
  ingest_demo.py          Upload-store demo corpus seeding (documents)

tests/                  pytest suite (353 tests, fully offline)

docs/                   ARCHITECTURE.md (trust model + diagrams)
                        DESCRIPTION.md / DESCRIPTION-MINI.txt (submission)
                        DEMO-OUTLINE.md (demo walkthrough)
```

## Configuration

All configuration is environment-driven. Defaults are for the hackathon demo
only — production deployments should override all secrets via environment
variables (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `FILEGUARD_DATA_DIR` | `./data` | Directory for DBs, index, encrypted store, sim DBs |
| `FILEGUARD_SECRET_KEY` | `dev-only-secret-key` | HMAC secret for session grants |
| `FILEGUARD_STORE_KEY` | `1f2e3d4c5b6a7988` ×4 | AES-256 key for content store (hex) |
| `FILEGUARD_RECEIPT_KEY` | `dev-only-receipt-key` | Ed25519 seed for delivery receipts |
| `FILEGUARD_GATEKEEPER_MODE` | `live` | `live` (Claude) or `test` (offline stubs) |
| `FILEGUARD_GATEKEEPER_MODEL` | `claude-sonnet-5-5` | Model for live Gatekeeper |
| `FILEGUARD_GRANT_TTL` | `3600` | Session grant TTL in seconds (sliding) |
| `FILEGUARD_NONCE_TTL` | `300` | Confirmation nonce TTL in seconds |
| `FILEGUARD_DEMO_NOW` | `2026-10-14T14:05:00+08:00` | Demo clock for the Company A generator |
| `FILEGUARD_POLICY_VERSION` | `1` | Bumped when log/receipt semantics change |

Simulator endpoints and the sync admin token are hardcoded demo values in
`fileguard/connectors/factory.py` (ports 8101–8104), on purpose.

## Testing

```bash
pytest tests/ -v
```

Tests run fully offline with `FILEGUARD_GATEKEEPER_MODE=test`. They cover
the connector contract (all five adapters), permission evaluators, sync
engine, identity/epoch, unified search, the pipeline and grounding check,
freshness, audit upgrades (restricted fields, query API, G16), plus the
original auth matrix, span extraction, hash chains, nonce lifecycle, abuse
guard and reconciliation suites.

## Operational Scripts

```bash
# Start/restart the simulators and sync the unified index
python3 scripts/sync_demo.py

# Run one simulator by hand (confluence | jira | slack | drive)
python3 scripts/sim_server.py confluence

# Storyline events (each re-syncs the affected connector)
python3 scripts/demo_story.py runbook-v8     # S2: CF-RUNBOOK v7 → v8
python3 scripts/demo_story.py revoke-raj     # R1: raj removed from private channel
python3 scripts/demo_story.py restrict-vendor # R2: CF-VENDOR-PRICING → sam only
python3 scripts/demo_story.py unshare-tom    # R3: Drive share removed
python3 scripts/demo_story.py clock 13:00    # set the sims' demo clock
python3 scripts/demo_story.py reset          # back to seeded state

# Verify a delivery receipt against the audit log
python3 scripts/verify_receipt.py '<receipt-json>'

# Reconcile harness-local log vs central audit log (dry run / apply)
python3 scripts/reconcile.py [--apply]

# Demonstrate tamper detection
python3 scripts/tamper_demo.py
```
