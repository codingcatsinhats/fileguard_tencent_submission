# demo-seed — curated demo state

Everything needed to put the Internal Brain back into a clean, realistic
demo state.

```
demo-seed/
├── README.md         this file
├── company_a/        Company A storyline: data generator (story.py),
│                     clearance overlay policy (containers.yaml)
├── build_seed.py     one-off: rebuilds seed/ (run only if seed.py changes)
├── reset-demo.py     THE reset button — restores the demo state
├── seed_story.py     Old-cast (alice/bob/carol/dave) audit history for the closed-network corpus
│                     generator — still run by reset-demo alongside the
│                     Company A audit seed
└── seed/             static assets: registry db + encrypted objects
```

## Resetting

```bash
python3 demo-seed/reset-demo.py
```

Then restart uvicorn (`uvicorn ui.web:app --port 8000`) — running chat
sessions live in process and won't see the new state.

What a reset does:

1. Wipes `data/` (central.db, harness_local.db, index.db, encrypted store)
   and `data/sim/` (simulator stores — reseeded by `scripts/sim_server.py`
   on next start; `scripts/sync_demo.py` also restarts any stale sim).
2. Copies in `seed/` — users, audit tokens, uploads file registry, encrypted
   objects. `dev_demo_files/` plaintext mirrors are untouched.
3. Generates ~12 business days of realistic audit history **relative to
   now** (working-hours timestamps, mixed tiers, real hash chain),
   including two planted incidents, via `seed_story.py` (old cast),
   **plus** the Company A storyline audit seed (S7 jdoe pattern, planted
   violations, routine history) from `company_a/story.py`.
4. Verifies both hash chains and prints the token checklist.

Note: reset does **not** sync the unified index — run
`python3 scripts/sync_demo.py` afterwards to start the simulators and pull
Company A content into the index.

## Demo tokens

Chat tokens (at `/`):

| Who | Token | Clearance |
|---|---|---|
| Maya Chen (Backend Eng, payments) | `token-maya` | confidential · eng, payments |
| Lena Okafor (Security Lead) | `token-lena` | top_secret · eng, security |
| Sam Alvarez (Eng Manager) | `token-sam` | secret · eng, payments, leads |
| Raj Patel (SRE, on-call) | `token-raj` | confidential · eng, sre, payments |
| Tom Becker (External contractor) | `token-tom` | open · contractors |
| Jo Park (Junior Engineer) | `token-jo` | confidential · eng |
| John Doe (Senior Payments Eng) | `token-jdoe` | confidential · eng, payments |
| Closed-network corpus: Alice (HR Lead) / Bob (Finance Analyst) / Carol (Manager) / Dave (Intern) | `token-alice` / `token-bob` / `token-carol` / `token-dave` | top_secret / confidential / secret / open |

The four closed-network-corpus chat users are bridged to Company A platform identities of
the same clearance ceiling; Company A personas map to themselves.

Audit tokens (at `/audit`, separate family):

| Token | Tier |
|---|---|
| `audit-priya` (Priya Nair, compliance officer) | standard — redacted |
| `audit-lena` (Lena Okafor, security lead) | top_secret — full |
| `audit-token-standard` | standard — redacted |
| `audit-token-topsecret` | top_secret — full |

## Headline demo flows

Sign in as **token-maya** and ask: *"What was the root cause of the payment
outage last quarter, and what follow-up tickets were created?"* — the agent
searches across connectors and answers with verbatim, hash-verified,
cited spans (postmortem + Slack thread, no decoys).

For freshness, revocation and audit flows, see "Demo Flows" in the root
`README.md` (runbook-v8, revoke-raj, the audit console as priya/lena).

Upload-store headline (closed-network corpus): sign in as `token-alice`,
ask *"what is the board of director's average salary?"* — the agent finds
`board_compensation.xlsx` (top_secret, finance), which triggers the
one-click replay-proof confirmation, then answers from verbatim,
hash-verified spans via the uploads connector.

## Rebuilding the static seed

Only needed if `scripts/seed.py` (users + tokens) or the uploads registry
changes:

```bash
python3 demo-seed/build_seed.py
```
