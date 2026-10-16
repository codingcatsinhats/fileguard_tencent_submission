# FileGuard — Project Description

## Project Overview: Target Scenarios, Users, and Value Proposition

**FileGuard** is a security gateway — an "internal brain" — that sits between
an enterprise LLM assistant and the company's knowledge across platforms
(Confluence, Jira, Slack, Google Drive, and a direct-upload document store).
Users ask questions in natural language; FileGuard decides, for every
retrieval, **who may see what, how much, and records everything**.

**Target scenarios.** Any organization where an AI assistant touches
sensitive internal knowledge: engineering organizations with incident
postmortems and on-call notes, finance and HR teams with board-level
documents, security teams with vulnerability and breach reports, and
compliance functions that must be able to prove — after the fact — exactly
what the AI accessed, delivered, and was denied.

**Users.** Three distinct audiences, each with their own surface:

| Audience | Surface | What they get |
|---|---|---|
| Employees | Chat assistant | Natural-language answers across five platforms in one question, with every sentence traceable to a hash-pinned verbatim source span |
| Auditors / compliance | Audit console | A tamper-evident log of every access — who asked, what was retrieved, what was answered, every allow and every deny — queryable in plain language, tier-redacted by seniority |
| Administrators | Confirmation cards | One-click human approval before any secret/top-secret content is delivered, with replay-proof single-use nonces |

**Value proposition.** Enterprise AI assistants fail in one of two ways:
they are locked down so tightly that nobody uses them, or they are useful
and quietly leak — over-broad retrieval, hallucinated citations, documents
that were de-shared yesterday but are still in the model's index today, and
no audit trail to prove anything afterwards. FileGuard makes the assistant
useful *and* provable: extractive-only delivery (every passage shown to the
user is a verified verbatim source span, delivered as a clickable chip they
can re-check against the answer), permission checks
that run live against the source platform at query time, and a
cryptographically tamper-evident audit log that covers not just accesses
but also **denials** — the questions someone tried to ask but was not
allowed to.

## Real World Scenario Insights: Pain Points, Audience, Core Problem

The pain points come from how AI retrieval actually fails inside companies:

1. **Permission drift.** A document is indexed when shared, de-shared or
   restricted weeks later — but the assistant's index still serves it.
   The classic real-world incident: an employee leaves a project team,
   keeps asking the assistant, keeps getting the restricted content.
   **Core fix:** FileGuard re-checks the source platform's *live*
   permissions on every retrieval, and a permission epoch invalidates all
   cached grants the instant a membership changes. Revocation takes effect
   at the next query, not at the next index rebuild.

2. **Existence leakage.** Even "filtered" assistants leak through
   metadata: titles, snippets, and "did you mean…" suggestions tell an
   unentitled user that a sensitive document *exists*. **Core fix:** in
   FileGuard, a forbidden document and a non-existent one produce
   byte-identical responses — an unentitled user gets no snippets, no
   names, and no trace at all. Search returns references only. The
   anonymous `hidden_counts` are a separate, deliberate mechanism: they
   appear only to users who are *already authorized* to open those items,
   when the agent voluntarily searches below the user's own clearance —
   they reflect a self-imposed ceiling choice, never a denied permission.

3. **Unverifiable answers.** An LLM summarizing a document can blend,
   paraphrase, or hallucinate; auditors cannot tell which sentences came
   from the source. **Core fix:** the delivery pipeline is extractive —
   a constrained LLM may only *select* spans, never compose text, and every
   delivered span is verbatim, hash-pinned to the exact source version, and
   shipped with a signed receipt the auditor can verify independently.

4. **Need-to-know is unenforced.** Standard RBAC says *which* documents a
   role may open; it says nothing about the fact that an AI assistant just
   pulled 50 documents when 3 would do. **Core fix:** every retrieval
   carries an agent-asserted *reason* and a clearance ceiling; requesting
   above the user's clearance is rejected outright and logged as a
   violation; a deterministic abuse guard caps broad searches, empty-result
   floods, denied-item floods, and per-turn retrieval volume.

5. **The audit gap.** When compliance asks "who saw the breach report?",
   platform logs show file opens by humans — not what an AI assistant
   retrieved, delivered, or refused. **Core fix:** a single append-only,
   hash-chained audit log at the gateway records every request and response
   (including denials and abuse blocks), with signed checkpoints anchored
   by RFC 3161 timestamps and tiered redaction so a standard-tier auditor
   and a top-secret-tier security lead see the same log at different
   depths.

**Core problem solved, in one line:** *let an AI assistant answer any
question across the whole company's knowledge, while making every byte it
delivers verified, permission-checked at query time, and audit-provable —
including what it was not allowed to deliver.*

## Comprehensive Solution Design

### Business architecture

FileGuard replaces "give the AI an index of everything" with a
**policy-enforced mediation layer**:

- **Connector layer.** Five connectors (Confluence, Jira, Slack, Drive,
  Uploads) implement one contract — change feed, content fetch, live ACL
  fetch, `can_access`, identity resolution — and pass the same test suite.
  Native platform permission semantics are preserved, not flattened:
  Confluence space + page restrictions, Jira project roles + issue security
  levels, Slack channel membership, and Drive file/folder sharing are each
  evaluated by their own logic.
- **Sync engine + unified index.** Incremental change feeds pull items into
  one searchable index — but the index holds *references*, not served
  content. Content is always fetched fresh through the pipeline.
- **Policy overlay.** An enterprise-side classification layer
  (open < confidential < secret < top_secret, plus group requirements) that
  can only ever *narrow* what the platform natively permits — never elevate
  it. Disagreements between the overlay and the platform are themselves
  audited as `policy_mismatch` warnings, so classification drift is
  detected, not silently ignored.
- **Audit gateway.** Every assistant action flows through one FastAPI
  interceptor that logs the request, enforces access, routes the operation,
  and logs the response — hash-chained, append-only (database triggers make
  edits physically impossible).
- **Human-in-the-loop.** Secret content requires a once-per-session
  confirmation; top-secret requires a fresh single-use nonce per request.
  Approval happens in the UI with one click; the grant is re-minted server
  side and never enters model context.

### Technical architecture

The retrieval path for one user question:

1. **`search`** — full-text search over the unified index, ACL-prefiltered,
   returning references only (id, title, platform, container, label) plus
   anonymous `hidden_counts`. No snippets, no file contents. Note:
   `hidden_counts` are **not** an information leak — they count items the
   user is *already authorized* to access (native permission passed), but
   which were deliberately withheld because the agent requested a ceiling
   below their label. They are the visible remainder of a self-imposed
   retrieval restriction, not of a denied permission — and they expose
   nothing the user could not have requested and received.
2. **`get_content`** — the only path content ever takes to reach the agent:
   live `can_access` check against the source platform → freshness gate
   (the indexed version is compared to the live version at query time;
   changed content is re-fetched synchronously) → deterministic one-hop
   link expansion → **Gatekeeper** span selection → verbatim hash-pinned
   extraction → confirmation gate → grounding check → signed receipt.
3. **Delivery, not promises.** What reaches the user per source is the
   verbatim, hash-pinned delivered text, classified by its shape: an
   **excerpt** (one continuous passage from the source) or **stitched**
   (multiple passages joined in document order, gaps marked with `(…)`)
   — or **no content** if nothing passed every gate. A composed answer is
   never shipped unverified: any sentence that cannot be tied back to a
   delivered span is dropped before the user sees it, and when nothing
   verifiable exists the reply is a generic no-evidence message —
   identical whether nothing exists or nothing the user may see.
4. **Audit.** Request and response land in the hash chain; salted-hash
   commitments cover restricted fields (raw user input, search terms,
   answer text) so plaintext can be purged later while the chain stays
   verifiable; signed checkpoints anchor the log against a third-party
   timestamping authority. The trail is also double-recorded: the
   assistant harness keeps its own local hash-chained log of every
   outgoing request, and a monthly reconciliation compares the two
   chains — any divergence is itself flagged in the audit log, so
   tampering would have to fool both records at once.
5. **Audit chat.** Auditors query the same log in natural language. The
   assistant runs structured queries *before* the model sees anything
   (redact-then-LLM), its tier choice is validated and clamped — never a
   grant — and it is read-only: it can query the log, never change it.

### How prompts drive the AI generation

The system uses two LLM roles, each constrained by prompt *and* by
mechanism — the prompt expresses intent, but the schema enforces it:

1. **The Gatekeeper (retrieval).** Its system prompt defines it as a
   *document gatekeeper*: given a full span index of the requested document
   and the agent-asserted access reason, select only the spans strictly
   relevant to that reason; prefer fewer spans; output nothing except a
   tool call (`submit_spans`) referencing span identifiers copied exactly
   from the index; never summarize, quote, or compose content. The prompt
   additionally injects *intra-document intelligence* — a
   `<span_relations>` block listing entities that appear across multiple
   spans — so the gatekeeper selects complete, coherent span sets rather
   than isolated fragments, while being told this context must never appear
   in its stated selection reason. Critically, the prompt's rules are
   backed by enforcement: every returned reference is validated against the
   real span index (invalid ones are dropped), an empty selection is a
   legitimate outcome, and any LLM failure is fail-closed into a
   no-evidence answer — the model can only *narrow* what is delivered,
   never widen it.

2. **The assistant brain (answering).** Its system prompt defines it as an
   enterprise assistant that must answer only from delivered spans, cite
   span ids, and honor confirmation gates. Note that "never reveal
   whether withheld content exists" is not an instruction the LLM must
   obey — it is a property the LLM cannot violate: withheld items never
   appear in any search result, reference, or retrieval the agent
   receives, so the model never learns they exist in the first place, and
   an empty result looks exactly like a non-existent one. Because delivery
   is extractive-only, the model's prose is grounded in verbatim,
   hash-pinned spans; the grounding validator checks the composed answer
   against those spans before delivery, and anything unverifiable
   degrades the response to the verbatim spans themselves — surfaced to
   the user as clickable chips whose full delivered text is right there
   to re-read.

3. **The audit assistant.** Its prompt enforces read-only behavior and
   seq-cited answers, but the tier filter it "chooses" is re-validated and
   clamped server-side against the signed-in auditor's real tier — the
   prompt shapes behavior; the server guarantees it.

Across all three roles the same principle holds: **prompts drive the shape
of the AI's contribution; the architecture guarantees its bounds.** The LLM
decides *which* relevant content to select and *how* to phrase an answer;
the system decides *what may* be selected and *what is provably delivered*.

## Business Value

Impact, mapped to measurable properties of the system:

| Dimension | Without FileGuard | With FileGuard | Quantified effect |
|---|---|---|---|
| **Hallucinated/paraphrased content in answers** | LLM freely summarizes; provenance unknown | Extractive-only: every delivered span is verbatim, hash-pinned, and surfaced to the user as a clickable chip whose full delivered text is inspectable in place | **Every claim re-verifiable** — hallucinations are strongly reduced when generation is grounded in verbatim, hash-pinned citations; whatever the model does deliver is fully visible via the chips, so the user (and any auditor) can cross-check the answer against the delivered text itself — verification never depends on trusting the model |
| **Revocation latency** | Effective when the index rebuilds (hours–days, or never) | Live permission check + permission epoch at query time | Revocation effective at the **next query** (seconds), not the next sync |
| **Existence leakage** | Titles/snippets visible to unentitled users | Forbidden and missing items are byte-identical in response | **0 metadata disclosure to the unentitled** — no snippets, no names, no counts, no trace at all. The anonymous `hidden_counts` are not shown to under-clearance users: they appear only to users already authorized to open those items, when the agent voluntarily searches below their own clearance |
| **Audit coverage** | Platform file-open logs only; AI retrievals and refusals invisible | Central hash-chained log of every request, response, denial and abuse block — plus a harness-side local log, reconciled monthly against the central chain | **100% of AI accesses audited**, tamper-evident (Ed25519 checkpoints + RFC 3161 anchoring); denials included — the log answers "who *tried* to see what"; the monthly reconciliation means tampering must fool two independent records at once |
| **Compliance evidence effort** | Manual log correlation across 4+ platforms | Filterable console, CSV export, natural-language audit chat with seq citations | Audit question turnaround drops from hours of cross-platform log pulling to **seconds** |
| **Over-retrieval / insider risk** | Agent pulls whatever the query matches | Reason-asserted retrieval, clearance ceilings, per-turn budgets (3 searches / 5 retrievals per message), abuse guard strikes | Need-to-know enforced per retrieval; anomalous patterns (broad searches, denied-item floods, near-duplicate refinement) blocked deterministically |
| **Plaintext retention risk** | Prompts and answers retained indefinitely | Restricted fields stored as salted-hash commitments; plaintext in a purge-able side table | GDPR-style **right-to-erasure on audit data** without breaking chain verifiability |

**For the business**, this means an AI assistant can finally be pointed at
the whole knowledge base — engineering, finance, HR, security — instead of
being restricted to "safe" corpora, because the safety now lives in the
gateway: provable provenance, query-time permissions, human approval on
sensitive tiers, and an audit trail that satisfies a compliance officer's
question ("exactly what did the AI deliver, to whom, and what did it
refuse?") with cryptographic evidence rather than assurance.

**Verification is not a claim — it is a feature.** Anyone holding the
tokens can independently verify receipts, checkpoints and the chain
(`scripts/verify_receipt.py`, `scripts/tamper_demo.py`): don't trust us,
verify us.
