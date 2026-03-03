# cairn — Full Implementation from Audit & Action Plan

Use delegate mode (Shift+Tab) now. You are the team lead and orchestrator — you
coordinate, you do not implement. All spec reading, task creation, coding, and
validation is done by teammates you spawn via agent teams.

The goal: complete the `cairn` universal P2P connectivity library as defined in
the technical specification and gap analysis, producing functional
implementations across all 5 languages (Rust, TypeScript, Go, Python, PHP) with
working API→transport→crypto→session integration, real conformance testing, and
proper project organization.

**Context**: cairn already has substantial code — well-tested primitives across
all 5 languages. The critical gap is that **API methods are not wired to the
transport/crypto/session stack** in any language. `node.connect()`, pairing
methods, `send()`/`on_message()` all return placeholder errors. The library is
a collection of well-implemented parts that are not connected end-to-end.

**Source documents** (read these, not each other's output):

| Document | Path | Lines | Purpose |
|----------|------|-------|---------|
| Technical Specification | `cairn-Technical-Specification.md` | 962 | Wire protocol, crypto, API surface, implementation strategy |
| Design & Architecture | `cairn-design-doc.md` | 1,055 | Detailed architecture, layer model, all subsystem designs |
| Product Requirements | `cairn-PRD.md` | 464 | Requirements, success criteria, infrastructure tiers |
| Audit & Action Plan | `ACTION-PLAN.md` | 559 | Gap analysis, current state, prioritized action items |

Total: 3,040 lines across 4 documents.

Work proceeds in three sequential phases. Create one agent team per phase, shut
it down and clean it up before starting the next.

---

## Phase 1: Spec Decomposition

<phase_1>

### Objective

Break the 4 source documents into self-contained module documents sized for a
single agent's context window. Each document must contain everything an
implementing agent needs for that module without requiring the full 3,040 lines
across 4 source files.

**Critical**: This is a completion project. Each module document must describe
both the **specification** (what to build) and the **current state** (what
already exists and what's missing). Agents will be modifying existing code, not
writing from scratch.

### Team Setup

Create a team. Spawn 5 teammates. Each teammate handles 3 module documents
(except the last who handles 3 including validation).

In each spawn prompt, tell the teammate:
- The exact section numbers and line ranges from each source document they are
  responsible for.
- The output file path(s) they should write to.
- The formatting rules below.
- That they must read the relevant sections from ALL applicable source documents
  (some modules draw from 2-3 source files).

#### Agent Assignments

**Teammate 1** → `spec/01-project-reorganization.md`, `spec/02-architecture-overview.md`, `spec/03-wire-protocol.md`
- Sources: ACTION-PLAN §3 (lines 178-228), §7 (lines 340-415); Tech Spec §2 (lines 17-52), §3 (lines 54-112); Design Doc §2 (lines 61-194), §3 (lines 195-242)

**Teammate 2** → `spec/04-crypto-key-management.md`, `spec/05-pairing-system.md`, `spec/06-transport-nat-traversal.md`
- Sources: Tech Spec §4 (lines 113-162), §5 (lines 163-281), §6 (lines 282-333); Design Doc §4 (lines 243-351), §5 (lines 352-390), §6 (lines 391-432)

**Teammate 3** → `spec/07-session-reconnection.md`, `spec/08-discovery-rendezvous.md`, `spec/09-mesh-networking.md`
- Sources: Tech Spec §7 (lines 334-427), §8 (lines 428-497), §9 (lines 498-536); Design Doc §7 (lines 433-514), §8 (lines 515-593), §9 (lines 594-628)

**Teammate 4** → `spec/10-server-mode.md`, `spec/11-api-surface.md`, `spec/12-error-config.md`
- Sources: Tech Spec §10 (lines 537-662), §11-12 (lines 663-796), §13 (lines 797-838); Design Doc §10 (lines 629-778), §11 (lines 779-809), §12 (lines 810-887); PRD §7 (lines 78-241)

**Teammate 5** → `spec/13-conformance-testing.md`, `spec/14-companion-infrastructure.md`, `spec/15-language-gaps-docs.md`
- Sources: Tech Spec §14-15 (lines 839-930); Design Doc §14 (lines 928-969); PRD §9 (lines 308-346), §11 (lines 366-383); ACTION-PLAN §2 (lines 40-175), §4 (lines 232-266), §5 (lines 269-321), §6 (lines 325-337)

### Output

Create a `spec/` directory with these files:

| File | Source Sections | Description |
|------|----------------|-------------|
| `spec/01-project-reorganization.md` | ACTION-PLAN §3, §7 | Directory restructure plan: `crates/`→`services/`, `packages/conformance/`→`conformance/`, `packages/demos/`→`demo/`, design docs→`docs/`. Git cleanup (118 unstaged deletions). .gitignore enhancements. Root LICENSE file. |
| `spec/02-architecture-overview.md` | Tech Spec §2, Design Doc §2 | 7-layer model, double-encryption architecture, 3 relay mechanism types, security layer design. Reference context for API wiring. |
| `spec/03-wire-protocol.md` | Tech Spec §3, Design Doc §3 | CBOR serialization, message envelope (version/type/msg_id/session_id/payload/auth_tag), all message type codes (0x01xx–0x07xx), version negotiation, deterministic encoding. |
| `spec/04-crypto-key-management.md` | Tech Spec §4, Design Doc §5 | Ed25519 identity, X25519 key exchange, Noise XX handshake, SPAKE2 pairing PAKE, Double Ratchet with header encryption, HKDF, AES-256-GCM, ChaCha20-Poly1305, key storage backends (filesystem encrypted, in-memory, custom adapter). |
| `spec/05-pairing-system.md` | Tech Spec §5, Design Doc §4 | 7 pairing methods: QR code, PIN (Crockford Base32), Link, PSK, SAS (numeric+emoji), NFC bump, proximity. Rate limiting. Unpairing protocol. CustomMessageRegistry (FR-9.4). State machine. |
| `spec/06-transport-nat-traversal.md` | Tech Spec §6, Design Doc §6 | 9-priority transport chain, NAT traversal strategy, STUN/TURN integration, Circuit Relay v2 limits, transport fallback, proactive migration, connection upgrade. |
| `spec/07-session-reconnection.md` | Tech Spec §7, Design Doc §7 | 7-state session machine (New→Connecting→Handshaking→Active→Suspended→Reconnecting→Closed), reconnection with backoff, session resumption vs re-establishment, network change detection, channel system (yamux). |
| `spec/08-discovery-rendezvous.md` | Tech Spec §8, Design Doc §8 | 5 discovery backends (mDNS, DHT, Tracker, Signaling, Rendezvous), rendezvous ID derivation (HKDF), rotation schedule (24h period, 1h overlap), bootstrap nodes. |
| `spec/09-mesh-networking.md` | Tech Spec §9, Design Doc §9 | Opt-in mesh routing, shortest-path selection, reachability exchange protocol, personal relay through paired peers, multi-hop forwarding. |
| `spec/10-server-mode.md` | Tech Spec §10, Design Doc §10 | Always-on server peer, store-and-forward (encrypted message queue, TTL, deduplication), management API (peer list, queue depths, relay stats, health, QR generation), resource accounting quotas. |
| `spec/11-api-surface.md` | Tech Spec §13, Design Doc §12, PRD §7 | Complete public API: `CairnNode` lifecycle, `connect()`/`send()`/`on_message()`, all pairing methods, event callbacks, configuration builder, per-language idiomatic wrappers. **This is the primary reference for API wiring.** |
| `spec/12-error-config.md` | Tech Spec §11-12, Design Doc §11 | 8 error categories with actionable suggestions, error code structure, configuration model (CairnConfigBuilder), all configurable parameters, transport preferences. |
| `spec/13-conformance-testing.md` | Tech Spec §15, ACTION-PLAN §5 | Conformance framework architecture, runner implementation (replace stubs), shared test vector format (JSON), fixture directory structure, 57 existing YAML scenarios, 10 language pairs, missing scenarios list. |
| `spec/14-companion-infrastructure.md` | Tech Spec §14, PRD §9 | Signaling server (WebSocket, topic subscription, CBOR forwarding, bearer auth), TURN relay (RFC 8656, static+dynamic credentials), Docker deployment, service Dockerfiles. |
| `spec/15-language-gaps-docs.md` | ACTION-PLAN §2, §4, §6, PRD §11 | Per-language gap inventory (Python: no key storage, missing discovery; PHP: PSR-4 violations, no ReactPHP, CBOR fragility; Go: broken Dockerfile; Rust: stub discovery, dummy swarm). Documentation requirements (README, per-package READMEs, getting-started, demo READMEs). Demo application status. |

### Rules for Each Module Document

1. **Self-contained** — include all relevant details inline. Do not write "see
   `cairn-Technical-Specification.md`" or summarize. An agent reading only this
   file must have everything it needs to implement or complete the module.
2. **Preserve verbatim** — exact names, types, message type codes, error
   messages, validation rules, data formats, algorithm steps, state machine
   transitions, CBOR field mappings. Copy from the spec, do not paraphrase
   technical specifics.
3. **Current state section** — each module document must include a "Current
   State" section describing what already exists in the codebase (file paths,
   what works, what's stubbed/missing). Extract this from ACTION-PLAN §2
   (Investigation Findings) for the relevant area.
4. **Cross-references at the top** — list which other module docs this one
   depends on and why (e.g., "Depends on: `07-session-reconnection.md` for
   session state machine used in API wiring").
5. **Under 400 lines each**.

### Validation

After all module docs are written, spawn one more teammate to validate:
1. Read all 4 source documents in full (`cairn-Technical-Specification.md`,
   `cairn-design-doc.md`, `cairn-PRD.md`, `ACTION-PLAN.md`).
2. Read every `spec/*.md` file.
3. Write `spec/VALIDATION.md` listing any omissions, contradictions, or spec
   drift. Specifically verify:
   - Every ACTION-PLAN P0 and P1 item is covered by at least one module doc.
   - Every PRD functional requirement (FR-1 through FR-10) is represented.
   - Every Tech Spec message type code is present in `spec/03-wire-protocol.md`.
   - Every pairing method is fully described in `spec/05-pairing-system.md`.
   - The full API surface (all public methods) appears in `spec/11-api-surface.md`.
4. If issues exist, message you with the list. You message the responsible
   teammates to fix them.
5. The validator re-checks after fixes. Phase 1 is complete only when
   `spec/VALIDATION.md` reports zero issues.

Shut down all teammates and clean up the team before proceeding.

</phase_1>

---

## Phase 2: Task Planning

<phase_2>

### Objective

Create a set of small, independently implementable tasks with a file-based
tracking system. Do not use Claude Code's built-in task tools
(TaskCreate/TaskUpdate/TaskList) — use the directory structure described below.

### Team Setup

Create a new team. Spawn 4 teammates. Each teammate reads a subset of the
`spec/*.md` files (not the original source documents — the decomposed modules
from Phase 1).

In each spawn prompt, tell the teammate:
- Which `spec/*.md` files to read.
- The task file template and naming convention.
- That all task files go in `tasks/todo/`.
- That this is a **completion project** — tasks should reference existing files
  to modify, not just new files to create. Check the actual codebase to
  understand current file paths.

#### Agent Assignments

**Teammate 1** → Read `spec/01-project-reorganization.md` and `spec/15-language-gaps-docs.md`
- Generates: project reorganization tasks, documentation tasks, language-specific fix tasks

**Teammate 2** → Read `spec/02-architecture-overview.md`, `spec/06-transport-nat-traversal.md`, `spec/07-session-reconnection.md`, `spec/11-api-surface.md`
- Generates: API wiring tasks (the critical path — connecting node.connect(), pairing methods, send()/on_message() to the transport/crypto/session stack)

**Teammate 3** → Read `spec/04-crypto-key-management.md`, `spec/05-pairing-system.md`, `spec/08-discovery-rendezvous.md`, `spec/09-mesh-networking.md`, `spec/10-server-mode.md`, `spec/12-error-config.md`
- Generates: missing primitives tasks, discovery stub replacement, mesh completion, server/management API, error handling

**Teammate 4** → Read `spec/03-wire-protocol.md`, `spec/13-conformance-testing.md`, `spec/14-companion-infrastructure.md`
- Generates: conformance test runner tasks, shared test vector tasks, infrastructure tasks

### Output

Directory structure:

```
tasks/
├── todo/
├── in-progress/
├── to-validate/
└── done/
```

Each task is a Markdown file: `NNN-short-slug.md` (e.g., `001-project-init.md`).
All start in `todo/`.

Task file template:

```markdown
# Task NNN: Short Title

## Status
todo

## Dependencies
- NNN-short-slug (what this task needs from that one)
- (or "None")

## Spec References
- spec/XX-module.md

## Scope
One paragraph. What this task implements — one focused piece of functionality.
For a completion project: describe what exists now and what changes are needed.

## Acceptance Criteria
- [ ] Criterion 1 (concrete, verifiable)
- [ ] Criterion 2
- [ ] ...

## Implementation Notes
Details the implementing agent needs: existing file paths to modify, what's
currently stubbed, exact API signatures to wire up, algorithm steps, library
APIs to use, edge cases. Quote the spec module directly.

## Language(s)
Which language implementation(s) this task applies to: Rust | TypeScript | Go |
Python | PHP | All | Infrastructure

## Files to Create or Modify
- packages/rs/cairn-p2p/src/foo.rs (modify)
- packages/ts/cairn-p2p/src/foo.ts (modify)

## Verification Commands
- `cargo test` (Rust)
- `cd packages/ts/cairn-p2p && npm test` (TypeScript)
```

### Sizing Rules

- Each task: implementable by one agent in one session.
- Maximum 4 source files per task. Multi-language tasks may list corresponding
  files across languages (e.g., the same module in Rust + TS + Go + Python + PHP)
  only if the change is mechanical/identical across languages.
- Maximum 7 acceptance criteria. If more, split the task.
- The "Files to Create or Modify" section prevents file conflicts during parallel
  implementation — no two tasks should list the same file unless one depends on
  the other.
- **Prefer per-language tasks for complex work** (API wiring) and
  **cross-language tasks for simple/mechanical work** (exposing a function,
  adding a constant).

### Ordering

Start with foundational tasks, then build up:

1. **Project reorganization** — Stage/commit 118 unstaged deletions, restructure
   directories (`crates/`→`services/`, `packages/conformance/`→`conformance/`,
   `packages/demos/`→`demo/`, design docs→`docs/`), enhance `.gitignore`, create
   root `LICENSE`
2. **API wiring — Rust reference** — Connect `node.connect()` to Noise XX
   handshake → session establishment. Connect all 7 pairing methods to
   transport → Noise XX + SPAKE2. Connect `send()`/`on_message()` to Double
   Ratchet → transport. This establishes the integration patterns.
3. **API wiring — TypeScript** — Port the Rust integration patterns to TypeScript
4. **API wiring — Go** — Port to Go
5. **API wiring — Python** — Port to Python + implement key storage backends
6. **API wiring — PHP** — Port to PHP
7. **CustomMessageRegistry** — Expose `on_custom_message` / `CustomMessageRegistry`
   in public API across all 5 languages
8. **Discovery backends** — Replace in-memory stubs in Rust with real network I/O.
   Add missing backends in Python (DHT, Tracker, Signaling).
9. **Swarm composition** — Replace `dummy::Behaviour` in Rust with composed
   protocol behaviours
10. **Server & management API** — Complete management API endpoints (peer list,
    queue depths, relay stats, health, QR generation) and resource quota
    enforcement across all languages
11. **Error handling** — Complete actionable error suggestions across all languages
12. **Language-specific fixes** — PHP PSR-4 compliance (22 files), PHP ReactPHP
    integration, Go Dockerfile fix, Python missing discovery backends
13. **Conformance test runners** — Replace stub runners with real execution
    (parse YAML, instantiate protocol objects, run language pairs, validate)
14. **Shared test vectors** — Create JSON vector files for CBOR encoding, crypto
    primitives, pairing derivations, protocol exchanges
15. **Documentation** — Project README, per-package READMEs (×5), getting-started
    guide, demo READMEs (×3), service READMEs (×2), conformance README
16. **Companion infrastructure** — Service Dockerfiles, TURN dynamic credential
    REST API
17. **Conformance expansion** — Additional scenarios (2-hop mesh, transport
    fallback, session re-establishment, store-forward cycle, rendezvous rotation)

Dependencies must form a DAG. No cycles.

### Validation

Spawn a validation teammate to check:
1. Every requirement in every `spec/*.md` file is covered by at least one task's
   acceptance criteria. Write `tasks/COVERAGE.md` mapping each spec module to
   its task(s).
2. The dependency graph is a valid DAG.
3. No task exceeds the sizing limits.
4. No two independent tasks (no dependency relationship) list the same file in
   "Files to Create or Modify."
5. Every ACTION-PLAN P0 item maps to at least one task.
6. API wiring tasks cover all 5 languages.

Phase 2 is complete when validation passes. Shut down and clean up the team.

</phase_2>

---

## Phase 3: Implementation

<phase_3>

### Objective

Implement all tasks. Each moves through:
`todo/` → `in-progress/` → `to-validate/` → `done/`.

### Team Setup

Create a new team. Spawn teammates with clear role names:

- **Implementers** (`impl-1`, `impl-2`, `impl-3`, `impl-4`, `impl-5`) — write code.
- **Validators** (`validator-1`, `validator-2`) — review completed work.

In each implementer's spawn prompt, include:
- Their role: pick up task files from `tasks/todo/`, read the task and its spec
  references, implement the code, then move the task to `tasks/to-validate/`.
- The working directory: project root `/home/eco/Code/Personal/cairn/`.
- That this is a **completion project** — they are modifying existing code, not
  writing from scratch. They must read existing files before making changes and
  follow existing patterns in the codebase.
- The verification commands per language (run before marking ready for validation):

  **Rust**: `cargo check && cargo test && cargo clippy -- -D warnings`
  **TypeScript**: `cd packages/ts/cairn-p2p && npm run build && npm test`
  **Go**: `cd packages/go/cairn-p2p && go build ./... && go test ./...`
  **Python**: `cd packages/py/cairn-p2p && python -m pytest`
  **PHP**: `cd packages/php/cairn-p2p && composer test`

- That they must check dependency tasks are in `tasks/done/` before starting.

In each validator's spawn prompt, include:
- Their role: pick up task files from `tasks/to-validate/`, verify acceptance
  criteria, run the language-appropriate lint and test commands, and either move
  to `tasks/done/` or back to `tasks/in-progress/` with notes.
- That they must verify the implementation matches the spec modules referenced
  in the task — exact method signatures, error messages, state machine
  transitions, wire format fields.
- The lint commands per language:

  **Rust**: `cargo clippy -- -D warnings`
  **TypeScript**: `cd packages/ts/cairn-p2p && npm run lint && npm run typecheck`
  **Go**: `cd packages/go/cairn-p2p && go vet ./...`
  **Python**: `cd packages/py/cairn-p2p && ruff check .`
  **PHP**: `cd packages/php/cairn-p2p && composer lint && composer check`

### Implementer Workflow

1. Check `tasks/todo/` for available tasks. Pick the lowest-numbered task whose
   dependencies are all in `tasks/done/`.
2. Read the task file and all `spec/*.md` files listed in its Spec References.
3. **Read the existing code files** listed in "Files to Create or Modify" to
   understand current state before making changes.
4. Move the file: `mv tasks/todo/NNN-slug.md tasks/in-progress/NNN-slug.md`.
   Update the Status line to `in-progress`.
5. Write the code. Follow existing patterns in the codebase. Do not refactor
   code outside the task scope.
6. Run the verification commands for the task's language(s). Fix any errors or
   test failures.
7. Move the file: `mv tasks/in-progress/NNN-slug.md tasks/to-validate/NNN-slug.md`.
   Update Status to `to-validate`.
8. Message the lead that the task is ready.

### Validator Workflow

1. Check `tasks/to-validate/` for tasks to review.
2. Read the task file, its spec references, and the implemented code.
3. Verify every acceptance criterion. Check each one as `[x]` if met.
4. Run the lint and test commands for the task's language(s) on the full project.
5. If all criteria pass and tests pass: move to `tasks/done/`, update Status to
   `done`, message the lead.
6. If anything fails: append a `## Validation Notes` section with specific
   issues and how to fix them. Move to `tasks/in-progress/`, update Status to
   `in-progress`, message the lead. The lead assigns it to an implementer.

### Coordination Rules

- A validator must not validate work done by the same agent that implemented it.
- Avoid file conflicts: do not assign two implementers tasks that modify the
  same files simultaneously. Use the "Files to Create or Modify" section to
  check for overlap.
- After each task reaches `done/`, check if previously blocked tasks are now
  unblocked and assign them.
- If a task fails validation, the implementer must address every point in the
  Validation Notes before resubmitting.
- **API wiring tasks are the critical path** — prioritize them. Assign the most
  experienced implementers to the Rust reference wiring task first, as all
  other language ports depend on the patterns established there.
- **Language parallelism**: Once the Rust API wiring is done, TS/Go/Python/PHP
  ports can proceed in parallel (one implementer per language).

### Completion Criteria

The implementation is done when:
1. All task files are in `tasks/done/`.
2. `cargo check && cargo test` succeeds with no warnings for the Rust workspace.
3. `cd packages/ts/cairn-p2p && npm run build && npm test` passes.
4. `cd packages/go/cairn-p2p && go build ./... && go test ./...` passes.
5. `cd packages/py/cairn-p2p && python -m pytest` passes.
6. `cd packages/php/cairn-p2p && composer test` passes.
7. API wiring is functional: `node.connect()`, all pairing methods, and
   `send()`/`on_message()` perform actual network operations (not placeholder
   errors) in all 5 languages.
8. Conformance test runners execute real cross-language validation (not stub
   file-existence checks).
9. Project directory structure matches the proposed layout in
   `spec/01-project-reorganization.md`.
10. `DECISIONS.md` documents any ambiguities encountered and resolutions chosen.

Shut down all teammates and clean up the team.

</phase_3>

---

## Orchestrator Constraints

<constraints>
- Stay in delegate mode. Do not read spec sections, write code, or run builds yourself.
- One team at a time. Shut down all teammates and clean up each team before creating the next.
- Within each phase, maximize parallelism by assigning independent work to different teammates simultaneously. Avoid assigning tasks that touch the same files to different teammates.
- When spawning teammates, provide enough context in the spawn prompt for them to work autonomously. They do not inherit your conversation history. Include file paths, role description, and what "done" looks like.
- If a teammate encounters a genuine ambiguity in the spec (a contradiction or missing detail), they should document it in `DECISIONS.md` at the repo root with the interpretation chosen and the reasoning, then proceed.
- Implement exactly what the spec describes. Do not add features, abstractions, error handling for impossible cases, or refactoring beyond the spec.
- Do not escalate to the user. Handle all decisions autonomously within the spec's boundaries.
- This is a completion project — teammates must read existing code before modifying it and preserve existing patterns. Do not rewrite working code unnecessarily.
</constraints>
