# Task Plan Coverage Report

Generated: 2026-03-06

## Spec-to-Task Mapping

### spec/01-docusaurus-setup.md
| Requirement | Task(s) |
|---|---|
| Docusaurus scaffolding (package.json, config, tsconfig) | 001-docusaurus-scaffolding |
| Sidebar configuration | 002-sidebar-css-assets |
| Custom CSS / theme overrides | 002-sidebar-css-assets |
| Static assets (logo) | 002-sidebar-css-assets |
| LanguageTabs component | 003-language-tabs-component |
| CI/CD docs deployment workflow | 008-docs-ci-workflow |

### spec/02-landing-page.md
| Requirement | Task(s) |
|---|---|
| Hero section, feature grid, code example, infrastructure tiers | 004-landing-page |

### spec/03-getting-started-content.md
| Requirement | Task(s) |
|---|---|
| installation.md | 005-installation-doc |
| quick-start.md | 006-quick-start-doc |
| first-app.md | 007-first-app-doc |

### spec/04-guides-content.md
| Requirement | Task(s) |
|---|---|
| guides/pairing.md | 016-guide-pairing |
| guides/sessions.md | 017-guide-sessions |
| guides/channels.md | 018-guide-channels |
| guides/server-mode.md | 019-guide-server-mode |
| guides/mesh-routing.md | 020-guide-mesh-routing |

### spec/05-infrastructure-content.md
| Requirement | Task(s) |
|---|---|
| infrastructure/overview.md | 021-infra-overview |
| infrastructure/signaling.md | 022-infra-signaling |
| infrastructure/relay.md | 023-infra-relay |
| infrastructure/server-node.md | 024-infra-server-node |
| infrastructure/cloudflare.md | 025-infra-cloudflare |
| demos/messaging.md | 031-demos-messaging-folder-sync |
| demos/folder-sync.md | 031-demos-messaging-folder-sync |
| demos/server-node.md | 032-demo-server-node |
| README update | 033-readme-update |

### spec/06-api-reference-content.md
| Requirement | Task(s) |
|---|---|
| api/node.md | 026-api-node |
| api/session.md | 027-api-session |
| api/events.md | 028-api-events |
| api/config.md | 029-api-config-errors |
| api/errors.md | 029-api-config-errors |
| internals/wire-protocol.md | 030-internals-wire-protocol-crypto |
| internals/cryptography.md | 030-internals-wire-protocol-crypto |

### spec/07-demo-dockerization.md
| Requirement | Task(s) |
|---|---|
| Messaging Dockerfiles (5 languages) | 039-dockerfiles-messaging |
| Folder-sync Dockerfiles (5 languages) | 040-dockerfiles-folder-sync |
| Messaging docker-compose.yml | 041-compose-messaging |
| Folder-sync docker-compose.yml | 042-compose-folder-sync |
| Server-node docker-compose.yml | 043-compose-server-node |

### spec/08-demo-folder-sync-expansion.md
| Requirement | Task(s) |
|---|---|
| Go folder-sync implementation | 036-folder-sync-go |
| Python folder-sync implementation | 037-folder-sync-python |
| PHP folder-sync implementation | 038-folder-sync-php |

### spec/09-cicd-workflows.md
| Requirement | Task(s) |
|---|---|
| Documentation deployment workflow (.github/workflows/docs.yml) | 008-docs-ci-workflow |
| Demo Docker image publishing workflow | 045-cicd-demo-image-publishing |

## Validation Checks

### Check 1: Coverage -- PASS
All requirements from all 9 spec files are covered by at least one task.

### Check 2: Dependency DAG -- PASS (after fixes)
No cycles detected. Dependency graph is a valid DAG.

**Fixes applied (round 1):** 18 tasks (016-033) referenced `001-docusaurus-init` which did not exist. Fixed all to reference `001-docusaurus-scaffolding`.

**Fixes applied (round 2):** Refined dependencies for tasks 016-033. Instead of depending on `001-docusaurus-scaffolding` alone, each now depends on the precise tasks it actually needs:
- Tasks using LanguageTabs (016-020, 022, 023, 026-029): depend on `002-sidebar-css-assets` + `003-language-tabs-component`
- Tasks not using LanguageTabs (021, 024, 025, 030-032): depend on `002-sidebar-css-assets`
- Task 033 (README): depends on `001-docusaurus-scaffolding` + `002-sidebar-css-assets`

### Check 3: Sizing -- PASS
- No task exceeds 4 source files. Maximum is 3 (tasks 036, 029, 030).
- No task exceeds 7 acceptance criteria. Maximum is 7 (tasks 004, 036, 037, 038, 039, 040, 045).

### Check 4: File Conflicts -- PASS (after fixes)
No two independent tasks modify the same files.

**Fix applied:** Removed duplicate task `044-cicd-docs-workflow` which conflicted with `008-docs-ci-workflow` (both created `.github/workflows/docs.yml`).

### Check 5: Duplicate Tasks -- PASS (after fixes)
**Duplicate found and removed:** Task `044-cicd-docs-workflow` (from planner-3) was a duplicate of `008-docs-ci-workflow` (from planner-1). Both created the same `.github/workflows/docs.yml` with identical content. Removed `044-cicd-docs-workflow`.

### Check 6: Dependency Slug Accuracy -- PASS (after fixes)
All dependency references now match actual filenames in `tasks/todo/`.

**Fixes applied:** 18 files updated across two rounds. First: `001-docusaurus-init` -> `001-docusaurus-scaffolding`. Second: replaced with precise `002`/`003` dependencies per task (see Check 2).

## Final Task Count

**33 tasks** in `tasks/todo/` (after removing 1 duplicate).

## Dependency Graph Summary

```
Layer 0 (no deps):     001, 036, 037, 038, 039, 043
Layer 1 (deps on L0):  002, 003, 008
Layer 2 (deps on L1):  004, 005, 006, 007, 016-024, 026-032, 033, 041
Layer 3 (deps on L2):  025, 040, 042, 045
```
