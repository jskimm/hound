# Changelog

## Unreleased

### Added

- Added implementation spec documents under `docs/specs/` for the multi-agent audit upgrade roadmap:
  - session foundation
  - orchestrator core
  - threat model lanes
  - invariant contrast
  - review and provenance
  - telemetry and API
  - chatbot progress UI
  - Solidity fixture and integration tests
- Added canonical session layout helpers and updated session consumers to read `sessions/<session-id>/session.json` with legacy flat-session fallback.
- Added a cooperative audit orchestrator state file and lightweight built-in roles for threat modeling and invariant artifact generation.
- Added agent-aware dashboard payloads and frontend audit-panel updates for orchestrator summaries, per-agent cards, and agent-tagged activity.
- Added a compilable Foundry fixture project with intentionally vulnerable Solidity contracts plus integration tests.
- Added a Codex OAuth bridge so OpenAI-configured profiles can fall back to local `codex` ChatGPT auth when `OPENAI_API_KEY` is not set.
- Added loop-adaptive proof planning with project-wide adaptive memory, per-session proof feedback, strategist-reviewed promotion, and dashboard exposure of adaptive proof stats.
- Renamed adaptive negative memory from `rejected_patterns` to `deprioritized_patterns`, split codegen/harness failures into `execution_blockers`, and made negative memory a soft penalty instead of a hard rejection concept.
