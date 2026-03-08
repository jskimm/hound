# Session Foundation

## Purpose

Normalize audit session persistence so all new runtime state lives under `sessions/<session-id>/` and can support multi-agent orchestration safely.

## Scope / Non-Goals

In scope: canonical session file layout, legacy read compatibility, session summary schema, project/chatbot reader updates, and tests.
Out of scope: orchestrator scheduling, threat modeling, invariant execution, and UI redesign beyond reading the new layout.

## Parent Spec

Multi-agent audit orchestration with cooperative scheduling and role-based collaboration.

## Compatibility Spec

New runs write only to `sessions/<session-id>/`.
Existing flat `sessions/<session-id>.json` files remain readable.
Existing CLI entrypoints stay unchanged.

## Data / Interface Changes

- Canonical files:
  - `sessions/<session-id>/session.json`
  - `sessions/<session-id>/plan.json`
  - `sessions/<session-id>/state.json`
- Session summary records include `session_id`, `status`, `models`, `coverage`, `planning_history`, `investigations`, `token_usage`.
- Session readers must prefer `session.json` and fall back to the legacy flat JSON if needed.

## Implementation Plan

1. Add helpers to resolve canonical session directories and summary files.
2. Update `SessionTracker` to write `session.json` inside the session directory.
3. Update project and chatbot readers to enumerate directory-backed sessions first.
4. Add migration-safe tests for new and legacy layouts.

## Discipline / Test Gate

Add direct unit tests for every new helper and every materially changed reader/writer path.
Do not proceed to orchestrator work until session read/write tests pass.

## Acceptance Criteria

- A new audit session creates and updates `sessions/<session-id>/session.json`.
- Existing commands still show legacy flat sessions correctly.
- Project/chatbot status views can read both layouts.
