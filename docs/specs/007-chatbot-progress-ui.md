# Chatbot Progress UI

## Purpose

Upgrade the existing audit panel to visualize orchestrator and per-agent progress without introducing a separate dashboard product.

## Scope / Non-Goals

In scope: orchestrator summary, per-agent cards, agent-aware activity, plan, and findings views.
Out of scope: a standalone SPA or deep design rewrite.

## Parent Spec

Telemetry And API.

## Compatibility Spec

Existing chat and artifact viewer behavior stays intact.
If new agent-aware fields are absent, the UI should degrade gracefully to the current single-agent view.

## Data / Interface Changes

- Add an orchestrator summary strip with loop and phase.
- Replace the single pinned “now investigating” assumption with per-agent progress cards.
- Add role/provenance badges in findings and activity views.

## Implementation Plan

1. Add render helpers for orchestrator summary and per-agent cards.
2. Update activity stream handling to dedupe per agent.
3. Update plan and finding views to show assignment/provenance.
4. Verify graceful fallback when only old payloads are present.

## Discipline / Test Gate

Add tests for UI data shaping where possible and backend support tests for all new fields.
Do not proceed to fixture integration until the monitoring surface can display multi-agent state.

## Acceptance Criteria

- The audit panel shows the current loop and each active role.
- Activity and findings show agent provenance.
- The page still works with old or partially populated payloads.
