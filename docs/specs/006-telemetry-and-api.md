# Telemetry And API

## Purpose

Extend live telemetry and backend APIs so the frontend can monitor orchestrator and per-agent progress in real time.

## Scope / Non-Goals

In scope: telemetry payload changes, dashboard/tool response updates, and backward-compatible event types.
Out of scope: a brand-new frontend application.

## Parent Spec

Review And Provenance.

## Compatibility Spec

Existing event `type` names stay unchanged.
Consumers may ignore the new fields safely.

## Data / Interface Changes

- Telemetry events add `session_id`, `agent_id`, `agent_role`, `loop_id`, `planning_batch`, `investigation_index`, `investigation_total`, `max_iterations`, `goal`.
- Dashboard and tool responses return agent-aware status data.

## Implementation Plan

1. Centralize telemetry payload shaping.
2. Extend runner/orchestrator publishers to include role and loop context.
3. Update chatbot API responses for plan, activity, findings, and dashboard.
4. Add tests for event and API compatibility.

## Discipline / Test Gate

Add direct tests for telemetry/event builders and chatbot response shaping.
Do not proceed to frontend changes until payload contracts are stable.

## Acceptance Criteria

- Live telemetry identifies the emitting role and loop.
- Existing consumers do not break when they ignore the new fields.
- Backend endpoints return enough state for the UI to render per-agent progress.
