# Threat Model Lanes

## Purpose

Add a dedicated `ThreatModeler` role that derives assets, trust boundaries, loss events, business rules, and threat lanes before deeper auditing.

## Scope / Non-Goals

In scope: session-scoped threat model artifacts, lane generation, and planner inputs.
Out of scope: vulnerability confirmation and executable invariant tests.

## Parent Spec

Orchestrator Core.

## Compatibility Spec

Threat modeling becomes part of the default audit loop but does not change the CLI contract.

## Data / Interface Changes

- Add `threat_model.json`.
- Threat lanes contain `lane_id`, `asset`, `loss_event`, `trust_boundary`, `rule`, `targets`, `status`.
- Planner input consumes lanes instead of only raw coverage heuristics.

## Implementation Plan

1. Add a threat model artifact writer/reader.
2. Implement a role adapter that derives lanes from graphs/code context.
3. Feed derived lanes into orchestrator planning.
4. Expose lane summaries to telemetry and session summaries.

## Discipline / Test Gate

Add direct tests for lane normalization, serialization, and planner integration.
Do not proceed to invariant work until threat lanes persist correctly and can seed plan items.

## Acceptance Criteria

- Each session has a persisted threat model artifact.
- The planner can assign work from threat lanes.
- Session summaries expose current lane counts and statuses.
