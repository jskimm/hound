# Invariant Contrast

## Purpose

Add an `InvariantAuditor` role that turns business rules into explicit invariants and reverse-traces candidate bypass paths or forbidden state transitions.

## Scope / Non-Goals

In scope: invariant artifact schema, contrast-check planning, counterexample reasoning, and optional harness metadata.
Out of scope: mandatory code generation for every language/runtime.

## Parent Spec

Threat Model Lanes.

## Compatibility Spec

Invariant reasoning is language-agnostic by default.
Executable harness data is optional and only emitted when a compatible test harness exists.

## Data / Interface Changes

- Add `invariants.json`.
- Invariant records include `invariant_id`, `statement`, `preconditions`, `forbidden_effect`, `related_targets`, `evidence_refs`, `harness_status`.
- Plan items gain invariant provenance fields so the orchestrator can track which rule is being challenged.

## Implementation Plan

1. Add invariant artifact readers/writers and normalization helpers.
2. Implement invariant derivation from threat lanes and graph context.
3. Add contrast-check generation for bypass questions and forbidden writes/state changes.
4. Attach optional harness metadata for supported repos.

## Discipline / Test Gate

Add direct tests for invariant normalization, contrast generation, and harness mode selection.
Do not proceed to telemetry/UI work until invariant artifacts and plan items are stable.

## Acceptance Criteria

- Sessions persist normalized invariants.
- The invariant role can generate contrast checks from business rules.
- Supported repos receive harness metadata without making harness generation mandatory.
