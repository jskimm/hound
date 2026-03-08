# Review And Provenance

## Purpose

Preserve clear ownership and decision trails as multiple roles collaborate on the same audit session.

## Scope / Non-Goals

In scope: investigation provenance, hypothesis provenance exposure, and strategist review ownership.
Out of scope: per-agent hypothesis namespaces or graph overlays.

## Parent Spec

Invariant Contrast.

## Compatibility Spec

Hypotheses remain project-global in storage for v1, but APIs and session records become session- and agent-aware.

## Data / Interface Changes

- Session investigations include `agent_id`, `agent_role`, `loop_id`, `status`, and timing.
- Plan items include assignment and result references.
- Hypothesis listing APIs expose provenance fields already stored in the data.

## Implementation Plan

1. Extend session investigation serialization.
2. Extend plan item metadata for assignments and result references.
3. Update strategist review outputs to preserve provenance.
4. Surface provenance in project/chatbot API responses.

## Discipline / Test Gate

Add direct tests for provenance serialization and API shaping.
Do not proceed to UI work until provenance is visible through backend responses.

## Acceptance Criteria

- Each investigation can be tied back to a role and loop.
- Findings APIs expose the originating agent metadata.
- Strategist remains the final promotion/review authority.
