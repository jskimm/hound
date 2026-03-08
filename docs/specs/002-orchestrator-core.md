# Orchestrator Core

## Purpose

Replace the single runner-owned audit loop with a cooperative orchestrator that coordinates multiple auditor roles in one session.

## Scope / Non-Goals

In scope: orchestrator loop, role registry, role state model, and reuse of existing Scout/Strategist behavior behind adapters.
Out of scope: parallel workers, lease-based claims, and distributed multi-process orchestration.

## Parent Spec

Session Foundation.

## Compatibility Spec

`hound agent audit` remains the entrypoint.
Existing Scout investigation behavior remains available through the orchestrator.

## Data / Interface Changes

- Add `orchestrator.json` to the session directory.
- Define runtime state for `loop_id`, `phase`, `enabled_roles`, `agent_states`, and `current_assignments`.
- Add an `orchestrator` config section for role ordering and invariant mode.

## Implementation Plan

1. Introduce orchestrator and role interfaces.
2. Wrap Scout and Strategist in role adapters.
3. Add registry-driven role selection from config.
4. Move planning/execution ownership from the runner into the orchestrator.

## Discipline / Test Gate

Unit-test role registration, loop progression, state persistence, and adapter boundaries.
Do not proceed until the orchestrator can run a mocked loop deterministically.

## Acceptance Criteria

- The orchestrator owns batch/loop progression.
- Built-in roles are registered and invoked in configured order.
- Session state records the current loop and per-role status.
