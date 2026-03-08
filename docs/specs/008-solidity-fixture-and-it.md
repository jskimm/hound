# Solidity Fixture And Integration Tests

## Purpose

Create a deliberately vulnerable Solidity fixture project and use it to validate graphing, orchestration, threat modeling, invariant reasoning, and progress reporting end to end.

## Scope / Non-Goals

In scope: a small compilable Foundry fixture, seeded SWC-style issues, and integration tests using it.
Out of scope: a production-grade vulnerability corpus or exhaustive exploit implementations for every issue.

## Parent Spec

Chatbot Progress UI.

## Compatibility Spec

The fixture lives under test assets only and is never used as production code.

## Data / Interface Changes

- Add a Foundry-style fixture project under `tests/fixtures/solidity/`.
- Add integration tests that drive Hound against the fixture and assert artifact/progress outputs.

## Implementation Plan

1. Create a small fixture with around ten intentional vulnerabilities across severity bands.
2. Add helper commands/fixtures so tests can point Hound at the Solidity repo.
3. Add integration tests for graph build, threat lanes, invariants, orchestrator state, and telemetry.
4. Keep tests deterministic with mocked LLM decisions where full model calls are unnecessary.

## Discipline / Test Gate

Every fixture helper and orchestration assertion must be directly tested.
Do not mark the implementation complete until the new integration suite passes in an environment with dev dependencies installed.

## Acceptance Criteria

- The Solidity fixture compiles with Foundry.
- Integration tests can run Hound over the fixture deterministically.
- The suite validates both seeded findings/progress and the new multi-agent artifacts.
