<!-- tier: A -->
# Workflow / Orchestration Notes (reusable gotchas)

Reusable lessons for authoring multi-agent `Workflow` runs in this repo. Keep
short; one gotcha per section.

## StructuredOutput + `agentType:"Explore"` is unreliable

- In the current harness, spawning a workflow agent with **`agentType:"Explore"`
  together with a forced `schema`** does **not** reliably produce structured output:
  the worker finishes its reading/analysis but **never calls the `StructuredOutput`
  tool**, so `agent({schema})` errors and the result is dropped (`null` in
  `parallel()`).
- **Evidence (A4.1, 2026-06-06):** a 3-phase spike workflow spawned 6 Explore
  extractors + 4 Explore verifiers = **10 Explore workers, all 10 failed** with
  "subagent completed without calling StructuredOutput (after 2 in-conversation
  nudges)". The only schema-forced agent that succeeded was the synthesizer, which
  used the **default** agent type.
- **Do:** for schema-constrained extraction or verification, use the **default agent
  type** (no `agentType`), or do the work with a **deterministic local script**
  (`python3` over the JSON corpus). Reserve `Explore` for free-text reconnaissance
  where you do *not* force a schema.

## Never treat an empty structured-output branch as verified evidence

- A `parallel()` slot that resolved to `null` (because the agent failed to emit
  structured output) is **not** a clean/empty result — it is **missing** evidence.
- If an adversarial-verify phase returns empty, the claims it was meant to check are
  **unverified**, not confirmed. In A4.1 the verify layer returned `[]`; the mapping
  was instead verified by a **deterministic local Python scan**, which in fact found
  errors the (failed) agent layer would have been relied on to catch. Always
  back-stop a failed verify phase with a deterministic check before trusting the
  synthesis.

## Prefer deterministic local scripts for "field inventory / type / presence" tasks

- Questions like "which rounds carry key X", "is field Y an int or object", "does
  token Z appear anywhere" are answered exhaustively and cheaply by a single
  read-only `python3` JSON walk — more reliable than fanning out readers, and not
  subject to the StructuredOutput failure mode above.
