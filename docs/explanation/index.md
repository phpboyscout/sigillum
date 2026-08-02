---
title: Explanation
description: Understanding-oriented material — how sigillum is assembled, why it is a separate tool from gtb, and what it deliberately does not do.
tags: [explanation, architecture, concepts, limitations]
---

# Explanation

Understanding-oriented material: what sigillum is, how it is put together, the
reasoning behind those choices, and where the edges are.

sigillum is a **standalone signing CLI**. It owns almost no logic of its own —
it wires together upstream modules and ships the signing backends. That thinness
is deliberate, and the pages below explain why.

- **[Components & architecture](components/index.md)** — the module stack
  (sigillum → `go/signing-cli` → `go/signing` + backends) and how the pieces fit
  together.
- **[Concepts](concepts/index.md)** — why sigillum exists as a separate tool
  from gtb, and the build-time backend blank-import model.
- **[What sigillum does not do](what-sigillum-does-not-do.md)** — the limits.
  No verify command, no key algorithm that serves both signature formats, no
  encrypted private keys, no runtime backend selection, no configurable signing.

## Where should I start?

- If you are trying to decide whether sigillum fits your pipeline, read
  [Concepts](concepts/index.md) and then
  [What sigillum does not do](what-sigillum-does-not-do.md).
- If something failed and you want to know whether it is meant to,
  [What sigillum does not do](what-sigillum-does-not-do.md) lists the refusals
  with their exact error messages.
- If you are changing the code or adding a backend,
  [Components & architecture](components/index.md) has the module boundaries.
