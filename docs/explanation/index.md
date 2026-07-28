# Explanation

Understanding-oriented material: what sigillum is, how it is put together, and
the reasoning behind those choices.

sigillum is a **pure, standalone signing/verification CLI**. It owns almost no
logic of its own — it wires together upstream modules and ships the signing
backends. That thinness is deliberate, and the pages below explain why.

- **[Components & architecture](components/index.md)** — the module stack
  (sigillum → `go/signing-cli` → `go/signing` + backends) and how the pieces
  fit together.
- **[Concepts](concepts/index.md)** — why sigillum exists as a separate tool
  from gtb, and the build-time backend blank-import model.
