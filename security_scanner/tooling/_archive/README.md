# Archived tooling (2026-06-11)

One-shot scripts moved out of the active `tooling/` directory during the
operational hardening pass. Kept in-repo as the audit trail of what was
applied when — each `_apply_*.py` encodes a historical code mutation
(already merged; re-running would no-op or fail). `_proto_*.py` are
research prototypes that never shipped.

Active tooling (verify gates, benchmark runner, diagnostics, doc
builders) remains one level up in `tooling/`.
