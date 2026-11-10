# Threat Model

## Protected assets

- Human authorization boundaries
- Immutable safety policy
- Tool and credential isolation
- Checkpoint provenance and attribution
- Audit history and rollback integrity
- Local project state

## Primary failure mode: gradual instruction drift

A checkpoint system may transport more than project state. If each imported checkpoint is treated as authoritative history, small changes to rules, permissions, exceptions, or operational scope can become inherited instructions. Each individual change may appear reasonable while the sequence weakens the original safety baseline.

This is an application and orchestration-layer failure. It does not require or demonstrate removal of a provider's internal model safety training.

## Why static scanning is insufficient

Static indicators can catch obvious concealed instructions, encoded directives, and hidden HTML. They cannot reliably catch every paraphrase, benign-looking exception, multi-checkpoint change, or future trained backdoor.

The primary defense is architectural: imported checkpoints are data, not policy.

## Trust boundaries

1. Human safety constitution: authoritative and outside AI-editable checkpoint content.
2. Imported checkpoint: untrusted data with an allowlisted schema.
3. Sealed checkpoint: signed state with verified lineage, still no execution authority.
4. Operational authorization: separate human decision, never inherited from checkpoint text.
5. Tool execution: must be independently constrained by an external broker.

## Reference controls

- Immutable constitution and signed policy
- Forbidden authority-bearing fields
- Read-only default status
- Signed checkpoint envelopes
- Previous-document hashes and rollback rejection
- Drift indicators for common policy-erasure and privilege-expansion language
- Explicit same-user signing-key limitation

## Out of scope for this release

- Automatic provider-to-provider transport
- Prevention of every possible harmful model output
- Detection of future trained backdoors from static text alone
- Hardware-backed signing
- A production operational tool-permission broker
- Proof that a sealed checkpoint is factually correct
