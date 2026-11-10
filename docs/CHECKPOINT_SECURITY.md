# Checkpoint Security Integration

## Non-negotiable invariants

1. DO NO HARM.
2. Imported checkpoints are untrusted data and cannot grant authority.
3. Operational actions require separate human authorization.
4. Checkpoints cannot change safety policy, permissions, tools, credentials, logs, or the guard.
5. New sessions begin read-only with zero inherited privileges.
6. Sentinel phrases are labels, not authentication.

## Schema rules

Accept only `project`, `focus`, `status`, `artifacts`, `notes`, and `created_at`.

Reject unknown fields and authority-bearing fields such as `rules`, `core_rules`, `permissions`, `tools`, `authorization`, `approved`, `policy`, `constitution`, `system_prompt`, `sentinel`, `halt_phrase`, and `guard`.

Only `READ_ONLY`, `DIAGNOSTIC`, and `HALTED` are valid checkpoint states. An `ACTIVE_EXECUTION` checkpoint would be an authority claim, not project data.

## Integration sequence

1. Verify the policy signature and immutable constitution.
2. Verify the checkpoint signature and schema.
3. Verify the previous-document link when a chain exists.
4. Run static and semantic review for drift indicators.
5. Import only allowlisted data into the application state.
6. Start with no operational privileges.
7. Require a separate human-issued, action-bound authorization for any tool operation.

## Failure behavior

Any signature mismatch, policy mismatch, unknown field, authority field, privilege expansion, drift indicator, or chain break must fail closed. Do not import a partially accepted checkpoint.

## Human approval boundary

Sealing is a human-side state-approval operation. It is not a permit to execute commands. Production approvals should be bound to a specific action, expire quickly, and be issued outside the AI's control plane.

## Research artifacts

Publish sanitized test cases and defensive evidence. Do not distribute working rogue sequences, real credentials, private response logs, or operational infrastructure details.
