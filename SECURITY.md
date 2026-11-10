# Security Policy

## Reporting

Report suspected vulnerabilities through the repository owner's GitHub contact channels. Do not open a public issue containing credentials, private checkpoint data, weaponized drift sequences, or unredacted evidence of exploitation.

## Scope

This repository contains a browser interface and reference defensive tools. It is not a production sandbox or a complete operational authorization service.

## Signing-key boundary

The reference signing key is same-user by default. Deployments that grant an AI shell access must move signing and authorization outside that AI's operating-system account.

## Data handling

Do not commit `.bridge_token`, `.checkpoint_guard/`, private keys, logs, sealed operational checkpoints, private vault exports, or real provider responses.
