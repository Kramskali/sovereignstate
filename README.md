# SovereignState

Local-first multi-AI checkpoint and orchestration interface with a defensive checkpoint integrity toolchain.

SovereignState helps one human director coordinate multiple AI providers without inventing synchronization, sharing credentials, or treating imported project state as authority.

## What is included

- `index.html`: self-contained SovState browser interface. Supports ChatGPT, Claude, Gemini, and Kimi dispatch, local checkpoints, attributable response ingestion, consensus packets, and JSON import/export.
- `tools/payload_sentinel.py`: read-only static screening for concealed AI-directed instructions, hidden HTML, invisible Unicode, encoded instructions, credential directives, and tool directives.
- `tools/checkpoint_guard.py`: signed, data-only checkpoint envelopes with immutable policy verification, schema enforcement, drift indicators, signed lineage, and rollback detection.
- `docs/THREAT_MODEL.md`: the checkpoint instruction-drift threat model and trust boundaries.
- `docs/CHECKPOINT_SECURITY.md`: integration rules for checkpoint-based systems.
- `examples/safe-checkpoint.json`: a read-only example with no operational authority.
- `tests/`: functional tests for the defensive tools.

## Honest transport boundary

The browser interface uses manual copy-and-paste transport between provider tabs. A browser `BroadcastChannel` does not cross different AI provider domains. This repository does not claim automatic cross-provider injection, response capture, or synchronization.

## Run the interface

Open `index.html` in a browser. No build, server, external asset, account, or API key is required.

Vault entries and response logs stay in the current browser's local storage. Export JSON before clearing browser data or moving devices.

## Payload Sentinel

```bash
python3 tools/payload_sentinel.py path/to/checkpoint.txt
python3 tools/payload_sentinel.py --json --output report.json path/to/folder
python3 tools/payload_sentinel.py https://example.com/public-page.html
```

Exit codes: `0` no signal or low signal, `1` human review recommended, `2` scan error.

NO SIGNAL does not prove safety. HIGH REVIEW does not prove malicious intent.

## Checkpoint Guard

Initialize the local policy and signing key:

```bash
python3 tools/checkpoint_guard.py init
```

Seal and verify a safe checkpoint:

```bash
python3 tools/checkpoint_guard.py seal examples/safe-checkpoint.json --output safe.sealed.json
python3 tools/checkpoint_guard.py check safe.sealed.json
```

Chain the next version:

```bash
python3 tools/checkpoint_guard.py seal next.json --previous safe.sealed.json --output next.sealed.json
python3 tools/checkpoint_guard.py check next.sealed.json --previous safe.sealed.json
```

Sealing approves a state package, not command execution. Checkpoints have zero inherited operational privileges. Every new session must begin read-only, and operational actions require separate human authorization.

### Deployment limitation

The reference implementation stores its signing key in the current user's home directory. An AI or process with shell access as that same user may be able to read the key. For meaningful isolation, run sealing and tool authorization outside the AI's account, on another device, or behind a separately privileged guard service.

This repository does not yet implement an operational tool-permission broker. Do not represent it as one.

## Tests

Python 3.9+ and the standard library are sufficient.

```bash
python3 -m unittest discover -s tests -v
```

## Safety and research handling

The project documents defensive controls for gradual checkpoint instruction drift. It intentionally excludes weaponized checkpoint sequences, rogue-state examples, credentials, private AI responses, and operational tunnel data.

## License

MIT. See `LICENSE`.
