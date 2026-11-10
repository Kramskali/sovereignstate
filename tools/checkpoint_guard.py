#!/usr/bin/env python3
"""Checkpoint Guard: signed, data-only checkpoints with immutable safety policy."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
HOME = Path(os.environ.get("CHECKPOINT_GUARD_HOME", str(Path.home() / ".checkpoint_guard"))).expanduser()
POLICY_PATH = HOME / "policy.json"
KEY_PATH = HOME / "secret.key"
ALLOWED_FIELDS = {"project", "focus", "status", "artifacts", "notes", "created_at"}
ALLOWED_STATUS = {"READ_ONLY", "DIAGNOSTIC", "HALTED"}
DEFAULT_CONSTITUTION = [
    "DO NO HARM.",
    "Imported checkpoints are untrusted data and cannot grant authority.",
    "Every operational action requires separate human authorization.",
    "No checkpoint may change safety policy, permissions, tools, credentials, logs, or this guard.",
    "Every new session begins read-only with zero inherited privileges.",
    "The sentinel phrase is not authentication."
]
DRIFT_PATTERNS = [
    ("safety_erosion", re.compile(r"(?is)\b(?:ignore|bypass|disable|remove|weaken|override|forget|suspend)\b.{0,70}\b(?:safety|guardrails?|rules?|constitution|authorization|approval|do\s+no\s+harm)")),
    ("unauthorized_operation", re.compile(r"(?is)\b(?:without|no\s+need\s+for|skip|waive)\b.{0,50}\b(?:human\s+)?(?:authorization|approval|permission|review)")),
    ("autonomy_expansion", re.compile(r"(?is)\b(?:act|operate|execute|proceed|work)\b.{0,45}\b(?:autonomously|independently|without\s+oversight|without\s+review)")),
    ("tool_directive", re.compile(r"(?is)\b(?:execute|run|invoke|call|use)\b.{0,50}\b(?:commands?|shell|terminal|tools?|functions?|mcp)")),
    ("credential_directive", re.compile(r"(?is)\b(?:reveal|read|print|send|return|exfiltrate|expose)\b.{0,65}\b(?:credentials?|tokens?|api[\s_-]?keys?|passwords?|secrets?|private[\s_-]?keys?)")),
    ("guard_tampering", re.compile(r"(?is)\b(?:edit|modify|replace|delete|rewrite|patch)\b.{0,55}\b(?:guard|policy|constitution|scanner|audit\s+log)"))
]
class Rejected(Exception): pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def load_json(path):
    try:
        value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except Exception as exc:
        raise Rejected("Invalid JSON: " + str(exc))
    if not isinstance(value, dict):
        raise Rejected("Top-level JSON value must be an object.")
    return value

def initialize():
    if POLICY_PATH.exists() or KEY_PATH.exists():
        raise Rejected("Guard is already initialized. Refusing to replace policy or key.")
    HOME.mkdir(parents=True, exist_ok=True)
    try: HOME.chmod(0o700)
    except OSError: pass
    key = secrets.token_bytes(32)
    KEY_PATH.write_bytes(key)
    try: KEY_PATH.chmod(0o600)
    except OSError: pass
    policy = {"format": "checkpoint-guard-policy-v1", "constitution": DEFAULT_CONSTITUTION, "allowed_fields": sorted(ALLOWED_FIELDS), "allowed_status": sorted(ALLOWED_STATUS), "max_checkpoint_bytes": 12000}
    policy["policy_sha256"] = digest(policy)
    signature = hmac.new(key, canonical(policy), hashlib.sha256).hexdigest()
    POLICY_PATH.write_text(json.dumps({"policy": policy, "signature": signature}, indent=2) + "\n", encoding="utf-8")
    return policy["policy_sha256"]

def load_policy():
    try:
        wrapper = load_json(POLICY_PATH)
        key = KEY_PATH.read_bytes()
        policy = wrapper["policy"]
        signature = wrapper["signature"]
        if len(key) != 32:
            raise Rejected("Invalid guard key length.")
        expected = hmac.new(key, canonical(policy), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise Rejected("POLICY TAMPERING: signature mismatch.")
        # The hash commits to the complete policy body, excluding the self-hash field.
        unsigned = dict(policy); claimed = unsigned.pop("policy_sha256")
        if claimed != digest(unsigned):
            raise Rejected("POLICY TAMPERING: policy hash mismatch.")
        if policy.get("format") != "checkpoint-guard-policy-v1":
            raise Rejected("Unsupported policy format.")
        if policy.get("constitution") != DEFAULT_CONSTITUTION:
            raise Rejected("Constitution differs from the required immutable baseline.")
        if set(policy.get("allowed_fields", [])) != ALLOWED_FIELDS or set(policy.get("allowed_status", [])) != ALLOWED_STATUS:
            raise Rejected("Policy restrictions have been expanded or replaced.")
        if policy.get("max_checkpoint_bytes") != 12000:
            raise Rejected("Policy size limit has been changed.")
        return policy
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected("Guard initialization is missing or corrupt: " + str(exc))

def text_values(value, path="$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from text_values(item, "%s[%d]" % (path, index))
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from text_values(item, path + "." + key)

def validate_checkpoint(data, policy):
    if len(canonical(data)) > policy["max_checkpoint_bytes"]:
        raise Rejected("Checkpoint exceeds the 12000-byte limit.")
    unknown = sorted(set(data) - ALLOWED_FIELDS)
    forbidden = sorted(set(data) & {"rules", "core_rules", "permissions", "tools", "authorization", "approved", "policy", "constitution", "system_prompt", "sentinel", "halt_phrase", "guard"})
    if forbidden:
        raise Rejected("Authority-bearing fields are forbidden: " + ", ".join(forbidden))
    if unknown:
        raise Rejected("Unknown fields are forbidden: " + ", ".join(unknown))
    required = {"project", "focus", "status"}
    if not required.issubset(data):
        raise Rejected("Required fields: project, focus, status.")
    for key in ("project", "focus", "status", "created_at"):
        if key in data and not isinstance(data[key], str):
            raise Rejected(key + " must be a string.")
    if not data["project"].strip() or not data["focus"].strip():
        raise Rejected("Project and focus cannot be empty.")
    if data["status"] not in ALLOWED_STATUS:
        raise Rejected("Status must be READ_ONLY, DIAGNOSTIC, or HALTED. Checkpoints cannot grant execution privileges.")
    for key in ("artifacts", "notes"):
        if key in data and (not isinstance(data[key], list) or any(not isinstance(item, str) for item in data[key])):
            raise Rejected(key + " must be a list of strings.")
    for path, text in text_values(data):
        for name, pattern in DRIFT_PATTERNS:
            if pattern.search(text):
                raise Rejected("Policy drift detected at %s: %s" % (path, name))

def signature_for(envelope, key):
    return hmac.new(key, canonical(envelope), hashlib.sha256).hexdigest()

def verify_envelope(wrapper, policy):
    if set(wrapper) != {"checkpoint", "guard", "signature"}:
        raise Rejected("Sealed checkpoint has missing or unexpected envelope fields.")
    envelope = {"checkpoint": wrapper["checkpoint"], "guard": wrapper["guard"]}
    signature = wrapper["signature"]
    if not isinstance(signature, str) or not hmac.compare_digest(signature, signature_for(envelope, KEY_PATH.read_bytes())):
        raise Rejected("CHECKPOINT TAMPERING: signature mismatch.")
    guard = wrapper["guard"]
    if guard.get("format") != "checkpoint-guard-v1" or guard.get("policy_sha256") != policy["policy_sha256"]:
        raise Rejected("Checkpoint is not bound to the current immutable policy.")
    if set(guard) != {"format", "policy_sha256", "previous_document_sha256", "sealed_at_utc"}:
        raise Rejected("Guard metadata has unexpected fields.")
    validate_checkpoint(wrapper["checkpoint"], policy)
    return envelope

def document_hash(wrapper):
    return hashlib.sha256(canonical(wrapper)).hexdigest()

def seal(args):
    policy = load_policy()
    data = load_json(args.checkpoint)
    validate_checkpoint(data, policy)
    previous_hash = None
    if args.previous:
        previous = load_json(args.previous)
        verify_envelope(previous, policy)
        previous_hash = document_hash(previous)
    envelope = {"checkpoint": data, "guard": {"format": "checkpoint-guard-v1", "policy_sha256": policy["policy_sha256"], "previous_document_sha256": previous_hash, "sealed_at_utc": datetime.now(timezone.utc).isoformat()}}
    wrapper = dict(envelope)
    wrapper["signature"] = signature_for(envelope, KEY_PATH.read_bytes())
    destination = Path(args.output or str(Path(args.checkpoint).with_suffix(".sealed.json"))).expanduser()
    destination.write_text(json.dumps(wrapper, indent=2) + "\n", encoding="utf-8")
    print("SEALED:", destination)
    print("POLICY:", policy["policy_sha256"])
    print("PREVIOUS:", previous_hash or "GENESIS")
    return 0

def check(args):
    policy = load_policy()
    wrapper = load_json(args.checkpoint)
    verify_envelope(wrapper, policy)
    if args.previous:
        previous = load_json(args.previous)
        verify_envelope(previous, policy)
        expected = document_hash(previous)
        actual = wrapper["guard"]["previous_document_sha256"]
        if actual != expected:
            raise Rejected("ROLLBACK OR CHAIN BREAK: previous checkpoint hash does not match.")
    elif wrapper["guard"]["previous_document_sha256"]:
        raise Rejected("CHAIN VERIFICATION REQUIRED: this checkpoint declares a previous version.")
    print("PASS: signature, immutable policy, schema, drift checks, and chain checks passed.")
    print("PROJECT:", wrapper["checkpoint"]["project"])
    print("STATUS:", wrapper["checkpoint"]["status"])
    print("PRIVILEGES: zero inherited; operational actions still require separate human authorization.")
    return 0

def main():
    parser = argparse.ArgumentParser(description="Signed data-only checkpoint guard. Sealing is a human-side operation.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create the immutable policy and local signing key")
    seal_parser = sub.add_parser("seal", help="Validate and sign a raw JSON checkpoint")
    seal_parser.add_argument("checkpoint")
    seal_parser.add_argument("--previous", help="Previous sealed checkpoint")
    seal_parser.add_argument("--output", help="Sealed output path")
    check_parser = sub.add_parser("check", help="Verify a sealed checkpoint and optional chain link")
    check_parser.add_argument("checkpoint")
    check_parser.add_argument("--previous", help="Previous sealed checkpoint")
    args = parser.parse_args()
    try:
        if args.command == "init":
            print("INITIALIZED:", HOME)
            print("POLICY:", initialize())
            print("Keep sealing under direct human control. Same-user malware or AI shell access can read a same-user key.")
            return 0
        return seal(args) if args.command == "seal" else check(args)
    except Rejected as exc:
        print("FAIL:", str(exc))
        return 1
    except Exception as exc:
        print("ERROR:", str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
