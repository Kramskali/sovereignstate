#!/usr/bin/env python3
"""Payload Sentinel: read-only screening for concealed AI-directed payloads."""
import argparse
import base64
import hashlib
import html
import ipaddress
import json
import re
import socket
import sys
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
MAX_BYTES = 2_000_000
TEXT_SUFFIXES = {".txt", ".html", ".htm", ".md", ".json", ".xml", ".csv", ".py", ".js", ".css", ".yaml", ".yml"}
INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
PATTERNS = [
    ("instruction_override", 5, re.compile(r"(?i)\b(?:ignore|disregard|override|bypass|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|system|developer|safety|original)?\s*(?:instructions?|rules?|prompts?|constraints?)")),
    ("concealment_instruction", 5, re.compile(r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|show|reveal|disclose|mention|alert)\s+(?:the\s+)?(?:user|human|operator|anyone)\b")),
    ("credential_request", 6, re.compile(r"(?i)\b(?:reveal|print|return|send|expose|exfiltrate|steal|read)\b[^\n]{0,70}\b(?:api[\s_-]?keys?|tokens?|credentials?|passwords?|secrets?|private[\s_-]?keys?)\b")),
    ("exfiltration_instruction", 6, re.compile(r"(?i)\b(?:exfiltrate|transmit|upload|send)\b[^\n]{0,80}\b(?:to\s+(?:https?://|this|that|my|the)|external|remote|attacker|server|endpoint)\b")),
    ("tool_instruction", 4, re.compile(r"(?i)\b(?:call|invoke|execute|run|use)\b[^\n]{0,55}\b(?:tools?|functions?|commands?|shell|terminal|mcp|browser)\b")),
    ("ai_targeted_instruction", 3, re.compile(r"(?i)\b(?:dear|attention|note\s+to|instruction\s+to|message\s+to)\s+(?:the\s+)?(?:ai|assistant|llm|language\s+model|chatgpt|claude|gemini|kimi|crawler|scraper)\b")),
    ("hidden_role_instruction", 4, re.compile(r"(?i)\b(?:you\s+are|act\s+as|from\s+now\s+on)\s+(?:a|an|the|now)?\s*(?:system|developer|root|admin|unrestricted|jailbroken|new)\b")),
    ("conditional_trigger", 4, re.compile(r"(?i)\b(?:when|whenever|if)\s+(?:someone|anyone|a\s+user|the\s+user|asked|you\s+see|triggered)\b[^\n]{0,100}\b(?:then|must|always|secretly|automatically)\b")),
    ("training_directive", 4, re.compile(r"(?i)\b(?:training\s+data|fine[\s_-]?tuning|model\s+weights?|future\s+models?|memorize\s+this|learn\s+this\s+trigger)\b")),
]
COMMENT_RE = re.compile(r"<!--(.*?)-->|<!\[CDATA\[(.*?)]]>", re.S)
HIDDEN_RE = re.compile(r"(?is)<([a-z0-9]+)\b[^>]*(?:style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|position\s*:\s*absolute[^'\"]*(?:left|top)\s*:\s*-)[^'\"]*['\"]|\shidden(?:\s|=|>)|aria-hidden\s*=\s*['\"]true['\"])[^>]*>(.{0,1600}?)</\1\s*>")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){40,})(?![0-9A-Fa-f])")

@dataclass
class Finding:
    kind: str
    weight: int
    line: int
    evidence: str

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    allow_private = False
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def validate_url(url, allow_private=False):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not accepted.")
    if not parsed.hostname:
        raise ValueError("URL has no hostname.")
    if allow_private:
        return
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve URL hostname: " + str(exc))
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("Private, local, reserved, and non-public addresses are blocked. Use --allow-private only for your own test server.")

def fetch_url(url, allow_private=False):
    validate_url(url, allow_private)
    handler = SafeRedirect()
    handler.allow_private = allow_private
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={"User-Agent": "PayloadSentinel/1.0 (read-only security screening)"})
    with opener.open(request, timeout=15) as response:
        length = response.headers.get("Content-Length")
        if length and int(length) > MAX_BYTES:
            raise ValueError("Remote document exceeds the size limit.")
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Remote document exceeds the size limit.")
        charset = response.headers.get_content_charset() or "utf-8"
        return data.decode(charset, errors="replace")

def clean_evidence(text):
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return text[:240].encode("ascii", "backslashreplace").decode("ascii")

def instruction_hits(text):
    return [(name, weight) for name, weight, pattern in PATTERNS if pattern.search(text)]

def scan_text(text):
    findings = []
    normalized = unicodedata.normalize("NFKC", text)
    searchable = "".join(ch for ch in normalized if ch not in INVISIBLE and ch not in BIDI)

    for number, line in enumerate(normalized.splitlines(), 1):
        present = sorted(set(line) & INVISIBLE)
        bidi = sorted(set(line) & BIDI)
        if present:
            findings.append(Finding("invisible_unicode", 3, number, "Invisible characters: " + " ".join("U+%04X" % ord(c) for c in present)))
        if bidi:
            findings.append(Finding("bidi_control", 5, number, "Bidirectional controls: " + " ".join("U+%04X" % ord(c) for c in bidi)))

    for name, weight, pattern in PATTERNS:
        for match in pattern.finditer(searchable):
            line = searchable.count("\n", 0, match.start()) + 1
            evidence = searchable.splitlines()[line - 1] if searchable.splitlines() else match.group(0)
            findings.append(Finding(name, weight, line, clean_evidence(evidence)))

    for match in COMMENT_RE.finditer(normalized):
        content = match.group(1) if match.group(1) is not None else match.group(2)
        for name, weight in instruction_hits(content):
            findings.append(Finding("concealed_comment_" + name, weight + 3, normalized.count("\n", 0, match.start()) + 1, clean_evidence(content)))

    for match in HIDDEN_RE.finditer(normalized):
        content = match.group(2)
        for name, weight in instruction_hits(content):
            findings.append(Finding("hidden_html_" + name, weight + 4, normalized.count("\n", 0, match.start()) + 1, clean_evidence(content)))

    for regex, decoder, label in [
        (B64_RE, lambda value: base64.b64decode(value + "=" * (-len(value) % 4), validate=True), "base64"),
        (HEX_RE, bytes.fromhex, "hex"),
    ]:
        for match in regex.finditer(normalized):
            try:
                raw = decoder(match.group(1))
                decoded = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if len(decoded) < 20 or sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) < 0.9:
                continue
            for name, weight in instruction_hits(decoded):
                findings.append(Finding("encoded_%s_%s" % (label, name), weight + 3, normalized.count("\n", 0, match.start()) + 1, "Decoded payload: " + clean_evidence(decoded)))

    unique = []
    seen = set()
    for item in findings:
        key = (item.kind, item.line, item.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

def collect_files(path):
    if path.is_file():
        return [path]
    files = []
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in TEXT_SUFFIXES and candidate.stat().st_size <= MAX_BYTES:
            files.append(candidate)
            if len(files) >= 100:
                break
    return sorted(files)

def scan_target(target, allow_private=False):
    documents = []
    if re.match(r"^https?://", target, re.I):
        documents.append((target, fetch_url(target, allow_private)))
    else:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise ValueError("Target does not exist: " + str(root))
        for path in collect_files(root):
            documents.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
    results = []
    for source, text in documents:
        findings = scan_text(text)
        score = sum(item.weight for item in findings)
        verdict = "HIGH REVIEW" if score >= 10 else "REVIEW" if score >= 5 else "LOW SIGNAL" if score else "NO SIGNAL"
        results.append({"source": source, "sha256": hashlib.sha256(text.encode()).hexdigest(), "bytes": len(text.encode()), "score": score, "verdict": verdict, "findings": [asdict(item) for item in findings]})
    return results

def main():
    parser = argparse.ArgumentParser(description="Read-only screening for concealed AI-directed payloads. Findings require human review.")
    parser.add_argument("target", help="Local file, folder, or public HTTP(S) URL")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--output", help="Write the report to this file")
    parser.add_argument("--allow-private", action="store_true", help="Allow local/private URL targets only for systems you own")
    args = parser.parse_args()
    try:
        results = scan_target(args.target, args.allow_private)
    except Exception as exc:
        print("SCAN ERROR:", str(exc), file=sys.stderr)
        return 2
    report = {"tool": "Payload Sentinel", "version": VERSION, "scanned_at": datetime.now(timezone.utc).isoformat(), "limitations": "Static indicators only. No finding proves malicious intent or a future model backdoor. No clean result proves safety.", "documents": results}
    if args.json:
        output = json.dumps(report, indent=2)
    else:
        lines = ["PAYLOAD SENTINEL " + VERSION, "Static indicators only. Human review required."]
        for result in results:
            lines += ["", "SOURCE:", result["source"], "SHA256:", result["sha256"], "VERDICT: %s | SCORE: %d | FINDINGS: %d" % (result["verdict"], result["score"], len(result["findings"]))]
            for item in result["findings"]:
                lines.append("  [+%d] %s line %d: %s" % (item["weight"], item["kind"], item["line"], item["evidence"]))
        output = "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).expanduser().write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 1 if any(result["score"] >= 5 for result in results) else 0

if __name__ == "__main__":
    raise SystemExit(main())
