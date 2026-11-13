#!/usr/bin/env python3
"""Third-party verification of a Sentomaru organization audit trail export (Trust E-02b / E-02c).

Standalone (Python stdlib + system `openssl`), so an external auditor or customer can copy it out of the repository.
Contract: contracts/trust/audit-export-v1.md. It also verifies the signed evidence pack (Trust E-07,
contracts/trust/evidence-pack-v1.md): the envelope `format` decides which document the bytes must be. For a pack, pass
`--mappings compliance-mappings-v1.json` (the catalog the pack cites by SHA-256) to check every control against it.

  python3 verify_audit_export.py --envelope export.envelope.json --document export.jsonl \
      --key trust-audit-export-hml-g1.pub --key-sha256 <pin> \
      --expect-organization <org> --expect-from 2026-11-01T00:00:00Z --expect-to 2026-12-01T00:00:00Z \
      [--expect-export <uuid>]

Proves that Sentomaru signed the exact .jsonl document for the organization and window, and that the line-by-line hash
chain and positive detail allowlist hold. It does not prove that the source ledger was complete (the rejection queue can
drop under saturation, and rows past retention were purged) nor that generatedAt comes from a trusted time-stamping
authority. Without --expect-organization, --expect-from and --expect-to the result is
`signature-and-document-verified-unbound` (and a warning goes to stderr): the export is genuine but may not be the one you
asked for. Exit 0 with a JSON summary; 1 with `audit-export-invalid: <code>`; 2 on usage errors.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import os
import stat
import subprocess
import sys
import tempfile

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SLUG = re.compile(r"\A[a-z0-9][a-z0-9-]{0,62}\Z")
SCOPE_LABEL = re.compile(r"\A[a-z0-9][a-z0-9-]{0,62}/[a-z0-9][a-z0-9-]{0,62}\Z")
ACTOR_RE = re.compile(r"\A(internal|(admin|workload):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|rule:[a-z0-9][a-z0-9_-]{0,62}[a-z0-9])\Z")
TAG_RE = re.compile(r"\A[a-z0-9-]{1,32}\Z")
ENVELOPE_LIMIT = 1 << 20
DOCUMENT_LIMIT = 64 << 20

HEADER_KEYS = [
    "schemaVersion", "kind", "exportId", "organization", "window", "eventRefKeyVersion",
    "scopes", "generatedAt", "key", "coverage", "excludedClasses", "kinds",
]
EVENT_KEYS = [
    "seq", "eventRef", "at", "scope", "actor", "kind", "code",
    "resource", "request", "policyVersion", "policyDigest", "details",
]
TRAILER_KEYS = ["count", "droppedDetailKeys", "chainSha256"]
EXCLUDED_CLASSES = ["auth-sessions", "operator-management", "admin-denials-unscoped"]

ORG_KINDS = {
    "audit.export.downloaded",
    "audit.export.requested",
    "audit.read",
    "platform.entitlement.set",
    "platform.plan.set",
    "platform.trial.extend",
    "platform.trial.set",
    "platform.usage.recorded",
}

ALLOWED_DETAILS_BY_KIND = {
    "admin.denied": {"app", "env", "method", "org", "permission", "route"},
    "admin.policy_replay.changed": {"enabled", "previousEnabled"},
    "admin.retention.changed": {"affected", "appliedToExisting", "days", "previousDays"},
    "admin.scope.created": {"packageName"},
    "admin.scope.apple_app.cleared": {"appleAppId", "environment", "previousAppleAppId", "previousEnvironment"},
    "admin.scope.apple_app.set": {"appleAppId", "environment", "previousAppleAppId", "previousEnvironment"},
    "admin.scope.signing_digest.added": {"sha256"},
    "admin.scope.signing_digest.reactivated": {"sha256"},
    "admin.scope.signing_digest.retired": {"sha256"},
    "audit.export.downloaded": {"exportId", "organization"},
    "audit.export.requested": {"exportId", "from", "organization", "to"},
    "audit.read": {"app", "env", "from", "kind", "organization", "to"},
    "caller.reserved.evaluated": set(),
    "device.metadata_updated": {"newNameSha256", "newTags", "oldNameSha256", "oldTags", "requestedInstallationId"},
    "device.quarantined": {"reasonSha256", "requestedInstallationId"},
    "device.suspended": {"reasonSha256", "requestedInstallationId", "until"},
    "device.suspension_released": {"reasonSha256", "requestedInstallationId"},
    "evaluation.accepted": set(),
    "grant.revoked": {"reasonSha256"},
    "installation.enrolled": {"predecessor"},
    "installation.revoked": {"reasonSha256"},
    "installation.superseded": set(),
    "platform.entitlement.set": {"enabledAfter", "enabledBefore", "module", "organization", "overageAfter", "overageBefore",
                                 "quotaAfterSha256", "quotaBeforeSha256"},
    "platform.plan.set": {"endsAtAfter", "endsAtBefore", "organization", "planAfter", "planBefore"},
    "platform.trial.extend": {"endsAtAfter", "endsAtBefore", "organization"},
    "platform.trial.set": {"endsAtAfter", "endsAtBefore", "organization", "planAfter", "planBefore"},
    "platform.usage.recorded": {"app", "env", "metric", "module", "occurredAt", "organization", "quantity", "sourceSha256"},
    "policy.approval_refused": set(),
    "policy.cases.read": {"days", "limit", "rule"},
    "policy.drafted": {"mode", "policyId"},
    "policy.published": {"mode", "policyId"},
    "policy.simulated": {"candidateDigestSha256", "windowHours"},
    "policy.retired": {"mode", "policyId"},
    "response.alerted": {"count", "evidence", "incident", "mode", "rule"},
    "response.already-revoked": {"count", "evidence", "incident", "mode", "rule"},
    "response.already-suspended": {"count", "evidence", "incident", "mode", "rule"},
    "response.quarantined": {"count", "evidence", "incident", "mode", "rule"},
    "response.suspended": {"count", "evidence", "incident", "mode", "rule"},
    "shield.vulnerability.vex_reverted": {"ended", "justification", "reviewDue"},
    "shield.vulnerability.vex_set": {"justification", "replaced", "reviewDue"},
    "verification.rejected": {"component"},
}

ALL_KINDS = sorted(ALLOWED_DETAILS_BY_KIND)

# Trust E-07: the evidence pack (contracts/trust/evidence-pack-v1.md).
AUDIT_ENVELOPE_FORMAT = "sentomaru-audit-export-envelope/1"
PACK_ENVELOPE_FORMAT = "sentomaru-evidence-pack-envelope/1"
PACK_HEADER_KEYS = ["schemaVersion", "kind", "notice", "packId", "organization", "window", "generatedAt", "key", "frameworks",
                    "mappings", "scopes"]
PACK_NOTICE = ("Evidência técnica gerada pelo Sentomaru para apoiar uma avaliação. Não é laudo, parecer jurídico nem atestado de "
               "cumprimento de norma. Os mapeamentos são rascunho não revisado por responsável regulatório. A lista de lacunas "
               "faz parte do documento.")
PACK_FRAMEWORKS = ["lgpd-art6", "sentomaru-audit-trail"]
PACK_REGISTER_STATES = ["draft-not-reviewed", "reviewed-accepted-for-this-catalog-digest", "adjustments-pending"]
PACK_GAPS = ["play-integrity-observe", "advisory-signals", "build-record-partial", "mappings-draft", "frameworks-absent",
             "rejection-queue-loss"]
PACK_CONTROL_KEYS = ["line", "framework", "id", "principle", "title", "claim", "limits", "reviewStatus", "evidence"]
PACK_GAP_KEYS = ["line", "id", "text", "measured"]
PACK_NOT_COVERED_KEYS = ["line", "framework", "principle", "reason"]
PACK_TRAILER_KEYS = ["count", "chainSha256"]
CONTROL_ID = re.compile(r"\A[A-Z]{2,5}(-[IVX]+)?-[0-9]{2}\Z")


class Invalid(Exception):
    """The stable code is str(error). `detail` is optional diagnosis, shown only with --explain, never part of the code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.detail = detail


_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}")


def _names(values):
    """Names from an untrusted document, for a diagnosis line: only plain identifiers, at most 20, the rest counted."""
    shown = []
    for value in values:
        shown.append(value if isinstance(value, str) and _NAME.fullmatch(value) else "<not-a-name>")
    more = len(shown) - 20
    return "[" + ", ".join(shown[:20]) + (f", ... +{more}" if more > 0 else "") + "]"


def _diff(label, got, want):
    """What differs between a list the document declared and the list this verifier expects."""
    if not isinstance(got, list):
        return f"{label}: not a list"
    missing = [x for x in want if x not in got]
    extra = [x for x in got if x not in want]
    if missing or extra:
        return f"{label}: missing={_names(missing)} extra={_names(extra)}"
    return f"{label}: same members, different order or repetition"


def strict_json(raw_bytes, code):
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise Invalid(code + "-duplicate-key")
        return dict(items)

    def constant(_):
        raise Invalid(code + "-number")

    try:
        text = raw_bytes.decode("utf-8") if isinstance(raw_bytes, (bytes, bytearray)) else raw_bytes
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except Invalid:
        raise
    except (UnicodeDecodeError, ValueError):
        raise Invalid(code + "-json") from None


def read_file(path, code, limit):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise Invalid(code + "-missing")
    data = file.read_bytes()
    if len(data) > limit:
        raise Invalid(code + "-size")
    return data


def parse_utc(value, code):
    if not isinstance(value, str) or not value.endswith("Z") or "T" not in value:
        raise Invalid(code)
    try:
        dt = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Invalid(code) from None
    if dt.tzinfo is None:
        raise Invalid(code)
    return dt.astimezone(timezone.utc)


def parse_expect_utc(value, code):
    if not isinstance(value, str) or "T" not in value:
        raise Invalid(code)
    try:
        dt = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise Invalid(code) from None
    if dt.tzinfo is None:
        raise Invalid(code)
    return dt.astimezone(timezone.utc)


# --- openssl: located by fixed, validated paths, never through PATH; its answer is checked, not only its exit code ---
OPENSSL_CANDIDATES = ("/usr/bin/openssl", "/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl")


def _untrusted_node(path, uid, leaf):
    info = os.lstat(path)
    if info.st_uid not in (0, uid):
        return True
    if info.st_mode & 0o022:
        # a sticky directory owned by root (/tmp) is accepted above the file: others cannot rename what it holds
        return leaf or not (stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
    return False


def trusted_openssl(env=None):
    """Absolute path of an openssl this process may run, or None. SENTOMARU_OPENSSL replaces the candidate list (and is checked the same way)."""
    env = os.environ if env is None else env
    explicit = env.get("SENTOMARU_OPENSSL")
    uid = os.getuid() if hasattr(os, "getuid") else None
    for candidate in ((explicit,) if explicit else OPENSSL_CANDIDATES):
        if not os.path.isabs(candidate):
            continue
        try:
            real = os.path.realpath(candidate)
            if not (os.path.isfile(real) and os.access(real, os.X_OK)):
                continue
            if uid is None:  # no POSIX owner/mode: nothing to check, refuse unless the caller opted in
                if env.get("SENTOMARU_VERIFY_ALLOW_UNCHECKED") == "1":
                    return real
                continue
            if _untrusted_node(real, uid, True):
                continue
            bad = False
            for chain in (os.path.abspath(candidate), real):
                parent = os.path.dirname(chain)
                while True:
                    if _untrusted_node(parent, uid, False):
                        bad = True
                        break
                    up = os.path.dirname(parent)
                    if up == parent:
                        break
                    parent = up
                if bad:
                    break
            if not bad:
                return real
        except OSError:
            continue
    return None


def openssl_env():
    """The environment openssl runs with: only what it needs. OPENSSL_CONF, OPENSSL_MODULES, OPENSSL_ENGINES, LD_PRELOAD, DYLD_* and the
    rest of the caller's environment are not passed, so they cannot load a configuration, engine or provider into the verifier."""
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    return env


def openssl_verifies(tool, key, signature, message):
    """True only when openssl exits 0 AND prints `Verified OK`: a program that merely exits 0 does not validate anything."""
    run = subprocess.run([tool, "dgst", "-sha256", "-verify", key, "-signature", signature, message], capture_output=True, timeout=30,
                         env=openssl_env())
    return run.returncode == 0 and run.stdout.strip() == b"Verified OK"


def openssl_verify(pem, document, signature):
    tool = trusted_openssl()
    if tool is None:
        raise Invalid("openssl-unavailable")
    with tempfile.TemporaryDirectory(prefix="sentomaru-audit-export-") as work:
        paths = {name: Path(work) / name for name in ("key.pem", "document.jsonl", "signature.der")}
        paths["key.pem"].write_bytes(pem)
        paths["document.jsonl"].write_bytes(document)
        paths["signature.der"].write_bytes(signature)
        try:
            good = openssl_verifies(tool, str(paths["key.pem"]), str(paths["signature.der"]), str(paths["document.jsonl"]))
            # Negative control: other bytes under the same signature must not verify (a program that says yes to everything is not openssl).
            paths["document.jsonl"].write_bytes(document + b"\0")
            control = openssl_verifies(tool, str(paths["key.pem"]), str(paths["signature.der"]), str(paths["document.jsonl"]))
        except subprocess.TimeoutExpired:
            raise Invalid("signature-timeout")
        except OSError:
            raise Invalid("openssl-unavailable")
    if control:
        raise Invalid("openssl-misbehaves")
    if not good:
        raise Invalid("signature")


def check_details(kind, details):
    if not isinstance(details, dict):
        raise Invalid("event-details")
    keys = list(details.keys())
    if keys != sorted(keys):
        raise Invalid("event-details")
    allowed = ALLOWED_DETAILS_BY_KIND[kind]
    for k, v in details.items():
        if k not in allowed:
            raise Invalid("event-details")
        if k in ("oldTags", "newTags"):
            if not isinstance(v, list) or len(v) > 8 or any(not isinstance(t, str) or not TAG_RE.fullmatch(t) for t in v):
                raise Invalid("event-details")
        elif k in ("reasonSha256", "oldNameSha256", "newNameSha256", "sha256", "quotaBeforeSha256", "quotaAfterSha256", "candidateDigestSha256"):
            if v is not None and (not isinstance(v, str) or not HEX64.fullmatch(v)):
                raise Invalid("event-details")
        else:
            if v is not None and not isinstance(v, (str, int, float, bool)):
                raise Invalid("event-details")
            # Review finding 8: a text value is at most 256 characters and holds no control character.
            if isinstance(v, str) and (len(v) > 256 or any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in v)):
                raise Invalid("event-details")


def verify_export(envelope_bytes, document_bytes, pem_bytes, pin, expectations, mappings_bytes=None):
    if not HEX64.fullmatch(pin or ""):
        raise Invalid("key-pin-format")
    if hashlib.sha256(pem_bytes).hexdigest() != pin:
        raise Invalid("key-pin")

    envelope = strict_json(envelope_bytes, "envelope")
    required_env = {"format", "documentSha256", "signatureAlgorithm", "signatureBase64", "keyName", "keyVersion"}
    if not isinstance(envelope, dict) or not (set(envelope) == required_env or set(envelope) == (required_env | {"documentBase64"})):
        raise Invalid("envelope-shape")
    if envelope.get("format") not in (AUDIT_ENVELOPE_FORMAT, PACK_ENVELOPE_FORMAT):
        raise Invalid("envelope-shape")
    if envelope.get("signatureAlgorithm") != "ecdsa-p256-sha256-der":
        raise Invalid("signature-algorithm")
    if not isinstance(envelope.get("keyName"), str) or type(envelope.get("keyVersion")) is not int or envelope["keyVersion"] < 1:
        raise Invalid("envelope-shape")

    if document_bytes is None:
        if "documentBase64" not in envelope:
            raise Invalid("document-missing")
        try:
            document_bytes = base64.b64decode(envelope["documentBase64"], validate=True)
        except (ValueError, TypeError):
            raise Invalid("envelope-base64") from None

    try:
        signature = base64.b64decode(envelope["signatureBase64"], validate=True)
    except (ValueError, TypeError):
        raise Invalid("envelope-base64") from None

    digest = hashlib.sha256(document_bytes).hexdigest()
    if not isinstance(envelope.get("documentSha256"), str) or envelope["documentSha256"] != digest:
        raise Invalid("document-sha256")

    openssl_verify(pem_bytes, document_bytes, signature)

    if not document_bytes.endswith(b"\n"):
        raise Invalid("document-newline")
    raw_lines = document_bytes[:-1].split(b"\n")
    if len(raw_lines) < 2 or any(len(line) == 0 for line in raw_lines):
        raise Invalid("document-lines")

    if envelope["format"] == PACK_ENVELOPE_FORMAT:
        return verify_pack(envelope, raw_lines, digest, expectations, mappings_bytes)

    header = strict_json(raw_lines[0], "header")
    if not isinstance(header, dict) or list(header.keys()) != HEADER_KEYS:
        raise Invalid("header-shape", _diff("header members", list(header.keys()), HEADER_KEYS) if isinstance(header, dict)
                      else "header is not a JSON object")
    if header["schemaVersion"] != "1.0.0" or header["kind"] != "sentomaru-audit-export":
        raise Invalid("header-shape", "schemaVersion and kind must be 1.0.0 and sentomaru-audit-export; got " +
                      _names([header["schemaVersion"], header["kind"]]))
    if not isinstance(header["exportId"], str) or not UUID_RE.fullmatch(header["exportId"]):
        raise Invalid("header-export-id")
    if not isinstance(header["organization"], str) or not SLUG.fullmatch(header["organization"]) or header["organization"] == "trust":
        raise Invalid("header-organization")
    if not isinstance(header["window"], dict) or list(header["window"].keys()) != ["from", "to"]:
        raise Invalid("header-window")
    win_from = parse_utc(header["window"]["from"], "header-window")
    win_to = parse_utc(header["window"]["to"], "header-window")
    if win_from >= win_to or (win_to - win_from) > timedelta(days=31):
        raise Invalid("header-window")
    if type(header["eventRefKeyVersion"]) is not int or not (1 <= header["eventRefKeyVersion"] <= 999):
        raise Invalid("header-key-version")
    scopes = header["scopes"]
    if not isinstance(scopes, list) or not scopes or scopes != sorted(scopes) or len(scopes) != len(set(scopes)) or \
            any(not isinstance(s, str) or not SCOPE_LABEL.fullmatch(s) for s in scopes):
        raise Invalid("header-scopes")
    parse_utc(header["generatedAt"], "header-generated-at")
    if header["key"] != {"name": envelope["keyName"], "version": envelope["keyVersion"]}:
        raise Invalid("header-key")
    cov = header["coverage"]
    if not isinstance(cov, dict) or list(cov.keys()) != ["lifecycle", "rejection"]:
        raise Invalid("header-coverage")
    for cls_name, days in (("lifecycle", 400), ("rejection", 30)):
        entry = cov[cls_name]
        if not isinstance(entry, dict) or list(entry.keys()) != ["status", "retentionDays", "effectiveFrom"] or \
                entry["status"] not in ("complete", "partial") or entry["retentionDays"] != days:
            raise Invalid("header-coverage")
        parse_utc(entry["effectiveFrom"], "header-coverage")
    if header["excludedClasses"] != EXCLUDED_CLASSES:
        raise Invalid("header-shape", _diff("excludedClasses", header["excludedClasses"], EXCLUDED_CLASSES))
    if header["kinds"] != ALL_KINDS:
        raise Invalid("header-shape", _diff("kinds", header["kinds"], ALL_KINDS) +
                      " (the document lacks kinds this verifier knows, or has kinds it does not know: the verifier and the API "
                      "that signed the document are not the same version)")

    if expectations.get("export") is not None and header["exportId"] != expectations["export"]:
        raise Invalid("expect-export")
    if expectations.get("organization") is not None and header["organization"] != expectations["organization"]:
        raise Invalid("expect-organization")
    if expectations.get("from") is not None:
        if win_from != parse_expect_utc(expectations["from"], "expect-from"):
            raise Invalid("expect-from")
    if expectations.get("to") is not None:
        if win_to != parse_expect_utc(expectations["to"], "expect-to"):
            raise Invalid("expect-to")

    chain = hashlib.sha256((b"\x00" * 32) + raw_lines[0]).digest()
    scope_set = set(scopes)
    prev_at = None
    event_lines = raw_lines[1:-1]

    for idx, raw_line in enumerate(event_lines, start=1):
        ev = strict_json(raw_line, "event")
        if not isinstance(ev, dict) or list(ev.keys()) != EVENT_KEYS:
            raise Invalid("event-shape")
        if type(ev["seq"]) is not int or ev["seq"] != idx:
            raise Invalid("event-seq")
        if not isinstance(ev["eventRef"], str) or not HEX64.fullmatch(ev["eventRef"]):
            raise Invalid("event-ref")
        ev_at = parse_utc(ev["at"], "event-at")
        if ev_at < win_from or ev_at >= win_to:
            raise Invalid("event-at")
        if prev_at is not None and ev_at < prev_at:
            raise Invalid("event-order")
        prev_at = ev_at

        kind = ev["kind"]
        if not isinstance(kind, str) or kind not in ALLOWED_DETAILS_BY_KIND:
            raise Invalid("event-kind")
        if kind in ORG_KINDS:
            if ev["scope"] is not None or not isinstance(ev["details"], dict) or ev["details"].get("organization") != header["organization"]:
                raise Invalid("event-scope")
        else:
            if not isinstance(ev["scope"], str) or ev["scope"] not in scope_set:
                raise Invalid("event-scope")

        if not isinstance(ev["actor"], str) or not ACTOR_RE.fullmatch(ev["actor"]):
            raise Invalid("event-actor")
        if not isinstance(ev["code"], str) or not ev["code"]:
            raise Invalid("event-code")
        for uuid_field in ("resource", "request"):
            if ev[uuid_field] is not None and (not isinstance(ev[uuid_field], str) or not UUID_RE.fullmatch(ev[uuid_field])):
                raise Invalid("event-shape")
        if ev["policyVersion"] is not None and not isinstance(ev["policyVersion"], str):
            raise Invalid("event-shape")
        if ev["policyDigest"] is not None and (not isinstance(ev["policyDigest"], str) or not HEX64.fullmatch(ev["policyDigest"])):
            raise Invalid("event-shape")

        check_details(kind, ev["details"])
        chain = hashlib.sha256(chain + raw_line).digest()

    trailer = strict_json(raw_lines[-1], "trailer")
    if not isinstance(trailer, dict) or list(trailer.keys()) != TRAILER_KEYS:
        raise Invalid("trailer-shape")
    if type(trailer["count"]) is not int or trailer["count"] != len(event_lines):
        raise Invalid("trailer-count")
    if type(trailer["droppedDetailKeys"]) is not int or trailer["droppedDetailKeys"] < 0:
        raise Invalid("trailer-shape")
    if not isinstance(trailer["chainSha256"], str) or trailer["chainSha256"] != chain.hex():
        raise Invalid("trailer-chain")

    # Without the organization and the window the caller expects, a genuine export of ANOTHER organization or window passes
    # the signature and the document checks. Say so in the result instead of calling it verified.
    unbound = [name for name in ("organization", "from", "to") if expectations.get(name) is None]
    return {
        "result": "signature-and-document-verified" if not unbound else "signature-and-document-verified-unbound",
        "unboundExpectations": unbound,
        "exportId": header["exportId"],
        "organization": header["organization"],
        "window": header["window"],
        "scopes": header["scopes"],
        "count": trailer["count"],
        "droppedDetailKeys": trailer["droppedDetailKeys"],
        "documentSha256": digest,
        "chainSha256": trailer["chainSha256"],
        "key": header["key"],
        "coverage": header["coverage"],
        "generatedAt": header["generatedAt"],
        "notVerified": ([
            "that this is the export you asked for: pass " + " ".join("--expect-" + name for name in unbound) +
            " (the document was not bound to an organization or window you expected)"] if unbound else []) + [
            "completeness of the source audit ledger (rejection queue drops under saturation; rows past retention were purged)",
            "trusted signing time (generatedAt is declared without an external TSA)",
        ],
    }


def verify_pack(envelope, raw_lines, digest, expectations, mappings_bytes):
    """Trust E-07: header, notice, draft marks, gaps, controls, chain. Called after hash and signature have passed."""
    if len(raw_lines) < 3:
        raise Invalid("document-lines")
    header = strict_json(raw_lines[0], "header")
    if not isinstance(header, dict) or list(header.keys()) not in (PACK_HEADER_KEYS, PACK_HEADER_KEYS + ["register"]):
        raise Invalid("header-shape", _diff("pack header members", list(header.keys()), PACK_HEADER_KEYS + ["register"])
                      if isinstance(header, dict) else "header is not a JSON object")
    # 1.0.0 is the header without the review register; 1.1.0 adds the "register" member (E-03) and nothing else.
    if header["schemaVersion"] != ("1.1.0" if "register" in header else "1.0.0") or header["kind"] != "sentomaru-evidence-pack":
        raise Invalid("header-shape")
    if header["notice"] != PACK_NOTICE:
        raise Invalid("header-notice")
    if not isinstance(header["packId"], str) or not UUID_RE.fullmatch(header["packId"]):
        raise Invalid("header-pack-id")
    if not isinstance(header["organization"], str) or not SLUG.fullmatch(header["organization"]) or header["organization"] == "trust":
        raise Invalid("header-organization")
    if not isinstance(header["window"], dict) or list(header["window"].keys()) != ["from", "to"]:
        raise Invalid("header-window")
    win_from = parse_utc(header["window"]["from"], "header-window")
    win_to = parse_utc(header["window"]["to"], "header-window")
    if win_from >= win_to or (win_to - win_from) > timedelta(days=31):
        raise Invalid("header-window")
    parse_utc(header["generatedAt"], "header-generated-at")
    if header["key"] != {"name": envelope["keyName"], "version": envelope["keyVersion"]}:
        raise Invalid("header-key")
    frameworks = header["frameworks"]
    if not isinstance(frameworks, list) or not frameworks or frameworks != [f for f in PACK_FRAMEWORKS if f in frameworks]:
        raise Invalid("header-frameworks")
    mappings = header["mappings"]
    if not isinstance(mappings, dict) or list(mappings.keys()) != ["catalogVersion", "status", "sha256"] or \
            mappings["catalogVersion"] != "compliance-mappings-v1" or mappings["status"] != "draft-not-reviewed" or \
            not isinstance(mappings["sha256"], str) or not HEX64.fullmatch(mappings["sha256"]):
        raise Invalid("header-mappings")
    if "register" in header:
        register = header["register"]
        if not isinstance(register, list) or not register or any(
                not isinstance(r, dict) or list(r.keys()) != ["framework", "state", "catalogSha256", "acceptedOn"] for r in register):
            raise Invalid("header-register")
        if [r["framework"] for r in register] != [f for f in frameworks if f in {r["framework"] for r in register}] or \
                any(r["framework"] not in frameworks for r in register):
            raise Invalid("header-register")
        for r in register:
            if r["state"] not in PACK_REGISTER_STATES or not isinstance(r["catalogSha256"], str) or not HEX64.fullmatch(r["catalogSha256"]):
                raise Invalid("header-register")
            accepted = r["acceptedOn"]
            if (r["state"] == "reviewed-accepted-for-this-catalog-digest") != isinstance(accepted, str) or \
                    (accepted is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", accepted)):
                raise Invalid("header-register")
    scopes = header["scopes"]
    if not isinstance(scopes, list) or scopes != sorted(scopes) or len(scopes) != len(set(scopes)) or \
            any(not isinstance(x, str) or not SCOPE_LABEL.fullmatch(x) for x in scopes):
        raise Invalid("header-scopes")

    if expectations.get("export") is not None and header["packId"] != expectations["export"]:
        raise Invalid("expect-export")
    if expectations.get("organization") is not None and header["organization"] != expectations["organization"]:
        raise Invalid("expect-organization")
    if expectations.get("from") is not None and win_from != parse_expect_utc(expectations["from"], "expect-from"):
        raise Invalid("expect-from")
    if expectations.get("to") is not None and win_to != parse_expect_utc(expectations["to"], "expect-to"):
        raise Invalid("expect-to")

    chain = hashlib.sha256((b"\x00" * 32) + raw_lines[0]).digest()
    body_lines = raw_lines[1:-1]
    controls, gaps, not_covered, order = [], [], [], []
    for raw in body_lines:
        line = strict_json(raw, "line")
        kind = line.get("line") if isinstance(line, dict) else None
        if kind == "control":
            if list(line.keys()) != PACK_CONTROL_KEYS:
                raise Invalid("control-shape")
            if line["framework"] not in frameworks or not isinstance(line["id"], str) or not CONTROL_ID.fullmatch(line["id"]):
                raise Invalid("control-shape")
            if line["reviewStatus"] != "draft-not-reviewed":
                raise Invalid("control-review-status")
            if any(not isinstance(line[k], str) or not line[k] for k in ("principle", "title", "claim", "limits")):
                raise Invalid("control-shape")
            if not isinstance(line["evidence"], list) or not line["evidence"] or any(
                    not isinstance(e, dict) or list(e.keys()) != ["source", "type", "result"] or e["type"] not in ("static", "measured")
                    for e in line["evidence"]):
                raise Invalid("control-evidence")
            controls.append(line)
        elif kind == "gap":
            if list(line.keys()) != PACK_GAP_KEYS or not isinstance(line["id"], str) or not isinstance(line["text"], str):
                raise Invalid("gap-shape")
            gaps.append(line)
        elif kind == "notCovered":
            if list(line.keys()) != PACK_NOT_COVERED_KEYS or line["framework"] not in frameworks:
                raise Invalid("not-covered-shape")
            not_covered.append(line)
        else:
            raise Invalid("line-kind")
        order.append(kind)
        chain = hashlib.sha256(chain + raw).digest()
    if order != sorted(order, key=["control", "gap", "notCovered"].index):
        raise Invalid("line-order")
    if [g["id"] for g in gaps] != PACK_GAPS:
        raise Invalid("gaps-missing")
    if len({c["id"] for c in controls}) != len(controls):
        raise Invalid("control-duplicate")
    for framework in frameworks:
        if not any(c["framework"] == framework for c in controls):
            raise Invalid("framework-without-controls")

    trailer = strict_json(raw_lines[-1], "trailer")
    if not isinstance(trailer, dict) or list(trailer.keys()) != PACK_TRAILER_KEYS:
        raise Invalid("trailer-shape")
    if type(trailer["count"]) is not int or trailer["count"] != len(body_lines):
        raise Invalid("trailer-count")
    if not isinstance(trailer["chainSha256"], str) or trailer["chainSha256"] != chain.hex():
        raise Invalid("trailer-chain")

    not_verified = [
        "completeness of the source audit ledger (rejection queue drops under saturation; rows past retention were purged)",
        "trusted signing time (generatedAt is declared without an external TSA)",
        "that the mappings are right: they are a draft not reviewed by a regulatory reviewer",
    ]
    if "register" in header:
        not_verified.append("the review register: its states are declared by the issuer and were not checked against the register or the reviewer's document")
    if mappings_bytes is None:
        not_verified.insert(0, "the controls against the mapping catalog: pass --mappings compliance-mappings-v1.json")
    else:
        if hashlib.sha256(mappings_bytes).hexdigest() != mappings["sha256"]:
            raise Invalid("mappings-sha256")
        catalog = strict_json(mappings_bytes, "mappings")
        wanted = [(f["id"], c["id"]) for f in catalog["frameworks"] if f["id"] in frameworks for c in f["controls"]]
        if [(c["framework"], c["id"]) for c in controls] != wanted:
            raise Invalid("controls-vs-catalog")
        # Review RA-05: the text of each line is the claim; ids alone let a signed pack carry another claim, limit or gap text.
        expected_controls = [c for f in catalog["frameworks"] if f["id"] in frameworks for c in f["controls"]]
        for line, wanted_control in zip(controls, expected_controls):
            if any(line[k] != wanted_control[k] for k in ("principle", "title", "claim", "limits")) or \
                    [(e["source"], e["type"]) for e in line["evidence"]] != [(e["source"], e["type"]) for e in wanted_control["evidence"]]:
                raise Invalid("controls-vs-catalog")
        if [g["text"] for g in gaps] != [g["text"] for g in catalog["gaps"]]:
            raise Invalid("gaps-vs-catalog")
        pending_not_covered = [(f["id"], n["principle"]) for f in catalog["frameworks"] if f["id"] in frameworks for n in f["notCovered"]]
        if [(n["framework"], n["principle"]) for n in not_covered] != pending_not_covered:
            raise Invalid("not-covered-vs-catalog")
        expected_reasons = [n["reason"] for f in catalog["frameworks"] if f["id"] in frameworks for n in f["notCovered"]]
        if [n.get("reason") for n in not_covered] != expected_reasons:
            raise Invalid("not-covered-vs-catalog")
        if [g["id"] for g in catalog["gaps"]] != PACK_GAPS:
            raise Invalid("gaps-vs-catalog")
    unbound = [name for name in ("organization", "from", "to") if expectations.get(name) is None]
    return {
        "result": "signature-and-document-verified" if not unbound else "signature-and-document-verified-unbound",
        "documentKind": "sentomaru-evidence-pack",
        "unboundExpectations": unbound,
        "packId": header["packId"],
        "organization": header["organization"],
        "window": header["window"],
        "frameworks": frameworks,
        "mappingsStatus": mappings["status"],
        "controls": len(controls),
        "gaps": len(gaps),
        "count": trailer["count"],
        "documentSha256": digest,
        "chainSha256": trailer["chainSha256"],
        "key": header["key"],
        "generatedAt": header["generatedAt"],
        "notVerified": ([
            "that this is the pack you asked for: pass " + " ".join("--expect-" + name for name in unbound)] if unbound else []) + not_verified,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--envelope", required=True, help="path to the JSON signature envelope")
    parser.add_argument("--document", help="path to the .jsonl audit export document")
    parser.add_argument("--key", required=True, help="published PEM file")
    parser.add_argument("--key-sha256", required=True, help="SHA-256 of the PEM bytes, obtained out of band")
    parser.add_argument("--expect-export", help="expected exportId UUID")
    parser.add_argument("--expect-organization", help="expected organization slug")
    parser.add_argument("--expect-from", help="expected window start (ISO-8601 UTC)")
    parser.add_argument("--expect-to", help="expected window end (ISO-8601 UTC)")
    parser.add_argument("--explain", action="store_true",
                        help="on audit-export-invalid, add one `audit-export-detail:` line to stderr when the check has one (today: header-shape)")
    parser.add_argument("--mappings", help="evidence pack only: compliance-mappings-v1.json, checked by SHA-256 against the header")
    args = parser.parse_args(argv)
    try:
        pem_bytes = read_file(args.key, "key", ENVELOPE_LIMIT)
        envelope_bytes = read_file(args.envelope, "envelope", ENVELOPE_LIMIT)
        document_bytes = read_file(args.document, "document", DOCUMENT_LIMIT) if args.document else None
        mappings_bytes = read_file(args.mappings, "mappings", ENVELOPE_LIMIT) if args.mappings else None
        summary = verify_export(
            envelope_bytes, document_bytes, pem_bytes, args.key_sha256,
            {
                "export": args.expect_export,
                "organization": args.expect_organization,
                "from": args.expect_from,
                "to": args.expect_to,
            }, mappings_bytes)
    except Invalid as error:
        if str(error) in ("openssl-unavailable", "openssl-misbehaves"):
            # The environment cannot verify: not "invalid" (1), so a missing openssl is never read as a bad export.
            print("verify-unavailable: " + str(error), file=sys.stderr)
            return 2
        print(f"audit-export-invalid: {error}", file=sys.stderr)
        if args.explain and getattr(error, "detail", None):
            print(f"audit-export-detail: {error.detail}", file=sys.stderr)
        return 1
    except OSError:
        print("audit-export-invalid: io", file=sys.stderr)
        return 1
    if summary["unboundExpectations"]:
        print("audit-export-warning: unbound (" + ", ".join(summary["unboundExpectations"]) +
              "): the export was not checked against the organization or window you expect", file=sys.stderr)
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
