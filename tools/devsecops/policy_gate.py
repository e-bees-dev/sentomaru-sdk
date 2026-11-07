#!/usr/bin/env python3
"""G-02: policy gate of the client's CI (contracts/devsecops/policy-gate-v1.md).

Fails the build that has no valid protection profile, no valid CycloneDX SBOM, or a known vulnerable dependency at
or above the chosen severity. Runs on the client's runner and never sends the binary, the profile or any secret.
With `--osv-api` the components' package URLs (including those of internal libraries) go to the OSV API; use
`--osv-db` to keep everything on the runner. Exit codes and error codes are stable; what is not understood (a version,
a range, a component without a package URL, a severity) fails closed.

Usage:
  policy_gate.py --profile protect-profile.json --sbom sbom.json --out build/sentomaru-policy
                 (--osv-api [--osv-api-url https://api.osv.dev] | --osv-db <dir> --osv-db-sha256 <hex>)
                 [--min-severity low|medium|high|critical]   (default high)
                 [--exceptions exceptions.json] [--profile-sha256 <hex>]
                 [--allow-unavailable-db] [--allow-components-without-purl]
  policy_gate.py --hash-db <dir>       prints the digest to pin as --osv-db-sha256
"""
import argparse
import datetime as dt
import functools
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osv_versions  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PROFILE_SCHEMA = ROOT / "contracts/devsecops/protect-profile-v1.schema.json"
CDX_DIR = ROOT / "contracts/devsecops/schemas/cyclonedx"
# Vendored official CycloneDX schemas (specification tag 1.6.1); checked before use, so an edited schema never passes.
CDX_SCHEMAS = {
    "bom-1.5.schema.json": "5a2f8740206e4afedcbc97a67fbdc6f5d20dc8d3a8bc0f7f14bf75884a6e7ddb",
    "bom-1.6.schema.json": "efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541",
    "spdx.schema.json": "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}
VERSION = "1"
SEVERITIES = ["low", "medium", "high", "critical"]
MAX_INPUT = 64 * 1024 * 1024
MAX_RECORD = 4 * 1024 * 1024
MAX_EXCEPTION_DAYS = 180
TEST_HTTP_ENV = "SENTOMARU_POLICY_GATE_TEST_HTTP"   # tests only: allow http://127.0.0.1 as the OSV API
EXIT = {"usage": 2, "exception-format": 2, "profile-missing": 3, "profile-invalid": 3, "profile-digest-mismatch": 3,
        "sbom-missing": 4, "sbom-invalid": 4, "sbom-version-unsupported": 4, "sbom-no-components": 4,
        "sbom-components-unmatched": 4, "vulnerable-dependency": 5, "exception-expired": 5,
        "vuln-db-integrity": 6, "vuln-db-unavailable": 6, "internal-error": 1}
PRECEDENCE = ["internal-error", "usage", "exception-format", "profile-missing", "profile-invalid", "profile-digest-mismatch",
              "sbom-missing", "sbom-invalid", "sbom-version-unsupported", "sbom-no-components",
              "sbom-components-unmatched", "vuln-db-integrity", "vuln-db-unavailable", "vulnerable-dependency",
              "exception-expired"]


class GateError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def strict_json(data, code):
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError) as e:
        raise GateError(code, f"not JSON ({type(e).__name__})")


def load_json(path, missing, invalid):
    p = Path(path)
    if not p.is_file():
        raise GateError(missing, p.name)
    if p.stat().st_size > MAX_INPUT:
        raise GateError(invalid, "above 64 MiB")
    return strict_json(p.read_bytes(), invalid)


def jsonschema_module():
    try:
        import jsonschema
        import referencing
        return jsonschema, referencing
    except ImportError:
        raise GateError("internal-error", "install the gate dependencies: pip install --require-hashes -r "
                                          "tools/devsecops/policy-gate.requirements.lock")


def schema_errors(instance, schema, registry=None):
    jsonschema, _ = jsonschema_module()
    cls = jsonschema.validators.validator_for(schema)
    kwargs = {"format_checker": cls.FORMAT_CHECKER}
    if registry:
        kwargs["registry"] = registry
    return sorted(cls(schema, **kwargs).iter_errors(instance), key=lambda e: list(e.absolute_path))


# ---- profile

def check_profile(path, pin):
    profile = load_json(path, "profile-missing", "profile-invalid")
    errors = schema_errors(profile, json.loads(PROFILE_SCHEMA.read_text()))
    if errors:
        where = "/".join(str(p) for p in errors[0].absolute_path) or "(root)"
        raise GateError("profile-invalid", f"{where}: {errors[0].validator}")
    digest = sha256_file(path)
    if pin and digest != pin.lower():
        raise GateError("profile-digest-mismatch", "the profile is not the pinned registry revision")
    return {"status": "pass", "profileId": profile["profileId"], "sha256": digest, "pinned": bool(pin)}


# ---- SBOM

def cdx_registry():
    _, referencing = jsonschema_module()
    resources = []
    for name, expected in CDX_SCHEMAS.items():
        data = (CDX_DIR / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise GateError("internal-error", f"vendored schema {name} changed")
        resource = referencing.Resource.from_contents(json.loads(data))
        # Registered under their own $id, the base their relative $refs resolve against; nothing is fetched.
        resources.append((resource.id(), resource))
    return referencing.Registry().with_resources(resources)


def check_sbom(path):
    sbom = load_json(path, "sbom-missing", "sbom-invalid")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise GateError("sbom-invalid", "not a CycloneDX document")
    version = sbom.get("specVersion")
    if version not in ("1.5", "1.6"):
        raise GateError("sbom-version-unsupported", f"specVersion {version!r} (1.5 or 1.6)")
    registry = cdx_registry()
    errors = schema_errors(sbom, registry.contents(f"http://cyclonedx.org/schema/bom-{version}.schema.json"), registry)
    if errors:
        where = "/".join(str(p) for p in errors[0].absolute_path) or "(root)"
        raise GateError("sbom-invalid", f"{where}: {errors[0].validator}")
    components = list(walk_components(sbom.get("components", [])))
    return sbom, {"status": "pass", "specVersion": version, "sha256": sha256_file(path), "components": len(components),
                  "withPurl": sum(1 for c in components if c.get("purl"))}


def walk_components(components):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from walk_components(c.get("components"))


PURL = re.compile(r"^pkg:([A-Za-z0-9.+-]+)/(.+?)@([^?#]+)")
ECOSYSTEMS = {"maven": "Maven", "pub": "Pub", "npm": "npm", "pypi": "PyPI", "nuget": "NuGet", "golang": "Go",
              "cargo": "crates.io", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex"}


def normalize_name(ecosystem, name):
    """Package name as OSV keys it: PEP 503 for PyPI, case-insensitive for npm and NuGet."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "NuGet"):
        return name.lower()
    return name


def purl_package(purl):
    """(ecosystem, normalized name, version) of a package URL in OSV terms, or None."""
    m = PURL.match(purl or "")
    if not m or m.group(1).lower() not in ECOSYSTEMS:
        return None
    ptype, path, version = m.group(1).lower(), urllib.parse.unquote(m.group(2)), urllib.parse.unquote(m.group(3))
    ecosystem = ECOSYSTEMS[ptype]
    name = path.replace("/", ":") if ptype == "maven" else path
    return ecosystem, normalize_name(ecosystem, name), version


# ---- severity

def cvss3_score(vector):
    """Base score of a CVSS v3.x vector (FIRST specification), or None."""
    if not str(vector).startswith("CVSS:3."):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        ac = {"L": .77, "H": .44}[m["AC"]]
        changed = {"U": False, "C": True}[m["S"]]
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        c, i, a = ({"H": .56, "L": .22, "N": 0}[m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = min((1.08 if changed else 1) * (impact + 8.22 * av * ac * pr * ui), 10)
    whole = round(raw * 100000)        # Roundup of the specification (v3.1, Appendix A)
    return whole / 100000 if whole % 10000 == 0 else (whole // 10000 + 1) / 10


def band(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def severity_of(record):
    """Highest of the record's readable severities: the database label (GHSA, trusted) and the CVSS v3.x scores.
    None (unknown, counts above any threshold) when there is neither: only a CVSS v4 vector (not scored here), an
    unreadable v3 vector, or no severity at all."""
    found = []
    label = str((record.get("database_specific") or {}).get("severity", "")).lower()
    label = {"moderate": "medium"}.get(label, label)
    if label in SEVERITIES:
        found.append(label)
    for s in record.get("severity") or []:
        if str(s.get("type", "")).upper() == "CVSS_V3":
            score = cvss3_score(str(s.get("score", "")))
            if score is not None:
                found.append(band(score))
    # CVSS v4 vectors and unreadable v3 vectors add nothing; with no label and no readable v3 the severity is unknown.
    return max(found, key=SEVERITIES.index) if found else None


# ---- offline matching (OSV schema evaluation)

def range_affects(rng, ecosystem, version):
    """True / False for one range; True when the range or the versions cannot be understood (fail closed)."""
    kind = rng.get("type")
    if kind == "GIT":
        return False                   # commit ranges cannot apply to a package version; documented
    cmp = osv_versions.comparator(kind, ecosystem)
    if cmp is None:
        return True
    events = [e for e in rng.get("events") or [] if isinstance(e, dict)]
    def position(e):
        value = str(next(iter(e.values()), ""))
        return (0, "") if value == "0" else (1, value)

    def order(x, y):
        (kx, vx), (ky, vy) = position(x), position(y)
        return kx - ky if kx != ky else (cmp(vx, vy) if kx else 0)
    try:
        events.sort(key=functools.cmp_to_key(order))     # the OSV schema evaluates events in version order
        vulnerable = False
        for e in events:
            if "introduced" in e:
                if e["introduced"] == "0" or cmp(version, e["introduced"]) >= 0:
                    vulnerable = True
            elif "fixed" in e:
                if cmp(version, e["fixed"]) >= 0:
                    vulnerable = False
            elif "last_affected" in e:
                if cmp(version, e["last_affected"]) > 0:
                    vulnerable = False
        return vulnerable
    except osv_versions.Unparseable:
        return True


def record_affects(record, ecosystem, name, version):
    for a in record.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or normalize_name(ecosystem, str(pkg.get("name", ""))) != name:
            continue
        if version in (a.get("versions") or []):
            return True
        if any(range_affects(r, ecosystem, version) for r in a.get("ranges") or [] if isinstance(r, dict)):
            return True
    return False


# ---- vulnerability sources

def tree_sha256(directory):
    digest = hashlib.sha256()
    for p in sorted(Path(directory).rglob("*.json")):
        if p.is_symlink():
            raise GateError("vuln-db-integrity", "symlink in the OSV database")
        digest.update(p.relative_to(directory).as_posix().encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return digest.hexdigest()


def offline_findings(packages, directory, pin):
    d = Path(directory)
    if not d.is_dir():
        raise GateError("vuln-db-unavailable", "OSV database directory missing")
    digest = tree_sha256(d)
    if not pin or digest != pin.lower():
        raise GateError("vuln-db-integrity", "OSV database digest not pinned or different")
    index, records, withdrawn = {}, 0, 0
    for p in sorted(d.rglob("*.json")):
        if p.stat().st_size > MAX_RECORD:
            raise GateError("vuln-db-integrity", f"OSV record above {MAX_RECORD // 1024 // 1024} MiB")
        record = strict_json(p.read_bytes(), "vuln-db-integrity")
        if not isinstance(record, dict):
            raise GateError("vuln-db-integrity", "OSV record is not an object")
        records += 1
        if record.get("withdrawn"):
            withdrawn += 1
            continue
        for a in record.get("affected") or []:
            pkg = (a or {}).get("package") or {}
            eco = str(pkg.get("ecosystem", ""))
            index.setdefault((eco, normalize_name(eco, str(pkg.get("name", "")))), []).append(record)
    found = []
    for purl, (eco, name, version) in packages.items():
        for record in index.get((eco, name), []):
            if record_affects(record, eco, name, version) and (purl, record) not in found:
                found.append((purl, record))
    return {"mode": "offline", "databaseSha256": digest, "records": records, "withdrawn": withdrawn}, found


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise urllib.error.URLError("redirect refused")


def api_client(base, retries=2, backoff=0.5):
    url = urllib.parse.urlsplit(base)
    loopback = url.scheme == "http" and url.hostname == "127.0.0.1" and os.environ.get(TEST_HTTP_ENV) == "1"
    if not (url.scheme == "https" or loopback) or url.username or not url.hostname:
        raise GateError("usage", "--osv-api-url must be https")
    handlers = [NoRedirect()] + ([urllib.request.ProxyHandler({})] if loopback else [])
    opener = urllib.request.build_opener(*handlers)

    def call(method, path, body=None):
        last = "unknown"
        for attempt in range(retries + 1):
            if attempt:
                time.sleep(backoff * attempt)
            request = urllib.request.Request(base.rstrip("/") + path, method=method,
                                             data=None if body is None else json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
            try:
                with opener.open(request, timeout=20) as response:
                    data = response.read(MAX_INPUT + 1)
                if len(data) > MAX_INPUT:
                    raise GateError("vuln-db-integrity", "OSV API answer too large")
                return strict_json(data, "vuln-db-integrity")
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code}"
                if e.code < 500 and e.code != 429:
                    break
            except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError) as e:
                last = type(e).__name__
        raise GateError("vuln-db-unavailable", f"OSV API {last}")
    return call


def api_findings(packages, base, retries=2, backoff=0.5):
    call = api_client(base, retries, backoff)
    found, details = [], {}

    def detail(vid):
        if vid not in details:
            record = call("GET", "/v1/vulns/" + urllib.parse.quote(vid, safe=""))
            if not isinstance(record, dict) or record.get("id") != vid:
                raise GateError("vuln-db-integrity", "OSV API detail does not match the requested id")
            details[vid] = record
        return details[vid]

    pending = [{"purl": p.split("?")[0].split("#")[0], "original": p, "token": None} for p in packages]
    while pending:
        chunk, pending = pending[:500], pending[500:]
        queries = [{"package": {"purl": q["purl"]}, **({"page_token": q["token"]} if q["token"] else {})} for q in chunk]
        result = call("POST", "/v1/querybatch", {"queries": queries})
        answers = result.get("results") if isinstance(result, dict) else None
        if not isinstance(answers, list) or len(answers) != len(chunk):
            raise GateError("vuln-db-integrity", "unexpected OSV API answer (number of results)")
        for q, answer in zip(chunk, answers):
            answer = answer or {}
            if not isinstance(answer, dict):
                raise GateError("vuln-db-integrity", "unexpected OSV API answer")
            for vuln in answer.get("vulns") or []:
                vid = str((vuln or {}).get("id", ""))
                if not re.fullmatch(r"[A-Za-z0-9._:-]{3,80}", vid):
                    raise GateError("vuln-db-integrity", "unexpected OSV id")
                record = detail(vid)
                if not record.get("withdrawn") and (q["original"], record) not in found:
                    found.append((q["original"], record))
            token = answer.get("next_page_token")
            if token:
                if not isinstance(token, str) or len(token) > 4096:
                    raise GateError("vuln-db-integrity", "OSV API page token cannot be followed")
                pending.append({**q, "token": token})
    return {"mode": "api", "url": base}, found


# ---- exceptions

DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def load_exceptions(path, today):
    if not path:
        return []
    doc = load_json(path, "exception-format", "exception-format")
    items = doc.get("exceptions") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise GateError("exception-format", "exceptions must be a list")
    out = []
    for e in items:
        if not isinstance(e, dict) or set(e) - {"id", "component", "reason", "expires"} or not all(
                isinstance(e.get(k), str) and e.get(k).strip() for k in ("id", "reason", "expires")):
            raise GateError("exception-format", "each exception needs id, reason and expires (and optionally component)")
        if not DATE.match(e["expires"]):
            raise GateError("exception-format", "expires must be YYYY-MM-DD")
        try:
            expires = dt.date.fromisoformat(e["expires"])
        except ValueError:
            raise GateError("exception-format", "expires must be a real date")
        if expires > today + dt.timedelta(days=MAX_EXCEPTION_DAYS):
            raise GateError("exception-format", f"an exception lasts at most {MAX_EXCEPTION_DAYS} days")
        component = purl_package(e["component"]) if "component" in e else None
        if "component" in e and component is None:
            raise GateError("exception-format", "component must be a package URL of a known ecosystem")
        # Valid through the end of the `expires` day, in UTC.
        out.append({**e, "expired": expires < today, "_component": component})
    return out


def matches(exception, vid, aliases, package):
    if exception["id"] != vid and exception["id"] not in aliases:
        return False
    return exception["_component"] is None or exception["_component"] == package


# ---- run

def utc_today():
    return dt.datetime.now(dt.timezone.utc).date()


def run(args, today=None, retries=2, backoff=0.5):
    today = today or utc_today()
    report = {"reportVersion": VERSION, "tool": {"name": "sentomaru-policy-gate", "version": VERSION},
              "minSeverity": args.min_severity, "checks": {"profile": None, "sbom": None, "vulnerabilities": None},
              "warnings": [], "errors": []}
    errors = []

    def fail(e):
        errors.append(e)
        report["errors"].append({"code": e.code, "detail": e.detail})

    def warn(code, detail):
        report["warnings"].append({"code": code, "detail": detail})

    try:
        exceptions = load_exceptions(args.exceptions, today)
    except GateError as e:
        fail(e)
        exceptions = []
    try:
        report["checks"]["profile"] = check_profile(args.profile, args.profile_sha256)
        if not args.profile_sha256:
            warn("profile-not-pinned", "no --profile-sha256: the registry revision of the profile was not checked")
    except GateError as e:
        report["checks"]["profile"] = {"status": "fail", "code": e.code}
        fail(e)
    sbom = None
    try:
        sbom, report["checks"]["sbom"] = check_sbom(args.sbom)
    except GateError as e:
        report["checks"]["sbom"] = {"status": "fail", "code": e.code}
        fail(e)
    if sbom is None:
        return finish(report, errors)

    packages, unmatched = {}, 0
    for c in walk_components(sbom.get("components", [])):
        pkg = purl_package(c.get("purl"))
        if pkg:
            packages[c["purl"]] = pkg
        else:
            unmatched += 1
    vuln = {"status": "pass", "components": len(packages), "withoutKnownPurl": unmatched, "findings": [], "excepted": []}
    report["checks"]["vulnerabilities"] = vuln
    if not packages and not unmatched:
        fail(GateError("sbom-no-components", "the SBOM lists no components: nothing could be checked"))
        vuln["status"] = "fail"
        return finish(report, errors)
    if unmatched:
        if args.allow_components_without_purl:
            warn("sbom-components-unmatched", f"{unmatched} component(s) without a known package URL were not checked")
        else:
            fail(GateError("sbom-components-unmatched", f"{unmatched} component(s) without a known package URL"))
            vuln["status"] = "fail"
    try:
        if args.osv_db:
            source, found = offline_findings(packages, args.osv_db, args.osv_db_sha256)
        else:
            warn("osv-api-purls-sent", f"{len(packages)} package URL(s), internal libraries included, were sent to "
                                       "the OSV API; use --osv-db to keep them on the runner")
            source, found = api_findings(packages, args.osv_api_url, retries, backoff)
    except GateError as e:
        # A database that cannot be read may be allowed to degrade; a database that is not the pinned one never.
        if e.code == "vuln-db-unavailable" and args.allow_unavailable_db:
            vuln["status"] = "skipped-unavailable"
            vuln["unavailable"] = e.detail
            warn("vuln-db-unavailable", "allowed by --allow-unavailable-db")
        else:
            vuln["status"] = "fail"
            fail(e)
        return finish(report, errors)
    vuln["source"] = source
    threshold = SEVERITIES.index(args.min_severity)
    seen = set()
    for purl, record in found:
        vid = str(record.get("id", ""))
        if (purl, vid) in seen:
            continue
        seen.add((purl, vid))
        severity = severity_of(record)
        # Unknown severity counts as meeting the threshold: the gate fails closed on what it cannot rank.
        if severity is not None and SEVERITIES.index(severity) < threshold:
            continue
        aliases = [str(a) for a in record.get("aliases") or []]
        finding = {"id": vid, "aliases": aliases, "component": purl, "severity": severity or "unknown"}
        covering = [e for e in exceptions if matches(e, vid, aliases, packages[purl])]
        active = [e for e in covering if not e["expired"]]
        if active:
            vuln["excepted"].append({**finding, "reason": active[0]["reason"], "expires": active[0]["expires"]})
            continue
        if covering:
            finding["exceptionExpired"] = covering[0]["expires"]
        vuln["findings"].append(finding)
    if vuln["findings"]:
        vuln["status"] = "fail"
        expired = [f for f in vuln["findings"] if f.get("exceptionExpired")]
        plain = [f for f in vuln["findings"] if not f.get("exceptionExpired")]
        if plain:
            fail(GateError("vulnerable-dependency", f"{len(plain)} finding(s): " + ", ".join(sorted({f['id'] for f in plain}))))
        if expired:
            fail(GateError("exception-expired", f"{len(expired)} finding(s) with an expired exception"))
    return finish(report, errors)


def finish(report, errors):
    codes = [e.code for e in errors]
    first = min(codes, key=PRECEDENCE.index) if codes else None
    report["result"] = "fail" if first else "pass"
    report["code"] = first
    return report, EXIT[first] if first else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--hash-db"] and len(argv) == 2:
        try:
            print(tree_sha256(Path(argv[1])))
            return 0
        except GateError as e:
            print(json.dumps({"code": e.code, "detail": e.detail}), file=sys.stderr)
            return EXIT[e.code]
    p = argparse.ArgumentParser(description="Sentomaru policy gate (G-02)")
    p.add_argument("--profile", required=True)
    p.add_argument("--sbom", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--profile-sha256")
    p.add_argument("--min-severity", default="high", choices=SEVERITIES)
    p.add_argument("--exceptions")
    p.add_argument("--osv-db")
    p.add_argument("--osv-db-sha256")
    p.add_argument("--osv-api", action="store_true")
    p.add_argument("--osv-api-url", default="https://api.osv.dev")
    p.add_argument("--allow-unavailable-db", action="store_true")
    p.add_argument("--allow-components-without-purl", action="store_true")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return EXIT["usage"] if e.code else 0

    def usage(detail):
        print(json.dumps({"code": "usage", "detail": detail}), file=sys.stderr)
        return EXIT["usage"]
    if bool(args.osv_db) == bool(args.osv_api):
        return usage("choose exactly one of --osv-db or --osv-api")
    if args.profile_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", args.profile_sha256):
        return usage("--profile-sha256 must be 64 hex")
    try:
        report, code = run(args)
    except GateError as e:
        report, code = {"reportVersion": VERSION, "result": "fail", "code": e.code,
                        "errors": [{"code": e.code, "detail": e.detail}], "warnings": []}, EXIT.get(e.code, 1)
    except Exception as e:  # never a traceback in the client's log
        report, code = {"reportVersion": VERSION, "result": "fail", "code": "internal-error",
                        "errors": [{"code": "internal-error", "detail": type(e).__name__}], "warnings": []}, 1
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "policy-report.json").write_text(json.dumps(report, indent=2) + "\n")
    except OSError:
        return usage("--out is not writable")
    if code:
        # Only codes, counts and advisory ids on stderr; component names stay in the report on the runner.
        print(json.dumps({"code": report["code"], "detail": next((e["detail"] for e in report["errors"]
                                                                  if e["code"] == report["code"]), "")}), file=sys.stderr)
    else:
        print(json.dumps({"result": "pass", "report": str(out / "policy-report.json")}))
    return code


if __name__ == "__main__":
    sys.exit(main())
