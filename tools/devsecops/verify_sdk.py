#!/usr/bin/env python3
"""G-04: verify a downloaded SDK distribution (Android Maven tree + Flutter plugin), then (only then) unpack it.

  verify_sdk.py --dist <dir with sentomaru-sdk-maven-<sdk>.zip, sentomaru_flutter-<plugin>.tar.gz,
                         sentomaru-sdk-sbom-<sdk>.cdx.json, SHA256SUMS, statement.json, signature.sigstore.json> \
      --sdk-version <v> --plugin-version <v> --key <release key .pub> --key-sha256 <pin obtained out of band> \
      --cosign <cosign> --cosign-sha256 <pin> --expect-repository <owner/repository that built the release> [--dest <dir>] \
      [--expect-ref refs/heads/main --expect-workflow-path .github/workflows/sdk-release.yml]

Same model as verify_cli.py (docs/devsecops/adr-0004-sdk-registry.md): the six files are first copied into a private 0700
directory and only that copy is checked, hashed and extracted. Checks, in order: tools/shield/verify_release.py (pinned
cosign and key, message-signature bundle over the statement, strict statement, the four subjects' digests, the signed
repository/ref/workflow equal to the expected ones); the signed buildType is the SDK distribution's; the signed
sdkVersion and pluginVersion are the ones asked for; SHA256SUMS lists exactly the two archives and the SBOM with their digests. Then
the archives are unpacked into a fresh --dest (`maven/` and `plugin/`), refusing absolute paths, `..`, links, devices and
anything outside the expected prefix; the SBOM is copied to `<dest>/sbom.cdx.json` after a shape check (CycloneDX 1.6, this SDK version). Prints the path of the Maven repository (what SENTOMARU_SDK_REPO points to), of the
plugin directory and of the SBOM. Exit 1 with `sdk-invalid: <code>` on stderr; nothing is unpacked on failure.
Stdlib + cosign.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile

BUILD_TYPE = "https://e-bees.com.br/sentomaru/devsecops/sdk-dist/v1"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?")
MAVEN_ROOT = PurePosixPath("br/com/ebees/sentomaru")
MAX_UNPACKED = 256 << 20


class Invalid(Exception):
    pass


def load_verifier():
    here = Path(__file__).resolve().parent
    for candidate in (here / "verify_release.py", here.parent / "shield" / "verify_release.py"):
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("verify_release", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise Invalid("verifier-missing")


def private_copy(dist, names):
    """One copy into a fresh 0700 directory: a file swapped in --dist after the check never reaches the verifier."""
    work = Path(tempfile.mkdtemp(prefix="sentomaru-verify-sdk-"))
    os.chmod(work, 0o700)
    for name in names:
        source = dist / name
        if not source.is_file() or source.is_symlink():
            shutil.rmtree(work, ignore_errors=True)
            raise Invalid("missing-" + name)
        with open(source, "rb") as src, open(work / name, "xb") as dst:
            shutil.copyfileobj(src, dst)
    return work


def safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts:
        raise Invalid("archive-entry")
    return path


def unpack_zip(data, dest):
    dest.mkdir(parents=True)
    total, names = 0, set()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            path = safe_member(info.filename)
            if info.filename in names or path.parts[:4] != MAVEN_ROOT.parts:
                raise Invalid("zip-entry")
            names.add(info.filename)
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise Invalid("zip-link")
            total += info.file_size
            if total > MAX_UNPACKED:
                raise Invalid("archive-too-large")
            target = dest.joinpath(*path.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)
            target.chmod(0o644)
    return dest


def unpack_tar(data, dest, prefix):
    dest.mkdir(parents=True)
    total, names = 0, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for member in t.getmembers():
            path = safe_member(member.name)
            if member.name in names or path.parts[0] != prefix:
                raise Invalid("tar-entry")
            names.add(member.name)
            if not (member.isfile() or member.isdir()):  # links, devices, fifos
                raise Invalid("tar-link")
            total += member.size
            if total > MAX_UNPACKED:
                raise Invalid("archive-too-large")
            target = dest.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = t.extractfile(member)
            with open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)
            target.chmod(0o644)
    return dest / prefix


def verify(args):
    for v in (args.sdk_version, args.plugin_version):
        if not VERSION.fullmatch(v):
            raise Invalid("version")
    maven_name = f"sentomaru-sdk-maven-{args.sdk_version}.zip"
    plugin_prefix = f"sentomaru_flutter-{args.plugin_version}"
    plugin_name = plugin_prefix + ".tar.gz"
    sbom_name = f"sentomaru-sdk-sbom-{args.sdk_version}.cdx.json"
    names = (maven_name, plugin_name, sbom_name, "SHA256SUMS", "statement.json", "signature.sigstore.json")
    dest = Path(args.dest) if args.dest else Path(tempfile.mkdtemp(prefix="sentomaru-sdk-")) / "sdk"
    if dest.exists():
        raise Invalid("dest-exists")
    try:
        work = private_copy(Path(args.dist), names)
    except Invalid:
        if not args.dest:
            shutil.rmtree(dest.parent, ignore_errors=True)
        raise
    try:
        files = {n: work / n for n in names}
        verifier = load_verifier()
        argv = ["--statement", str(files["statement.json"]), "--signature", str(files["signature.sigstore.json"]),
                "--key", args.key, "--key-sha256", args.key_sha256, "--cosign", args.cosign,
                "--cosign-sha256", args.cosign_sha256, "--artifact", str(files[maven_name]),
                "--artifact", str(files[plugin_name]), "--artifact", str(files[sbom_name]),
                "--artifact", str(files["SHA256SUMS"]),
                "--expect-repository", args.expect_repository, "--expect-ref", args.expect_ref,
                "--expect-workflow-path", args.expect_workflow_path]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = verifier.main(argv)
        if code != 0:
            raise Invalid(err.getvalue().strip().removeprefix("release-invalid: ") or "verifier")
        statement = json.loads(files["statement.json"].read_bytes())
        build = statement.get("predicate", {}).get("buildDefinition", {})
        if build.get("buildType") != BUILD_TYPE:
            raise Invalid("build-type")
        internal = build.get("internalParameters", {})
        if internal.get("sdkVersion") != args.sdk_version or internal.get("pluginVersion") != args.plugin_version:
            raise Invalid("version-mismatch")
        maven_bytes, plugin_bytes = files[maven_name].read_bytes(), files[plugin_name].read_bytes()  # read once
        sbom_bytes = files[sbom_name].read_bytes()
        expected = f"{hashlib.sha256(maven_bytes).hexdigest()}  {maven_name}\n" \
                   f"{hashlib.sha256(plugin_bytes).hexdigest()}  {plugin_name}\n" \
                   f"{hashlib.sha256(sbom_bytes).hexdigest()}  {sbom_name}\n"
        if files["SHA256SUMS"].read_text() != expected:
            raise Invalid("sha256sums")
        signed = {s["name"]: s["digest"]["sha256"] for s in statement.get("subject", [])}
        if signed.get(maven_name) != hashlib.sha256(maven_bytes).hexdigest() \
                or signed.get(plugin_name) != hashlib.sha256(plugin_bytes).hexdigest() \
                or signed.get(sbom_name) != hashlib.sha256(sbom_bytes).hexdigest():
            raise Invalid("archive-changed")
        try:
            bom = json.loads(sbom_bytes)
            root = bom["metadata"]["component"]
            ok = (bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6" and root["name"] == "sentomaru-sdk"
                  and root["version"] == args.sdk_version and isinstance(bom["components"], list))
        except (ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            raise Invalid("sbom-shape")
        dest.mkdir(parents=True)
        try:
            maven = unpack_zip(maven_bytes, dest / "maven")
            plugin = unpack_tar(plugin_bytes, dest / "plugin", plugin_prefix)
            (dest / "sbom.cdx.json").write_bytes(sbom_bytes)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        return maven, plugin, dest / "sbom.cdx.json"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dist", required=True)
    p.add_argument("--sdk-version", required=True)
    p.add_argument("--plugin-version", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--key-sha256", required=True)
    p.add_argument("--cosign", required=True)
    p.add_argument("--cosign-sha256", required=True)
    p.add_argument("--dest")
    p.add_argument("--expect-repository", required=True)
    p.add_argument("--expect-ref", default="refs/heads/main")
    p.add_argument("--expect-workflow-path", default=".github/workflows/sdk-release.yml")
    args = p.parse_args(argv)
    try:
        maven, plugin, bom = verify(args)
        print(f"maven={maven}")
        print(f"plugin={plugin}")
        print(f"sbom={bom}")
    except Invalid as e:
        print(f"sdk-invalid: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError):
        print("sdk-invalid: io", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
