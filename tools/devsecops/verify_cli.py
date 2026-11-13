#!/usr/bin/env python3
"""G-03f: verify a downloaded `sentomaru protect` distribution, then (only then) unpack it.

  verify_cli.py --dist <dir with sentomaru-protect-<v>.zip, SHA256SUMS, statement.json, signature.sigstore.json> \
      --version <v> --key <release key .pub> --key-sha256 <pin obtained out of band> \
      --cosign <cosign> --cosign-sha256 <pin> [--dest <dir>] \
      [--expect-repository e-bees-dev/Sentomaru --expect-ref refs/heads/main \
       --expect-workflow-path .github/workflows/cli-release.yml]

The four files are first copied into a private 0700 directory and only that copy is checked, hashed and extracted
(a file swapped in --dist during the check changes nothing).

Checks, in order: tools/shield/verify_release.py (pinned cosign and key, message-signature bundle over the statement,
strict statement, every file's digest a subject, the signed repository/ref/workflow/version equal to the expected
ones); the signed buildType is the CLI distribution's (a statement for another product signed with the same key is
refused); the signed runner class (item 36: internalParameters.runner) is well formed, and a statement without it is
reported on stderr as `cli-notice: runner-not-asserted`, never approved in silence (--require-runner refuses it;
--expect-runner-environment github-hosted|self-hosted refuses another class); the zip and SHA256SUMS agree. Then the zip is unpacked into a fresh --dest, refusing absolute paths, `..`,
links and anything outside `sentomaru-protect-<v>/`. Prints the path of the `sentomaru` launcher. Exit 1 with
`cli-invalid: <code>` (or `release-invalid: <code>` from the verifier) on stderr; nothing is unpacked on failure.
Contract: contracts/devsecops/cli-distribution-v1.md. Stdlib + cosign.
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
import tempfile
import zipfile

BUILD_TYPE = "https://e-bees.com.br/sentomaru/devsecops/cli-dist/v1"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?")
MAX_UNPACKED = 256 << 20


class Invalid(Exception):
    pass


RUNNER_ENVIRONMENTS = ("github-hosted", "self-hosted")
RUNNER_OS = ("Linux", "macOS", "Windows")
RUNNER_ARCH = ("X86", "X64", "ARM", "ARM64")


def read_runner(build, args):
    """Item 36: the runner class the signed statement asserts (internalParameters.runner), or None when the statement
    does not assert one (builds before item 36). A present value must be exactly {environment, os, arch} from the closed
    tables; --require-runner refuses a statement without it and --expect-runner-environment refuses another class
    (or a statement that says nothing). It is the packager's claim, signed by the release key: not a third party's."""
    internal = build.get("internalParameters", {})
    runner = internal.get("runner") if isinstance(internal, dict) else None
    if runner is None:
        if args.require_runner or args.expect_runner_environment:
            raise Invalid("runner-not-asserted")
        return None
    if not isinstance(runner, dict) or set(runner) != {"environment", "os", "arch"} \
            or runner["environment"] not in RUNNER_ENVIRONMENTS or runner["os"] not in RUNNER_OS \
            or runner["arch"] not in RUNNER_ARCH:
        raise Invalid("runner-shape")
    if args.expect_runner_environment and runner["environment"] != args.expect_runner_environment:
        raise Invalid("runner-environment")
    return runner


def runner_notice(prefix, runner):
    """One line on stderr, never on stdout (stdout carries the paths a caller consumes)."""
    if runner is None:
        print(f"{prefix}-notice: runner-not-asserted", file=sys.stderr)
    else:
        print(f"{prefix}-notice: runner environment={runner['environment']} os={runner['os']} arch={runner['arch']}",
              file=sys.stderr)


def load_verifier():
    here = Path(__file__).resolve().parent
    for candidate in (here / "verify_release.py", here.parent / "shield" / "verify_release.py"):
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("verify_release", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise Invalid("verifier-missing")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unpack(zip_source, dest, prefix):
    dest.mkdir(parents=True)
    total = 0
    with zipfile.ZipFile(zip_source) as z:
        names = set()
        for info in z.infolist():
            name = PurePosixPath(info.filename)
            if info.filename in names or name.is_absolute() or ".." in name.parts or "\\" in info.filename \
                    or not name.parts or name.parts[0] != prefix:
                raise Invalid("zip-entry")
            names.add(info.filename)
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise Invalid("zip-link")
            total += info.file_size
            if total > MAX_UNPACKED:
                raise Invalid("zip-too-large")
            target = dest.joinpath(*name.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)
            target.chmod(0o755 if name.parts[1:2] == ("bin",) else 0o644)
    return dest / prefix / "bin" / "sentomaru"


def private_copy(dist, names):
    """The four files copied once into a fresh 0700 directory: everything below reads only this copy, so a file
    swapped in --dist after the check (TOCTOU) never reaches the verifier, the digest or the extraction."""
    work = Path(tempfile.mkdtemp(prefix="sentomaru-verify-"))
    os.chmod(work, 0o700)
    for name in names:
        source = dist / name
        if not source.is_file() or source.is_symlink():
            shutil.rmtree(work, ignore_errors=True)
            raise Invalid("missing-" + name)
        with open(source, "rb") as src, open(work / name, "xb") as dst:
            shutil.copyfileobj(src, dst)
    return work


def verify(args):
    if not VERSION.fullmatch(args.version):
        raise Invalid("version")
    prefix = f"sentomaru-protect-{args.version}"
    names = (f"{prefix}.zip", "SHA256SUMS", "statement.json", "signature.sigstore.json")
    dest = Path(args.dest) if args.dest else Path(tempfile.mkdtemp(prefix="sentomaru-cli-")) / "cli"
    if dest.exists():
        raise Invalid("dest-exists")
    try:
        work = private_copy(Path(args.dist), names)
    except Invalid:
        if not args.dest:
            shutil.rmtree(dest.parent, ignore_errors=True)  # the default --dest parent is ours: leave nothing behind
        raise
    try:
        files = {n: work / n for n in names}
        verifier = load_verifier()
        argv = ["--statement", str(files["statement.json"]), "--signature", str(files["signature.sigstore.json"]),
                "--key", args.key, "--key-sha256", args.key_sha256, "--cosign", args.cosign,
                "--cosign-sha256", args.cosign_sha256, "--artifact", str(files[f"{prefix}.zip"]),
                "--artifact", str(files["SHA256SUMS"]), "--expect-repository", args.expect_repository,
                "--expect-ref", args.expect_ref, "--expect-workflow-path", args.expect_workflow_path,
                "--expect-version", args.version]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = verifier.main(argv)
        if code != 0:
            raise Invalid(err.getvalue().strip().removeprefix("release-invalid: ") or "verifier")
        # The same private bytes the verifier checked: the signed buildType must be the CLI distribution's.
        statement = json.loads(files["statement.json"].read_bytes())
        build = statement.get("predicate", {}).get("buildDefinition", {})
        if build.get("buildType") != BUILD_TYPE:
            raise Invalid("build-type")
        runner = read_runner(build, args)
        zip_bytes = files[prefix + ".zip"].read_bytes()  # read once; digest and extraction use these bytes
        expected = f"{hashlib.sha256(zip_bytes).hexdigest()}  {prefix}.zip\n"
        if files["SHA256SUMS"].read_text() != expected:
            raise Invalid("sha256sums")
        verified = {s["name"]: s["digest"]["sha256"] for s in statement.get("subject", [])}
        if verified.get(prefix + ".zip") != hashlib.sha256(zip_bytes).hexdigest():
            raise Invalid("zip-changed")
        try:
            launcher = unpack(io.BytesIO(zip_bytes), dest, prefix)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        if not launcher.is_file():
            shutil.rmtree(dest, ignore_errors=True)
            raise Invalid("launcher-missing")
        runner_notice("cli", runner)
        return launcher
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dist", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--key-sha256", required=True)
    p.add_argument("--cosign", required=True)
    p.add_argument("--cosign-sha256", required=True)
    p.add_argument("--dest")
    p.add_argument("--require-runner", action="store_true",
                   help="refuse a statement that does not assert the runner class (item 36)")
    p.add_argument("--expect-runner-environment", choices=RUNNER_ENVIRONMENTS,
                   help="refuse a statement whose signed runner environment differs (or is not asserted)")
    p.add_argument("--expect-repository", default="e-bees-dev/Sentomaru")
    p.add_argument("--expect-ref", default="refs/heads/main")
    p.add_argument("--expect-workflow-path", default=".github/workflows/cli-release.yml")
    args = p.parse_args(argv)
    try:
        print(verify(args))
    except Invalid as e:
        print(f"cli-invalid: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError, zipfile.BadZipFile):
        print("cli-invalid: io", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
