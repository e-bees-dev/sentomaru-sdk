#!/usr/bin/env python3
"""G-05: download the four files of a `sentomaru protect` release (cli-v<version>) for tools/devsecops/verify_cli.py.

  SENTOMARU_DOWNLOAD_TOKEN=<token> download_cli.py --version <v> --dest <new dir> \
      [--repository e-bees-dev/sentomaru-sdk] [--api-url https://api.github.com]

Reads release `cli-v<version>` of --repository through the GitHub REST API (`/releases/tags/<tag>`, then each asset by
id with `Accept: application/octet-stream`) and writes sentomaru-protect-<v>.zip, SHA256SUMS, statement.json and
signature.sigstore.json into --dest, which must not exist. Prints the --dest path on success.

What is downloaded is untrusted: this script adds no trust. verify_cli.py (pinned cosign, pinned release key, signed
repository/ref/workflow/version, SHA256SUMS) is the only judge, and the key pin never comes from here. The token comes
from the environment only (never argv) and is never printed; it is sent only to --api-url, never to a redirect target
(the signed asset URL). Only https is accepted, except a loopback --api-url (tests). Names are fixed by the version, the
repository is a strict owner/name, each body is capped. On failure nothing is left in --dest and the last line of
stderr is `cli-download-failed:<reason>` (reason: version, repository, url, token, dest-exists, http-<status>, network,
release-malformed, missing-<zip|sha256sums|statement|signature>, redirect, too-large, truncated, io). Stdlib only. Contract:
contracts/devsecops/cli-distribution-v1.md.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")  # stricter than verify_cli.py (which also takes -prerelease)
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_ASSET = 128 << 20
MAX_JSON = 4 << 20
TIMEOUT = 60
MAX_REDIRECTS = 3


class Failed(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url, reason="url"):
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or not parts.hostname:
        raise Failed(reason)
    if parts.scheme == "https" or (parts.scheme == "http" and loopback(parts.hostname)):
        return parts
    raise Failed(reason)


def fetch(url, headers, limit):
    """GET without following redirects on its own; returns (status, location, body)."""
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status, location = response.status, None
            declared = response.headers.get("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > limit:
                raise Failed("too-large")
            body = response.read(limit + 1)
            if len(body) > limit:
                raise Failed("too-large")
            if declared is not None and declared.isdigit() and len(body) != int(declared):
                raise Failed("truncated")
            return status, location, body
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            return e.code, e.headers.get("Location"), b""
        raise Failed(f"http-{e.code}")
    except Failed:
        raise
    except (urllib.error.URLError, OSError, ValueError):
        raise Failed("network")
    except Exception:  # http.client.IncompleteRead and friends: a body shorter than announced
        raise Failed("truncated")


def get(url, token, accept, limit):
    """The first hop carries the token; a redirect target (a signed URL on another host) never does."""
    parts = check_url(url)
    headers = {"Accept": accept, "Authorization": f"Bearer {token}", "User-Agent": "sentomaru-download-cli",
               "X-GitHub-Api-Version": "2022-11-28"}
    for hop in range(MAX_REDIRECTS + 1):
        status, location, body = fetch(url, headers, limit)
        if status == 200:
            return body
        if status not in (301, 302, 303, 307, 308) or not location or hop == MAX_REDIRECTS:
            raise Failed("redirect")
        url = urllib.parse.urljoin(url, location)
        check_url(url, "redirect")
        headers = {"Accept": accept, "User-Agent": "sentomaru-download-cli"}
    raise Failed("redirect")


def download(args, token):
    if not VERSION.fullmatch(args.version):
        raise Failed("version")
    if not REPOSITORY.fullmatch(args.repository) or any(p in (".", "..") for p in args.repository.split("/")):
        raise Failed("repository")
    if not token:
        raise Failed("token")
    api = args.api_url.rstrip("/")
    check_url(api)
    dest = Path(args.dest)
    if dest.exists() or dest.is_symlink():
        raise Failed("dest-exists")
    names = (f"sentomaru-protect-{args.version}.zip", "SHA256SUMS", "statement.json", "signature.sigstore.json")
    base = f"{api}/repos/{args.repository}"
    raw = get(f"{base}/releases/tags/cli-v{args.version}", token, "application/vnd.github+json", MAX_JSON)
    try:
        assets = json.loads(raw).get("assets")
        ids = {}
        for asset in assets:
            if asset["name"] in names:
                if not isinstance(asset["id"], int) or isinstance(asset["id"], bool) or asset["id"] < 0:
                    raise ValueError
                ids[asset["name"]] = asset["id"]
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Failed("release-malformed")
    for name in names:
        if name not in ids:
            raise Failed("missing-" + ("zip" if name.endswith(".zip") else name.split(".")[0].lower()))
    dest.mkdir(parents=True, mode=0o700)
    try:
        for name in names:
            body = get(f"{base}/releases/assets/{ids[name]}", token, "application/octet-stream", MAX_ASSET)
            if not body:
                raise Failed("truncated")
            with open(dest / name, "xb") as f:
                f.write(body)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--version", required=True)
    p.add_argument("--dest", required=True)
    p.add_argument("--repository", default="e-bees-dev/sentomaru-sdk")
    p.add_argument("--api-url", default="https://api.github.com")
    args = p.parse_args(argv)
    try:
        print(download(args, os.environ.get("SENTOMARU_DOWNLOAD_TOKEN", "")))
    except Failed as e:
        print(f"cli-download-failed:{e}", file=sys.stderr)
        return 1
    except OSError:
        print("cli-download-failed:io", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
