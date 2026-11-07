#!/usr/bin/env python3
"""Third-party verification of a Sentomaru Shield release (D-03): in-toto/SLSA v1 statement + Sigstore bundle signed with a
published key, against files the verifier downloaded itself.

Standalone (stdlib + cosign), so it can be copied out of this repository. Contract: contracts/shield/release-verification-v1.md.

  verify_release.py --statement statement.json --signature signature.sigstore.json \
      --key shield-ci-example-hml-g1.pub --key-sha256 <pin obtained out of band> \
      --cosign ./cosign --cosign-sha256 <pin of your cosign binary> \
      --artifact ExampleApp-1.0.0+342-arm64.apk [--artifact sbom.json ...] \
      [--expect-repository example-org/example-app --expect-ref refs/heads/dev --expect-scope example-org/example-app/hml \
       --expect-version 1.0.0 --expect-build-number 342 --expect-subject app-arm64-v8a-debug.apk]

Proves only that every --artifact has a digest listed in a statement whose bytes were signed (message signature, not
DSSE) with the pinned key. Without --expect-version/--expect-build-number it does not say WHICH release you hold
(rollback/substitution); it never attests the builder, the installed app, a SLSA level or the APK signature.
Exit 0 with a JSON report on stdout; 1 with `release-invalid: <code>` on stderr; 2 on usage errors.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

STATEMENT_TYPE = 'https://in-toto.io/Statement/v1'
PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'
LIMITS = {'statement': 1 << 20, 'signature': 64 << 10, 'key': 16 << 10, 'cosign': 512 << 20}
HEX64 = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,254}')
NOT_VERIFIED = [
    'builder isolation or independent builder attestation',
    'installed application (server-side check is S2/D-04)',
    'APK signing certificate (checked by Android; compare with profile.json expectedSigningDigests)',
    'transparency log inclusion (key-signed bundle, trust is the pinned key)',
    'any SLSA level or MASVS mapping',
]


BUNDLE_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json'


class Invalid(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def read_bounded(path, kind):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise Invalid(kind + '-missing')
    with file.open('rb') as handle:
        data = handle.read(LIMITS[kind] + 1)
    if len(data) > LIMITS[kind]:
        raise Invalid(kind + '-size')
    return data


def strict_json(data, code):
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise Invalid(code + '-duplicate-key')
        return dict(items)

    def constant(_):
        raise Invalid(code + '-number')

    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except Invalid:
        raise
    except (UnicodeDecodeError, ValueError):
        raise Invalid(code + '-json') from None


def cosign_verify(cosign, key, signature, statement):
    try:
        result = subprocess.run([cosign, 'verify-blob', '--key', key, '--bundle', signature,
                                 '--insecure-ignore-tlog=true', statement],
                                capture_output=True, timeout=120, env={'PATH': os.defpath, 'HOME': os.path.dirname(key)})
    except (OSError, subprocess.TimeoutExpired):
        raise Invalid('cosign-unavailable') from None
    if result.returncode:
        raise Invalid('signature')


def require_message_signature(bundle, statement_bytes):
    """Only a key-signed message signature over these exact statement bytes. cosign also accepts a DSSE envelope and
    then checks only that the blob is one of ITS subjects, so any attestation by the key would pass (review I1)."""
    if not isinstance(bundle, dict) or set(bundle) != {'mediaType', 'verificationMaterial', 'messageSignature'} \
            or bundle['mediaType'] != BUNDLE_TYPE:
        raise Invalid('signature-shape')
    material, message = bundle['verificationMaterial'], bundle['messageSignature']
    if not isinstance(material, dict) or set(material) != {'publicKey'} or not isinstance(message, dict) \
            or set(message) != {'messageDigest', 'signature'}:
        raise Invalid('signature-shape')
    digest = message['messageDigest']
    if not isinstance(digest, dict) or digest.get('algorithm') != 'SHA2_256' or not isinstance(digest.get('digest'), str):
        raise Invalid('signature-shape')
    try:
        signed = base64.b64decode(digest['digest'], validate=True)
    except ValueError:
        raise Invalid('signature-shape') from None
    if signed != hashlib.sha256(statement_bytes).digest():
        raise Invalid('signature-digest')


def subjects_of(statement):
    if not isinstance(statement, dict) or statement.get('_type') != STATEMENT_TYPE:
        raise Invalid('statement-type')
    if statement.get('predicateType') != PREDICATE_TYPE or not isinstance(statement.get('predicate'), dict):
        raise Invalid('predicate-type')
    subjects = statement.get('subject')
    if not isinstance(subjects, list) or not 1 <= len(subjects) <= 64:
        raise Invalid('subject-list')
    by_digest, names = {}, set()
    for item in subjects:
        if not isinstance(item, dict) or set(item) != {'name', 'digest'}:
            raise Invalid('subject-shape')
        name, digest = item['name'], item['digest']
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise Invalid('subject-name')
        if not isinstance(digest, dict) or set(digest) != {'sha256'} or not isinstance(digest['sha256'], str) \
                or not HEX64.fullmatch(digest['sha256']):
            raise Invalid('subject-digest')
        names.add(name)
        by_digest.setdefault(digest['sha256'], []).append(name)
    return by_digest


def field(document, *path):
    for key in path:
        document = document.get(key) if isinstance(document, dict) else None
    return document


def check_expectations(statement, args):
    build = field(statement, 'predicate', 'buildDefinition')
    expected = {
        'repository': (args.expect_repository, field(build, 'externalParameters', 'workflow', 'repository')),
        'ref': (args.expect_ref, field(build, 'externalParameters', 'workflow', 'ref')),
        'workflow': (args.expect_workflow_path, field(build, 'externalParameters', 'workflow', 'path')),
        'scope': (args.expect_scope, field(build, 'externalParameters', 'profileRevision', 'scope')),
        'version': (args.expect_version, field(build, 'internalParameters', 'versionName')),
        'build-number': (args.expect_build_number, field(build, 'internalParameters', 'buildNumber')),
    }
    for code, (want, got) in expected.items():
        if want is not None and want != got:
            raise Invalid('expect-' + code)
    return sorted(code for code, (want, _) in expected.items() if want is not None)


def copy_cosign(cosign, private):
    """The cosign copied into the private directory, at most LIMITS['cosign'] bytes: unreadable is cosign-missing,
    larger is cosign-size, a failed write there (no space, a directory that refuses it) is cosign-copy."""
    try:
        source = open(cosign, 'rb')
    except OSError:
        raise Invalid('cosign-missing') from None
    with source:
        try:
            target = open(private, 'xb')
        except OSError:
            raise Invalid('cosign-copy') from None
        with target:
            total = 0
            while True:
                try:
                    block = source.read(1 << 20)
                except OSError:
                    raise Invalid('cosign-missing') from None
                if not block:
                    break
                total += len(block)
                if total > LIMITS['cosign']:
                    raise Invalid('cosign-size')
                try:
                    target.write(block)
                except OSError:
                    raise Invalid('cosign-copy') from None
    try:
        os.chmod(private, 0o700)
    except OSError:
        raise Invalid('cosign-copy') from None


def verify(args):
    if not HEX64.fullmatch(args.key_sha256):
        raise Invalid('key-pin-format')
    if not HEX64.fullmatch(args.cosign_sha256):
        raise Invalid('cosign-pin-format')
    cosign = Path(args.cosign)
    if cosign.is_symlink() or not cosign.is_file() or not os.access(cosign, os.X_OK):
        raise Invalid('cosign-missing')
    # One private 0700 directory for everything cosign touches. The cosign itself is copied there once, its pin is
    # checked on the copy and the copy is what runs, so a binary swapped at --cosign after the check never runs (TOCTOU,
    # R M-3 of D-16b). Verify and parse the same private copy of the bytes, so nothing can swap a file between the steps.
    work = Path(tempfile.mkdtemp(prefix='shield-verify-'))
    try:
        os.chmod(work, 0o700)
        private = work / 'cosign'
        copy_cosign(cosign, private)
        if sha256_file(private) != args.cosign_sha256:
            raise Invalid('cosign-pin')
        material = {kind: read_bounded(path, kind)
                    for kind, path in (('statement', args.statement), ('signature', args.signature), ('key', args.key))}
        if hashlib.sha256(material['key']).hexdigest() != args.key_sha256:
            raise Invalid('key-pin')
        require_message_signature(strict_json(material['signature'], 'signature'), material['statement'])
        for kind, data in material.items():
            (work / kind).write_bytes(data)
        cosign_verify(str(private), str(work / 'key'), str(work / 'signature'), str(work / 'statement'))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    statement = strict_json(material['statement'], 'statement')
    by_digest = subjects_of(statement)
    checked = check_expectations(statement, args)
    matched = []
    for path in args.artifact:
        file = Path(path)
        if file.is_symlink() or not file.is_file():
            raise Invalid('artifact-missing')
        digest = sha256_file(file)
        if digest not in by_digest:
            raise Invalid('artifact-not-in-statement')
        matched.append({'file': file.name, 'sha256': digest, 'subjects': by_digest[digest]})
    covered = {name for item in matched for name in item['subjects']}
    for name in args.expect_subject or []:
        if name not in covered:
            raise Invalid('expect-subject')
    if args.expect_subject:
        checked.append('subject')
    build = field(statement, 'predicate', 'buildDefinition')
    return {
        'result': 'signature-and-artifact-digests-verified',
        'keySha256': args.key_sha256,
        'statementSha256': hashlib.sha256(material['statement']).hexdigest(),
        'artifacts': matched,
        'expectationsChecked': sorted(checked),  # empty = the bytes are attested, but not WHICH release they are
        'declared': {  # signed claims of the builder, not independently checked
            'buildType': field(build, 'buildType'),
            'workflow': field(build, 'externalParameters', 'workflow'),
            'profileRevision': field(build, 'externalParameters', 'profileRevision'),
            'internalParameters': field(build, 'internalParameters'),
            'resolvedDependencies': field(build, 'resolvedDependencies'),
            'builder': field(statement, 'predicate', 'runDetails', 'builder', 'id'),
            'invocationId': field(statement, 'predicate', 'runDetails', 'metadata', 'invocationId'),
        },
        'notVerified': NOT_VERIFIED,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--statement', required=True)
    parser.add_argument('--signature', required=True, help='Sigstore bundle (signature.sigstore.json)')
    parser.add_argument('--key', required=True, help='published PEM')
    parser.add_argument('--key-sha256', required=True, help='SHA-256 of the PEM bytes, obtained out of band')
    parser.add_argument('--cosign', required=True)
    parser.add_argument('--cosign-sha256', required=True, help='SHA-256 of the cosign binary you trust')
    parser.add_argument('--artifact', action='append', required=True)
    parser.add_argument('--expect-repository')
    parser.add_argument('--expect-ref')
    parser.add_argument('--expect-workflow-path')
    parser.add_argument('--expect-scope')
    parser.add_argument('--expect-version', help='signed internalParameters.versionName')
    parser.add_argument('--expect-build-number', help='signed internalParameters.buildNumber')
    parser.add_argument('--expect-subject', action='append', help='subject name that some --artifact must match')
    args = parser.parse_args(argv)
    try:
        report = verify(args)
    except Invalid as error:
        print(f'release-invalid: {error}', file=sys.stderr)
        return 1
    except OSError:
        print('release-invalid: io', file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
