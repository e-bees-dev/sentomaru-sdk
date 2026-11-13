#!/usr/bin/env python3
"""Verificador do recibo de conclusão do Sentomaru (E-04, contracts/trust/completion-receipt-v1.md).

Só biblioteca padrão e o binário `openssl`. Não acessa a rede. Confere, nesta ordem: o formato do envelope, o manifesto (membros
fechados, tipos, `userPresenceVerified` booleano), o SHA-256 dos bytes JCS (RFC 8785) do manifesto e a assinatura ECDSA P-256 com a
chave pública informada (`--pubkey` ou `--keys-index` com o `pem` do `keyName` do recibo). Um membro desconhecido reprova.

O que a aprovação diz: estes bytes foram assinados pela chave informada. Não diz que a chave é a do Sentomaru (o chamador fixa a
chave por `--pubkey-sha256` a partir da tabela de pinos), nem que o usuário estava presente, nem que a operação do consumidor foi concluída.

Saída: uma linha `ok` ou o código do motivo; código de saída 0 (ok) ou 1.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

SCHEMA = "sentomaru-completion-receipt/1"
SCHEMA_V2 = "sentomaru-completion-receipt/2"  # contracts/trust/completion-receipt-v2.md: installationRef instead of installationCode
TOP = {"schema", "receiptId", "issuedAt", "organization", "app", "environment", "installationCode", "operation", "operationId",
       "proofStatus", "decision", "policy", "userPresenceVerified", "notice"}
TOP_V2 = (TOP - {"installationCode"}) | {"installationRef"}
DECISION = {"policyStatus", "recommendedAction", "reasonCodes"}
POLICY = {"digest", "id", "version"}
UUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
INSTANT = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
SLUG = re.compile(r"\A[a-z0-9][a-z0-9-]{0,62}\Z")
PRINTABLE = re.compile(r"\A[ -~]{1,128}\Z")
CODE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")


class Reject(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def jcs(value):
    """RFC 8785 para o que o manifesto contém: objetos, listas, textos, booleanos e nulo (sem números)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # ordem por unidade de código UTF-16; os nomes do manifesto são ASCII, e ASCII ordena igual em qualquer codificação
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in sorted(value, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise Reject("manifest-value-kind")


def check_manifest(manifest):
    if not isinstance(manifest, dict):
        raise Reject("manifest-format")
    if manifest.get("schema") not in (SCHEMA, SCHEMA_V2):
        raise Reject("schema-unsupported")
    v2 = manifest["schema"] == SCHEMA_V2
    top = TOP_V2 if v2 else TOP
    if set(manifest) != top:
        raise Reject("unknown-member" if set(manifest) - top else "missing-member")
    if not isinstance(manifest["userPresenceVerified"], bool):
        raise Reject("user-presence-format")
    decision = manifest["decision"]
    if not isinstance(decision, dict) or set(decision) != DECISION:
        raise Reject("unknown-member" if isinstance(decision, dict) and set(decision) - DECISION else "missing-member")
    if not isinstance(decision["reasonCodes"], list) or not all(isinstance(c, str) for c in decision["reasonCodes"]) \
            or decision["reasonCodes"] != sorted(set(decision["reasonCodes"])):
        raise Reject("reason-codes-format")
    if not all(isinstance(decision[k], str) and PRINTABLE.match(decision[k]) for k in ("policyStatus", "recommendedAction")):
        raise Reject("decision-format")
    policy = manifest["policy"]
    if policy is not None:
        if not isinstance(policy, dict) or set(policy) != POLICY:
            raise Reject("unknown-member" if isinstance(policy, dict) and set(policy) - POLICY else "missing-member")
        if not all(isinstance(v, str) and PRINTABLE.match(v) for v in policy.values()):
            raise Reject("policy-format")
    checks = [
        UUID.match(str(manifest["receiptId"])), INSTANT.match(str(manifest["issuedAt"])),
        all(isinstance(manifest[k], str) and SLUG.match(manifest[k]) for k in ("organization", "app", "environment")),
        (isinstance(manifest["installationRef"], str) and HEX32.match(manifest["installationRef"])) if v2
        else (isinstance(manifest["installationCode"], str) and CODE.match(manifest["installationCode"])),
        isinstance(manifest["operation"], str) and PRINTABLE.match(manifest["operation"]),
        manifest["operationId"] is None or isinstance(manifest["operationId"], str) and PRINTABLE.match(manifest["operationId"]),
        manifest["proofStatus"] == "valid", isinstance(manifest["notice"], str),
    ]
    if not all(checks):
        raise Reject("manifest-format")


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


def verify_signature(message, signature_der, pem):
    with tempfile.TemporaryDirectory() as folder:
        paths = {name: os.path.join(folder, name) for name in ("msg", "sig", "key")}
        for name, data in (("msg", message), ("sig", signature_der), ("key", pem)):
            with open(paths[name], "wb") as handle:
                handle.write(data)
        tool = trusted_openssl()
        if tool is None:
            raise Reject("openssl-unavailable")
        try:
            good = openssl_verifies(tool, paths["key"], paths["sig"], paths["msg"])
            # Negative control: the same key and signature over other bytes must NOT verify. A program that answers "ok" to
            # everything is not openssl and cannot validate a receipt.
            with open(paths["msg"], "ab") as handle:
                handle.write(b"\0")
            control = openssl_verifies(tool, paths["key"], paths["sig"], paths["msg"])
        except (OSError, subprocess.TimeoutExpired):
            raise Reject("openssl-unavailable") from None
    if control:
        raise Reject("openssl-misbehaves")
    if not good:
        raise Reject("signature-invalid")


def verify(receipt, pem=None, keys_index=None, expect_scope=None, expect_operation_id=None, pubkey_sha256=None):
    """Devolve normalmente quando o recibo confere; levanta Reject(código) caso contrário."""
    if not isinstance(receipt, dict) or set(receipt) != {"receiptId", "manifest", "manifestSha256", "signature"}:
        raise Reject("envelope-format")
    signature = receipt["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "signatureBase64", "keyName", "keyVersion"} \
            or signature["algorithm"] != "ecdsa-p256-sha256-der":
        raise Reject("signature-format")
    manifest = receipt["manifest"]
    check_manifest(manifest)
    if receipt["receiptId"] != manifest["receiptId"]:
        raise Reject("receipt-id-mismatch")
    message = jcs(manifest).encode("utf-8")
    digest = hashlib.sha256(message).hexdigest()
    if not isinstance(receipt["manifestSha256"], str) or not HEX64.match(receipt["manifestSha256"]) or receipt["manifestSha256"] != digest:
        raise Reject("manifest-digest-mismatch")
    if pem is None and keys_index is not None:
        for key in keys_index.get("keys", []):
            if key.get("name") == signature["keyName"]:
                pem = key.get("pem", "").encode("ascii")
    if pem is None:
        raise Reject("key-not-found")
    if pubkey_sha256 is not None and hashlib.sha256(pem).hexdigest() != pubkey_sha256:
        raise Reject("pubkey-pin-mismatch")
    try:
        der = base64.b64decode(signature["signatureBase64"], validate=True)
    except ValueError:
        raise Reject("signature-format") from None
    verify_signature(message, der, pem)
    if expect_scope is not None and "/".join(manifest[k] for k in ("organization", "app", "environment")) != expect_scope:
        raise Reject("scope-mismatch")
    if expect_operation_id is not None and manifest["operationId"] != expect_operation_id:
        raise Reject("operation-id-mismatch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--receipt", required=True, help="arquivo JSON com o objeto completionReceipt")
    parser.add_argument("--pubkey", help="PEM da chave pública de recibo")
    parser.add_argument("--keys-index", help="JSON de /.well-known/sentomaru-trust-keys (usa o pem do keyName)")
    parser.add_argument("--pubkey-sha256", help="SHA-256 (hex) esperado dos bytes do PEM, da tabela de pinos")
    parser.add_argument("--expect-scope", help="org/app/env esperado")
    parser.add_argument("--expect-operation-id", help="operationId esperado")
    args = parser.parse_args(argv)
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            receipt = json.load(handle)
        pem = open(args.pubkey, "rb").read() if args.pubkey else None
        index = json.load(open(args.keys_index, encoding="utf-8")) if args.keys_index else None
        verify(receipt, pem, index, args.expect_scope, args.expect_operation_id, args.pubkey_sha256)
    except Reject as reject:
        if reject.code in ("openssl-unavailable", "openssl-misbehaves"):
            # The environment cannot verify: not "invalid" (1), so a missing openssl is never read as a bad receipt.
            print("verify-unavailable: " + reject.code, file=sys.stderr)
            return 2
        print(reject.code)
        return 1
    except (OSError, ValueError):
        print("input-unreadable")
        return 1
    # A aprovação é só "estes bytes foram assinados pela chave informada" (docstring). O que o chamador não fixou vai para o stderr, como no
    # verificador da exportação; a saída padrão continua sendo a linha `ok` do contrato.
    unbound = [name for name, value in (("--pubkey-sha256", args.pubkey_sha256), ("--expect-scope", args.expect_scope),
                                        ("--expect-operation-id", args.expect_operation_id)) if value is None]
    if unbound:
        print("receipt-warning: unbound (" + ", ".join(unbound) + "): ok only says the bytes were signed by the key you passed; "
              "it does not say that key is Sentomaru's, nor that this is the receipt you expect", file=sys.stderr)
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
