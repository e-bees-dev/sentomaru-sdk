package br.com.ebees.sentomaru.protect

/** Stable error codes and exit codes of contracts/devsecops/cli-v1.md ("Erros e códigos de saída"). */
enum class ErrorCode(val code: String, val exit: Int) {
    INTERNAL("internal-error", 1),
    USAGE("usage", 2),
    OUTPUT_UNWRITABLE("output-unwritable", 2),
    INPUT_FORMAT("input-format", 3),
    INPUT_SIGNATURE("input-signature", 3),
    INPUT_TOO_LARGE("input-too-large", 3),
    MIN_SDK_UNSUPPORTED("min-sdk-unsupported", 3),
    PROFILE_FORMAT("profile-format", 4),
    CONTROL_NOT_AVAILABLE("control-not-available", 4),
    CONTROL_VERSION_UNSUPPORTED("control-version-unsupported", 4),
    CONTROL_PREREQUISITE("control-prerequisite", 4),
    SCOPE_MISMATCH("scope-mismatch", 4),
    PERMISSION_MISSING("permission-missing", 5),
    APP_INCOMPATIBLE("app-incompatible", 5),
    CONTROL_FAILED("control-failed", 6),
    SIGN_FAILED("sign-failed", 7),
    SIGNER_UNAVAILABLE("signer-unavailable", 7),
    CREDENTIAL_MISSING("credential-missing", 8),
    ENTITLEMENT_DENIED("entitlement-denied", 8),
    REGISTRY_UNAVAILABLE("registry-unavailable", 8),
    REGISTER_FAILED("register-failed", 8),
}

/** A refusal with a stable code; [detail] never carries app content (names and digests only). */
class ProtectException(val error: ErrorCode, val detail: String) : Exception("${error.code}: $detail")
