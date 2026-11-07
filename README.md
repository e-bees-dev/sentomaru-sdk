# sentomaru-sdk

Distribution repository of Sentomaru: SDKs (Android, Flutter and hybrid plugins), the GitHub Actions
(`actions/protect`, `actions/policy-gate`), the CLI sources and the client guides. It is generated from the
Sentomaru source repository by `tools/devsecops/export_distribution.py`; do not edit it by hand.

Start with `docs/devsecops/CLI_PIPELINE.md` (CI pipeline) and `docs/devsecops/GUIA_TERCEIRO.md` (third parties).
Releases (`cli-v<version>`, `sdk-v<version>`) are signed; the guides explain how to verify them before use.

Pin the Actions by the full SHA of a commit of THIS repository (the commit of the release you verified): wherever a guide
shows `@<SHA-DO-RELEASE>`, replace it with that SHA. Names of customers and pilots are replaced by neutral names in this
tree; the signing identity of the releases is the private builder repository named in the guides.
