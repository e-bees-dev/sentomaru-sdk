package br.com.ebees.sentomaru.sdk.sealed

import java.io.IOException

/**
 * A typed failure of the sealed reader. [code] is the contract's name (`not-sealed`, `integrity`, `format-unsupported`).
 * In a file of its own, without Android imports (D-14c): the CLI's tests compile the JVM part of this reader
 * (`SealedFormat`, `SealedReader`, `StringsJson` and this class) to read what the CLI writes.
 */
class SentomaruSealedException(val code: Code) : IOException(code.wire) {
    enum class Code(val wire: String) {
        /** No `header.bin` (and no plain fallback), or no sealed entry for the path, or no strings file in the header. */
        NOT_SEALED("not-sealed"),
        /** A size out of the format's bounds, a tag that does not verify, an invalid DEFLATE stream or strings file. */
        INTEGRITY("integrity"),
        /** A magic or a format version this reader does not know. */
        FORMAT_UNSUPPORTED("format-unsupported"),
    }
}
