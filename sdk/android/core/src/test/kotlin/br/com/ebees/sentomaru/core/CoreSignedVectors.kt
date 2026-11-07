package br.com.ebees.sentomaru.core

import java.io.File
import java.util.Base64

/**
 * core-signed-v1.json: every positive vector signed by THIS core with a fresh JDK P-256 key (public SPKI only) and
 * encoded by [EnvelopeCodec]. Consumed by the server tests (real server verification path) and by
 * the vendor's vector checker (Python verifier). Regenerate with `./gradlew :core:exportCoreSignedVectors`.
 *
 * One vector per line, so the test-only reader below needs no JSON parser.
 */
object CoreSignedVectors {
    const val NAME = "core-signed-v1.json"
    private const val ENTRY = "  {\"id\": \""

    fun request(vector: Vector) = FrozenRequest(vector.method, vector.targetUri, vector.headers, vector.body)

    fun envelope(vector: Vector, signed: SignedMessage): ByteArray =
        if (vector.route == "enrollment") EnvelopeCodec.encodeEnrollment(signed) else EnvelopeCodec.encode(signed)

    fun write(vectors: VectorFile, out: File) {
        val pair = JdkKeys.generate()
        val signer = JdkKeys.signer(pair)
        val text = StringBuilder()
        text.append("{\n")
        text.append(" \"version\": 1,\n")
        text.append(" \"generator\": \"sdk/android: ./gradlew :core:exportCoreSignedVectors\",\n")
        text.append(" \"note\": \"Synthetic, public test data: Kotlin core base + EnvelopeCodec, signed with a fresh ")
            .append("JDK P-256 key per run; only its public SPKI is stored. Timestamps fixed in 2100 (see gen_vectors.py).\",\n")
        text.append(" \"publicKeySpki\": \"").append(Base64.getEncoder().encodeToString(pair.public.encoded)).append("\",\n")
        text.append(" \"vectors\": [\n")
        vectors.positives.forEachIndexed { index, vector ->
            val signed = MessageSigner.sign(request(vector), vector.params(), signer)
            text.append(ENTRY).append(vector.id).append("\", \"route\": \"").append(vector.route)
                .append("\", \"envelope\": ").append(String(envelope(vector, signed), Charsets.UTF_8)).append('}')
                .append(if (index == vectors.positives.size - 1) "\n" else ",\n")
        }
        text.append(" ]\n}\n")
        out.writeText(text.toString(), Charsets.UTF_8)
    }

    class Entry(val id: String, val route: String, val envelope: String) {
        /** The P1363 bytes inside `"signature":["sig1=:<b64>:"]`. */
        fun signature(): ByteArray {
            val start = envelope.indexOf("\"signature\":[\"sig1=:") + "\"signature\":[\"sig1=:".length
            return Base64.getDecoder().decode(envelope.substring(start, envelope.indexOf(":\"]", start)))
        }
    }

    fun read(file: File): Pair<ByteArray, List<Entry>> {
        val lines = file.readLines(Charsets.UTF_8)
        val key = lines.single { it.startsWith(" \"publicKeySpki\": \"") }
            .removePrefix(" \"publicKeySpki\": \"").removeSuffix("\",")
        val entries = lines.filter { it.startsWith(ENTRY) }.map { line ->
            val id = line.substring(ENTRY.length, line.indexOf('"', ENTRY.length))
            val routeStart = line.indexOf("\"route\": \"") + "\"route\": \"".length
            val route = line.substring(routeStart, line.indexOf('"', routeStart))
            val envelope = line.substring(line.indexOf("\"envelope\": ") + "\"envelope\": ".length).removeSuffix(",")
                .removeSuffix("}")
            Entry(id, route, envelope)
        }
        return Base64.getDecoder().decode(key) to entries
    }
}

/** Entry point of the `exportCoreSignedVectors` Gradle task: args = <vectors dir>. */
fun main(args: Array<String>) {
    val dir = File(args.single())
    CoreSignedVectors.write(VectorFile.load(File(dir, VectorFile.NAME)), File(dir, CoreSignedVectors.NAME))
    println("wrote ${File(dir, CoreSignedVectors.NAME).path}")
}
