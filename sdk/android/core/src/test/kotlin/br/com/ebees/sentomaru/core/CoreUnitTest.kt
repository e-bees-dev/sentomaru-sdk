package br.com.ebees.sentomaru.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class CoreUnitTest {
    private val keyId = "11111111-2222-4333-8444-555555555555"
    private val nonce = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val params = SignatureParams(1_700_000_000, 1_700_000_060, nonce, keyId)
    private val headers = linkedMapOf(
        "content-type" to "application/json",
        "x-sentomaru-profile" to "sentomaru-p0",
        "x-sentomaru-org" to "org-a",
        "x-sentomaru-app" to "app-a",
        "x-sentomaru-environment" to "hml",
        "x-sentomaru-session" to keyId,
        "x-sentomaru-operation" to "submit",
    )
    private val uri = "https://consumer.example/api/ops?x=1"
    private val sig64 = SignatureFunction { ByteArray(64) { it.toByte() } }

    private fun refused(expected: String, case: String = "", block: () -> Unit) {
        try {
            block()
            fail("accepted $case, expected $expected")
        } catch (e: SentomaruException) {
            assertEquals(expected, e.error.code)
        }
    }

    @Test
    fun contentDigestRfc9530Example() {
        // RFC 9530 §2, example body {"hello": "world"} (no trailing newline).
        assertEquals("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            ContentDigest.sha256("{\"hello\": \"world\"}".toByteArray()))
        assertEquals("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:", ContentDigest.sha256(ByteArray(0)))
    }

    @Test
    fun signatureParamsSerializeInReferenceOrder() {
        assertEquals(
            "(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\" \"x-sentomaru-profile\" " +
                "\"x-sentomaru-org\" \"x-sentomaru-app\" \"x-sentomaru-environment\" \"x-sentomaru-session\" " +
                "\"x-sentomaru-operation\");created=1700000000;keyid=\"$keyId\";alg=\"ecdsa-p256-sha256\";" +
                "expires=1700000060;nonce=\"$nonce\";tag=\"sentomaru-p0\"",
            params.serialize(),
        )
        assertEquals("sig1=" + params.serialize(), MessageSigner.signatureInput(params))
    }

    @Test
    fun signatureParamsWindowAndIdentifiers() {
        SignatureParams(0, 1, nonce, keyId)
        refused("InvalidRequest:PARAMS") { SignatureParams(10, 10, nonce, keyId) }
        refused("InvalidRequest:PARAMS") { SignatureParams(10, 71, nonce, keyId) }
        refused("InvalidRequest:PARAMS") { SignatureParams(-1, 10, nonce, keyId) }
        refused("InvalidRequest:PARAMS") { SignatureParams(10, 20, nonce.uppercase(), keyId) }
        refused("InvalidRequest:PARAMS") { SignatureParams(10, 20, nonce, "{$keyId}") }
        refused("InvalidRequest:PARAMS") { SignatureParams(10, 20, "$nonce\"", keyId) }
        refused("InvalidRequest:PARAMS") { SignatureParams(1_000_000_000_000_000, 1_000_000_000_000_001, nonce, keyId) }
        val now = SignatureParams.now(Clock.fixed(Instant.ofEpochSecond(1_800_000_000, 999_000_000), ZoneOffset.UTC), keyId, nonce)
        assertEquals(1_800_000_000, now.created)
        assertEquals(1_800_000_060, now.expires)
    }

    @Test
    fun targetUriCanonicalFormOnly() {
        val accepted = listOf(
            "https://a.example/", "https://a.example/p?", "https://a.example:8443/p", "https://10.0.0.5/p",
            "https://a.example/caf%C3%A9?q=%2F%20+", "https://a.example/a/b/?k=v&k2=",
            "https://a.example/p?q=a?b/c", "https://a.example/" + "x".repeat(4096 - 18),
            "https://a.example/a%2Fb%25c%20d%3Fe%5B%7F%23%01", "https://a.example/a:b@c!d\$e&f'g(h)i*j+k,l;m=n",
            "https://a.example/p?q=%3A%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%00", "https://255.255.255.255/",
            "https://0.0.0.0/", "https://1.2.3.4:8443/", "https://0x7f.example/", "https://1e.example/",
        )
        for (u in accepted) SignatureBase.build("POST", u, headers, ContentDigest.sha256(ByteArray(0)), params)
        val refusedUris = listOf(
            "", "http://a.example/", "HTTPS://a.example/", "https://a.example", "https://a.example?x=1",
            "https://A.example/", "https://a.example:443/", "https://a.example:0/", "https://a.example:08443/",
            "https://a.example:65536/", "https://a.example:/", "https://u@a.example/", "https://a.example/#f",
            "https://a.example/a b", "https://a.example/café", "https://a.example/%c3%a9", "https://a.example/%41",
            "https://a.example/%7E", "https://a.example/%2E%2E/x", "https://a.example/%G0", "https://a.example/%C",
            "https://a.example/./x", "https://a.example/a/../x", "https://a.example/a\\b", "https://a.example/{x}",
            "https://[::1]/", "https://a..example/", "https://-a.example/", "https://a.example./",
            "https://a.example/" + "x".repeat(4096 - 17), "/relative",
            "https://a.example/a%3Ab", "https://a.example/a%40b", "https://a.example/a%21b", "https://a.example/a%24b",
            "https://a.example/a%26b", "https://a.example/a%27b", "https://a.example/a%28b", "https://a.example/a%29b",
            "https://a.example/a%2Ab", "https://a.example/a%2Bb", "https://a.example/a%2Cb", "https://a.example/a%3Bb",
            "https://a.example/a%3Db", "https://a.example/a%00b", "https://a.example/p?q=%41", "https://a.example/p?q=%7E",
            "https://123/", "https://1.2.3/", "https://0x7f.0.0.1/", "https://010.0.0.1/", "https://256.0.0.1/",
            "https://1.2.3.4.5/", "https://a.123/", "https://a.0x1f/", "https://1.2.3.04/", "https://1.2.3.4:443/",
        )
        for (u in refusedUris) {
            refused("InvalidRequest:TARGET_URI", u) {
                SignatureBase.build("POST", u, headers, ContentDigest.sha256(ByteArray(0)), params)
            }
        }
    }

    @Test
    fun headerRules() {
        val digest = ContentDigest.sha256(ByteArray(0))
        fun with(name: String, value: String) = LinkedHashMap(headers).also { it[name] = value }
        refused("InvalidRequest:HEADER_NAME") {
            SignatureBase.build("POST", uri, LinkedHashMap(headers).also { it.remove("x-sentomaru-app") }, digest, params)
        }
        refused("InvalidRequest:HEADER_NAME") { SignatureBase.build("POST", uri, with("X-Sentomaru-App", "app-a"), digest, params) }
        refused("InvalidRequest:HEADER_NAME") { SignatureBase.build("POST", uri, with("content-digest", digest), digest, params) }
        for ((name, value) in listOf(
            "x-sentomaru-operation" to "submit\n", "x-sentomaru-operation" to "sub\rmit", "x-sentomaru-operation" to "",
            "x-sentomaru-operation" to "submit ", "x-sentomaru-operation" to "a".repeat(65),
            "x-sentomaru-org" to "-org", "x-sentomaru-org" to "org_a", "x-sentomaru-environment" to "h".repeat(64),
            "x-sentomaru-session" to nonce.uppercase(), "x-sentomaru-profile" to "sentomaru-p1",
            "content-type" to "application/json;charset=utf-8", "x-sentomaru-app" to "appã",
        )) refused("InvalidRequest:HEADER_VALUE", "$name=$value") { SignatureBase.build("POST", uri, with(name, value), digest, params) }
        // Operation follows the server's rule (printable ASCII, 1..64, no edge spaces), not a slug.
        SignatureBase.build("POST", uri, with("x-sentomaru-operation", "Checklist.Upload_v2:final"), digest, params)
        SignatureBase.build("POST", uri, with("x-sentomaru-operation", "o".repeat(64)), digest, params)
        refused("InvalidRequest:METHOD") { SignatureBase.build("Post", uri, headers, digest, params) }
        refused("InvalidRequest:METHOD") { SignatureBase.build("", uri, headers, digest, params) }
        refused("InvalidRequest:METHOD") { SignatureBase.build("P".repeat(17), uri, headers, digest, params) }
        refused("InvalidRequest:CONTENT_DIGEST") { SignatureBase.build("POST", uri, headers, "sha-512=:AA==:", params) }
        refused("InvalidRequest:CONTENT_DIGEST") { SignatureBase.build("POST", uri, headers, digest.dropLast(1), params) }
    }

    @Test
    fun bodyLimitAndSignerOutput() {
        FrozenRequest("POST", uri, headers, ByteArray(Profile.MAX_BODY_BYTES))
        try {
            FrozenRequest("POST", uri, headers, ByteArray(Profile.MAX_BODY_BYTES + 1))
            fail("accepted")
        } catch (e: SentomaruException) {
            val error = e.error as SentomaruError.BodyTooLarge
            assertEquals(Profile.MAX_BODY_BYTES + 1, error.size)
            assertEquals(Profile.MAX_BODY_BYTES, error.limit)
        }
        for (size in listOf(0, 63, 65, 72)) {
            refused("SignatureFormat") { MessageSigner.sign(FrozenRequest("POST", uri, headers, ByteArray(0)), params) { ByteArray(size) } }
        }
    }

    @Test
    fun bodyIsFrozenAndSignerSeesExactlyTheBase() {
        val body = "{\"a\":1}".toByteArray()
        val request = FrozenRequest("POST", uri, headers, body)
        body[0] = 'X'.code.toByte()
        var seen: ByteArray? = null
        val signed = MessageSigner.sign(request, params) { base -> seen = base.copyOf(); base[0] = 0; ByteArray(64) }
        assertArrayEquals("{\"a\":1}".toByteArray(), signed.body())
        assertArrayEquals(seen, signed.signatureBase())
        assertEquals(ContentDigest.sha256("{\"a\":1}".toByteArray()), signed.header("content-digest"))
        signed.body()[0] = 0
        assertArrayEquals("{\"a\":1}".toByteArray(), signed.body())
    }

    @Test
    fun envelopeMatchesTheOpenApiMessageDto() {
        val signed = MessageSigner.sign(FrozenRequest("POST", uri, headers, "{\"a\":1}".toByteArray()), params, sig64)
        val digest = ContentDigest.sha256("{\"a\":1}".toByteArray())
        val signature = MessageSigner.signatureHeader(ByteArray(64) { it.toByte() })
        val expected = "{\"method\":\"POST\",\"uri\":\"$uri\",\"headers\":{\"content-digest\":[\"$digest\"]," +
            "\"content-type\":[\"application/json\"],\"x-sentomaru-profile\":[\"sentomaru-p0\"]," +
            "\"x-sentomaru-org\":[\"org-a\"],\"x-sentomaru-app\":[\"app-a\"],\"x-sentomaru-environment\":[\"hml\"]," +
            "\"x-sentomaru-session\":[\"$keyId\"],\"x-sentomaru-operation\":[\"submit\"]," +
            "\"signature-input\":[\"sig1=" + params.serialize().replace("\"", "\\\"") + "\"]," +
            "\"signature\":[\"$signature\"]},\"body\":\"eyJhIjoxfQ==\"}"
        assertEquals(expected, String(EnvelopeCodec.encode(signed), Charsets.UTF_8))
        assertEquals("{\"request\":$expected}", String(EnvelopeCodec.encodeEnrollment(signed), Charsets.UTF_8))
    }

    @Test
    fun errorsCarryNoRequestValues() {
        try {
            SignatureBase.build("POST", "https://secret-tenant.example/a b", headers, ContentDigest.sha256(ByteArray(0)), params)
            fail("accepted")
        } catch (e: SentomaruException) {
            assertTrue(!e.message!!.contains("secret") && !e.error.toString().contains("secret"))
        }
        assertEquals("HostNotAllowed", SentomaruError.HostNotAllowed().code)
    }

    // ---- J-01f2: optional components (H3 signals, J-01f operation id), signed when present, in a fixed order

    @Test
    fun optionalHeadersAreSignedAfterTheBaseComponentsInProfileOrder() {
        val withOptional = LinkedHashMap(headers).apply {
            put(Profile.OPERATION_ID_HEADER, "op-0123456789abcdef")  // inserted first on purpose: the order is the profile's
            put(Profile.SIGNALS_HEADER, "{\"catalogVersion\":\"1.1.0\",\"observations\":[]}")
        }
        val signed = MessageSigner.sign(FrozenRequest("POST", uri, withOptional, "{}".toByteArray()), params, sig64)
        val input = signed.headers.first { it.first == Profile.SIGNATURE_INPUT }.second
        assertTrue(input, input.startsWith("sig1=(" + (Profile.COMPONENTS + listOf(Profile.SIGNALS_HEADER, Profile.OPERATION_ID_HEADER)).joinToString(" ") { "\"$it\"" } + ")"))
        val base = String(signed.signatureBase(), Charsets.US_ASCII)
        val signalsLine = base.indexOf("\"x-sentomaru-signals\": ")
        val idLine = base.indexOf("\"x-sentomaru-operation-id\": op-0123456789abcdef\n")
        assertTrue(base, signalsLine > base.indexOf("\"x-sentomaru-operation\": submit\n") && idLine > signalsLine)
        assertEquals(listOf(Profile.SIGNALS_HEADER, Profile.OPERATION_ID_HEADER),
            signed.headers.map { it.first }.filter { it in Profile.OPTIONAL_HEADERS })
        // Without optional headers the list is exactly the base one (no change for existing callers).
        val plain = MessageSigner.sign(FrozenRequest("POST", uri, headers, "{}".toByteArray()), params, sig64)
        assertTrue(plain.headers.first { it.first == Profile.SIGNATURE_INPUT }.second
            .startsWith("sig1=(" + Profile.COMPONENTS.joinToString(" ") { "\"$it\"" } + ")"))
    }

    @Test
    fun txSignatureIsSignedLastAndMalformedValuesAreRefused() {
        val good = "sentomaru-tx-v1." + "A".repeat(22) + "." + "B".repeat(86)
        val withTx = LinkedHashMap(headers).apply {
            put(Profile.TX_SIGNATURE_HEADER, good)
            put(Profile.OPERATION_ID_HEADER, "op-0123456789abcdef")
        }
        val signed = MessageSigner.sign(FrozenRequest("POST", uri, withTx, "{}".toByteArray()), params, sig64)
        assertEquals(listOf(Profile.OPERATION_ID_HEADER, Profile.TX_SIGNATURE_HEADER),
            signed.headers.map { it.first }.filter { it in Profile.OPTIONAL_HEADERS })
        val base = String(signed.signatureBase(), Charsets.US_ASCII)
        assertTrue(base, base.indexOf("\"x-sentomaru-tx-signature\": $good\n") > base.indexOf("\"x-sentomaru-operation-id\": "))
        // v2 (F1): version, nonce, issuedAt of 10 digits, signature; it is signed last like v1.
        val goodV2 = "sentomaru-tx-v2." + "A".repeat(22) + ".1793000000." + "B".repeat(86)
        val v2 = LinkedHashMap(headers).apply {
            put(Profile.TX_SIGNATURE_HEADER, goodV2)
            put(Profile.OPERATION_ID_HEADER, "op-0123456789abcdef")
        }
        MessageSigner.sign(FrozenRequest("POST", uri, v2, "{}".toByteArray()), params, sig64)
        for (bad in listOf("", good + "A", good.replace("v1", "v2"), goodV2.replace(".1793000000.", ".179300000."),
            goodV2.replace(".1793000000.", ".17930000000."), goodV2.replace(".1793000000.", ".17930000a0."), goodV2.replace("v2", "v1"),
            goodV2.replace("v2", "v3"), "sentomaru-tx-v1." + "A".repeat(21) + "." + "B".repeat(86),
            "sentomaru-tx-v1." + "A".repeat(22) + "." + "B".repeat(85), good.replace('A', '+'), "$good ")) {
            val h = LinkedHashMap(headers).apply { put(Profile.TX_SIGNATURE_HEADER, bad) }
            refused("InvalidRequest:HEADER_VALUE", bad) { MessageSigner.sign(FrozenRequest("POST", uri, h, "{}".toByteArray()), params, sig64) }
        }
    }

    @Test
    fun malformedOperationIdAndUnknownHeadersAreRefused() {
        for (bad in listOf("short", "op with space-0123", "x".repeat(65))) {
            val h = LinkedHashMap(headers).apply { put(Profile.OPERATION_ID_HEADER, bad) }
            refused("InvalidRequest:HEADER_VALUE", bad) { MessageSigner.sign(FrozenRequest("POST", uri, h, "{}".toByteArray()), params, sig64) }
        }
        val unknown = LinkedHashMap(headers).apply { put("x-sentomaru-other", "v") }
        refused("InvalidRequest:HEADER_NAME") { MessageSigner.sign(FrozenRequest("POST", uri, unknown, "{}".toByteArray()), params, sig64) }
    }

    @Test
    fun paramsWithComponentsOutsideTheProfileAreRefused() {
        refused("InvalidRequest:PARAMS") {
            SignatureParams(1, 2, nonce, keyId, Profile.COMPONENTS + listOf(Profile.OPERATION_ID_HEADER, Profile.SIGNALS_HEADER))
        }
        refused("InvalidRequest:PARAMS") { SignatureParams(1, 2, nonce, keyId, Profile.COMPONENTS.drop(1)) }
    }
}
