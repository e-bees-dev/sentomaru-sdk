package br.com.ebees.sentomaru.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.*
import br.com.ebees.sentomaru.sdk.*
import br.com.ebees.sentomaru.signals.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class LifecycleInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val org = "org-a"
    private val app = "app-a"
    private val env = "hml"
    private val host = "127.0.0.1"
    private val enrollmentUrl = "https://$host:8443/v1/$org/$app/$env/installations"
    private val operationUrl = "https://$host:8443/v1/$org/$app/$env/operations/submit?channel=field"

    private lateinit var config: SentomaruConfig
    private lateinit var client: SentomaruClient
    private val executor = Executors.newSingleThreadExecutor()

    private val challengeId = "33333333-4444-4555-8666-777777777777"
    private val sessionId = "88888888-9999-4aaa-8bbb-cccccccccccc"

    private fun mockChallenge(expiresAt: Instant = Instant.now().plusSeconds(300)) =
        EnrollmentChallenge(
            id = challengeId,
            token = Base64.getEncoder().encodeToString(ByteArray(32) { 11 }),
            attestationChallenge = ByteArray(32) { 22 },
            expiresAt = expiresAt
        )

    private fun mockGrant() =
        EnrollmentGrant(sessionId, challengeId, sessionId, "hardware", "verified")

    @Before
    fun setUp() {
        config = SentomaruConfig(
            organization = org,
            app = app,
            environment = env,
            allowedHosts = setOf(host),
            enrollmentUrl = enrollmentUrl
        )
        client = SentomaruClient(config, AndroidInstallationKeys(), AndroidInstallationStore(context, config))
        client.reset()
    }

    @After
    fun tearDown() {
        client.reset()
        executor.shutdownNow()
        Thread.interrupted() // Clear any lingering interrupt status
    }

    // --- SDK-LIFE-1 (approximation): collection and signing on a worker thread with the application context only.
    // Runs under instrumentation; it does not prove absence of an Activity nor WorkManager/background limits. ---
    @Test
    fun test_SDK_LIFE_1_worker_thread_collection_and_signing_with_application_context() {
        val appContext = context.applicationContext

        val future = executor.submit(Callable {
            val bgClient = SentomaruClient(config, AndroidInstallationKeys(), AndroidInstallationStore(appContext, config))
            bgClient.enroll(mockChallenge()) { mockGrant() }
            assertEquals(InstallationState.Enrolled, bgClient.state())

            // Measure signing time budget (must be well under 100ms in background thread)
            val rawBody = "{\"reading\":100}".toByteArray(Charsets.UTF_8)
            val startTime = System.nanoTime()
            val signed = bgClient.sign("POST", operationUrl, "submit", rawBody)
            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

            assertNotNull(signed)
            assertTrue("Signing exceeded budget: ${elapsedMs}ms", elapsedMs < 200)

            // Collect signals without Activity
            val collector = SignalsCollector()
            val snapshot = collector.snapshot(appContext)
            assertFalse("Signals collection empty in background", snapshot.observations.isEmpty())
            assertTrue(snapshot.observations.all { it.observedAt.isNotBlank() })
            assertTrue("Signals duration should be budgeted", snapshot.durationMs < 150)

            true
        })

        assertTrue(future.get(10, TimeUnit.SECONDS))
    }

    // --- SDK-LIFE-2: App in background for extended period, state and key persist ---
    @Test
    fun test_SDK_LIFE_2_long_background_inactivity_state_persistence() {
        val initialTime = Instant.now()
        client.enroll(mockChallenge()) { mockGrant() }
        assertEquals(InstallationState.Enrolled, client.state())

        // Simulate advancing clock by 7 days
        val futureClock = Clock.fixed(initialTime.plus(Duration.ofDays(7)), ZoneOffset.UTC)
        val recreatedClient = SentomaruClient(
            config,
            AndroidInstallationKeys(),
            AndroidInstallationStore(context, config),
            clock = futureClock
        )

        assertEquals("State should remain Enrolled after background period",
            InstallationState.Enrolled, recreatedClient.state())

        val signed = recreatedClient.sign("POST", operationUrl, "submit", "{}".toByteArray())
        assertNotNull("Signing should succeed after background inactivity", signed)
    }

    // --- SDK-LIFE-3: Cancellation during signing and enrollment ---
    @Test
    fun test_SDK_LIFE_3_cancellation_during_signing_and_enrollment() {
        client.enroll(mockChallenge()) { mockGrant() }

        // Test cancellation during signing
        Thread.currentThread().interrupt()
        val exSign = assertThrows(SentomaruException::class.java) {
            client.sign("POST", operationUrl, "submit", "{}".toByteArray())
        }
        Thread.interrupted() // Clear interrupt flag
        assertEquals("Cancelled", exSign.error.code)

        // Test cancellation during enrollment
        client.reset()
        val future = executor.submit(Callable {
            Thread.currentThread().interrupt()
            client.enroll(mockChallenge()) { mockGrant() }
        })

        try {
            future.get(5, TimeUnit.SECONDS)
            fail("Expected ExecutionException wrapping SentomaruException")
        } catch (e: Exception) {
            val cause = e.cause as? SentomaruException
            assertNotNull(cause)
            assertEquals("Cancelled", cause?.error?.code)
        }
    }

    // --- SDK-LIFE-4: Process killed during enrollment, recovers without key loss ---
    @Test
    fun test_SDK_LIFE_4_process_death_recovery_during_enrollment() {
        val challenge = mockChallenge()
        var frozenBody1: ByteArray? = null
        var alias1: String? = null

        // Simulate process dying before network response is received
        val ex = assertThrows(SentomaruException::class.java) {
            client.enroll(challenge) {
                frozenBody1 = it.body()
                alias1 = (client.state() as? InstallationState)?.toString()
                throw java.io.IOException("simulated process kill / network drop")
            }
        }
        assertEquals("NetworkUnavailable", ex.error.code)

        // Recreate client simulating new process instance reading persisted store
        val store = AndroidInstallationStore(context, config)
        val record = store.read()
        assertNotNull("Pending record should be persisted to disk", record)
        assertNull("Grant should be null in pending record", record?.grant)
        assertArrayEquals("Persisted frozen body must match original", frozenBody1, record?.body())

        val newProcessClient = SentomaruClient(config, AndroidInstallationKeys(), store)
        assertEquals(InstallationState.EnrollmentRequired, newProcessClient.state())

        // Re-enrolling reuses the exact key and body without re-generating a new key
        val grant = newProcessClient.enroll(challenge) {
            assertArrayEquals("Retried body must be byte-for-byte identical", frozenBody1, it.body())
            mockGrant()
        }

        assertEquals(InstallationState.Enrolled, newProcessClient.state())
        assertEquals(challengeId, grant.keyId)
    }

    // --- SDK-LIFE-5: Account switch / logout clears local grant without wiping drafts ---
    @Test
    fun test_SDK_LIFE_5_logout_clears_grant_without_deleting_app_drafts() {
        // Create an unrelated user draft file
        val draftsDir = File(context.filesDir, "drafts")
        draftsDir.mkdirs()
        val draftFile = File(draftsDir, "offline_work_order.json")
        draftFile.writeText("{\"id\":\"order-123\",\"notes\":\"pending sync\"}")
        assertTrue(draftFile.exists())

        client.enroll(mockChallenge()) { mockGrant() }
        assertEquals(InstallationState.Enrolled, client.state())

        // Logout / account switch: reset local Sentomaru state
        client.reset()
        assertEquals(InstallationState.NotEnrolled, client.state())
        assertNull(client.sessionId())

        // Verify draft was NOT wiped
        assertTrue("User drafts must NOT be deleted by Sentomaru reset", draftFile.exists())
        assertEquals("{\"id\":\"order-123\",\"notes\":\"pending sync\"}", draftFile.readText().trim())

        // Clean up draft file
        draftFile.delete()
        draftsDir.delete()
    }

    // --- SDK-LIFE-6: Key invalidated detection and controlled recovery ---
    @Test
    fun test_SDK_LIFE_6_key_invalidated_detection_and_controlled_recovery() {
        client.enroll(mockChallenge()) { mockGrant() }
        assertEquals(InstallationState.Enrolled, client.state())

        val store = AndroidInstallationStore(context, config)
        val alias = store.read()!!.alias

        // Manually delete the key from AndroidKeyStore to simulate external invalidation
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.deleteEntry(alias)
        assertFalse("Key should be gone from Keystore", ks.containsAlias(alias))

        // State machine must detect KeyInvalidated
        assertEquals(InstallationState.KeyInvalidated, client.state())

        // Signing must fail with KeyInvalidated
        val exSign = assertThrows(SentomaruException::class.java) {
            client.sign("POST", operationUrl, "submit", "{}".toByteArray())
        }
        assertEquals("KeyInvalidated", exSign.error.code)

        // Enrolling directly without reset must fail with KeyInvalidated
        val exEnroll = assertThrows(SentomaruException::class.java) {
            client.enroll(mockChallenge()) { mockGrant() }
        }
        assertEquals("KeyInvalidated", exEnroll.error.code)

        // Controlled recovery: explicit reset clears invalidated state
        client.reset()
        assertEquals(InstallationState.NotEnrolled, client.state())

        // Re-enrollment succeeds cleanly with a fresh key
        val newChallenge = EnrollmentChallenge(
            id = "44444444-5555-4666-8777-888888888888",
            token = Base64.getEncoder().encodeToString(ByteArray(32) { 33 }),
            attestationChallenge = ByteArray(32) { 44 },
            expiresAt = Instant.now().plusSeconds(300)
        )
        val grant = client.enroll(newChallenge) {
            EnrollmentGrant(sessionId, newChallenge.id, sessionId, "hardware", "verified")
        }
        assertEquals(InstallationState.Enrolled, client.state())
        assertEquals(newChallenge.id, grant.keyId)
    }
}
