package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.signer.GenerationResult
import br.com.ebees.sentomaru.signer.KeystoreSigner
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException

/** No shared mutable signer: every signature binds its own instance to the persisted alias. */
class AndroidInstallationKeys : InstallationKeys {
    override fun exists(alias: String): Boolean = access(EnrollmentError.KeyInvalidated()) {
        KeystoreSigner.containsAlias(alias)
    }

    override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial =
        access(EnrollmentError.KeyUnavailable()) {
            // The proven P0 signer deletes an existing alias. The product adapter never regenerates one.
            if (KeystoreSigner.containsAlias(alias)) fail(EnrollmentError.KeyInvalidated())
            when (KeystoreSigner().generateResult(alias, challenge, strongBox)) {
                GenerationResult.StrongBoxUnavailable -> fail(EnrollmentError.StrongBoxUnavailable())
                is GenerationResult.Generated -> material(alias)
            }
        }

    override fun material(alias: String): KeyMaterial = access(EnrollmentError.KeyInvalidated()) {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val chain = store.getCertificateChain(alias) ?: fail(EnrollmentError.KeyInvalidated())
        KeystoreSigner().useExisting(alias) // validates EC P-256 private/public entry
        KeyMaterial(chain[0].publicKey.encoded, chain.map { it.encoded })
    }

    override fun sign(alias: String, bytes: ByteArray): ByteArray = access(EnrollmentError.KeyInvalidated()) {
        KeystoreSigner().run { useExisting(alias); sign(bytes) }
    }

    override fun delete(alias: String) = access(EnrollmentError.KeyUnavailable()) { KeystoreSigner.deleteKey(alias) }

    override fun deleteOwned(prefix: String) = access(EnrollmentError.KeyUnavailable()) {
        require(Regex("sentomaru\\.v1\\.[0-9a-f]{64}\\.").matches(prefix)) { "Invalid SDK namespace" }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val aliases = java.util.Collections.list(store.aliases()).filter { it.startsWith(prefix) }
        aliases.forEach { store.deleteEntry(it) }
    }

    private inline fun <T> access(error: EnrollmentError, block: () -> T): T = try { block() }
    catch (e: SentomaruException) { throw e }
    catch (_: GeneralSecurityException) { fail(error) }
    catch (_: ProviderException) { fail(error) }
    catch (_: IllegalStateException) { fail(error) }
    catch (_: IllegalArgumentException) { fail(error) }
}
