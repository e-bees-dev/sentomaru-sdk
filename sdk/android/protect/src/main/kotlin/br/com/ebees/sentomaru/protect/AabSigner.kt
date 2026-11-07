package br.com.ebees.sentomaru.protect

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile
import jdk.security.jarsigner.JarSigner

/**
 * G-03e `--sign keystore` for an AAB: a JAR signature (the bundle's signature, the one the Play Console checks for
 * the upload key) by the JDK signer, SHA-256 digests. The keystore path is an argument; its passwords come only from
 * the environment (`SENTOMARU_KEYSTORE_PASSWORD`, and `SENTOMARU_KEY_PASSWORD` when the key has its own), never argv.
 * Signs [file] in place through a sibling temporary file; returns the SHA-256 of the signer certificate.
 */
object AabSigner {
    fun sign(file: File, keystore: File, alias: String, env: Map<String, String>): String {
        val storePassword = env["SENTOMARU_KEYSTORE_PASSWORD"]?.toCharArray()
            ?: throw ProtectException(ErrorCode.SIGN_FAILED, "SENTOMARU_KEYSTORE_PASSWORD missing")
        val keyPassword = env["SENTOMARU_KEY_PASSWORD"]?.toCharArray() ?: storePassword
        val entry = try {
            val store = KeyStore.getInstance(keystore, storePassword)
            store.getEntry(alias, KeyStore.PasswordProtection(keyPassword)) as? KeyStore.PrivateKeyEntry
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "keystore unreadable or wrong password (${e.javaClass.simpleName})")
        } finally {
            storePassword.fill('\u0000')
            keyPassword.fill('\u0000')
        } ?: throw ProtectException(ErrorCode.SIGN_FAILED, "no private key entry for the alias")
        val signed = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.signing")
        try {
            val signer = JarSigner.Builder(entry).digestAlgorithm("SHA-256").build()
            ZipFile(file).use { zip -> signed.outputStream().use { out -> signer.sign(zip, out) } }
            Files.move(signed.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "JAR signing (${e.javaClass.simpleName})")
        } finally {
            signed.delete()
        }
        return MessageDigest.getInstance("SHA-256").digest(entry.certificate.encoded).joinToString("") { "%02x".format(it) }
    }
}
