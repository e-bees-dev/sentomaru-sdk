package br.com.ebees.sentomaru.sdk

import android.content.Context
import android.util.AtomicFile
import br.com.ebees.sentomaru.core.SentomaruException
import java.io.File
import java.io.IOException
import java.time.Instant
import java.util.Base64
import org.json.JSONException
import org.json.JSONObject

/** Atomic local state under noBackupFilesDir, even if the consumer enables app backup. No logging. */
class AndroidInstallationStore(context: Context, private val config: SentomaruConfig) : InstallationStore {
    private val directory = File(context.applicationContext.noBackupFilesDir, "sentomaru")
    private val file = AtomicFile(File(directory, "${config.identity}.json"))

    @Synchronized override fun read(): InstallationRecord? {
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return null
        return try {
            val bytes = file.openRead().use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (output.size() <= MAX_RECORD_BYTES) {
                    val count = input.read(buffer, 0, minOf(buffer.size, MAX_RECORD_BYTES + 1 - output.size()))
                    if (count == -1) break
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            if (bytes.size > MAX_RECORD_BYTES) fail(EnrollmentError.KeyInvalidated())
            val json = JSONObject(String(bytes, Charsets.UTF_8))
            if (json.getInt("version") != 1) fail(EnrollmentError.KeyInvalidated())
            val challenge = EnrollmentChallenge(json.getString("challengeId"), json.getString("token"),
                Base64.getDecoder().decode(json.getString("attestationChallenge")), Instant.parse(json.getString("expiresAt")))
            val grant = if (!json.has("grant")) null else json.getJSONObject("grant").let {
                EnrollmentGrant(it.getString("installationId"), it.getString("keyId"), it.getString("sessionId"),
                    it.getString("hardwareStatus"), it.getString("attestationStatus"),
                    if (it.has("issuedAt")) Instant.parse(it.getString("issuedAt")) else null, // J-04r; absent before
                    if (it.has("ttlSeconds")) it.getLong("ttlSeconds") else null)
            }
            val body = if (!json.has("body")) null else Base64.getDecoder().decode(json.getString("body"))
            val generation = json.optLong("generation", 1L)
            val retiredList = mutableListOf<RetiredKey>()
            val retiredArray = json.optJSONArray("retiredKeys")
            if (retiredArray != null) {
                for (i in 0 until retiredArray.length()) {
                    val item = retiredArray.getJSONObject(i)
                    retiredList.add(RetiredKey(item.getString("alias"),
                        Instant.parse(item.getString("retiredAt")),
                        Instant.parse(item.getString("expiresAt"))))
                }
            }
            val pendingRotation = if (!json.has("pendingRotation")) null else json.getJSONObject("pendingRotation").let { rot ->
                val rotChallenge = EnrollmentChallenge(rot.getString("challengeId"), rot.getString("token"),
                    Base64.getDecoder().decode(rot.getString("attestationChallenge")), Instant.parse(rot.getString("expiresAt")))
                PendingRotation(rot.getString("alias"), rotChallenge, rot.getBoolean("strongBox"),
                    Base64.getDecoder().decode(rot.getString("body")), rot.getBoolean("requiresHardware"),
                    StoredVersionCode.parse(rot.opt("versionCode")),
                    rot.opt("sent") == true) // D-04d; tolerant: absent or anything but JSON true = not sent
            }
            InstallationRecord(json.getString("scopeIdentity"), json.getString("alias"), challenge,
                json.getBoolean("strongBox"), body, grant, json.getBoolean("requiresHardware"),
                generation, retiredList, pendingRotation,
                StoredVersionCode.parse(json.opt("versionCode"))) // D-04b; absent before
        } catch (e: SentomaruException) { throw e }
        catch (_: IOException) { fail(EnrollmentError.StorageUnavailable()) }
        catch (_: JSONException) { fail(EnrollmentError.KeyInvalidated()) }
        catch (_: IllegalArgumentException) { fail(EnrollmentError.KeyInvalidated()) }
        catch (_: java.time.format.DateTimeParseException) { fail(EnrollmentError.KeyInvalidated()) }
    }

    @Synchronized override fun write(record: InstallationRecord?) {
        if (record == null) {
            file.delete()
            if (file.baseFile.exists()) fail(EnrollmentError.StorageUnavailable())
            return
        }
        if (record.scopeIdentity != config.identity) fail(EnrollmentError.KeyInvalidated())
        val encoder = Base64.getEncoder()
        val json = JSONObject().put("version", 1).put("scopeIdentity", record.scopeIdentity).put("alias", record.alias)
            .put("challengeId", record.challenge.id).put("token", record.challenge.token)
            .put("attestationChallenge", encoder.encodeToString(record.challenge.attestationChallenge()))
            .put("expiresAt", record.challenge.expiresAt.toString()).put("strongBox", record.strongBox)
            .put("requiresHardware", record.requiresHardware).put("generation", record.generation)
        record.body()?.let { json.put("body", encoder.encodeToString(it)) }
        StoredVersionCode.serialize(record.versionCode)?.let { json.put("versionCode", it) }
        record.grant?.let {
            json.put("grant", JSONObject().put("installationId", it.installationId).put("keyId", it.keyId)
                .put("sessionId", it.sessionId).put("hardwareStatus", it.hardwareStatus).put("attestationStatus", it.attestationStatus)
                .apply {
                    it.issuedAt?.let { at -> put("issuedAt", at.toString()) }
                    it.ttlSeconds?.let { ttl -> put("ttlSeconds", ttl) }
                })
        }
        if (record.retiredKeys.isNotEmpty()) {
            val arr = org.json.JSONArray()
            for (ret in record.retiredKeys) {
                arr.put(JSONObject().put("alias", ret.alias)
                    .put("retiredAt", ret.retiredAt.toString())
                    .put("expiresAt", ret.expiresAt.toString()))
            }
            json.put("retiredKeys", arr)
        }
        record.pendingRotation?.let { rot ->
            json.put("pendingRotation", JSONObject().put("alias", rot.alias)
                .put("challengeId", rot.challenge.id).put("token", rot.challenge.token)
                .put("attestationChallenge", encoder.encodeToString(rot.challenge.attestationChallenge()))
                .put("expiresAt", rot.challenge.expiresAt.toString()).put("strongBox", rot.strongBox)
                .put("requiresHardware", rot.requiresHardware)
                .put("body", encoder.encodeToString(rot.body()))
                .apply {
                    StoredVersionCode.serialize(rot.versionCode)?.let { put("versionCode", it) }
                    if (rot.sent) put("sent", true)
                })
        }
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_RECORD_BYTES) fail(EnrollmentError.StorageUnavailable())
        if (!directory.isDirectory && !directory.mkdirs()) fail(EnrollmentError.StorageUnavailable())
        var stream: java.io.FileOutputStream? = null
        try {
            stream = file.startWrite()
            stream.write(bytes)
            file.finishWrite(stream)
        } catch (_: IOException) {
            file.failWrite(stream)
            fail(EnrollmentError.StorageUnavailable())
        }
    }

    companion object { private const val MAX_RECORD_BYTES = 100_000 }
}

/**
 * D-04b: the `versionCode` member of the stored record and of its pending rotation, read tolerantly. The value comes
 * from `JSONObject.opt` (absent = null, JSON null = `JSONObject.NULL`); only a positive integer (org.json gives
 * `Integer` or `Long`) is a version. Anything else (null, string, negative, zero, fraction) is unknown, never
 * [EnrollmentError.KeyInvalidated]: an unreadable version only means the SDK does not ask for re-enrollment.
 */
internal object StoredVersionCode {
    fun parse(raw: Any?): Long? = when (raw) {
        is Int -> raw.toLong().takeIf { it > 0 }
        is Long -> raw.takeIf { it > 0 }
        else -> null
    }

    /** What is written: a positive version, or nothing (an unknown version is not written). */
    fun serialize(versionCode: Long?): Long? = versionCode?.takeIf { it > 0 }
}
