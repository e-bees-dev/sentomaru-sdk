package br.com.ebees.sentomaru.sentomaru_flutter

import android.os.Handler
import android.os.Looper
import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.sdk.ReattestationOutcome
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.signals.AndroidPlatformEnvironment
import br.com.ebees.sentomaru.signals.CodeDigestCache
import br.com.ebees.sentomaru.signals.PlatformEnvironment
import br.com.ebees.sentomaru.signals.SentomaruServerResponseEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvent
import br.com.ebees.sentomaru.signals.SignalsCollector
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * Flutter plugin bridging Dart to native Sentomaru SDK.
 *
 * Implements typed method channel IPC (Decision E1, E2, E7). Since D-22a1 the calls are answered by the shared
 * [SentomaruBridge] (`sdk/hybrid-core`, also the base of the React Native layer); this class keeps what is Flutter's:
 * the channels, the engine lifecycle, the sealed reader and the mapping of [MethodCall] and [Result].
 * Purely cryptographic background execution; strictly no biometric prompts (Decision E4 / FLT-8).
 */
class SentomaruFlutterPlugin : FlutterPlugin, ActivityAware, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * D-15c: signal events (D-15a) of this engine, delivered to Dart through [EVENT_CHANNEL] only while Dart listens.
     * The collectors of `collectSignalsSnapshot` feed them only then ([SignalEventsBridge.current]); `collectSignals`
     * (the frozen path) never does. In memory, nothing sent anywhere. Server response events (D-15b) come from the Dio
     * interceptor in Dart (the plugin signs, Dio sends); the bridge forwards native ones too, should a native transport
     * of this engine ever feed them.
     */
    private val bridge = SignalEventsBridge { mainHandler.post(it) }
    private val core = SentomaruBridge(bridge)
    private lateinit var eventChannel: EventChannel
    /** D-14b: `SentomaruSealed.load`/`string` of Dart, on its own worker thread (the sealed reader marker). */
    @Volatile internal var sealed: SentomaruFlutterSealed? = null

    /** D-26: `offlineSeal`/`offlineReconcileBody` of Dart, on their own worker thread. */
    @Volatile internal var offline: SentomaruFlutterOffline? = null

    /** D-25: `txKeyCreate`/`txSign`/`txIsEnrolled`/`txDiscard` of Dart; the prompt needs the foreground activity. */
    @Volatile internal var transaction: SentomaruFlutterTransaction? = null
    @Volatile private var activity: java.lang.ref.WeakReference<FragmentActivity>? = null

    override fun onAttachedToActivity(binding: ActivityPluginBinding) { activity = java.lang.ref.WeakReference(binding.activity as? FragmentActivity) }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)
    override fun onDetachedFromActivityForConfigChanges() { activity = null }
    override fun onDetachedFromActivity() { activity = null }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        core.context = flutterPluginBinding.applicationContext
        offline = SentomaruFlutterOffline(flutterPluginBinding.applicationContext, { core.client }) { mainHandler.post(it) }
        transaction = SentomaruFlutterTransaction(
            port = { core.client?.let { AndroidTransactionPort(it, { activity?.get() }) } },
            post = { mainHandler.post(it) },
        )
        sealed = SentomaruFlutterSealed(flutterPluginBinding.applicationContext) { mainHandler.post(it) }
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "sentomaru_flutter")
        channel.setMethodCallHandler(this)
        eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, EVENT_CHANNEL)
        eventChannel.setStreamHandler(bridge)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        eventChannel.setStreamHandler(null)
        bridge.onCancel(null)
        channel.setMethodCallHandler(null)
        releaseSealed()
        offline?.shutdown()
        offline = null
        transaction?.shutdown()
        transaction = null
        core.shutdown()
    }

    /** D-14b, on detach: pending sealed reads are answered with an error and the handler is dropped. */
    internal fun releaseSealed() {
        sealed?.shutdown()
        sealed = null
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        sealed?.takeIf { it.handles(call.method) }?.let { return it.onMethodCall(call, result) }
        // The plugin has its own sealed reader; once it is released (detach) the sealed methods must not fall through
        // to the shared bridge core, which also answers them since D-14b and replies on the main looper.
        if (call.method in SentomaruFlutterSealed.METHODS) return result.notImplemented()
        offline?.takeIf { it.handles(call.method) }?.let { return it.onMethodCall(call, result) }
        transaction?.takeIf { it.handles(call.method) }?.let { return it.onMethodCall(call, result) }
        if (call.method == "scaffoldInfo") return result.success("sentomaru_flutter:0.0.1")
        core.onMethodCall(FlutterCall(call), FlutterResult(result))
    }

    private class FlutterCall(private val call: MethodCall) : BridgeCall {
        override val method: String get() = call.method
        override fun <T> argument(key: String): T? = call.argument<T>(key)
    }

    private class FlutterResult(private val result: Result) : BridgeResult {
        override fun success(value: Any?) = result.success(value)
        override fun error(code: String, message: String?, details: Any?) = result.error(code, message, details)
        override fun notImplemented() = result.notImplemented()
    }

    /** The helpers of the bridge core under the names this plugin and its tests always had. */
    internal companion object {
        /** D-15c: the EventChannel of [SentomaruSignalEvent]s and [SentomaruServerResponseEvent]s. */
        const val EVENT_CHANNEL = "sentomaru_flutter/signal_events"
        const val NOT_CONFIGURED = SentomaruBridge.NOT_CONFIGURED

        fun signalEventReply(event: SentomaruSignalEvent) = SentomaruBridge.signalEventReply(event)
        fun serverResponseReply(event: SentomaruServerResponseEvent) = SentomaruBridge.serverResponseReply(event)
        fun feedEvents(collector: SignalsCollector, bridge: SignalEventsBridge) = SentomaruBridge.feedEvents(collector, bridge)
        fun signalsCollector(
            rasp: Boolean,
            expectedSignerDigests: List<String>? = null,
            env: PlatformEnvironment = AndroidPlatformEnvironment,
            codeDigests: CodeDigestCache = CodeDigestCache.shared,
        ) = SentomaruBridge.signalsCollector(rasp, expectedSignerDigests, env, codeDigests)
        fun expectedSignerDigests(raw: Any?) = SentomaruBridge.expectedSignerDigests(raw)
        fun reattestationReplyOrError(run: () -> ReattestationOutcome) = SentomaruBridge.reattestationReplyOrError(run)
        fun reattestationReply(outcome: ReattestationOutcome) = SentomaruBridge.reattestationReply(outcome)
        fun snapshotReply(snapshot: SignalsSnapshot) = SentomaruBridge.snapshotReply(snapshot)
        fun reenrollmentReply(client: SentomaruClient) = SentomaruBridge.reenrollmentReply(client)
        fun renewalRefusal(backingOff: Boolean, canRenewNow: Boolean): SentomaruError? =
            SentomaruBridge.renewalRefusal(backingOff, canRenewNow)
        fun refusalDetails(refusal: SentomaruError, lastFailure: String?) = SentomaruBridge.refusalDetails(refusal, lastFailure)
        fun renewalRefusalReply(gate: SentomaruClient.RenewalGate) = SentomaruBridge.renewalRefusalReply(gate)
    }
}
