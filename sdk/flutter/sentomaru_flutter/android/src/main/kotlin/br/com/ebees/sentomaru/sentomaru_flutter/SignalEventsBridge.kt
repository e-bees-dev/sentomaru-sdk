package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.hybrid.SignalEventFeed
import br.com.ebees.sentomaru.signals.SentomaruServerResponseListener
import br.com.ebees.sentomaru.signals.SentomaruSignalEventListener
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import io.flutter.plugin.common.EventChannel
import java.util.concurrent.Executor

/**
 * D-15c: the EventChannel stream handler. While Dart listens there is one [SentomaruSignalEvents] (a NEW one per
 * subscription, so a new listener, a hot restart included, sees the first observation of each capability again) with
 * one listener of each kind, and every event is posted to the sink through [post] (the main looper in the plugin, where
 * the sink must be called). On cancel, or when the engine detaches, the instance is dropped. Informative events only:
 * nothing is decided here, and nothing is kept once Dart stops listening.
 */
internal class SignalEventsBridge(private val post: (Runnable) -> Unit) : EventChannel.StreamHandler, SignalEventFeed {
    private class Subscription(val sink: EventChannel.EventSink, val events: SentomaruSignalEvents)

    @Volatile private var subscription: Subscription? = null

    /** The events instance the collectors feed while Dart listens; null otherwise (no event is built then). */
    override fun current(): SentomaruSignalEvents? = subscription?.events

    @Synchronized
    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        if (events == null) return
        val instance = SentomaruSignalEvents()
        val sub = Subscription(events, instance)
        val executor = Executor { task -> post(task) }
        // A sink of an older subscription never receives: each listener checks it is still the current one on main.
        instance.addListener(executor, SentomaruSignalEventListener { event ->
            if (subscription === sub) sub.sink.success(SentomaruFlutterPlugin.signalEventReply(event))
        })
        instance.addServerResponseListener(executor, SentomaruServerResponseListener { event ->
            if (subscription === sub) sub.sink.success(SentomaruFlutterPlugin.serverResponseReply(event))
        })
        subscription = sub
    }

    @Synchronized
    override fun onCancel(arguments: Any?) {
        subscription = null
    }
}
