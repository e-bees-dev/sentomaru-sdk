package br.com.ebees.sentomaru.runtime;

/**
 * State of the injected Sentomaru runtime in the app process (G-03b2). Set at most once by {@link InitProvider}, which
 * Android creates in the app's default process after {@code attachBaseContext} and before {@code Application.onCreate}.
 * Code instrumented later (G-03c) asks {@link #isInitialized()}: when it is false (another process, or a refused
 * configuration) a request on a profile route is not sent (fail closed, contract "Limites conhecidos").
 */
public final class SentomaruRuntime {
    /** Manifest meta-data key the CLI writes inside the provider element (no resources: the contract forbids res/). */
    public static final String ENROLLMENT_URL_KEY = "br.com.ebees.sentomaru.runtime.ENROLLMENT_URL";
    /** Runtime version, equal to the CLI's `cli.runtime.sdk` report field. */
    public static final String VERSION = "runtime-0.1.0";

    private static volatile String enrollmentUrl;

    private SentomaruRuntime() {}

    /** Records an accepted URL (see {@link Bootstrap#decide}); null or a second call changes nothing. Never throws. */
    static synchronized void initialize(String acceptedUrl) {
        if (enrollmentUrl == null && Bootstrap.valid(acceptedUrl)) enrollmentUrl = acceptedUrl;
    }

    public static boolean isInitialized() {
        return enrollmentUrl != null;
    }

    /** The profile's enrollment URL, or null when the runtime was not initialized in this process. */
    public static String enrollmentUrl() {
        return enrollmentUrl;
    }
}
