package br.com.ebees.sentomaru.runtime;

import java.net.URI;
import java.util.concurrent.Callable;

/**
 * Initialization decision of the injected runtime, free of Android types so it is tested on the JVM. It never throws:
 * the provider runs on every app start, before {@code Application.onCreate}, and an exception there would crash the
 * app. Anything unexpected (a missing or invalid URL, an exported provider, a failing reader) leaves the runtime not
 * initialized, which the instrumented code treats as fail closed (G-03c).
 */
final class Bootstrap {
    static final int MAX_URL_LENGTH = 2048;

    private Bootstrap() {}

    /** Returns the accepted URL, or null; [exported] or a reader failure is a refusal, never an exception. */
    static String decide(boolean exported, Callable<String> readUrl) {
        try {
            if (exported) return null;
            String url = readUrl.call();
            return valid(url) ? url : null;
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean valid(String url) {
        if (url == null || url.isEmpty() || url.length() > MAX_URL_LENGTH) return false;
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= ' ' || c == 0x7f || Character.isISOControl(c)) return false;
        }
        try {
            URI uri = new URI(url);
            return "https".equals(uri.getScheme()) && uri.getHost() != null && !uri.getHost().isEmpty()
                && uri.getRawUserInfo() == null;
        } catch (Exception e) {
            return false;
        }
    }
}
