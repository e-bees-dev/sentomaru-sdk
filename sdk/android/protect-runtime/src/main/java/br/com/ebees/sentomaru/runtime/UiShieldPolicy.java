package br.com.ebees.sentomaru.runtime;

import java.util.HashSet;
import java.util.Set;

/**
 * G-10 (`ui-shield`): the decisions of the screen shield, free of Android types so they are tested on the JVM.
 * The CLI writes three provider meta-data values; this reads them back. Nothing here throws: a configuration it cannot
 * read gives {@code null} (no screen is touched) and every protection step runs on its own, so a window that refuses one
 * call still gets the others.
 */
final class UiShieldPolicy {
    static final String MODE_LISTED_ONLY = "listed_only";
    static final String MODE_ALL = "all_activities";
    static final int MAX_ACTIVITIES = 64;
    static final int MAX_NAME_LENGTH = 256;

    final boolean all;
    final Set<String> activities;
    final boolean hideOverlayWindows;

    private UiShieldPolicy(boolean all, Set<String> activities, boolean hideOverlayWindows) {
        this.all = all;
        this.activities = activities;
        this.hideOverlayWindows = hideOverlayWindows;
    }

    /** The calls one screen gets; each is invoked alone inside a try, so one failure never skips another. */
    interface Steps {
        void secureFlag();

        void recentsOff();

        void hideOverlay();

        void filterObscuredTouches();

        void accessibilityDataSensitive();
    }

    /**
     * Reads the meta-data: {@code mode} is {@code listed_only} (then {@code activities} is a non-empty comma list of binary
     * class names) or {@code all_activities} (then it is empty); {@code hideOverlay} is {@code true} or {@code false}.
     * Anything else, a missing value included, is null: the shield stays off rather than guess.
     */
    /**
     * G10-2: a meta-data value as text. The CLI writes strings, and the installed manifest keeps them as strings (proved with
     * aapt2 in {@code UiShieldTest}), but {@code Bundle.getString} answers null for a boolean- or int-typed value, which would
     * leave the shield off with no warning. A boolean is accepted as its text; any other type is null (the shield stays off).
     */
    static String text(Object value) {
        if (value instanceof String) return (String) value;
        if (value instanceof Boolean) return value.toString();
        return null;
    }

    static UiShieldPolicy parse(String mode, String activities, String hideOverlay) {
        try {
            if (mode == null || hideOverlay == null || activities == null) return null;
            boolean hide;
            if ("true".equals(hideOverlay)) hide = true;
            else if ("false".equals(hideOverlay)) hide = false;
            else return null;
            if (MODE_ALL.equals(mode)) return activities.isEmpty() ? new UiShieldPolicy(true, new HashSet<String>(), hide) : null;
            if (!MODE_LISTED_ONLY.equals(mode) || activities.isEmpty()) return null;
            Set<String> names = new HashSet<String>();
            for (String name : activities.split(",", -1)) {
                if (!className(name) || !names.add(name)) return null;
            }
            return names.size() > MAX_ACTIVITIES ? null : new UiShieldPolicy(false, names, hide);
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean className(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_NAME_LENGTH) return false;
        boolean start = true;
        boolean dotted = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '.') {
                if (start) return false;
                start = true;
                dotted = true;
            } else if (start ? Character.isJavaIdentifierStart(c) : Character.isJavaIdentifierPart(c)) {
                start = false;
            } else {
                return false;
            }
        }
        return dotted && !start;
    }

    boolean marks(String className) {
        return all || (className != null && activities.contains(className));
    }

    /** Applies the shield to one screen: nothing for a screen the app did not list (unless the mode is all). */
    void apply(String className, int sdkInt, Steps steps) {
        if (!marks(className)) return;
        safely(steps::secureFlag);
        if (sdkInt >= 33) safely(steps::recentsOff);
        if (hideOverlayWindows && sdkInt >= 31) safely(steps::hideOverlay);
        safely(steps::filterObscuredTouches);
        if (sdkInt >= 34) safely(steps::accessibilityDataSensitive);
    }

    private static void safely(Runnable step) {
        try {
            step.run();
        } catch (Throwable ignored) {
            // one refused call costs only that protection on that screen
        }
    }
}
