package br.com.ebees.sentomaru.runtime;

import android.app.Activity;
import android.app.Application;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;

/**
 * G-10 (`ui-shield`): installs the screen shield the CLI configured, from {@link InitProvider}. It rides on the activity
 * lifecycle instead of rewriting each target's {@code onCreate}: the flags are set in {@code onActivityStarted}, before the
 * first frame, on the screens the profile lists (or on all of them under {@code all_activities}). The calls are the public
 * ones: {@code FLAG_SECURE}, {@code Activity.setRecentsScreenshotEnabled(false)} (API 33), {@code Window.setHideOverlayWindows}
 * (API 31, permission {@code HIDE_OVERLAY_WINDOWS}, which the CLI declares when the profile asks), {@code
 * View.setFilterTouchesWhenObscured} and {@code View.setAccessibilityDataSensitive} (API 34). It changes how the app
 * behaves: a protected screen cannot be captured, its recents thumbnail is blank, and a service that reads the screen sees
 * it marked sensitive. It does not stop an external camera, a hook, or a memory read.
 * <p>
 * Limit (G10-1): every call acts on the Activity's own window. A {@code Dialog}, {@code DialogFragment}, bottom sheet or
 * {@code PopupWindow} opens a window of its own that does not carry these flags, so what the user types there (a PIN in a
 * dialog) stays capturable unless the app sets {@code FLAG_SECURE} on that window itself.
 */
final class UiShield {
    /** Provider meta-data written by the CLI; no resources are used (the contract forbids res/). */
    static final String MODE_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_MODE";
    static final String ACTIVITIES_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_ACTIVITIES";
    static final String HIDE_OVERLAY_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_HIDE_OVERLAY";

    private static boolean installed;

    private UiShield() {}

    /** Installs once; a null policy (no meta-data, or a refused one) leaves every screen alone. Never throws. */
    static synchronized void install(Application application, final UiShieldPolicy policy) {
        if (installed || application == null || policy == null) return;
        installed = true;
        try {
            application.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
                @Override public void onActivityStarted(final Activity activity) {
                    try {
                        policy.apply(activity.getClass().getName(), Build.VERSION.SDK_INT, new Android(activity, policy));
                    } catch (Throwable ignored) {
                        // the app itself is never affected
                    }
                }

                @Override public void onActivityCreated(Activity activity, Bundle savedInstanceState) {}

                @Override public void onActivityResumed(Activity activity) {}

                @Override public void onActivityPaused(Activity activity) {}

                @Override public void onActivityStopped(Activity activity) {}

                @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}

                @Override public void onActivityDestroyed(Activity activity) {}
            });
        } catch (Throwable ignored) {
            installed = false;
        }
    }

    private static final class Android implements UiShieldPolicy.Steps {
        private final Activity activity;
        private final UiShieldPolicy policy;

        Android(Activity activity, UiShieldPolicy policy) {
            this.activity = activity;
            this.policy = policy;
        }

        @Override public void secureFlag() {
            activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }

        @Override public void recentsOff() {
            activity.setRecentsScreenshotEnabled(false);
        }

        @Override public void hideOverlay() {
            if (policy.hideOverlayWindows) activity.getWindow().setHideOverlayWindows(true);
        }

        @Override public void filterObscuredTouches() {
            activity.getWindow().getDecorView().setFilterTouchesWhenObscured(true);
        }

        @Override public void accessibilityDataSensitive() {
            activity.getWindow().getDecorView().setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
        }
    }
}
