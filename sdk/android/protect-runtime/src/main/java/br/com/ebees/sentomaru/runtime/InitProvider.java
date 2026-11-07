package br.com.ebees.sentomaru.runtime;

import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

/**
 * Initialization hook declared by `sentomaru protect` in the app manifest: exported=false, default process, no data.
 * The enrollment URL is read from the provider's meta-data through {@code PackageManager.getProviderInfo(...,
 * GET_META_DATA)} (the {@link ProviderInfo} given to attachInfo does not carry meta-data), as androidx.startup does.
 * Nothing here may throw: a failure leaves {@link SentomaruRuntime} not initialized and the app starts normally.
 */
public final class InitProvider extends ContentProvider {
    @Override
    public void attachInfo(final Context context, ProviderInfo info) {
        try {
            super.attachInfo(context, info);
            boolean exported = info != null && info.exported;
            SentomaruRuntime.initialize(Bootstrap.decide(exported, () -> {
                ProviderInfo own = context.getPackageManager().getProviderInfo(
                    new ComponentName(context, InitProvider.class), PackageManager.GET_META_DATA);
                Bundle metaData = own == null ? null : own.metaData;
                return metaData == null ? null : metaData.getString(SentomaruRuntime.ENROLLMENT_URL_KEY);
            }));
            installUiShield(context);
        } catch (Throwable ignored) {
            // Not initialized: instrumented code fails closed; the app itself is never affected.
        }
    }

    /** G-10: the screen shield, only when the CLI wrote its meta-data (a profile without `ui-shield` writes none). */
    @SuppressWarnings("deprecation") // Bundle.get(String): the typed getters answer null for another type, which is the point (G10-2)
    private static void installUiShield(Context context) {
        try {
            ProviderInfo own = context.getPackageManager().getProviderInfo(
                new ComponentName(context, InitProvider.class), PackageManager.GET_META_DATA);
            Bundle meta = own == null ? null : own.metaData;
            if (meta == null || !meta.containsKey(UiShield.MODE_KEY)) return;
            String activities = UiShieldPolicy.text(meta.get(UiShield.ACTIVITIES_KEY));
            UiShieldPolicy policy = UiShieldPolicy.parse(UiShieldPolicy.text(meta.get(UiShield.MODE_KEY)), activities == null ? "" : activities,
                UiShieldPolicy.text(meta.get(UiShield.HIDE_OVERLAY_KEY)));
            android.content.Context app = context.getApplicationContext();
            if (app instanceof android.app.Application) UiShield.install((android.app.Application) app, policy);
        } catch (Throwable ignored) {
            // no shield: the screens are left as the app made them
        }
    }

    @Override public boolean onCreate() { return true; }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override public String getType(Uri uri) { return null; }

    @Override public Uri insert(Uri uri, ContentValues values) { return null; }

    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }

    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
