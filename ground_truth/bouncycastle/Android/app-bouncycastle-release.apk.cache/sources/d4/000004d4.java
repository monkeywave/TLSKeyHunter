package androidx.core.app;

import android.app.LocaleManager;
import android.content.Context;
import android.content.res.Configuration;
import android.os.LocaleList;
import androidx.core.p003os.BuildCompat;
import androidx.core.p003os.LocaleListCompat;
import java.util.Locale;

/* loaded from: classes.dex */
public final class LocaleManagerCompat {
    private LocaleManagerCompat() {
    }

    public static LocaleListCompat getSystemLocales(Context context) {
        LocaleListCompat emptyLocaleList = LocaleListCompat.getEmptyLocaleList();
        if (BuildCompat.isAtLeastT()) {
            Object localeManagerForApplication = getLocaleManagerForApplication(context);
            return localeManagerForApplication != null ? LocaleListCompat.wrap(Api33Impl.localeManagerGetSystemLocales(localeManagerForApplication)) : emptyLocaleList;
        }
        return getConfigurationLocales(context.getApplicationContext().getResources().getConfiguration());
    }

    private static Object getLocaleManagerForApplication(Context context) {
        return context.getSystemService("locale");
    }

    static LocaleListCompat getConfigurationLocales(Configuration configuration) {
        return Api24Impl.getLocales(configuration);
    }

    /* loaded from: classes.dex */
    static class Api21Impl {
        private Api21Impl() {
        }

        static String toLanguageTag(Locale locale) {
            return locale.toLanguageTag();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Api24Impl {
        private Api24Impl() {
        }

        static LocaleListCompat getLocales(Configuration configuration) {
            return LocaleListCompat.forLanguageTags(configuration.getLocales().toLanguageTags());
        }
    }

    /* loaded from: classes.dex */
    static class Api33Impl {
        private Api33Impl() {
        }

        static LocaleList localeManagerGetSystemLocales(Object obj) {
            return ((LocaleManager) obj).getSystemLocales();
        }
    }
}