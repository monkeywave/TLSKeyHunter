package androidx.core.p003os;

import android.os.Environment;
import java.io.File;

/* renamed from: androidx.core.os.EnvironmentCompat */
/* loaded from: classes.dex */
public final class EnvironmentCompat {
    public static final String MEDIA_UNKNOWN = "unknown";
    private static final String TAG = "EnvironmentCompat";

    public static String getStorageState(File file) {
        return Api21Impl.getExternalStorageState(file);
    }

    private EnvironmentCompat() {
    }

    /* renamed from: androidx.core.os.EnvironmentCompat$Api21Impl */
    /* loaded from: classes.dex */
    static class Api21Impl {
        private Api21Impl() {
        }

        static String getExternalStorageState(File file) {
            return Environment.getExternalStorageState(file);
        }
    }

    /* renamed from: androidx.core.os.EnvironmentCompat$Api19Impl */
    /* loaded from: classes.dex */
    static class Api19Impl {
        private Api19Impl() {
        }

        static String getStorageState(File file) {
            return Environment.getStorageState(file);
        }
    }
}