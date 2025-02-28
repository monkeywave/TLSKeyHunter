package androidx.core.content.p002pm;

import android.content.pm.PermissionInfo;
import android.os.Build;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* renamed from: androidx.core.content.pm.PermissionInfoCompat */
/* loaded from: classes.dex */
public final class PermissionInfoCompat {

    @Retention(RetentionPolicy.SOURCE)
    /* renamed from: androidx.core.content.pm.PermissionInfoCompat$Protection */
    /* loaded from: classes.dex */
    public @interface Protection {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* renamed from: androidx.core.content.pm.PermissionInfoCompat$ProtectionFlags */
    /* loaded from: classes.dex */
    public @interface ProtectionFlags {
    }

    private PermissionInfoCompat() {
    }

    public static int getProtection(PermissionInfo permissionInfo) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getProtection(permissionInfo);
        }
        return permissionInfo.protectionLevel & 15;
    }

    public static int getProtectionFlags(PermissionInfo permissionInfo) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getProtectionFlags(permissionInfo);
        }
        return permissionInfo.protectionLevel & (-16);
    }

    /* renamed from: androidx.core.content.pm.PermissionInfoCompat$Api28Impl */
    /* loaded from: classes.dex */
    static class Api28Impl {
        private Api28Impl() {
        }

        static int getProtection(PermissionInfo permissionInfo) {
            return permissionInfo.getProtection();
        }

        static int getProtectionFlags(PermissionInfo permissionInfo) {
            return permissionInfo.getProtectionFlags();
        }
    }
}