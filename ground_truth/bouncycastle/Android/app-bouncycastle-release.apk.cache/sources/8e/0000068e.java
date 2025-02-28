package androidx.core.p003os;

import android.content.Context;
import android.os.UserManager;

/* renamed from: androidx.core.os.UserManagerCompat */
/* loaded from: classes.dex */
public class UserManagerCompat {
    private UserManagerCompat() {
    }

    public static boolean isUserUnlocked(Context context) {
        return Api24Impl.isUserUnlocked(context);
    }

    /* renamed from: androidx.core.os.UserManagerCompat$Api24Impl */
    /* loaded from: classes.dex */
    static class Api24Impl {
        private Api24Impl() {
        }

        static boolean isUserUnlocked(Context context) {
            return ((UserManager) context.getSystemService(UserManager.class)).isUserUnlocked();
        }
    }
}