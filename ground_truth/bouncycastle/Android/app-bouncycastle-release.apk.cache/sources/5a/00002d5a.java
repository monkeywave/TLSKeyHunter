package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class KeyUpdateRequest {
    public static final short update_not_requested = 0;
    public static final short update_requested = 1;

    public static String getName(short s) {
        return s != 0 ? s != 1 ? "UNKNOWN" : "update_requested" : "update_not_requested";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isValid(short s) {
        return s >= 0 && s <= 1;
    }
}