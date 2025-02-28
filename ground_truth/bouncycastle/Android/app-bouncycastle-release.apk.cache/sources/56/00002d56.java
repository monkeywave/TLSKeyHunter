package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class HeartbeatMode {
    public static final short peer_allowed_to_send = 1;
    public static final short peer_not_allowed_to_send = 2;

    public static String getName(short s) {
        return s != 1 ? s != 2 ? "UNKNOWN" : "peer_not_allowed_to_send" : "peer_allowed_to_send";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isValid(short s) {
        return s >= 1 && s <= 2;
    }
}