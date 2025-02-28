package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class HeartbeatMessageType {
    public static final short heartbeat_request = 1;
    public static final short heartbeat_response = 2;

    public static String getName(short s) {
        return s != 1 ? s != 2 ? "UNKNOWN" : "heartbeat_response" : "heartbeat_request";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isValid(short s) {
        return s >= 1 && s <= 2;
    }
}