package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public interface TlsHeartbeat {
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}