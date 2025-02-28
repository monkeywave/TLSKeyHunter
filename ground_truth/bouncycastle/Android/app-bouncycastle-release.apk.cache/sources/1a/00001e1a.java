package org.bouncycastle.crypto.modes.gcm;

/* loaded from: classes2.dex */
public interface GCMExponentiator {
    void exponentiateX(long j, byte[] bArr);

    void init(byte[] bArr);
}