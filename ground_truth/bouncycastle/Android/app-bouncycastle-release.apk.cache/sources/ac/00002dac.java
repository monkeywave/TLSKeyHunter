package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public interface TlsPSKIdentityManager {
    byte[] getHint();

    byte[] getPSK(byte[] bArr);
}