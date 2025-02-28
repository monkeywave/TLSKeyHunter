package org.bouncycastle.crypto.modes.gcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/GCMExponentiator.class */
public interface GCMExponentiator {
    void init(byte[] bArr);

    void exponentiateX(long j, byte[] bArr);
}