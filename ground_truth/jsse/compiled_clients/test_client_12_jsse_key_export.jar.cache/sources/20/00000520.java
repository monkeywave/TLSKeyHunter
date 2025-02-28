package org.bouncycastle.crypto.modes.gcm;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/GCMMultiplier.class */
public interface GCMMultiplier {
    void init(byte[] bArr);

    void multiplyH(byte[] bArr);
}