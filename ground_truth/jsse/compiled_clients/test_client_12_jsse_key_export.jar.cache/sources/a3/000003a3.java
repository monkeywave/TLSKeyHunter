package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Digest.class */
public interface Digest {
    String getAlgorithmName();

    int getDigestSize();

    void update(byte b);

    void update(byte[] bArr, int i, int i2);

    int doFinal(byte[] bArr, int i);

    void reset();
}