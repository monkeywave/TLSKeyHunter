package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Wrapper.class */
public interface Wrapper {
    void init(boolean z, CipherParameters cipherParameters);

    String getAlgorithmName();

    byte[] wrap(byte[] bArr, int i, int i2);

    byte[] unwrap(byte[] bArr, int i, int i2) throws InvalidCipherTextException;
}