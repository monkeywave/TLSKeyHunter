package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Signer.class */
public interface Signer {
    void init(boolean z, CipherParameters cipherParameters);

    void update(byte b);

    void update(byte[] bArr, int i, int i2);

    byte[] generateSignature() throws CryptoException, DataLengthException;

    boolean verifySignature(byte[] bArr);

    void reset();
}