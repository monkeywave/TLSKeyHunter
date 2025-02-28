package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/AsymmetricBlockCipher.class */
public interface AsymmetricBlockCipher {
    void init(boolean z, CipherParameters cipherParameters);

    int getInputBlockSize();

    int getOutputBlockSize();

    byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException;
}