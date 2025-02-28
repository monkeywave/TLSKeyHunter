package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/BlockCipher.class */
public interface BlockCipher {
    void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException;

    String getAlgorithmName();

    int getBlockSize();

    int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException;

    void reset();
}