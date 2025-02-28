package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface AsymmetricBlockCipher {
    int getInputBlockSize();

    int getOutputBlockSize();

    void init(boolean z, CipherParameters cipherParameters);

    byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException;
}