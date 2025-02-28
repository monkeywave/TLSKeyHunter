package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface BlockCipher {
    String getAlgorithmName();

    int getBlockSize();

    void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException;

    int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException;

    void reset();
}