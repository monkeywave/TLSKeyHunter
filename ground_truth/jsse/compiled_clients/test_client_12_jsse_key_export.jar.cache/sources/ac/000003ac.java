package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Mac.class */
public interface Mac {
    void init(CipherParameters cipherParameters) throws IllegalArgumentException;

    String getAlgorithmName();

    int getMacSize();

    void update(byte b) throws IllegalStateException;

    void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException;

    int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException;

    void reset();
}