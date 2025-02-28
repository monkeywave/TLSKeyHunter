package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/DerivationFunction.class */
public interface DerivationFunction {
    void init(DerivationParameters derivationParameters);

    int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException;
}