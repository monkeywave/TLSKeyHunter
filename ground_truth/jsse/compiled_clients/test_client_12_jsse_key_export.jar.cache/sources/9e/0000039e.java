package org.bouncycastle.crypto;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/DSA.class */
public interface DSA {
    void init(boolean z, CipherParameters cipherParameters);

    BigInteger[] generateSignature(byte[] bArr);

    boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2);
}