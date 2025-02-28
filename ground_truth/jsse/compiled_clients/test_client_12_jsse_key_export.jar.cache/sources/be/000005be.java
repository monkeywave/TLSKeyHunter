package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/DSAKCalculator.class */
public interface DSAKCalculator {
    boolean isDeterministic();

    void init(BigInteger bigInteger, SecureRandom secureRandom);

    void init(BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr);

    BigInteger nextK();
}