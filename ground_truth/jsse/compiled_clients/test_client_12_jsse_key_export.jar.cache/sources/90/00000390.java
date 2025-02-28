package org.bouncycastle.crypto;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/BasicAgreement.class */
public interface BasicAgreement {
    void init(CipherParameters cipherParameters);

    int getFieldSize();

    BigInteger calculateAgreement(CipherParameters cipherParameters);
}