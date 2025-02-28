package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/RawAgreement.class */
public interface RawAgreement {
    void init(CipherParameters cipherParameters);

    int getAgreementSize();

    void calculateAgreement(CipherParameters cipherParameters, byte[] bArr, int i);
}