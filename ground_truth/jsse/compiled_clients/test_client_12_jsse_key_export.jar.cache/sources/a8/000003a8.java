package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/KeyEncapsulation.class */
public interface KeyEncapsulation {
    void init(CipherParameters cipherParameters);

    CipherParameters encrypt(byte[] bArr, int i, int i2);

    CipherParameters decrypt(byte[] bArr, int i, int i2, int i3);
}