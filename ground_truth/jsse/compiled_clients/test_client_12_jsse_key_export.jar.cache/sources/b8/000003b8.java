package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/SignerWithRecovery.class */
public interface SignerWithRecovery extends Signer {
    boolean hasFullMessage();

    byte[] getRecoveredMessage();

    void updateWithRecoveredMessage(byte[] bArr) throws InvalidCipherTextException;
}