package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/MessageSigner.class */
public interface MessageSigner {
    void init(boolean z, CipherParameters cipherParameters);

    byte[] generateSignature(byte[] bArr);

    boolean verifySignature(byte[] bArr, byte[] bArr2);
}