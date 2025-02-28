package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Committer.class */
public interface Committer {
    Commitment commit(byte[] bArr);

    boolean isRevealed(Commitment commitment, byte[] bArr);
}