package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Commitment.class */
public class Commitment {
    private final byte[] secret;
    private final byte[] commitment;

    public Commitment(byte[] bArr, byte[] bArr2) {
        this.secret = bArr;
        this.commitment = bArr2;
    }

    public byte[] getSecret() {
        return this.secret;
    }

    public byte[] getCommitment() {
        return this.commitment;
    }
}