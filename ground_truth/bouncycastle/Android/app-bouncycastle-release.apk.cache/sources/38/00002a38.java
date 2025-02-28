package org.bouncycastle.pqc.crypto.ntru;

/* loaded from: classes2.dex */
class OWCPAKeyPair {
    public final byte[] privateKey;
    public final byte[] publicKey;

    public OWCPAKeyPair(byte[] bArr, byte[] bArr2) {
        this.publicKey = bArr;
        this.privateKey = bArr2;
    }
}