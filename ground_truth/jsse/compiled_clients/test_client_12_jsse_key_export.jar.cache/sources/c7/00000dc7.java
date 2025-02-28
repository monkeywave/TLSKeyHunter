package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SIG_XMSS.class */
class SIG_XMSS {
    final byte[] sig;
    final byte[][] auth;

    public SIG_XMSS(byte[] bArr, byte[][] bArr2) {
        this.sig = bArr;
        this.auth = bArr2;
    }

    public byte[] getWOTSSig() {
        return this.sig;
    }

    public byte[][] getXMSSAUTH() {
        return this.auth;
    }
}