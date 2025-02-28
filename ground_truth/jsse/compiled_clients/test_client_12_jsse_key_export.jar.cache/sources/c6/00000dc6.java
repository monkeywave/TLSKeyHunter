package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SIG_FORS.class */
class SIG_FORS {
    final byte[][] authPath;

    /* renamed from: sk */
    final byte[] f911sk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SIG_FORS(byte[] bArr, byte[][] bArr2) {
        this.authPath = bArr2;
        this.f911sk = bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getSK() {
        return this.f911sk;
    }

    public byte[][] getAuthPath() {
        return this.authPath;
    }
}