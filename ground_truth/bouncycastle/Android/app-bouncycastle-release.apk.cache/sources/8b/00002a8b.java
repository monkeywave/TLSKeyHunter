package org.bouncycastle.pqc.crypto.slhdsa;

/* loaded from: classes2.dex */
class SIG_FORS {
    final byte[][] authPath;

    /* renamed from: sk */
    final byte[] f1399sk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SIG_FORS(byte[] bArr, byte[][] bArr2) {
        this.authPath = bArr2;
        this.f1399sk = bArr;
    }

    public byte[][] getAuthPath() {
        return this.authPath;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getSK() {
        return this.f1399sk;
    }
}