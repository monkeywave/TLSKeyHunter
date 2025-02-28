package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SIG.class */
class SIG {

    /* renamed from: r */
    private final byte[] f910r;
    private final SIG_FORS[] sig_fors;
    private final SIG_XMSS[] sig_ht;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v19, types: [byte[], byte[][]] */
    /* JADX WARN: Type inference failed for: r0v34, types: [byte[], byte[][]] */
    public SIG(int i, int i2, int i3, int i4, int i5, int i6, byte[] bArr) {
        this.f910r = new byte[i];
        System.arraycopy(bArr, 0, this.f910r, 0, i);
        this.sig_fors = new SIG_FORS[i2];
        int i7 = i;
        for (int i8 = 0; i8 != i2; i8++) {
            byte[] bArr2 = new byte[i];
            System.arraycopy(bArr, i7, bArr2, 0, i);
            i7 += i;
            ?? r0 = new byte[i3];
            for (int i9 = 0; i9 != i3; i9++) {
                r0[i9] = new byte[i];
                System.arraycopy(bArr, i7, r0[i9], 0, i);
                i7 += i;
            }
            this.sig_fors[i8] = new SIG_FORS(bArr2, r0);
        }
        this.sig_ht = new SIG_XMSS[i4];
        for (int i10 = 0; i10 != i4; i10++) {
            byte[] bArr3 = new byte[i6 * i];
            System.arraycopy(bArr, i7, bArr3, 0, bArr3.length);
            i7 += bArr3.length;
            ?? r02 = new byte[i5];
            for (int i11 = 0; i11 != i5; i11++) {
                r02[i11] = new byte[i];
                System.arraycopy(bArr, i7, r02[i11], 0, i);
                i7 += i;
            }
            this.sig_ht[i10] = new SIG_XMSS(bArr3, r02);
        }
        if (i7 != bArr.length) {
            throw new IllegalArgumentException("signature wrong length");
        }
    }

    public byte[] getR() {
        return this.f910r;
    }

    public SIG_FORS[] getSIG_FORS() {
        return this.sig_fors;
    }

    public SIG_XMSS[] getSIG_HT() {
        return this.sig_ht;
    }
}