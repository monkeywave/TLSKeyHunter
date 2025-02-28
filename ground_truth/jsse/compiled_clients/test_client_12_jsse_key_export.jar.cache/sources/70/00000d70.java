package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/SeedDerive.class */
class SeedDerive {

    /* renamed from: I */
    private final byte[] f849I;
    private final byte[] masterSeed;
    private final Digest digest;

    /* renamed from: q */
    private int f850q;

    /* renamed from: j */
    private int f851j;

    public SeedDerive(byte[] bArr, byte[] bArr2, Digest digest) {
        this.f849I = bArr;
        this.masterSeed = bArr2;
        this.digest = digest;
    }

    public int getQ() {
        return this.f850q;
    }

    public void setQ(int i) {
        this.f850q = i;
    }

    public int getJ() {
        return this.f851j;
    }

    public void setJ(int i) {
        this.f851j = i;
    }

    public byte[] getI() {
        return this.f849I;
    }

    public byte[] getMasterSeed() {
        return this.masterSeed;
    }

    public byte[] deriveSeed(byte[] bArr, int i) {
        if (bArr.length < this.digest.getDigestSize()) {
            throw new IllegalArgumentException("target length is less than digest size.");
        }
        this.digest.update(this.f849I, 0, this.f849I.length);
        this.digest.update((byte) (this.f850q >>> 24));
        this.digest.update((byte) (this.f850q >>> 16));
        this.digest.update((byte) (this.f850q >>> 8));
        this.digest.update((byte) this.f850q);
        this.digest.update((byte) (this.f851j >>> 8));
        this.digest.update((byte) this.f851j);
        this.digest.update((byte) -1);
        this.digest.update(this.masterSeed, 0, this.masterSeed.length);
        this.digest.doFinal(bArr, i);
        return bArr;
    }

    public void deriveSeed(byte[] bArr, boolean z) {
        deriveSeed(bArr, z, 0);
    }

    public void deriveSeed(byte[] bArr, boolean z, int i) {
        deriveSeed(bArr, i);
        if (z) {
            this.f851j++;
        }
    }
}