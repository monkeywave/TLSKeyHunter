package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/SM3Digest.class */
public class SM3Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 32;
    private static final int BLOCK_SIZE = 16;

    /* renamed from: V */
    private int[] f253V;
    private int[] inwords;
    private int xOff;

    /* renamed from: W */
    private int[] f254W;

    /* renamed from: T */
    private static final int[] f255T = new int[64];

    public SM3Digest() {
        this.f253V = new int[8];
        this.inwords = new int[16];
        this.f254W = new int[68];
        reset();
    }

    public SM3Digest(SM3Digest sM3Digest) {
        super(sM3Digest);
        this.f253V = new int[8];
        this.inwords = new int[16];
        this.f254W = new int[68];
        copyIn(sM3Digest);
    }

    private void copyIn(SM3Digest sM3Digest) {
        System.arraycopy(sM3Digest.f253V, 0, this.f253V, 0, this.f253V.length);
        System.arraycopy(sM3Digest.inwords, 0, this.inwords, 0, this.inwords.length);
        this.xOff = sM3Digest.xOff;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "SM3";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SM3Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        SM3Digest sM3Digest = (SM3Digest) memoable;
        super.copyIn((GeneralDigest) sM3Digest);
        copyIn(sM3Digest);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f253V[0] = 1937774191;
        this.f253V[1] = 1226093241;
        this.f253V[2] = 388252375;
        this.f253V[3] = -628488704;
        this.f253V[4] = -1452330820;
        this.f253V[5] = 372324522;
        this.f253V[6] = -477237683;
        this.f253V[7] = -1325724082;
        this.xOff = 0;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToBigEndian(this.f253V, bArr, i);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        this.inwords[this.xOff] = ((bArr[i] & 255) << 24) | ((bArr[i2] & 255) << 16) | ((bArr[i3] & 255) << 8) | (bArr[i3 + 1] & 255);
        this.xOff++;
        if (this.xOff >= 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            this.inwords[this.xOff] = 0;
            this.xOff++;
            processBlock();
        }
        while (this.xOff < 14) {
            this.inwords[this.xOff] = 0;
            this.xOff++;
        }
        int[] iArr = this.inwords;
        int i = this.xOff;
        this.xOff = i + 1;
        iArr[i] = (int) (j >>> 32);
        int[] iArr2 = this.inwords;
        int i2 = this.xOff;
        this.xOff = i2 + 1;
        iArr2[i2] = (int) j;
    }

    /* renamed from: P0 */
    private int m68P0(int i) {
        return (i ^ ((i << 9) | (i >>> 23))) ^ ((i << 17) | (i >>> 15));
    }

    /* renamed from: P1 */
    private int m67P1(int i) {
        return (i ^ ((i << 15) | (i >>> 17))) ^ ((i << 23) | (i >>> 9));
    }

    private int FF0(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    private int FF1(int i, int i2, int i3) {
        return (i & i2) | (i & i3) | (i2 & i3);
    }

    private int GG0(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    private int GG1(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        for (int i = 0; i < 16; i++) {
            this.f254W[i] = this.inwords[i];
        }
        for (int i2 = 16; i2 < 68; i2++) {
            int i3 = this.f254W[i2 - 3];
            int i4 = (i3 << 15) | (i3 >>> 17);
            int i5 = this.f254W[i2 - 13];
            this.f254W[i2] = (m67P1((this.f254W[i2 - 16] ^ this.f254W[i2 - 9]) ^ i4) ^ ((i5 << 7) | (i5 >>> 25))) ^ this.f254W[i2 - 6];
        }
        int i6 = this.f253V[0];
        int i7 = this.f253V[1];
        int i8 = this.f253V[2];
        int i9 = this.f253V[3];
        int i10 = this.f253V[4];
        int i11 = this.f253V[5];
        int i12 = this.f253V[6];
        int i13 = this.f253V[7];
        for (int i14 = 0; i14 < 16; i14++) {
            int i15 = (i6 << 12) | (i6 >>> 20);
            int i16 = i15 + i10 + f255T[i14];
            int i17 = (i16 << 7) | (i16 >>> 25);
            int i18 = i17 ^ i15;
            int i19 = this.f254W[i14];
            int FF0 = FF0(i6, i7, i8) + i9 + i18 + (i19 ^ this.f254W[i14 + 4]);
            int GG0 = GG0(i10, i11, i12) + i13 + i17 + i19;
            i9 = i8;
            i8 = (i7 << 9) | (i7 >>> 23);
            i7 = i6;
            i6 = FF0;
            i13 = i12;
            i12 = (i11 << 19) | (i11 >>> 13);
            i11 = i10;
            i10 = m68P0(GG0);
        }
        for (int i20 = 16; i20 < 64; i20++) {
            int i21 = (i6 << 12) | (i6 >>> 20);
            int i22 = i21 + i10 + f255T[i20];
            int i23 = (i22 << 7) | (i22 >>> 25);
            int i24 = i23 ^ i21;
            int i25 = this.f254W[i20];
            int FF1 = FF1(i6, i7, i8) + i9 + i24 + (i25 ^ this.f254W[i20 + 4]);
            int GG1 = GG1(i10, i11, i12) + i13 + i23 + i25;
            i9 = i8;
            i8 = (i7 << 9) | (i7 >>> 23);
            i7 = i6;
            i6 = FF1;
            i13 = i12;
            i12 = (i11 << 19) | (i11 >>> 13);
            i11 = i10;
            i10 = m68P0(GG1);
        }
        int[] iArr = this.f253V;
        iArr[0] = iArr[0] ^ i6;
        int[] iArr2 = this.f253V;
        iArr2[1] = iArr2[1] ^ i7;
        int[] iArr3 = this.f253V;
        iArr3[2] = iArr3[2] ^ i8;
        int[] iArr4 = this.f253V;
        iArr4[3] = iArr4[3] ^ i9;
        int[] iArr5 = this.f253V;
        iArr5[4] = iArr5[4] ^ i10;
        int[] iArr6 = this.f253V;
        iArr6[5] = iArr6[5] ^ i11;
        int[] iArr7 = this.f253V;
        iArr7[6] = iArr7[6] ^ i12;
        int[] iArr8 = this.f253V;
        iArr8[7] = iArr8[7] ^ i13;
        this.xOff = 0;
    }

    static {
        for (int i = 0; i < 16; i++) {
            f255T[i] = (2043430169 << i) | (2043430169 >>> (32 - i));
        }
        for (int i2 = 16; i2 < 64; i2++) {
            int i3 = i2 % 32;
            f255T[i2] = (2055708042 << i3) | (2055708042 >>> (32 - i3));
        }
    }
}