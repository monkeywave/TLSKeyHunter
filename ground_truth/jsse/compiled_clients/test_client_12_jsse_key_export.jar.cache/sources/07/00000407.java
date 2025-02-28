package org.bouncycastle.crypto.digests;

import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/SHA1Digest.class */
public class SHA1Digest extends GeneralDigest implements EncodableDigest {
    private static final int DIGEST_LENGTH = 20;

    /* renamed from: H1 */
    private int f223H1;

    /* renamed from: H2 */
    private int f224H2;

    /* renamed from: H3 */
    private int f225H3;

    /* renamed from: H4 */
    private int f226H4;

    /* renamed from: H5 */
    private int f227H5;

    /* renamed from: X */
    private int[] f228X;
    private int xOff;

    /* renamed from: Y1 */
    private static final int f229Y1 = 1518500249;

    /* renamed from: Y2 */
    private static final int f230Y2 = 1859775393;

    /* renamed from: Y3 */
    private static final int f231Y3 = -1894007588;

    /* renamed from: Y4 */
    private static final int f232Y4 = -899497514;

    public SHA1Digest() {
        this.f228X = new int[80];
        reset();
    }

    public SHA1Digest(SHA1Digest sHA1Digest) {
        super(sHA1Digest);
        this.f228X = new int[80];
        copyIn(sHA1Digest);
    }

    public SHA1Digest(byte[] bArr) {
        super(bArr);
        this.f228X = new int[80];
        this.f223H1 = Pack.bigEndianToInt(bArr, 16);
        this.f224H2 = Pack.bigEndianToInt(bArr, 20);
        this.f225H3 = Pack.bigEndianToInt(bArr, 24);
        this.f226H4 = Pack.bigEndianToInt(bArr, 28);
        this.f227H5 = Pack.bigEndianToInt(bArr, 32);
        this.xOff = Pack.bigEndianToInt(bArr, 36);
        for (int i = 0; i != this.xOff; i++) {
            this.f228X[i] = Pack.bigEndianToInt(bArr, 40 + (i * 4));
        }
    }

    private void copyIn(SHA1Digest sHA1Digest) {
        this.f223H1 = sHA1Digest.f223H1;
        this.f224H2 = sHA1Digest.f224H2;
        this.f225H3 = sHA1Digest.f225H3;
        this.f226H4 = sHA1Digest.f226H4;
        this.f227H5 = sHA1Digest.f227H5;
        System.arraycopy(sHA1Digest.f228X, 0, this.f228X, 0, sHA1Digest.f228X.length);
        this.xOff = sHA1Digest.xOff;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return McElieceCCA2KeyGenParameterSpec.SHA1;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 20;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        this.f228X[this.xOff] = (bArr[i] << 24) | ((bArr[i2] & 255) << 16) | ((bArr[i3] & 255) << 8) | (bArr[i3 + 1] & 255);
        int i4 = this.xOff + 1;
        this.xOff = i4;
        if (i4 == 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        this.f228X[14] = (int) (j >>> 32);
        this.f228X[15] = (int) j;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToBigEndian(this.f223H1, bArr, i);
        Pack.intToBigEndian(this.f224H2, bArr, i + 4);
        Pack.intToBigEndian(this.f225H3, bArr, i + 8);
        Pack.intToBigEndian(this.f226H4, bArr, i + 12);
        Pack.intToBigEndian(this.f227H5, bArr, i + 16);
        reset();
        return 20;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f223H1 = 1732584193;
        this.f224H2 = -271733879;
        this.f225H3 = -1732584194;
        this.f226H4 = 271733878;
        this.f227H5 = -1009589776;
        this.xOff = 0;
        for (int i = 0; i != this.f228X.length; i++) {
            this.f228X[i] = 0;
        }
    }

    /* renamed from: f */
    private int m73f(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: h */
    private int m71h(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: g */
    private int m72g(int i, int i2, int i3) {
        return (i & i2) | (i & i3) | (i2 & i3);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        for (int i = 16; i < 80; i++) {
            int i2 = ((this.f228X[i - 3] ^ this.f228X[i - 8]) ^ this.f228X[i - 14]) ^ this.f228X[i - 16];
            this.f228X[i] = (i2 << 1) | (i2 >>> 31);
        }
        int i3 = this.f223H1;
        int i4 = this.f224H2;
        int i5 = this.f225H3;
        int i6 = this.f226H4;
        int i7 = this.f227H5;
        int i8 = 0;
        for (int i9 = 0; i9 < 4; i9++) {
            int i10 = i8;
            int i11 = i8 + 1;
            int m73f = i7 + ((i3 << 5) | (i3 >>> 27)) + m73f(i4, i5, i6) + this.f228X[i10] + f229Y1;
            int i12 = (i4 << 30) | (i4 >>> 2);
            int i13 = i11 + 1;
            int m73f2 = i6 + ((m73f << 5) | (m73f >>> 27)) + m73f(i3, i12, i5) + this.f228X[i11] + f229Y1;
            int i14 = (i3 << 30) | (i3 >>> 2);
            int i15 = i13 + 1;
            int m73f3 = i5 + ((m73f2 << 5) | (m73f2 >>> 27)) + m73f(m73f, i14, i12) + this.f228X[i13] + f229Y1;
            i7 = (m73f << 30) | (m73f >>> 2);
            int i16 = i15 + 1;
            i4 = i12 + ((m73f3 << 5) | (m73f3 >>> 27)) + m73f(m73f2, i7, i14) + this.f228X[i15] + f229Y1;
            i6 = (m73f2 << 30) | (m73f2 >>> 2);
            i8 = i16 + 1;
            i3 = i14 + ((i4 << 5) | (i4 >>> 27)) + m73f(m73f3, i6, i7) + this.f228X[i16] + f229Y1;
            i5 = (m73f3 << 30) | (m73f3 >>> 2);
        }
        for (int i17 = 0; i17 < 4; i17++) {
            int i18 = i8;
            int i19 = i8 + 1;
            int m71h = i7 + ((i3 << 5) | (i3 >>> 27)) + m71h(i4, i5, i6) + this.f228X[i18] + f230Y2;
            int i20 = (i4 << 30) | (i4 >>> 2);
            int i21 = i19 + 1;
            int m71h2 = i6 + ((m71h << 5) | (m71h >>> 27)) + m71h(i3, i20, i5) + this.f228X[i19] + f230Y2;
            int i22 = (i3 << 30) | (i3 >>> 2);
            int i23 = i21 + 1;
            int m71h3 = i5 + ((m71h2 << 5) | (m71h2 >>> 27)) + m71h(m71h, i22, i20) + this.f228X[i21] + f230Y2;
            i7 = (m71h << 30) | (m71h >>> 2);
            int i24 = i23 + 1;
            i4 = i20 + ((m71h3 << 5) | (m71h3 >>> 27)) + m71h(m71h2, i7, i22) + this.f228X[i23] + f230Y2;
            i6 = (m71h2 << 30) | (m71h2 >>> 2);
            i8 = i24 + 1;
            i3 = i22 + ((i4 << 5) | (i4 >>> 27)) + m71h(m71h3, i6, i7) + this.f228X[i24] + f230Y2;
            i5 = (m71h3 << 30) | (m71h3 >>> 2);
        }
        for (int i25 = 0; i25 < 4; i25++) {
            int i26 = i8;
            int i27 = i8 + 1;
            int m72g = i7 + ((i3 << 5) | (i3 >>> 27)) + m72g(i4, i5, i6) + this.f228X[i26] + f231Y3;
            int i28 = (i4 << 30) | (i4 >>> 2);
            int i29 = i27 + 1;
            int m72g2 = i6 + ((m72g << 5) | (m72g >>> 27)) + m72g(i3, i28, i5) + this.f228X[i27] + f231Y3;
            int i30 = (i3 << 30) | (i3 >>> 2);
            int i31 = i29 + 1;
            int m72g3 = i5 + ((m72g2 << 5) | (m72g2 >>> 27)) + m72g(m72g, i30, i28) + this.f228X[i29] + f231Y3;
            i7 = (m72g << 30) | (m72g >>> 2);
            int i32 = i31 + 1;
            i4 = i28 + ((m72g3 << 5) | (m72g3 >>> 27)) + m72g(m72g2, i7, i30) + this.f228X[i31] + f231Y3;
            i6 = (m72g2 << 30) | (m72g2 >>> 2);
            i8 = i32 + 1;
            i3 = i30 + ((i4 << 5) | (i4 >>> 27)) + m72g(m72g3, i6, i7) + this.f228X[i32] + f231Y3;
            i5 = (m72g3 << 30) | (m72g3 >>> 2);
        }
        for (int i33 = 0; i33 <= 3; i33++) {
            int i34 = i8;
            int i35 = i8 + 1;
            int m71h4 = i7 + ((i3 << 5) | (i3 >>> 27)) + m71h(i4, i5, i6) + this.f228X[i34] + f232Y4;
            int i36 = (i4 << 30) | (i4 >>> 2);
            int i37 = i35 + 1;
            int m71h5 = i6 + ((m71h4 << 5) | (m71h4 >>> 27)) + m71h(i3, i36, i5) + this.f228X[i35] + f232Y4;
            int i38 = (i3 << 30) | (i3 >>> 2);
            int i39 = i37 + 1;
            int m71h6 = i5 + ((m71h5 << 5) | (m71h5 >>> 27)) + m71h(m71h4, i38, i36) + this.f228X[i37] + f232Y4;
            i7 = (m71h4 << 30) | (m71h4 >>> 2);
            int i40 = i39 + 1;
            i4 = i36 + ((m71h6 << 5) | (m71h6 >>> 27)) + m71h(m71h5, i7, i38) + this.f228X[i39] + f232Y4;
            i6 = (m71h5 << 30) | (m71h5 >>> 2);
            i8 = i40 + 1;
            i3 = i38 + ((i4 << 5) | (i4 >>> 27)) + m71h(m71h6, i6, i7) + this.f228X[i40] + f232Y4;
            i5 = (m71h6 << 30) | (m71h6 >>> 2);
        }
        this.f223H1 += i3;
        this.f224H2 += i4;
        this.f225H3 += i5;
        this.f226H4 += i6;
        this.f227H5 += i7;
        this.xOff = 0;
        for (int i41 = 0; i41 < 16; i41++) {
            this.f228X[i41] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA1Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        SHA1Digest sHA1Digest = (SHA1Digest) memoable;
        super.copyIn((GeneralDigest) sHA1Digest);
        copyIn(sHA1Digest);
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        byte[] bArr = new byte[40 + (this.xOff * 4)];
        super.populateState(bArr);
        Pack.intToBigEndian(this.f223H1, bArr, 16);
        Pack.intToBigEndian(this.f224H2, bArr, 20);
        Pack.intToBigEndian(this.f225H3, bArr, 24);
        Pack.intToBigEndian(this.f226H4, bArr, 28);
        Pack.intToBigEndian(this.f227H5, bArr, 32);
        Pack.intToBigEndian(this.xOff, bArr, 36);
        for (int i = 0; i != this.xOff; i++) {
            Pack.intToBigEndian(this.f228X[i], bArr, 40 + (i * 4));
        }
        return bArr;
    }
}