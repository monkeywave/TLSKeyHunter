package org.bouncycastle.crypto.digests;

import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/SHA224Digest.class */
public class SHA224Digest extends GeneralDigest implements EncodableDigest {
    private static final int DIGEST_LENGTH = 28;

    /* renamed from: H1 */
    private int f233H1;

    /* renamed from: H2 */
    private int f234H2;

    /* renamed from: H3 */
    private int f235H3;

    /* renamed from: H4 */
    private int f236H4;

    /* renamed from: H5 */
    private int f237H5;

    /* renamed from: H6 */
    private int f238H6;

    /* renamed from: H7 */
    private int f239H7;

    /* renamed from: H8 */
    private int f240H8;

    /* renamed from: X */
    private int[] f241X;
    private int xOff;

    /* renamed from: K */
    static final int[] f242K = {1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998};

    public SHA224Digest() {
        this.f241X = new int[64];
        reset();
    }

    public SHA224Digest(SHA224Digest sHA224Digest) {
        super(sHA224Digest);
        this.f241X = new int[64];
        doCopy(sHA224Digest);
    }

    private void doCopy(SHA224Digest sHA224Digest) {
        super.copyIn(sHA224Digest);
        this.f233H1 = sHA224Digest.f233H1;
        this.f234H2 = sHA224Digest.f234H2;
        this.f235H3 = sHA224Digest.f235H3;
        this.f236H4 = sHA224Digest.f236H4;
        this.f237H5 = sHA224Digest.f237H5;
        this.f238H6 = sHA224Digest.f238H6;
        this.f239H7 = sHA224Digest.f239H7;
        this.f240H8 = sHA224Digest.f240H8;
        System.arraycopy(sHA224Digest.f241X, 0, this.f241X, 0, sHA224Digest.f241X.length);
        this.xOff = sHA224Digest.xOff;
    }

    public SHA224Digest(byte[] bArr) {
        super(bArr);
        this.f241X = new int[64];
        this.f233H1 = Pack.bigEndianToInt(bArr, 16);
        this.f234H2 = Pack.bigEndianToInt(bArr, 20);
        this.f235H3 = Pack.bigEndianToInt(bArr, 24);
        this.f236H4 = Pack.bigEndianToInt(bArr, 28);
        this.f237H5 = Pack.bigEndianToInt(bArr, 32);
        this.f238H6 = Pack.bigEndianToInt(bArr, 36);
        this.f239H7 = Pack.bigEndianToInt(bArr, 40);
        this.f240H8 = Pack.bigEndianToInt(bArr, 44);
        this.xOff = Pack.bigEndianToInt(bArr, 48);
        for (int i = 0; i != this.xOff; i++) {
            this.f241X[i] = Pack.bigEndianToInt(bArr, 52 + (i * 4));
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return McElieceCCA2KeyGenParameterSpec.SHA224;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 28;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        this.f241X[this.xOff] = (bArr[i] << 24) | ((bArr[i2] & 255) << 16) | ((bArr[i3] & 255) << 8) | (bArr[i3 + 1] & 255);
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
        this.f241X[14] = (int) (j >>> 32);
        this.f241X[15] = (int) (j & (-1));
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToBigEndian(this.f233H1, bArr, i);
        Pack.intToBigEndian(this.f234H2, bArr, i + 4);
        Pack.intToBigEndian(this.f235H3, bArr, i + 8);
        Pack.intToBigEndian(this.f236H4, bArr, i + 12);
        Pack.intToBigEndian(this.f237H5, bArr, i + 16);
        Pack.intToBigEndian(this.f238H6, bArr, i + 20);
        Pack.intToBigEndian(this.f239H7, bArr, i + 24);
        reset();
        return 28;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f233H1 = -1056596264;
        this.f234H2 = 914150663;
        this.f235H3 = 812702999;
        this.f236H4 = -150054599;
        this.f237H5 = -4191439;
        this.f238H6 = 1750603025;
        this.f239H7 = 1694076839;
        this.f240H8 = -1090891868;
        this.xOff = 0;
        for (int i = 0; i != this.f241X.length; i++) {
            this.f241X[i] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        for (int i = 16; i <= 63; i++) {
            this.f241X[i] = Theta1(this.f241X[i - 2]) + this.f241X[i - 7] + Theta0(this.f241X[i - 15]) + this.f241X[i - 16];
        }
        int i2 = this.f233H1;
        int i3 = this.f234H2;
        int i4 = this.f235H3;
        int i5 = this.f236H4;
        int i6 = this.f237H5;
        int i7 = this.f238H6;
        int i8 = this.f239H7;
        int i9 = this.f240H8;
        int i10 = 0;
        for (int i11 = 0; i11 < 8; i11++) {
            int Sum1 = i9 + Sum1(i6) + m70Ch(i6, i7, i8) + f242K[i10] + this.f241X[i10];
            int i12 = i5 + Sum1;
            int Sum0 = Sum1 + Sum0(i2) + Maj(i2, i3, i4);
            int i13 = i10 + 1;
            int Sum12 = i8 + Sum1(i12) + m70Ch(i12, i6, i7) + f242K[i13] + this.f241X[i13];
            int i14 = i4 + Sum12;
            int Sum02 = Sum12 + Sum0(Sum0) + Maj(Sum0, i2, i3);
            int i15 = i13 + 1;
            int Sum13 = i7 + Sum1(i14) + m70Ch(i14, i12, i6) + f242K[i15] + this.f241X[i15];
            int i16 = i3 + Sum13;
            int Sum03 = Sum13 + Sum0(Sum02) + Maj(Sum02, Sum0, i2);
            int i17 = i15 + 1;
            int Sum14 = i6 + Sum1(i16) + m70Ch(i16, i14, i12) + f242K[i17] + this.f241X[i17];
            int i18 = i2 + Sum14;
            int Sum04 = Sum14 + Sum0(Sum03) + Maj(Sum03, Sum02, Sum0);
            int i19 = i17 + 1;
            int Sum15 = i12 + Sum1(i18) + m70Ch(i18, i16, i14) + f242K[i19] + this.f241X[i19];
            i9 = Sum0 + Sum15;
            i5 = Sum15 + Sum0(Sum04) + Maj(Sum04, Sum03, Sum02);
            int i20 = i19 + 1;
            int Sum16 = i14 + Sum1(i9) + m70Ch(i9, i18, i16) + f242K[i20] + this.f241X[i20];
            i8 = Sum02 + Sum16;
            i4 = Sum16 + Sum0(i5) + Maj(i5, Sum04, Sum03);
            int i21 = i20 + 1;
            int Sum17 = i16 + Sum1(i8) + m70Ch(i8, i9, i18) + f242K[i21] + this.f241X[i21];
            i7 = Sum03 + Sum17;
            i3 = Sum17 + Sum0(i4) + Maj(i4, i5, Sum04);
            int i22 = i21 + 1;
            int Sum18 = i18 + Sum1(i7) + m70Ch(i7, i8, i9) + f242K[i22] + this.f241X[i22];
            i6 = Sum04 + Sum18;
            i2 = Sum18 + Sum0(i3) + Maj(i3, i4, i5);
            i10 = i22 + 1;
        }
        this.f233H1 += i2;
        this.f234H2 += i3;
        this.f235H3 += i4;
        this.f236H4 += i5;
        this.f237H5 += i6;
        this.f238H6 += i7;
        this.f239H7 += i8;
        this.f240H8 += i9;
        this.xOff = 0;
        for (int i23 = 0; i23 < 16; i23++) {
            this.f241X[i23] = 0;
        }
    }

    /* renamed from: Ch */
    private int m70Ch(int i, int i2, int i3) {
        return (i & i2) ^ ((i ^ (-1)) & i3);
    }

    private int Maj(int i, int i2, int i3) {
        return ((i & i2) ^ (i & i3)) ^ (i2 & i3);
    }

    private int Sum0(int i) {
        return (((i >>> 2) | (i << 30)) ^ ((i >>> 13) | (i << 19))) ^ ((i >>> 22) | (i << 10));
    }

    private int Sum1(int i) {
        return (((i >>> 6) | (i << 26)) ^ ((i >>> 11) | (i << 21))) ^ ((i >>> 25) | (i << 7));
    }

    private int Theta0(int i) {
        return (((i >>> 7) | (i << 25)) ^ ((i >>> 18) | (i << 14))) ^ (i >>> 3);
    }

    private int Theta1(int i) {
        return (((i >>> 17) | (i << 15)) ^ ((i >>> 19) | (i << 13))) ^ (i >>> 10);
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA224Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        doCopy((SHA224Digest) memoable);
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        byte[] bArr = new byte[52 + (this.xOff * 4)];
        super.populateState(bArr);
        Pack.intToBigEndian(this.f233H1, bArr, 16);
        Pack.intToBigEndian(this.f234H2, bArr, 20);
        Pack.intToBigEndian(this.f235H3, bArr, 24);
        Pack.intToBigEndian(this.f236H4, bArr, 28);
        Pack.intToBigEndian(this.f237H5, bArr, 32);
        Pack.intToBigEndian(this.f238H6, bArr, 36);
        Pack.intToBigEndian(this.f239H7, bArr, 40);
        Pack.intToBigEndian(this.f240H8, bArr, 44);
        Pack.intToBigEndian(this.xOff, bArr, 48);
        for (int i = 0; i != this.xOff; i++) {
            Pack.intToBigEndian(this.f241X[i], bArr, 52 + (i * 4));
        }
        return bArr;
    }
}