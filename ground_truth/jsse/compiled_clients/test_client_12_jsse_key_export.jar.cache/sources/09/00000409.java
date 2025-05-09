package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/SHA256Digest.class */
public class SHA256Digest extends GeneralDigest implements EncodableDigest {
    private static final int DIGEST_LENGTH = 32;

    /* renamed from: H1 */
    private int f243H1;

    /* renamed from: H2 */
    private int f244H2;

    /* renamed from: H3 */
    private int f245H3;

    /* renamed from: H4 */
    private int f246H4;

    /* renamed from: H5 */
    private int f247H5;

    /* renamed from: H6 */
    private int f248H6;

    /* renamed from: H7 */
    private int f249H7;

    /* renamed from: H8 */
    private int f250H8;

    /* renamed from: X */
    private int[] f251X;
    private int xOff;

    /* renamed from: K */
    static final int[] f252K = {1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998};

    public SHA256Digest() {
        this.f251X = new int[64];
        reset();
    }

    public SHA256Digest(SHA256Digest sHA256Digest) {
        super(sHA256Digest);
        this.f251X = new int[64];
        copyIn(sHA256Digest);
    }

    private void copyIn(SHA256Digest sHA256Digest) {
        super.copyIn((GeneralDigest) sHA256Digest);
        this.f243H1 = sHA256Digest.f243H1;
        this.f244H2 = sHA256Digest.f244H2;
        this.f245H3 = sHA256Digest.f245H3;
        this.f246H4 = sHA256Digest.f246H4;
        this.f247H5 = sHA256Digest.f247H5;
        this.f248H6 = sHA256Digest.f248H6;
        this.f249H7 = sHA256Digest.f249H7;
        this.f250H8 = sHA256Digest.f250H8;
        System.arraycopy(sHA256Digest.f251X, 0, this.f251X, 0, sHA256Digest.f251X.length);
        this.xOff = sHA256Digest.xOff;
    }

    public SHA256Digest(byte[] bArr) {
        super(bArr);
        this.f251X = new int[64];
        this.f243H1 = Pack.bigEndianToInt(bArr, 16);
        this.f244H2 = Pack.bigEndianToInt(bArr, 20);
        this.f245H3 = Pack.bigEndianToInt(bArr, 24);
        this.f246H4 = Pack.bigEndianToInt(bArr, 28);
        this.f247H5 = Pack.bigEndianToInt(bArr, 32);
        this.f248H6 = Pack.bigEndianToInt(bArr, 36);
        this.f249H7 = Pack.bigEndianToInt(bArr, 40);
        this.f250H8 = Pack.bigEndianToInt(bArr, 44);
        this.xOff = Pack.bigEndianToInt(bArr, 48);
        for (int i = 0; i != this.xOff; i++) {
            this.f251X[i] = Pack.bigEndianToInt(bArr, 52 + (i * 4));
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "SHA-256";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        this.f251X[this.xOff] = (bArr[i] << 24) | ((bArr[i2] & 255) << 16) | ((bArr[i3] & 255) << 8) | (bArr[i3 + 1] & 255);
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
        this.f251X[14] = (int) (j >>> 32);
        this.f251X[15] = (int) (j & (-1));
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToBigEndian(this.f243H1, bArr, i);
        Pack.intToBigEndian(this.f244H2, bArr, i + 4);
        Pack.intToBigEndian(this.f245H3, bArr, i + 8);
        Pack.intToBigEndian(this.f246H4, bArr, i + 12);
        Pack.intToBigEndian(this.f247H5, bArr, i + 16);
        Pack.intToBigEndian(this.f248H6, bArr, i + 20);
        Pack.intToBigEndian(this.f249H7, bArr, i + 24);
        Pack.intToBigEndian(this.f250H8, bArr, i + 28);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f243H1 = 1779033703;
        this.f244H2 = -1150833019;
        this.f245H3 = 1013904242;
        this.f246H4 = -1521486534;
        this.f247H5 = 1359893119;
        this.f248H6 = -1694144372;
        this.f249H7 = 528734635;
        this.f250H8 = 1541459225;
        this.xOff = 0;
        for (int i = 0; i != this.f251X.length; i++) {
            this.f251X[i] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        for (int i = 16; i <= 63; i++) {
            this.f251X[i] = Theta1(this.f251X[i - 2]) + this.f251X[i - 7] + Theta0(this.f251X[i - 15]) + this.f251X[i - 16];
        }
        int i2 = this.f243H1;
        int i3 = this.f244H2;
        int i4 = this.f245H3;
        int i5 = this.f246H4;
        int i6 = this.f247H5;
        int i7 = this.f248H6;
        int i8 = this.f249H7;
        int i9 = this.f250H8;
        int i10 = 0;
        for (int i11 = 0; i11 < 8; i11++) {
            int Sum1 = i9 + Sum1(i6) + m69Ch(i6, i7, i8) + f252K[i10] + this.f251X[i10];
            int i12 = i5 + Sum1;
            int Sum0 = Sum1 + Sum0(i2) + Maj(i2, i3, i4);
            int i13 = i10 + 1;
            int Sum12 = i8 + Sum1(i12) + m69Ch(i12, i6, i7) + f252K[i13] + this.f251X[i13];
            int i14 = i4 + Sum12;
            int Sum02 = Sum12 + Sum0(Sum0) + Maj(Sum0, i2, i3);
            int i15 = i13 + 1;
            int Sum13 = i7 + Sum1(i14) + m69Ch(i14, i12, i6) + f252K[i15] + this.f251X[i15];
            int i16 = i3 + Sum13;
            int Sum03 = Sum13 + Sum0(Sum02) + Maj(Sum02, Sum0, i2);
            int i17 = i15 + 1;
            int Sum14 = i6 + Sum1(i16) + m69Ch(i16, i14, i12) + f252K[i17] + this.f251X[i17];
            int i18 = i2 + Sum14;
            int Sum04 = Sum14 + Sum0(Sum03) + Maj(Sum03, Sum02, Sum0);
            int i19 = i17 + 1;
            int Sum15 = i12 + Sum1(i18) + m69Ch(i18, i16, i14) + f252K[i19] + this.f251X[i19];
            i9 = Sum0 + Sum15;
            i5 = Sum15 + Sum0(Sum04) + Maj(Sum04, Sum03, Sum02);
            int i20 = i19 + 1;
            int Sum16 = i14 + Sum1(i9) + m69Ch(i9, i18, i16) + f252K[i20] + this.f251X[i20];
            i8 = Sum02 + Sum16;
            i4 = Sum16 + Sum0(i5) + Maj(i5, Sum04, Sum03);
            int i21 = i20 + 1;
            int Sum17 = i16 + Sum1(i8) + m69Ch(i8, i9, i18) + f252K[i21] + this.f251X[i21];
            i7 = Sum03 + Sum17;
            i3 = Sum17 + Sum0(i4) + Maj(i4, i5, Sum04);
            int i22 = i21 + 1;
            int Sum18 = i18 + Sum1(i7) + m69Ch(i7, i8, i9) + f252K[i22] + this.f251X[i22];
            i6 = Sum04 + Sum18;
            i2 = Sum18 + Sum0(i3) + Maj(i3, i4, i5);
            i10 = i22 + 1;
        }
        this.f243H1 += i2;
        this.f244H2 += i3;
        this.f245H3 += i4;
        this.f246H4 += i5;
        this.f247H5 += i6;
        this.f248H6 += i7;
        this.f249H7 += i8;
        this.f250H8 += i9;
        this.xOff = 0;
        for (int i23 = 0; i23 < 16; i23++) {
            this.f251X[i23] = 0;
        }
    }

    /* renamed from: Ch */
    private static int m69Ch(int i, int i2, int i3) {
        return (i & i2) ^ ((i ^ (-1)) & i3);
    }

    private static int Maj(int i, int i2, int i3) {
        return (i & i2) | (i3 & (i ^ i2));
    }

    private static int Sum0(int i) {
        return (((i >>> 2) | (i << 30)) ^ ((i >>> 13) | (i << 19))) ^ ((i >>> 22) | (i << 10));
    }

    private static int Sum1(int i) {
        return (((i >>> 6) | (i << 26)) ^ ((i >>> 11) | (i << 21))) ^ ((i >>> 25) | (i << 7));
    }

    private static int Theta0(int i) {
        return (((i >>> 7) | (i << 25)) ^ ((i >>> 18) | (i << 14))) ^ (i >>> 3);
    }

    private static int Theta1(int i) {
        return (((i >>> 17) | (i << 15)) ^ ((i >>> 19) | (i << 13))) ^ (i >>> 10);
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA256Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((SHA256Digest) memoable);
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        byte[] bArr = new byte[52 + (this.xOff * 4)];
        super.populateState(bArr);
        Pack.intToBigEndian(this.f243H1, bArr, 16);
        Pack.intToBigEndian(this.f244H2, bArr, 20);
        Pack.intToBigEndian(this.f245H3, bArr, 24);
        Pack.intToBigEndian(this.f246H4, bArr, 28);
        Pack.intToBigEndian(this.f247H5, bArr, 32);
        Pack.intToBigEndian(this.f248H6, bArr, 36);
        Pack.intToBigEndian(this.f249H7, bArr, 40);
        Pack.intToBigEndian(this.f250H8, bArr, 44);
        Pack.intToBigEndian(this.xOff, bArr, 48);
        for (int i = 0; i != this.xOff; i++) {
            Pack.intToBigEndian(this.f251X[i], bArr, 52 + (i * 4));
        }
        return bArr;
    }
}