package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SHA1Digest extends GeneralDigest implements EncodableDigest {
    private static final int DIGEST_LENGTH = 20;

    /* renamed from: Y1 */
    private static final int f497Y1 = 1518500249;

    /* renamed from: Y2 */
    private static final int f498Y2 = 1859775393;

    /* renamed from: Y3 */
    private static final int f499Y3 = -1894007588;

    /* renamed from: Y4 */
    private static final int f500Y4 = -899497514;

    /* renamed from: H1 */
    private int f501H1;

    /* renamed from: H2 */
    private int f502H2;

    /* renamed from: H3 */
    private int f503H3;

    /* renamed from: H4 */
    private int f504H4;

    /* renamed from: H5 */
    private int f505H5;

    /* renamed from: X */
    private int[] f506X;
    private int xOff;

    public SHA1Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public SHA1Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f506X = new int[80];
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset();
    }

    public SHA1Digest(SHA1Digest sHA1Digest) {
        super(sHA1Digest);
        this.f506X = new int[80];
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        copyIn(sHA1Digest);
    }

    public SHA1Digest(byte[] bArr) {
        super(bArr);
        this.f506X = new int[80];
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        this.f501H1 = Pack.bigEndianToInt(bArr, 16);
        this.f502H2 = Pack.bigEndianToInt(bArr, 20);
        this.f503H3 = Pack.bigEndianToInt(bArr, 24);
        this.f504H4 = Pack.bigEndianToInt(bArr, 28);
        this.f505H5 = Pack.bigEndianToInt(bArr, 32);
        this.xOff = Pack.bigEndianToInt(bArr, 36);
        for (int i = 0; i != this.xOff; i++) {
            this.f506X[i] = Pack.bigEndianToInt(bArr, (i * 4) + 40);
        }
    }

    private void copyIn(SHA1Digest sHA1Digest) {
        this.f501H1 = sHA1Digest.f501H1;
        this.f502H2 = sHA1Digest.f502H2;
        this.f503H3 = sHA1Digest.f503H3;
        this.f504H4 = sHA1Digest.f504H4;
        this.f505H5 = sHA1Digest.f505H5;
        int[] iArr = sHA1Digest.f506X;
        System.arraycopy(iArr, 0, this.f506X, 0, iArr.length);
        this.xOff = sHA1Digest.xOff;
    }

    /* renamed from: f */
    private int m93f(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: g */
    private int m92g(int i, int i2, int i3) {
        return (i & (i2 | i3)) | (i2 & i3);
    }

    /* renamed from: h */
    private int m91h(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA1Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, 128, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToBigEndian(this.f501H1, bArr, i);
        Pack.intToBigEndian(this.f502H2, bArr, i + 4);
        Pack.intToBigEndian(this.f503H3, bArr, i + 8);
        Pack.intToBigEndian(this.f504H4, bArr, i + 12);
        Pack.intToBigEndian(this.f505H5, bArr, i + 16);
        reset();
        return 20;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return McElieceCCA2KeyGenParameterSpec.SHA1;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 20;
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        int i = this.xOff * 4;
        byte[] bArr = new byte[i + 41];
        super.populateState(bArr);
        Pack.intToBigEndian(this.f501H1, bArr, 16);
        Pack.intToBigEndian(this.f502H2, bArr, 20);
        Pack.intToBigEndian(this.f503H3, bArr, 24);
        Pack.intToBigEndian(this.f504H4, bArr, 28);
        Pack.intToBigEndian(this.f505H5, bArr, 32);
        Pack.intToBigEndian(this.xOff, bArr, 36);
        for (int i2 = 0; i2 != this.xOff; i2++) {
            Pack.intToBigEndian(this.f506X[i2], bArr, (i2 * 4) + 40);
        }
        bArr[i + 40] = (byte) this.purpose.ordinal();
        return bArr;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        for (int i = 16; i < 80; i++) {
            int[] iArr = this.f506X;
            int i2 = ((iArr[i - 3] ^ iArr[i - 8]) ^ iArr[i - 14]) ^ iArr[i - 16];
            iArr[i] = (i2 >>> 31) | (i2 << 1);
        }
        int i3 = this.f501H1;
        int i4 = this.f502H2;
        int i5 = this.f503H3;
        int i6 = this.f504H4;
        int i7 = this.f505H5;
        int i8 = 0;
        for (int i9 = 0; i9 < 4; i9++) {
            int m93f = i7 + ((i3 << 5) | (i3 >>> 27)) + m93f(i4, i5, i6) + this.f506X[i8] + f497Y1;
            int i10 = (i4 >>> 2) | (i4 << 30);
            int m93f2 = i6 + ((m93f << 5) | (m93f >>> 27)) + m93f(i3, i10, i5) + this.f506X[i8 + 1] + f497Y1;
            int i11 = (i3 >>> 2) | (i3 << 30);
            int m93f3 = i5 + ((m93f2 << 5) | (m93f2 >>> 27)) + m93f(m93f, i11, i10) + this.f506X[i8 + 2] + f497Y1;
            i7 = (m93f >>> 2) | (m93f << 30);
            int i12 = i8 + 4;
            i4 = i10 + ((m93f3 << 5) | (m93f3 >>> 27)) + m93f(m93f2, i7, i11) + this.f506X[i8 + 3] + f497Y1;
            i6 = (m93f2 >>> 2) | (m93f2 << 30);
            i8 += 5;
            i3 = i11 + ((i4 << 5) | (i4 >>> 27)) + m93f(m93f3, i6, i7) + this.f506X[i12] + f497Y1;
            i5 = (m93f3 >>> 2) | (m93f3 << 30);
        }
        for (int i13 = 0; i13 < 4; i13++) {
            int m91h = i7 + ((i3 << 5) | (i3 >>> 27)) + m91h(i4, i5, i6) + this.f506X[i8] + f498Y2;
            int i14 = (i4 >>> 2) | (i4 << 30);
            int m91h2 = i6 + ((m91h << 5) | (m91h >>> 27)) + m91h(i3, i14, i5) + this.f506X[i8 + 1] + f498Y2;
            int i15 = (i3 >>> 2) | (i3 << 30);
            int m91h3 = i5 + ((m91h2 << 5) | (m91h2 >>> 27)) + m91h(m91h, i15, i14) + this.f506X[i8 + 2] + f498Y2;
            i7 = (m91h >>> 2) | (m91h << 30);
            int i16 = i8 + 4;
            i4 = i14 + ((m91h3 << 5) | (m91h3 >>> 27)) + m91h(m91h2, i7, i15) + this.f506X[i8 + 3] + f498Y2;
            i6 = (m91h2 >>> 2) | (m91h2 << 30);
            i8 += 5;
            i3 = i15 + ((i4 << 5) | (i4 >>> 27)) + m91h(m91h3, i6, i7) + this.f506X[i16] + f498Y2;
            i5 = (m91h3 >>> 2) | (m91h3 << 30);
        }
        for (int i17 = 0; i17 < 4; i17++) {
            int m92g = i7 + ((i3 << 5) | (i3 >>> 27)) + m92g(i4, i5, i6) + this.f506X[i8] + f499Y3;
            int i18 = (i4 >>> 2) | (i4 << 30);
            int m92g2 = i6 + ((m92g << 5) | (m92g >>> 27)) + m92g(i3, i18, i5) + this.f506X[i8 + 1] + f499Y3;
            int i19 = (i3 >>> 2) | (i3 << 30);
            int m92g3 = i5 + ((m92g2 << 5) | (m92g2 >>> 27)) + m92g(m92g, i19, i18) + this.f506X[i8 + 2] + f499Y3;
            i7 = (m92g >>> 2) | (m92g << 30);
            int i20 = i8 + 4;
            i4 = i18 + ((m92g3 << 5) | (m92g3 >>> 27)) + m92g(m92g2, i7, i19) + this.f506X[i8 + 3] + f499Y3;
            i6 = (m92g2 >>> 2) | (m92g2 << 30);
            i8 += 5;
            i3 = i19 + ((i4 << 5) | (i4 >>> 27)) + m92g(m92g3, i6, i7) + this.f506X[i20] + f499Y3;
            i5 = (m92g3 >>> 2) | (m92g3 << 30);
        }
        for (int i21 = 0; i21 <= 3; i21++) {
            int m91h4 = i7 + ((i3 << 5) | (i3 >>> 27)) + m91h(i4, i5, i6) + this.f506X[i8] + f500Y4;
            int i22 = (i4 >>> 2) | (i4 << 30);
            int m91h5 = i6 + ((m91h4 << 5) | (m91h4 >>> 27)) + m91h(i3, i22, i5) + this.f506X[i8 + 1] + f500Y4;
            int i23 = (i3 >>> 2) | (i3 << 30);
            int m91h6 = i5 + ((m91h5 << 5) | (m91h5 >>> 27)) + m91h(m91h4, i23, i22) + this.f506X[i8 + 2] + f500Y4;
            i7 = (m91h4 >>> 2) | (m91h4 << 30);
            int i24 = i8 + 4;
            i4 = i22 + ((m91h6 << 5) | (m91h6 >>> 27)) + m91h(m91h5, i7, i23) + this.f506X[i8 + 3] + f500Y4;
            i6 = (m91h5 >>> 2) | (m91h5 << 30);
            i8 += 5;
            i3 = i23 + ((i4 << 5) | (i4 >>> 27)) + m91h(m91h6, i6, i7) + this.f506X[i24] + f500Y4;
            i5 = (m91h6 >>> 2) | (m91h6 << 30);
        }
        this.f501H1 += i3;
        this.f502H2 += i4;
        this.f503H3 += i5;
        this.f504H4 += i6;
        this.f505H5 += i7;
        this.xOff = 0;
        for (int i25 = 0; i25 < 16; i25++) {
            this.f506X[i25] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        int[] iArr = this.f506X;
        iArr[14] = (int) (j >>> 32);
        iArr[15] = (int) j;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        this.f506X[this.xOff] = Pack.bigEndianToInt(bArr, i);
        int i2 = this.xOff + 1;
        this.xOff = i2;
        if (i2 == 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f501H1 = 1732584193;
        this.f502H2 = -271733879;
        this.f503H3 = -1732584194;
        this.f504H4 = 271733878;
        this.f505H5 = -1009589776;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f506X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        SHA1Digest sHA1Digest = (SHA1Digest) memoable;
        super.copyIn((GeneralDigest) sHA1Digest);
        copyIn(sHA1Digest);
    }
}