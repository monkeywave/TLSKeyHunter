package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class RIPEMD256Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 32;

    /* renamed from: H0 */
    private int f477H0;

    /* renamed from: H1 */
    private int f478H1;

    /* renamed from: H2 */
    private int f479H2;

    /* renamed from: H3 */
    private int f480H3;

    /* renamed from: H4 */
    private int f481H4;

    /* renamed from: H5 */
    private int f482H5;

    /* renamed from: H6 */
    private int f483H6;

    /* renamed from: H7 */
    private int f484H7;

    /* renamed from: X */
    private int[] f485X;
    private int xOff;

    public RIPEMD256Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public RIPEMD256Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f485X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, cryptoServicePurpose));
        reset();
    }

    public RIPEMD256Digest(RIPEMD256Digest rIPEMD256Digest) {
        super(rIPEMD256Digest.purpose);
        this.f485X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, this.purpose));
        copyIn(rIPEMD256Digest);
    }

    /* renamed from: F1 */
    private int m108F1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m103f1(i2, i3, i4) + i5, i6);
    }

    /* renamed from: F2 */
    private int m107F2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m102f2(i2, i3, i4) + i5 + 1518500249, i6);
    }

    /* renamed from: F3 */
    private int m106F3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m101f3(i2, i3, i4) + i5 + 1859775393, i6);
    }

    /* renamed from: F4 */
    private int m105F4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(((i + m100f4(i2, i3, i4)) + i5) - 1894007588, i6);
    }

    private int FF1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m103f1(i2, i3, i4) + i5, i6);
    }

    private int FF2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m102f2(i2, i3, i4) + i5 + 1836072691, i6);
    }

    private int FF3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m101f3(i2, i3, i4) + i5 + 1548603684, i6);
    }

    private int FF4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m104RL(i + m100f4(i2, i3, i4) + i5 + 1352829926, i6);
    }

    /* renamed from: RL */
    private int m104RL(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    private void copyIn(RIPEMD256Digest rIPEMD256Digest) {
        super.copyIn((GeneralDigest) rIPEMD256Digest);
        this.f477H0 = rIPEMD256Digest.f477H0;
        this.f478H1 = rIPEMD256Digest.f478H1;
        this.f479H2 = rIPEMD256Digest.f479H2;
        this.f480H3 = rIPEMD256Digest.f480H3;
        this.f481H4 = rIPEMD256Digest.f481H4;
        this.f482H5 = rIPEMD256Digest.f482H5;
        this.f483H6 = rIPEMD256Digest.f483H6;
        this.f484H7 = rIPEMD256Digest.f484H7;
        int[] iArr = rIPEMD256Digest.f485X;
        System.arraycopy(iArr, 0, this.f485X, 0, iArr.length);
        this.xOff = rIPEMD256Digest.xOff;
    }

    /* renamed from: f1 */
    private int m103f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m102f2(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: f3 */
    private int m101f3(int i, int i2, int i3) {
        return (i | (~i2)) ^ i3;
    }

    /* renamed from: f4 */
    private int m100f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (~i3));
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD256Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f477H0, bArr, i);
        Pack.intToLittleEndian(this.f478H1, bArr, i + 4);
        Pack.intToLittleEndian(this.f479H2, bArr, i + 8);
        Pack.intToLittleEndian(this.f480H3, bArr, i + 12);
        Pack.intToLittleEndian(this.f481H4, bArr, i + 16);
        Pack.intToLittleEndian(this.f482H5, bArr, i + 20);
        Pack.intToLittleEndian(this.f483H6, bArr, i + 24);
        Pack.intToLittleEndian(this.f484H7, bArr, i + 28);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "RIPEMD256";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f477H0;
        int i2 = this.f478H1;
        int i3 = this.f479H2;
        int i4 = this.f480H3;
        int i5 = this.f481H4;
        int i6 = this.f482H5;
        int i7 = this.f483H6;
        int i8 = this.f484H7;
        int m108F1 = m108F1(i, i2, i3, i4, this.f485X[0], 11);
        int m108F12 = m108F1(i4, m108F1, i2, i3, this.f485X[1], 14);
        int m108F13 = m108F1(i3, m108F12, m108F1, i2, this.f485X[2], 15);
        int m108F14 = m108F1(i2, m108F13, m108F12, m108F1, this.f485X[3], 12);
        int m108F15 = m108F1(m108F1, m108F14, m108F13, m108F12, this.f485X[4], 5);
        int m108F16 = m108F1(m108F12, m108F15, m108F14, m108F13, this.f485X[5], 8);
        int m108F17 = m108F1(m108F13, m108F16, m108F15, m108F14, this.f485X[6], 7);
        int m108F18 = m108F1(m108F14, m108F17, m108F16, m108F15, this.f485X[7], 9);
        int m108F19 = m108F1(m108F15, m108F18, m108F17, m108F16, this.f485X[8], 11);
        int m108F110 = m108F1(m108F16, m108F19, m108F18, m108F17, this.f485X[9], 13);
        int m108F111 = m108F1(m108F17, m108F110, m108F19, m108F18, this.f485X[10], 14);
        int m108F112 = m108F1(m108F18, m108F111, m108F110, m108F19, this.f485X[11], 15);
        int m108F113 = m108F1(m108F19, m108F112, m108F111, m108F110, this.f485X[12], 6);
        int m108F114 = m108F1(m108F110, m108F113, m108F112, m108F111, this.f485X[13], 7);
        int m108F115 = m108F1(m108F111, m108F114, m108F113, m108F112, this.f485X[14], 9);
        int m108F116 = m108F1(m108F112, m108F115, m108F114, m108F113, this.f485X[15], 8);
        int FF4 = FF4(i5, i6, i7, i8, this.f485X[5], 8);
        int FF42 = FF4(i8, FF4, i6, i7, this.f485X[14], 9);
        int FF43 = FF4(i7, FF42, FF4, i6, this.f485X[7], 9);
        int FF44 = FF4(i6, FF43, FF42, FF4, this.f485X[0], 11);
        int FF45 = FF4(FF4, FF44, FF43, FF42, this.f485X[9], 13);
        int FF46 = FF4(FF42, FF45, FF44, FF43, this.f485X[2], 15);
        int FF47 = FF4(FF43, FF46, FF45, FF44, this.f485X[11], 15);
        int FF48 = FF4(FF44, FF47, FF46, FF45, this.f485X[4], 5);
        int FF49 = FF4(FF45, FF48, FF47, FF46, this.f485X[13], 7);
        int FF410 = FF4(FF46, FF49, FF48, FF47, this.f485X[6], 7);
        int FF411 = FF4(FF47, FF410, FF49, FF48, this.f485X[15], 8);
        int FF412 = FF4(FF48, FF411, FF410, FF49, this.f485X[8], 11);
        int FF413 = FF4(FF49, FF412, FF411, FF410, this.f485X[1], 14);
        int FF414 = FF4(FF410, FF413, FF412, FF411, this.f485X[10], 14);
        int FF415 = FF4(FF411, FF414, FF413, FF412, this.f485X[3], 12);
        int FF416 = FF4(FF412, FF415, FF414, FF413, this.f485X[12], 6);
        int m107F2 = m107F2(FF413, m108F116, m108F115, m108F114, this.f485X[7], 7);
        int m107F22 = m107F2(m108F114, m107F2, m108F116, m108F115, this.f485X[4], 6);
        int m107F23 = m107F2(m108F115, m107F22, m107F2, m108F116, this.f485X[13], 8);
        int m107F24 = m107F2(m108F116, m107F23, m107F22, m107F2, this.f485X[1], 13);
        int m107F25 = m107F2(m107F2, m107F24, m107F23, m107F22, this.f485X[10], 11);
        int m107F26 = m107F2(m107F22, m107F25, m107F24, m107F23, this.f485X[6], 9);
        int m107F27 = m107F2(m107F23, m107F26, m107F25, m107F24, this.f485X[15], 7);
        int m107F28 = m107F2(m107F24, m107F27, m107F26, m107F25, this.f485X[3], 15);
        int m107F29 = m107F2(m107F25, m107F28, m107F27, m107F26, this.f485X[12], 7);
        int m107F210 = m107F2(m107F26, m107F29, m107F28, m107F27, this.f485X[0], 12);
        int m107F211 = m107F2(m107F27, m107F210, m107F29, m107F28, this.f485X[9], 15);
        int m107F212 = m107F2(m107F28, m107F211, m107F210, m107F29, this.f485X[5], 9);
        int m107F213 = m107F2(m107F29, m107F212, m107F211, m107F210, this.f485X[2], 11);
        int m107F214 = m107F2(m107F210, m107F213, m107F212, m107F211, this.f485X[14], 7);
        int m107F215 = m107F2(m107F211, m107F214, m107F213, m107F212, this.f485X[11], 13);
        int m107F216 = m107F2(m107F212, m107F215, m107F214, m107F213, this.f485X[8], 12);
        int FF3 = FF3(m108F113, FF416, FF415, FF414, this.f485X[6], 9);
        int FF32 = FF3(FF414, FF3, FF416, FF415, this.f485X[11], 13);
        int FF33 = FF3(FF415, FF32, FF3, FF416, this.f485X[3], 15);
        int FF34 = FF3(FF416, FF33, FF32, FF3, this.f485X[7], 7);
        int FF35 = FF3(FF3, FF34, FF33, FF32, this.f485X[0], 12);
        int FF36 = FF3(FF32, FF35, FF34, FF33, this.f485X[13], 8);
        int FF37 = FF3(FF33, FF36, FF35, FF34, this.f485X[5], 9);
        int FF38 = FF3(FF34, FF37, FF36, FF35, this.f485X[10], 11);
        int FF39 = FF3(FF35, FF38, FF37, FF36, this.f485X[14], 7);
        int FF310 = FF3(FF36, FF39, FF38, FF37, this.f485X[15], 7);
        int FF311 = FF3(FF37, FF310, FF39, FF38, this.f485X[8], 12);
        int FF312 = FF3(FF38, FF311, FF310, FF39, this.f485X[12], 7);
        int FF313 = FF3(FF39, FF312, FF311, FF310, this.f485X[4], 6);
        int FF314 = FF3(FF310, FF313, FF312, FF311, this.f485X[9], 15);
        int FF315 = FF3(FF311, FF314, FF313, FF312, this.f485X[1], 13);
        int FF316 = FF3(FF312, FF315, FF314, FF313, this.f485X[2], 11);
        int m106F3 = m106F3(m107F213, FF316, m107F215, m107F214, this.f485X[3], 11);
        int m106F32 = m106F3(m107F214, m106F3, FF316, m107F215, this.f485X[10], 13);
        int m106F33 = m106F3(m107F215, m106F32, m106F3, FF316, this.f485X[14], 6);
        int m106F34 = m106F3(FF316, m106F33, m106F32, m106F3, this.f485X[4], 7);
        int m106F35 = m106F3(m106F3, m106F34, m106F33, m106F32, this.f485X[9], 14);
        int m106F36 = m106F3(m106F32, m106F35, m106F34, m106F33, this.f485X[15], 9);
        int m106F37 = m106F3(m106F33, m106F36, m106F35, m106F34, this.f485X[8], 13);
        int m106F38 = m106F3(m106F34, m106F37, m106F36, m106F35, this.f485X[1], 15);
        int m106F39 = m106F3(m106F35, m106F38, m106F37, m106F36, this.f485X[2], 14);
        int m106F310 = m106F3(m106F36, m106F39, m106F38, m106F37, this.f485X[7], 8);
        int m106F311 = m106F3(m106F37, m106F310, m106F39, m106F38, this.f485X[0], 13);
        int m106F312 = m106F3(m106F38, m106F311, m106F310, m106F39, this.f485X[6], 6);
        int m106F313 = m106F3(m106F39, m106F312, m106F311, m106F310, this.f485X[13], 5);
        int m106F314 = m106F3(m106F310, m106F313, m106F312, m106F311, this.f485X[11], 12);
        int m106F315 = m106F3(m106F311, m106F314, m106F313, m106F312, this.f485X[5], 7);
        int m106F316 = m106F3(m106F312, m106F315, m106F314, m106F313, this.f485X[12], 5);
        int FF2 = FF2(FF313, m107F216, FF315, FF314, this.f485X[15], 9);
        int FF22 = FF2(FF314, FF2, m107F216, FF315, this.f485X[5], 7);
        int FF23 = FF2(FF315, FF22, FF2, m107F216, this.f485X[1], 15);
        int FF24 = FF2(m107F216, FF23, FF22, FF2, this.f485X[3], 11);
        int FF25 = FF2(FF2, FF24, FF23, FF22, this.f485X[7], 8);
        int FF26 = FF2(FF22, FF25, FF24, FF23, this.f485X[14], 6);
        int FF27 = FF2(FF23, FF26, FF25, FF24, this.f485X[6], 6);
        int FF28 = FF2(FF24, FF27, FF26, FF25, this.f485X[9], 14);
        int FF29 = FF2(FF25, FF28, FF27, FF26, this.f485X[11], 12);
        int FF210 = FF2(FF26, FF29, FF28, FF27, this.f485X[8], 13);
        int FF211 = FF2(FF27, FF210, FF29, FF28, this.f485X[12], 5);
        int FF212 = FF2(FF28, FF211, FF210, FF29, this.f485X[2], 14);
        int FF213 = FF2(FF29, FF212, FF211, FF210, this.f485X[10], 13);
        int FF214 = FF2(FF210, FF213, FF212, FF211, this.f485X[0], 13);
        int FF215 = FF2(FF211, FF214, FF213, FF212, this.f485X[4], 7);
        int FF216 = FF2(FF212, FF215, FF214, FF213, this.f485X[13], 5);
        int m105F4 = m105F4(m106F313, m106F316, FF215, m106F314, this.f485X[1], 11);
        int m105F42 = m105F4(m106F314, m105F4, m106F316, FF215, this.f485X[9], 12);
        int m105F43 = m105F4(FF215, m105F42, m105F4, m106F316, this.f485X[11], 14);
        int m105F44 = m105F4(m106F316, m105F43, m105F42, m105F4, this.f485X[10], 15);
        int m105F45 = m105F4(m105F4, m105F44, m105F43, m105F42, this.f485X[0], 14);
        int m105F46 = m105F4(m105F42, m105F45, m105F44, m105F43, this.f485X[8], 15);
        int m105F47 = m105F4(m105F43, m105F46, m105F45, m105F44, this.f485X[12], 9);
        int m105F48 = m105F4(m105F44, m105F47, m105F46, m105F45, this.f485X[4], 8);
        int m105F49 = m105F4(m105F45, m105F48, m105F47, m105F46, this.f485X[13], 9);
        int m105F410 = m105F4(m105F46, m105F49, m105F48, m105F47, this.f485X[3], 14);
        int m105F411 = m105F4(m105F47, m105F410, m105F49, m105F48, this.f485X[7], 5);
        int m105F412 = m105F4(m105F48, m105F411, m105F410, m105F49, this.f485X[15], 6);
        int m105F413 = m105F4(m105F49, m105F412, m105F411, m105F410, this.f485X[14], 8);
        int m105F414 = m105F4(m105F410, m105F413, m105F412, m105F411, this.f485X[5], 6);
        int m105F415 = m105F4(m105F411, m105F414, m105F413, m105F412, this.f485X[6], 5);
        int m105F416 = m105F4(m105F412, m105F415, m105F414, m105F413, this.f485X[2], 12);
        int FF1 = FF1(FF213, FF216, m106F315, FF214, this.f485X[8], 15);
        int FF12 = FF1(FF214, FF1, FF216, m106F315, this.f485X[6], 5);
        int FF13 = FF1(m106F315, FF12, FF1, FF216, this.f485X[4], 8);
        int FF14 = FF1(FF216, FF13, FF12, FF1, this.f485X[1], 11);
        int FF15 = FF1(FF1, FF14, FF13, FF12, this.f485X[3], 14);
        int FF16 = FF1(FF12, FF15, FF14, FF13, this.f485X[11], 14);
        int FF17 = FF1(FF13, FF16, FF15, FF14, this.f485X[15], 6);
        int FF18 = FF1(FF14, FF17, FF16, FF15, this.f485X[0], 14);
        int FF19 = FF1(FF15, FF18, FF17, FF16, this.f485X[5], 6);
        int FF110 = FF1(FF16, FF19, FF18, FF17, this.f485X[12], 9);
        int FF111 = FF1(FF17, FF110, FF19, FF18, this.f485X[2], 12);
        int FF112 = FF1(FF18, FF111, FF110, FF19, this.f485X[13], 9);
        int FF113 = FF1(FF19, FF112, FF111, FF110, this.f485X[9], 12);
        int FF114 = FF1(FF110, FF113, FF112, FF111, this.f485X[7], 5);
        int FF115 = FF1(FF111, FF114, FF113, FF112, this.f485X[10], 15);
        int FF116 = FF1(FF112, FF115, FF114, FF113, this.f485X[14], 8);
        this.f477H0 += m105F413;
        this.f478H1 += m105F416;
        this.f479H2 += m105F415;
        this.f480H3 += FF114;
        this.f481H4 += FF113;
        this.f482H5 += FF116;
        this.f483H6 += FF115;
        this.f484H7 += m105F414;
        this.xOff = 0;
        int i9 = 0;
        while (true) {
            int[] iArr = this.f485X;
            if (i9 == iArr.length) {
                return;
            }
            iArr[i9] = 0;
            i9++;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        int[] iArr = this.f485X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f485X;
        int i2 = this.xOff;
        this.xOff = i2 + 1;
        iArr[i2] = Pack.littleEndianToInt(bArr, i);
        if (this.xOff == 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f477H0 = 1732584193;
        this.f478H1 = -271733879;
        this.f479H2 = -1732584194;
        this.f480H3 = 271733878;
        this.f481H4 = 1985229328;
        this.f482H5 = -19088744;
        this.f483H6 = -1985229329;
        this.f484H7 = 19088743;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f485X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD256Digest) memoable);
    }
}