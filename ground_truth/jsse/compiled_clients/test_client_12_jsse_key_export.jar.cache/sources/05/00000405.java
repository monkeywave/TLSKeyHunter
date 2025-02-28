package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/RIPEMD256Digest.class */
public class RIPEMD256Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 32;

    /* renamed from: H0 */
    private int f203H0;

    /* renamed from: H1 */
    private int f204H1;

    /* renamed from: H2 */
    private int f205H2;

    /* renamed from: H3 */
    private int f206H3;

    /* renamed from: H4 */
    private int f207H4;

    /* renamed from: H5 */
    private int f208H5;

    /* renamed from: H6 */
    private int f209H6;

    /* renamed from: H7 */
    private int f210H7;

    /* renamed from: X */
    private int[] f211X;
    private int xOff;

    public RIPEMD256Digest() {
        this.f211X = new int[16];
        reset();
    }

    public RIPEMD256Digest(RIPEMD256Digest rIPEMD256Digest) {
        super(rIPEMD256Digest);
        this.f211X = new int[16];
        copyIn(rIPEMD256Digest);
    }

    private void copyIn(RIPEMD256Digest rIPEMD256Digest) {
        super.copyIn((GeneralDigest) rIPEMD256Digest);
        this.f203H0 = rIPEMD256Digest.f203H0;
        this.f204H1 = rIPEMD256Digest.f204H1;
        this.f205H2 = rIPEMD256Digest.f205H2;
        this.f206H3 = rIPEMD256Digest.f206H3;
        this.f207H4 = rIPEMD256Digest.f207H4;
        this.f208H5 = rIPEMD256Digest.f208H5;
        this.f209H6 = rIPEMD256Digest.f209H6;
        this.f210H7 = rIPEMD256Digest.f210H7;
        System.arraycopy(rIPEMD256Digest.f211X, 0, this.f211X, 0, rIPEMD256Digest.f211X.length);
        this.xOff = rIPEMD256Digest.xOff;
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
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f211X;
        int i2 = this.xOff;
        this.xOff = i2 + 1;
        iArr[i2] = (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24);
        if (this.xOff == 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        this.f211X[14] = (int) (j & (-1));
        this.f211X[15] = (int) (j >>> 32);
    }

    private void unpackWord(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 3] = (byte) (i >>> 24);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        unpackWord(this.f203H0, bArr, i);
        unpackWord(this.f204H1, bArr, i + 4);
        unpackWord(this.f205H2, bArr, i + 8);
        unpackWord(this.f206H3, bArr, i + 12);
        unpackWord(this.f207H4, bArr, i + 16);
        unpackWord(this.f208H5, bArr, i + 20);
        unpackWord(this.f209H6, bArr, i + 24);
        unpackWord(this.f210H7, bArr, i + 28);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f203H0 = 1732584193;
        this.f204H1 = -271733879;
        this.f205H2 = -1732584194;
        this.f206H3 = 271733878;
        this.f207H4 = 1985229328;
        this.f208H5 = -19088744;
        this.f209H6 = -1985229329;
        this.f210H7 = 19088743;
        this.xOff = 0;
        for (int i = 0; i != this.f211X.length; i++) {
            this.f211X[i] = 0;
        }
    }

    /* renamed from: RL */
    private int m84RL(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    /* renamed from: f1 */
    private int m83f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m82f2(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: f3 */
    private int m81f3(int i, int i2, int i3) {
        return (i | (i2 ^ (-1))) ^ i3;
    }

    /* renamed from: f4 */
    private int m80f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (i3 ^ (-1)));
    }

    /* renamed from: F1 */
    private int m88F1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m83f1(i2, i3, i4) + i5, i6);
    }

    /* renamed from: F2 */
    private int m87F2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m82f2(i2, i3, i4) + i5 + 1518500249, i6);
    }

    /* renamed from: F3 */
    private int m86F3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m81f3(i2, i3, i4) + i5 + 1859775393, i6);
    }

    /* renamed from: F4 */
    private int m85F4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(((i + m80f4(i2, i3, i4)) + i5) - 1894007588, i6);
    }

    private int FF1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m83f1(i2, i3, i4) + i5, i6);
    }

    private int FF2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m82f2(i2, i3, i4) + i5 + 1836072691, i6);
    }

    private int FF3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m81f3(i2, i3, i4) + i5 + 1548603684, i6);
    }

    private int FF4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m84RL(i + m80f4(i2, i3, i4) + i5 + 1352829926, i6);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f203H0;
        int i2 = this.f204H1;
        int i3 = this.f205H2;
        int i4 = this.f206H3;
        int i5 = this.f207H4;
        int i6 = this.f208H5;
        int i7 = this.f209H6;
        int i8 = this.f210H7;
        int m88F1 = m88F1(i, i2, i3, i4, this.f211X[0], 11);
        int m88F12 = m88F1(i4, m88F1, i2, i3, this.f211X[1], 14);
        int m88F13 = m88F1(i3, m88F12, m88F1, i2, this.f211X[2], 15);
        int m88F14 = m88F1(i2, m88F13, m88F12, m88F1, this.f211X[3], 12);
        int m88F15 = m88F1(m88F1, m88F14, m88F13, m88F12, this.f211X[4], 5);
        int m88F16 = m88F1(m88F12, m88F15, m88F14, m88F13, this.f211X[5], 8);
        int m88F17 = m88F1(m88F13, m88F16, m88F15, m88F14, this.f211X[6], 7);
        int m88F18 = m88F1(m88F14, m88F17, m88F16, m88F15, this.f211X[7], 9);
        int m88F19 = m88F1(m88F15, m88F18, m88F17, m88F16, this.f211X[8], 11);
        int m88F110 = m88F1(m88F16, m88F19, m88F18, m88F17, this.f211X[9], 13);
        int m88F111 = m88F1(m88F17, m88F110, m88F19, m88F18, this.f211X[10], 14);
        int m88F112 = m88F1(m88F18, m88F111, m88F110, m88F19, this.f211X[11], 15);
        int m88F113 = m88F1(m88F19, m88F112, m88F111, m88F110, this.f211X[12], 6);
        int m88F114 = m88F1(m88F110, m88F113, m88F112, m88F111, this.f211X[13], 7);
        int m88F115 = m88F1(m88F111, m88F114, m88F113, m88F112, this.f211X[14], 9);
        int m88F116 = m88F1(m88F112, m88F115, m88F114, m88F113, this.f211X[15], 8);
        int FF4 = FF4(i5, i6, i7, i8, this.f211X[5], 8);
        int FF42 = FF4(i8, FF4, i6, i7, this.f211X[14], 9);
        int FF43 = FF4(i7, FF42, FF4, i6, this.f211X[7], 9);
        int FF44 = FF4(i6, FF43, FF42, FF4, this.f211X[0], 11);
        int FF45 = FF4(FF4, FF44, FF43, FF42, this.f211X[9], 13);
        int FF46 = FF4(FF42, FF45, FF44, FF43, this.f211X[2], 15);
        int FF47 = FF4(FF43, FF46, FF45, FF44, this.f211X[11], 15);
        int FF48 = FF4(FF44, FF47, FF46, FF45, this.f211X[4], 5);
        int FF49 = FF4(FF45, FF48, FF47, FF46, this.f211X[13], 7);
        int FF410 = FF4(FF46, FF49, FF48, FF47, this.f211X[6], 7);
        int FF411 = FF4(FF47, FF410, FF49, FF48, this.f211X[15], 8);
        int FF412 = FF4(FF48, FF411, FF410, FF49, this.f211X[8], 11);
        int FF413 = FF4(FF49, FF412, FF411, FF410, this.f211X[1], 14);
        int FF414 = FF4(FF410, FF413, FF412, FF411, this.f211X[10], 14);
        int FF415 = FF4(FF411, FF414, FF413, FF412, this.f211X[3], 12);
        int FF416 = FF4(FF412, FF415, FF414, FF413, this.f211X[12], 6);
        int m87F2 = m87F2(FF413, m88F116, m88F115, m88F114, this.f211X[7], 7);
        int m87F22 = m87F2(m88F114, m87F2, m88F116, m88F115, this.f211X[4], 6);
        int m87F23 = m87F2(m88F115, m87F22, m87F2, m88F116, this.f211X[13], 8);
        int m87F24 = m87F2(m88F116, m87F23, m87F22, m87F2, this.f211X[1], 13);
        int m87F25 = m87F2(m87F2, m87F24, m87F23, m87F22, this.f211X[10], 11);
        int m87F26 = m87F2(m87F22, m87F25, m87F24, m87F23, this.f211X[6], 9);
        int m87F27 = m87F2(m87F23, m87F26, m87F25, m87F24, this.f211X[15], 7);
        int m87F28 = m87F2(m87F24, m87F27, m87F26, m87F25, this.f211X[3], 15);
        int m87F29 = m87F2(m87F25, m87F28, m87F27, m87F26, this.f211X[12], 7);
        int m87F210 = m87F2(m87F26, m87F29, m87F28, m87F27, this.f211X[0], 12);
        int m87F211 = m87F2(m87F27, m87F210, m87F29, m87F28, this.f211X[9], 15);
        int m87F212 = m87F2(m87F28, m87F211, m87F210, m87F29, this.f211X[5], 9);
        int m87F213 = m87F2(m87F29, m87F212, m87F211, m87F210, this.f211X[2], 11);
        int m87F214 = m87F2(m87F210, m87F213, m87F212, m87F211, this.f211X[14], 7);
        int m87F215 = m87F2(m87F211, m87F214, m87F213, m87F212, this.f211X[11], 13);
        int m87F216 = m87F2(m87F212, m87F215, m87F214, m87F213, this.f211X[8], 12);
        int FF3 = FF3(m88F113, FF416, FF415, FF414, this.f211X[6], 9);
        int FF32 = FF3(FF414, FF3, FF416, FF415, this.f211X[11], 13);
        int FF33 = FF3(FF415, FF32, FF3, FF416, this.f211X[3], 15);
        int FF34 = FF3(FF416, FF33, FF32, FF3, this.f211X[7], 7);
        int FF35 = FF3(FF3, FF34, FF33, FF32, this.f211X[0], 12);
        int FF36 = FF3(FF32, FF35, FF34, FF33, this.f211X[13], 8);
        int FF37 = FF3(FF33, FF36, FF35, FF34, this.f211X[5], 9);
        int FF38 = FF3(FF34, FF37, FF36, FF35, this.f211X[10], 11);
        int FF39 = FF3(FF35, FF38, FF37, FF36, this.f211X[14], 7);
        int FF310 = FF3(FF36, FF39, FF38, FF37, this.f211X[15], 7);
        int FF311 = FF3(FF37, FF310, FF39, FF38, this.f211X[8], 12);
        int FF312 = FF3(FF38, FF311, FF310, FF39, this.f211X[12], 7);
        int FF313 = FF3(FF39, FF312, FF311, FF310, this.f211X[4], 6);
        int FF314 = FF3(FF310, FF313, FF312, FF311, this.f211X[9], 15);
        int FF315 = FF3(FF311, FF314, FF313, FF312, this.f211X[1], 13);
        int FF316 = FF3(FF312, FF315, FF314, FF313, this.f211X[2], 11);
        int m86F3 = m86F3(m87F213, FF316, m87F215, m87F214, this.f211X[3], 11);
        int m86F32 = m86F3(m87F214, m86F3, FF316, m87F215, this.f211X[10], 13);
        int m86F33 = m86F3(m87F215, m86F32, m86F3, FF316, this.f211X[14], 6);
        int m86F34 = m86F3(FF316, m86F33, m86F32, m86F3, this.f211X[4], 7);
        int m86F35 = m86F3(m86F3, m86F34, m86F33, m86F32, this.f211X[9], 14);
        int m86F36 = m86F3(m86F32, m86F35, m86F34, m86F33, this.f211X[15], 9);
        int m86F37 = m86F3(m86F33, m86F36, m86F35, m86F34, this.f211X[8], 13);
        int m86F38 = m86F3(m86F34, m86F37, m86F36, m86F35, this.f211X[1], 15);
        int m86F39 = m86F3(m86F35, m86F38, m86F37, m86F36, this.f211X[2], 14);
        int m86F310 = m86F3(m86F36, m86F39, m86F38, m86F37, this.f211X[7], 8);
        int m86F311 = m86F3(m86F37, m86F310, m86F39, m86F38, this.f211X[0], 13);
        int m86F312 = m86F3(m86F38, m86F311, m86F310, m86F39, this.f211X[6], 6);
        int m86F313 = m86F3(m86F39, m86F312, m86F311, m86F310, this.f211X[13], 5);
        int m86F314 = m86F3(m86F310, m86F313, m86F312, m86F311, this.f211X[11], 12);
        int m86F315 = m86F3(m86F311, m86F314, m86F313, m86F312, this.f211X[5], 7);
        int m86F316 = m86F3(m86F312, m86F315, m86F314, m86F313, this.f211X[12], 5);
        int FF2 = FF2(FF313, m87F216, FF315, FF314, this.f211X[15], 9);
        int FF22 = FF2(FF314, FF2, m87F216, FF315, this.f211X[5], 7);
        int FF23 = FF2(FF315, FF22, FF2, m87F216, this.f211X[1], 15);
        int FF24 = FF2(m87F216, FF23, FF22, FF2, this.f211X[3], 11);
        int FF25 = FF2(FF2, FF24, FF23, FF22, this.f211X[7], 8);
        int FF26 = FF2(FF22, FF25, FF24, FF23, this.f211X[14], 6);
        int FF27 = FF2(FF23, FF26, FF25, FF24, this.f211X[6], 6);
        int FF28 = FF2(FF24, FF27, FF26, FF25, this.f211X[9], 14);
        int FF29 = FF2(FF25, FF28, FF27, FF26, this.f211X[11], 12);
        int FF210 = FF2(FF26, FF29, FF28, FF27, this.f211X[8], 13);
        int FF211 = FF2(FF27, FF210, FF29, FF28, this.f211X[12], 5);
        int FF212 = FF2(FF28, FF211, FF210, FF29, this.f211X[2], 14);
        int FF213 = FF2(FF29, FF212, FF211, FF210, this.f211X[10], 13);
        int FF214 = FF2(FF210, FF213, FF212, FF211, this.f211X[0], 13);
        int FF215 = FF2(FF211, FF214, FF213, FF212, this.f211X[4], 7);
        int FF216 = FF2(FF212, FF215, FF214, FF213, this.f211X[13], 5);
        int m85F4 = m85F4(m86F313, m86F316, FF215, m86F314, this.f211X[1], 11);
        int m85F42 = m85F4(m86F314, m85F4, m86F316, FF215, this.f211X[9], 12);
        int m85F43 = m85F4(FF215, m85F42, m85F4, m86F316, this.f211X[11], 14);
        int m85F44 = m85F4(m86F316, m85F43, m85F42, m85F4, this.f211X[10], 15);
        int m85F45 = m85F4(m85F4, m85F44, m85F43, m85F42, this.f211X[0], 14);
        int m85F46 = m85F4(m85F42, m85F45, m85F44, m85F43, this.f211X[8], 15);
        int m85F47 = m85F4(m85F43, m85F46, m85F45, m85F44, this.f211X[12], 9);
        int m85F48 = m85F4(m85F44, m85F47, m85F46, m85F45, this.f211X[4], 8);
        int m85F49 = m85F4(m85F45, m85F48, m85F47, m85F46, this.f211X[13], 9);
        int m85F410 = m85F4(m85F46, m85F49, m85F48, m85F47, this.f211X[3], 14);
        int m85F411 = m85F4(m85F47, m85F410, m85F49, m85F48, this.f211X[7], 5);
        int m85F412 = m85F4(m85F48, m85F411, m85F410, m85F49, this.f211X[15], 6);
        int m85F413 = m85F4(m85F49, m85F412, m85F411, m85F410, this.f211X[14], 8);
        int m85F414 = m85F4(m85F410, m85F413, m85F412, m85F411, this.f211X[5], 6);
        int m85F415 = m85F4(m85F411, m85F414, m85F413, m85F412, this.f211X[6], 5);
        int m85F416 = m85F4(m85F412, m85F415, m85F414, m85F413, this.f211X[2], 12);
        int FF1 = FF1(FF213, FF216, m86F315, FF214, this.f211X[8], 15);
        int FF12 = FF1(FF214, FF1, FF216, m86F315, this.f211X[6], 5);
        int FF13 = FF1(m86F315, FF12, FF1, FF216, this.f211X[4], 8);
        int FF14 = FF1(FF216, FF13, FF12, FF1, this.f211X[1], 11);
        int FF15 = FF1(FF1, FF14, FF13, FF12, this.f211X[3], 14);
        int FF16 = FF1(FF12, FF15, FF14, FF13, this.f211X[11], 14);
        int FF17 = FF1(FF13, FF16, FF15, FF14, this.f211X[15], 6);
        int FF18 = FF1(FF14, FF17, FF16, FF15, this.f211X[0], 14);
        int FF19 = FF1(FF15, FF18, FF17, FF16, this.f211X[5], 6);
        int FF110 = FF1(FF16, FF19, FF18, FF17, this.f211X[12], 9);
        int FF111 = FF1(FF17, FF110, FF19, FF18, this.f211X[2], 12);
        int FF112 = FF1(FF18, FF111, FF110, FF19, this.f211X[13], 9);
        int FF113 = FF1(FF19, FF112, FF111, FF110, this.f211X[9], 12);
        int FF114 = FF1(FF110, FF113, FF112, FF111, this.f211X[7], 5);
        int FF115 = FF1(FF111, FF114, FF113, FF112, this.f211X[10], 15);
        int FF116 = FF1(FF112, FF115, FF114, FF113, this.f211X[14], 8);
        this.f203H0 += m85F413;
        this.f204H1 += m85F416;
        this.f205H2 += m85F415;
        this.f206H3 += FF114;
        this.f207H4 += FF113;
        this.f208H5 += FF116;
        this.f209H6 += FF115;
        this.f210H7 += m85F414;
        this.xOff = 0;
        for (int i9 = 0; i9 != this.f211X.length; i9++) {
            this.f211X[i9] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD256Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD256Digest) memoable);
    }
}