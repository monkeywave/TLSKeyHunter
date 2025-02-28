package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/RIPEMD128Digest.class */
public class RIPEMD128Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;

    /* renamed from: H0 */
    private int f192H0;

    /* renamed from: H1 */
    private int f193H1;

    /* renamed from: H2 */
    private int f194H2;

    /* renamed from: H3 */
    private int f195H3;

    /* renamed from: X */
    private int[] f196X;
    private int xOff;

    public RIPEMD128Digest() {
        this.f196X = new int[16];
        reset();
    }

    public RIPEMD128Digest(RIPEMD128Digest rIPEMD128Digest) {
        super(rIPEMD128Digest);
        this.f196X = new int[16];
        copyIn(rIPEMD128Digest);
    }

    private void copyIn(RIPEMD128Digest rIPEMD128Digest) {
        super.copyIn((GeneralDigest) rIPEMD128Digest);
        this.f192H0 = rIPEMD128Digest.f192H0;
        this.f193H1 = rIPEMD128Digest.f193H1;
        this.f194H2 = rIPEMD128Digest.f194H2;
        this.f195H3 = rIPEMD128Digest.f195H3;
        System.arraycopy(rIPEMD128Digest.f196X, 0, this.f196X, 0, rIPEMD128Digest.f196X.length);
        this.xOff = rIPEMD128Digest.xOff;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "RIPEMD128";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f196X;
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
        this.f196X[14] = (int) (j & (-1));
        this.f196X[15] = (int) (j >>> 32);
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
        unpackWord(this.f192H0, bArr, i);
        unpackWord(this.f193H1, bArr, i + 4);
        unpackWord(this.f194H2, bArr, i + 8);
        unpackWord(this.f195H3, bArr, i + 12);
        reset();
        return 16;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f192H0 = 1732584193;
        this.f193H1 = -271733879;
        this.f194H2 = -1732584194;
        this.f195H3 = 271733878;
        this.xOff = 0;
        for (int i = 0; i != this.f196X.length; i++) {
            this.f196X[i] = 0;
        }
    }

    /* renamed from: RL */
    private int m99RL(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    /* renamed from: f1 */
    private int m98f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m97f2(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: f3 */
    private int m96f3(int i, int i2, int i3) {
        return (i | (i2 ^ (-1))) ^ i3;
    }

    /* renamed from: f4 */
    private int m95f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (i3 ^ (-1)));
    }

    /* renamed from: F1 */
    private int m103F1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m98f1(i2, i3, i4) + i5, i6);
    }

    /* renamed from: F2 */
    private int m102F2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m97f2(i2, i3, i4) + i5 + 1518500249, i6);
    }

    /* renamed from: F3 */
    private int m101F3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m96f3(i2, i3, i4) + i5 + 1859775393, i6);
    }

    /* renamed from: F4 */
    private int m100F4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(((i + m95f4(i2, i3, i4)) + i5) - 1894007588, i6);
    }

    private int FF1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m98f1(i2, i3, i4) + i5, i6);
    }

    private int FF2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m97f2(i2, i3, i4) + i5 + 1836072691, i6);
    }

    private int FF3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m96f3(i2, i3, i4) + i5 + 1548603684, i6);
    }

    private int FF4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m99RL(i + m95f4(i2, i3, i4) + i5 + 1352829926, i6);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f192H0;
        int i2 = this.f193H1;
        int i3 = this.f194H2;
        int i4 = this.f195H3;
        int m103F1 = m103F1(i, i2, i3, i4, this.f196X[0], 11);
        int m103F12 = m103F1(i4, m103F1, i2, i3, this.f196X[1], 14);
        int m103F13 = m103F1(i3, m103F12, m103F1, i2, this.f196X[2], 15);
        int m103F14 = m103F1(i2, m103F13, m103F12, m103F1, this.f196X[3], 12);
        int m103F15 = m103F1(m103F1, m103F14, m103F13, m103F12, this.f196X[4], 5);
        int m103F16 = m103F1(m103F12, m103F15, m103F14, m103F13, this.f196X[5], 8);
        int m103F17 = m103F1(m103F13, m103F16, m103F15, m103F14, this.f196X[6], 7);
        int m103F18 = m103F1(m103F14, m103F17, m103F16, m103F15, this.f196X[7], 9);
        int m103F19 = m103F1(m103F15, m103F18, m103F17, m103F16, this.f196X[8], 11);
        int m103F110 = m103F1(m103F16, m103F19, m103F18, m103F17, this.f196X[9], 13);
        int m103F111 = m103F1(m103F17, m103F110, m103F19, m103F18, this.f196X[10], 14);
        int m103F112 = m103F1(m103F18, m103F111, m103F110, m103F19, this.f196X[11], 15);
        int m103F113 = m103F1(m103F19, m103F112, m103F111, m103F110, this.f196X[12], 6);
        int m103F114 = m103F1(m103F110, m103F113, m103F112, m103F111, this.f196X[13], 7);
        int m103F115 = m103F1(m103F111, m103F114, m103F113, m103F112, this.f196X[14], 9);
        int m103F116 = m103F1(m103F112, m103F115, m103F114, m103F113, this.f196X[15], 8);
        int m102F2 = m102F2(m103F113, m103F116, m103F115, m103F114, this.f196X[7], 7);
        int m102F22 = m102F2(m103F114, m102F2, m103F116, m103F115, this.f196X[4], 6);
        int m102F23 = m102F2(m103F115, m102F22, m102F2, m103F116, this.f196X[13], 8);
        int m102F24 = m102F2(m103F116, m102F23, m102F22, m102F2, this.f196X[1], 13);
        int m102F25 = m102F2(m102F2, m102F24, m102F23, m102F22, this.f196X[10], 11);
        int m102F26 = m102F2(m102F22, m102F25, m102F24, m102F23, this.f196X[6], 9);
        int m102F27 = m102F2(m102F23, m102F26, m102F25, m102F24, this.f196X[15], 7);
        int m102F28 = m102F2(m102F24, m102F27, m102F26, m102F25, this.f196X[3], 15);
        int m102F29 = m102F2(m102F25, m102F28, m102F27, m102F26, this.f196X[12], 7);
        int m102F210 = m102F2(m102F26, m102F29, m102F28, m102F27, this.f196X[0], 12);
        int m102F211 = m102F2(m102F27, m102F210, m102F29, m102F28, this.f196X[9], 15);
        int m102F212 = m102F2(m102F28, m102F211, m102F210, m102F29, this.f196X[5], 9);
        int m102F213 = m102F2(m102F29, m102F212, m102F211, m102F210, this.f196X[2], 11);
        int m102F214 = m102F2(m102F210, m102F213, m102F212, m102F211, this.f196X[14], 7);
        int m102F215 = m102F2(m102F211, m102F214, m102F213, m102F212, this.f196X[11], 13);
        int m102F216 = m102F2(m102F212, m102F215, m102F214, m102F213, this.f196X[8], 12);
        int m101F3 = m101F3(m102F213, m102F216, m102F215, m102F214, this.f196X[3], 11);
        int m101F32 = m101F3(m102F214, m101F3, m102F216, m102F215, this.f196X[10], 13);
        int m101F33 = m101F3(m102F215, m101F32, m101F3, m102F216, this.f196X[14], 6);
        int m101F34 = m101F3(m102F216, m101F33, m101F32, m101F3, this.f196X[4], 7);
        int m101F35 = m101F3(m101F3, m101F34, m101F33, m101F32, this.f196X[9], 14);
        int m101F36 = m101F3(m101F32, m101F35, m101F34, m101F33, this.f196X[15], 9);
        int m101F37 = m101F3(m101F33, m101F36, m101F35, m101F34, this.f196X[8], 13);
        int m101F38 = m101F3(m101F34, m101F37, m101F36, m101F35, this.f196X[1], 15);
        int m101F39 = m101F3(m101F35, m101F38, m101F37, m101F36, this.f196X[2], 14);
        int m101F310 = m101F3(m101F36, m101F39, m101F38, m101F37, this.f196X[7], 8);
        int m101F311 = m101F3(m101F37, m101F310, m101F39, m101F38, this.f196X[0], 13);
        int m101F312 = m101F3(m101F38, m101F311, m101F310, m101F39, this.f196X[6], 6);
        int m101F313 = m101F3(m101F39, m101F312, m101F311, m101F310, this.f196X[13], 5);
        int m101F314 = m101F3(m101F310, m101F313, m101F312, m101F311, this.f196X[11], 12);
        int m101F315 = m101F3(m101F311, m101F314, m101F313, m101F312, this.f196X[5], 7);
        int m101F316 = m101F3(m101F312, m101F315, m101F314, m101F313, this.f196X[12], 5);
        int m100F4 = m100F4(m101F313, m101F316, m101F315, m101F314, this.f196X[1], 11);
        int m100F42 = m100F4(m101F314, m100F4, m101F316, m101F315, this.f196X[9], 12);
        int m100F43 = m100F4(m101F315, m100F42, m100F4, m101F316, this.f196X[11], 14);
        int m100F44 = m100F4(m101F316, m100F43, m100F42, m100F4, this.f196X[10], 15);
        int m100F45 = m100F4(m100F4, m100F44, m100F43, m100F42, this.f196X[0], 14);
        int m100F46 = m100F4(m100F42, m100F45, m100F44, m100F43, this.f196X[8], 15);
        int m100F47 = m100F4(m100F43, m100F46, m100F45, m100F44, this.f196X[12], 9);
        int m100F48 = m100F4(m100F44, m100F47, m100F46, m100F45, this.f196X[4], 8);
        int m100F49 = m100F4(m100F45, m100F48, m100F47, m100F46, this.f196X[13], 9);
        int m100F410 = m100F4(m100F46, m100F49, m100F48, m100F47, this.f196X[3], 14);
        int m100F411 = m100F4(m100F47, m100F410, m100F49, m100F48, this.f196X[7], 5);
        int m100F412 = m100F4(m100F48, m100F411, m100F410, m100F49, this.f196X[15], 6);
        int m100F413 = m100F4(m100F49, m100F412, m100F411, m100F410, this.f196X[14], 8);
        int m100F414 = m100F4(m100F410, m100F413, m100F412, m100F411, this.f196X[5], 6);
        int m100F415 = m100F4(m100F411, m100F414, m100F413, m100F412, this.f196X[6], 5);
        int m100F416 = m100F4(m100F412, m100F415, m100F414, m100F413, this.f196X[2], 12);
        int FF4 = FF4(i, i2, i3, i4, this.f196X[5], 8);
        int FF42 = FF4(i4, FF4, i2, i3, this.f196X[14], 9);
        int FF43 = FF4(i3, FF42, FF4, i2, this.f196X[7], 9);
        int FF44 = FF4(i2, FF43, FF42, FF4, this.f196X[0], 11);
        int FF45 = FF4(FF4, FF44, FF43, FF42, this.f196X[9], 13);
        int FF46 = FF4(FF42, FF45, FF44, FF43, this.f196X[2], 15);
        int FF47 = FF4(FF43, FF46, FF45, FF44, this.f196X[11], 15);
        int FF48 = FF4(FF44, FF47, FF46, FF45, this.f196X[4], 5);
        int FF49 = FF4(FF45, FF48, FF47, FF46, this.f196X[13], 7);
        int FF410 = FF4(FF46, FF49, FF48, FF47, this.f196X[6], 7);
        int FF411 = FF4(FF47, FF410, FF49, FF48, this.f196X[15], 8);
        int FF412 = FF4(FF48, FF411, FF410, FF49, this.f196X[8], 11);
        int FF413 = FF4(FF49, FF412, FF411, FF410, this.f196X[1], 14);
        int FF414 = FF4(FF410, FF413, FF412, FF411, this.f196X[10], 14);
        int FF415 = FF4(FF411, FF414, FF413, FF412, this.f196X[3], 12);
        int FF416 = FF4(FF412, FF415, FF414, FF413, this.f196X[12], 6);
        int FF3 = FF3(FF413, FF416, FF415, FF414, this.f196X[6], 9);
        int FF32 = FF3(FF414, FF3, FF416, FF415, this.f196X[11], 13);
        int FF33 = FF3(FF415, FF32, FF3, FF416, this.f196X[3], 15);
        int FF34 = FF3(FF416, FF33, FF32, FF3, this.f196X[7], 7);
        int FF35 = FF3(FF3, FF34, FF33, FF32, this.f196X[0], 12);
        int FF36 = FF3(FF32, FF35, FF34, FF33, this.f196X[13], 8);
        int FF37 = FF3(FF33, FF36, FF35, FF34, this.f196X[5], 9);
        int FF38 = FF3(FF34, FF37, FF36, FF35, this.f196X[10], 11);
        int FF39 = FF3(FF35, FF38, FF37, FF36, this.f196X[14], 7);
        int FF310 = FF3(FF36, FF39, FF38, FF37, this.f196X[15], 7);
        int FF311 = FF3(FF37, FF310, FF39, FF38, this.f196X[8], 12);
        int FF312 = FF3(FF38, FF311, FF310, FF39, this.f196X[12], 7);
        int FF313 = FF3(FF39, FF312, FF311, FF310, this.f196X[4], 6);
        int FF314 = FF3(FF310, FF313, FF312, FF311, this.f196X[9], 15);
        int FF315 = FF3(FF311, FF314, FF313, FF312, this.f196X[1], 13);
        int FF316 = FF3(FF312, FF315, FF314, FF313, this.f196X[2], 11);
        int FF2 = FF2(FF313, FF316, FF315, FF314, this.f196X[15], 9);
        int FF22 = FF2(FF314, FF2, FF316, FF315, this.f196X[5], 7);
        int FF23 = FF2(FF315, FF22, FF2, FF316, this.f196X[1], 15);
        int FF24 = FF2(FF316, FF23, FF22, FF2, this.f196X[3], 11);
        int FF25 = FF2(FF2, FF24, FF23, FF22, this.f196X[7], 8);
        int FF26 = FF2(FF22, FF25, FF24, FF23, this.f196X[14], 6);
        int FF27 = FF2(FF23, FF26, FF25, FF24, this.f196X[6], 6);
        int FF28 = FF2(FF24, FF27, FF26, FF25, this.f196X[9], 14);
        int FF29 = FF2(FF25, FF28, FF27, FF26, this.f196X[11], 12);
        int FF210 = FF2(FF26, FF29, FF28, FF27, this.f196X[8], 13);
        int FF211 = FF2(FF27, FF210, FF29, FF28, this.f196X[12], 5);
        int FF212 = FF2(FF28, FF211, FF210, FF29, this.f196X[2], 14);
        int FF213 = FF2(FF29, FF212, FF211, FF210, this.f196X[10], 13);
        int FF214 = FF2(FF210, FF213, FF212, FF211, this.f196X[0], 13);
        int FF215 = FF2(FF211, FF214, FF213, FF212, this.f196X[4], 7);
        int FF216 = FF2(FF212, FF215, FF214, FF213, this.f196X[13], 5);
        int FF1 = FF1(FF213, FF216, FF215, FF214, this.f196X[8], 15);
        int FF12 = FF1(FF214, FF1, FF216, FF215, this.f196X[6], 5);
        int FF13 = FF1(FF215, FF12, FF1, FF216, this.f196X[4], 8);
        int FF14 = FF1(FF216, FF13, FF12, FF1, this.f196X[1], 11);
        int FF15 = FF1(FF1, FF14, FF13, FF12, this.f196X[3], 14);
        int FF16 = FF1(FF12, FF15, FF14, FF13, this.f196X[11], 14);
        int FF17 = FF1(FF13, FF16, FF15, FF14, this.f196X[15], 6);
        int FF18 = FF1(FF14, FF17, FF16, FF15, this.f196X[0], 14);
        int FF19 = FF1(FF15, FF18, FF17, FF16, this.f196X[5], 6);
        int FF110 = FF1(FF16, FF19, FF18, FF17, this.f196X[12], 9);
        int FF111 = FF1(FF17, FF110, FF19, FF18, this.f196X[2], 12);
        int FF112 = FF1(FF18, FF111, FF110, FF19, this.f196X[13], 9);
        int FF113 = FF1(FF19, FF112, FF111, FF110, this.f196X[9], 12);
        int FF114 = FF1(FF110, FF113, FF112, FF111, this.f196X[7], 5);
        int FF115 = FF1(FF111, FF114, FF113, FF112, this.f196X[10], 15);
        int FF116 = FF1(FF112, FF115, FF114, FF113, this.f196X[14], 8);
        int i5 = FF114 + m100F415 + this.f193H1;
        this.f193H1 = this.f194H2 + m100F414 + FF113;
        this.f194H2 = this.f195H3 + m100F413 + FF116;
        this.f195H3 = this.f192H0 + m100F416 + FF115;
        this.f192H0 = i5;
        this.xOff = 0;
        for (int i6 = 0; i6 != this.f196X.length; i6++) {
            this.f196X[i6] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD128Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD128Digest) memoable);
    }
}