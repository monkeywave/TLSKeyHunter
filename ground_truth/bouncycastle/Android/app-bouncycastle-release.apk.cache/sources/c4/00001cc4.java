package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class RIPEMD128Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;

    /* renamed from: H0 */
    private int f466H0;

    /* renamed from: H1 */
    private int f467H1;

    /* renamed from: H2 */
    private int f468H2;

    /* renamed from: H3 */
    private int f469H3;

    /* renamed from: X */
    private int[] f470X;
    private int xOff;

    public RIPEMD128Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public RIPEMD128Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f470X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, cryptoServicePurpose));
        reset();
    }

    public RIPEMD128Digest(RIPEMD128Digest rIPEMD128Digest) {
        super(rIPEMD128Digest.purpose);
        this.f470X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, this.purpose));
        copyIn(rIPEMD128Digest);
    }

    /* renamed from: F1 */
    private int m123F1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m118f1(i2, i3, i4) + i5, i6);
    }

    /* renamed from: F2 */
    private int m122F2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m117f2(i2, i3, i4) + i5 + 1518500249, i6);
    }

    /* renamed from: F3 */
    private int m121F3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m116f3(i2, i3, i4) + i5 + 1859775393, i6);
    }

    /* renamed from: F4 */
    private int m120F4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(((i + m115f4(i2, i3, i4)) + i5) - 1894007588, i6);
    }

    private int FF1(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m118f1(i2, i3, i4) + i5, i6);
    }

    private int FF2(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m117f2(i2, i3, i4) + i5 + 1836072691, i6);
    }

    private int FF3(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m116f3(i2, i3, i4) + i5 + 1548603684, i6);
    }

    private int FF4(int i, int i2, int i3, int i4, int i5, int i6) {
        return m119RL(i + m115f4(i2, i3, i4) + i5 + 1352829926, i6);
    }

    /* renamed from: RL */
    private int m119RL(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    private void copyIn(RIPEMD128Digest rIPEMD128Digest) {
        super.copyIn((GeneralDigest) rIPEMD128Digest);
        this.f466H0 = rIPEMD128Digest.f466H0;
        this.f467H1 = rIPEMD128Digest.f467H1;
        this.f468H2 = rIPEMD128Digest.f468H2;
        this.f469H3 = rIPEMD128Digest.f469H3;
        int[] iArr = rIPEMD128Digest.f470X;
        System.arraycopy(iArr, 0, this.f470X, 0, iArr.length);
        this.xOff = rIPEMD128Digest.xOff;
    }

    /* renamed from: f1 */
    private int m118f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m117f2(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: f3 */
    private int m116f3(int i, int i2, int i3) {
        return (i | (~i2)) ^ i3;
    }

    /* renamed from: f4 */
    private int m115f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (~i3));
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD128Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f466H0, bArr, i);
        Pack.intToLittleEndian(this.f467H1, bArr, i + 4);
        Pack.intToLittleEndian(this.f468H2, bArr, i + 8);
        Pack.intToLittleEndian(this.f469H3, bArr, i + 12);
        reset();
        return 16;
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
    protected void processBlock() {
        int i = this.f466H0;
        int i2 = this.f467H1;
        int i3 = this.f468H2;
        int i4 = this.f469H3;
        int m123F1 = m123F1(i, i2, i3, i4, this.f470X[0], 11);
        int m123F12 = m123F1(i4, m123F1, i2, i3, this.f470X[1], 14);
        int m123F13 = m123F1(i3, m123F12, m123F1, i2, this.f470X[2], 15);
        int m123F14 = m123F1(i2, m123F13, m123F12, m123F1, this.f470X[3], 12);
        int m123F15 = m123F1(m123F1, m123F14, m123F13, m123F12, this.f470X[4], 5);
        int m123F16 = m123F1(m123F12, m123F15, m123F14, m123F13, this.f470X[5], 8);
        int m123F17 = m123F1(m123F13, m123F16, m123F15, m123F14, this.f470X[6], 7);
        int m123F18 = m123F1(m123F14, m123F17, m123F16, m123F15, this.f470X[7], 9);
        int m123F19 = m123F1(m123F15, m123F18, m123F17, m123F16, this.f470X[8], 11);
        int m123F110 = m123F1(m123F16, m123F19, m123F18, m123F17, this.f470X[9], 13);
        int m123F111 = m123F1(m123F17, m123F110, m123F19, m123F18, this.f470X[10], 14);
        int m123F112 = m123F1(m123F18, m123F111, m123F110, m123F19, this.f470X[11], 15);
        int m123F113 = m123F1(m123F19, m123F112, m123F111, m123F110, this.f470X[12], 6);
        int m123F114 = m123F1(m123F110, m123F113, m123F112, m123F111, this.f470X[13], 7);
        int m123F115 = m123F1(m123F111, m123F114, m123F113, m123F112, this.f470X[14], 9);
        int m123F116 = m123F1(m123F112, m123F115, m123F114, m123F113, this.f470X[15], 8);
        int m122F2 = m122F2(m123F113, m123F116, m123F115, m123F114, this.f470X[7], 7);
        int m122F22 = m122F2(m123F114, m122F2, m123F116, m123F115, this.f470X[4], 6);
        int m122F23 = m122F2(m123F115, m122F22, m122F2, m123F116, this.f470X[13], 8);
        int m122F24 = m122F2(m123F116, m122F23, m122F22, m122F2, this.f470X[1], 13);
        int m122F25 = m122F2(m122F2, m122F24, m122F23, m122F22, this.f470X[10], 11);
        int m122F26 = m122F2(m122F22, m122F25, m122F24, m122F23, this.f470X[6], 9);
        int m122F27 = m122F2(m122F23, m122F26, m122F25, m122F24, this.f470X[15], 7);
        int m122F28 = m122F2(m122F24, m122F27, m122F26, m122F25, this.f470X[3], 15);
        int m122F29 = m122F2(m122F25, m122F28, m122F27, m122F26, this.f470X[12], 7);
        int m122F210 = m122F2(m122F26, m122F29, m122F28, m122F27, this.f470X[0], 12);
        int m122F211 = m122F2(m122F27, m122F210, m122F29, m122F28, this.f470X[9], 15);
        int m122F212 = m122F2(m122F28, m122F211, m122F210, m122F29, this.f470X[5], 9);
        int m122F213 = m122F2(m122F29, m122F212, m122F211, m122F210, this.f470X[2], 11);
        int m122F214 = m122F2(m122F210, m122F213, m122F212, m122F211, this.f470X[14], 7);
        int m122F215 = m122F2(m122F211, m122F214, m122F213, m122F212, this.f470X[11], 13);
        int m122F216 = m122F2(m122F212, m122F215, m122F214, m122F213, this.f470X[8], 12);
        int m121F3 = m121F3(m122F213, m122F216, m122F215, m122F214, this.f470X[3], 11);
        int m121F32 = m121F3(m122F214, m121F3, m122F216, m122F215, this.f470X[10], 13);
        int m121F33 = m121F3(m122F215, m121F32, m121F3, m122F216, this.f470X[14], 6);
        int m121F34 = m121F3(m122F216, m121F33, m121F32, m121F3, this.f470X[4], 7);
        int m121F35 = m121F3(m121F3, m121F34, m121F33, m121F32, this.f470X[9], 14);
        int m121F36 = m121F3(m121F32, m121F35, m121F34, m121F33, this.f470X[15], 9);
        int m121F37 = m121F3(m121F33, m121F36, m121F35, m121F34, this.f470X[8], 13);
        int m121F38 = m121F3(m121F34, m121F37, m121F36, m121F35, this.f470X[1], 15);
        int m121F39 = m121F3(m121F35, m121F38, m121F37, m121F36, this.f470X[2], 14);
        int m121F310 = m121F3(m121F36, m121F39, m121F38, m121F37, this.f470X[7], 8);
        int m121F311 = m121F3(m121F37, m121F310, m121F39, m121F38, this.f470X[0], 13);
        int m121F312 = m121F3(m121F38, m121F311, m121F310, m121F39, this.f470X[6], 6);
        int m121F313 = m121F3(m121F39, m121F312, m121F311, m121F310, this.f470X[13], 5);
        int m121F314 = m121F3(m121F310, m121F313, m121F312, m121F311, this.f470X[11], 12);
        int m121F315 = m121F3(m121F311, m121F314, m121F313, m121F312, this.f470X[5], 7);
        int m121F316 = m121F3(m121F312, m121F315, m121F314, m121F313, this.f470X[12], 5);
        int m120F4 = m120F4(m121F313, m121F316, m121F315, m121F314, this.f470X[1], 11);
        int m120F42 = m120F4(m121F314, m120F4, m121F316, m121F315, this.f470X[9], 12);
        int m120F43 = m120F4(m121F315, m120F42, m120F4, m121F316, this.f470X[11], 14);
        int m120F44 = m120F4(m121F316, m120F43, m120F42, m120F4, this.f470X[10], 15);
        int m120F45 = m120F4(m120F4, m120F44, m120F43, m120F42, this.f470X[0], 14);
        int m120F46 = m120F4(m120F42, m120F45, m120F44, m120F43, this.f470X[8], 15);
        int m120F47 = m120F4(m120F43, m120F46, m120F45, m120F44, this.f470X[12], 9);
        int m120F48 = m120F4(m120F44, m120F47, m120F46, m120F45, this.f470X[4], 8);
        int m120F49 = m120F4(m120F45, m120F48, m120F47, m120F46, this.f470X[13], 9);
        int m120F410 = m120F4(m120F46, m120F49, m120F48, m120F47, this.f470X[3], 14);
        int m120F411 = m120F4(m120F47, m120F410, m120F49, m120F48, this.f470X[7], 5);
        int m120F412 = m120F4(m120F48, m120F411, m120F410, m120F49, this.f470X[15], 6);
        int m120F413 = m120F4(m120F49, m120F412, m120F411, m120F410, this.f470X[14], 8);
        int m120F414 = m120F4(m120F410, m120F413, m120F412, m120F411, this.f470X[5], 6);
        int m120F415 = m120F4(m120F411, m120F414, m120F413, m120F412, this.f470X[6], 5);
        int m120F416 = m120F4(m120F412, m120F415, m120F414, m120F413, this.f470X[2], 12);
        int FF4 = FF4(i, i2, i3, i4, this.f470X[5], 8);
        int FF42 = FF4(i4, FF4, i2, i3, this.f470X[14], 9);
        int FF43 = FF4(i3, FF42, FF4, i2, this.f470X[7], 9);
        int FF44 = FF4(i2, FF43, FF42, FF4, this.f470X[0], 11);
        int FF45 = FF4(FF4, FF44, FF43, FF42, this.f470X[9], 13);
        int FF46 = FF4(FF42, FF45, FF44, FF43, this.f470X[2], 15);
        int FF47 = FF4(FF43, FF46, FF45, FF44, this.f470X[11], 15);
        int FF48 = FF4(FF44, FF47, FF46, FF45, this.f470X[4], 5);
        int FF49 = FF4(FF45, FF48, FF47, FF46, this.f470X[13], 7);
        int FF410 = FF4(FF46, FF49, FF48, FF47, this.f470X[6], 7);
        int FF411 = FF4(FF47, FF410, FF49, FF48, this.f470X[15], 8);
        int FF412 = FF4(FF48, FF411, FF410, FF49, this.f470X[8], 11);
        int FF413 = FF4(FF49, FF412, FF411, FF410, this.f470X[1], 14);
        int FF414 = FF4(FF410, FF413, FF412, FF411, this.f470X[10], 14);
        int FF415 = FF4(FF411, FF414, FF413, FF412, this.f470X[3], 12);
        int FF416 = FF4(FF412, FF415, FF414, FF413, this.f470X[12], 6);
        int FF3 = FF3(FF413, FF416, FF415, FF414, this.f470X[6], 9);
        int FF32 = FF3(FF414, FF3, FF416, FF415, this.f470X[11], 13);
        int FF33 = FF3(FF415, FF32, FF3, FF416, this.f470X[3], 15);
        int FF34 = FF3(FF416, FF33, FF32, FF3, this.f470X[7], 7);
        int FF35 = FF3(FF3, FF34, FF33, FF32, this.f470X[0], 12);
        int FF36 = FF3(FF32, FF35, FF34, FF33, this.f470X[13], 8);
        int FF37 = FF3(FF33, FF36, FF35, FF34, this.f470X[5], 9);
        int FF38 = FF3(FF34, FF37, FF36, FF35, this.f470X[10], 11);
        int FF39 = FF3(FF35, FF38, FF37, FF36, this.f470X[14], 7);
        int FF310 = FF3(FF36, FF39, FF38, FF37, this.f470X[15], 7);
        int FF311 = FF3(FF37, FF310, FF39, FF38, this.f470X[8], 12);
        int FF312 = FF3(FF38, FF311, FF310, FF39, this.f470X[12], 7);
        int FF313 = FF3(FF39, FF312, FF311, FF310, this.f470X[4], 6);
        int FF314 = FF3(FF310, FF313, FF312, FF311, this.f470X[9], 15);
        int FF315 = FF3(FF311, FF314, FF313, FF312, this.f470X[1], 13);
        int FF316 = FF3(FF312, FF315, FF314, FF313, this.f470X[2], 11);
        int FF2 = FF2(FF313, FF316, FF315, FF314, this.f470X[15], 9);
        int FF22 = FF2(FF314, FF2, FF316, FF315, this.f470X[5], 7);
        int FF23 = FF2(FF315, FF22, FF2, FF316, this.f470X[1], 15);
        int FF24 = FF2(FF316, FF23, FF22, FF2, this.f470X[3], 11);
        int FF25 = FF2(FF2, FF24, FF23, FF22, this.f470X[7], 8);
        int FF26 = FF2(FF22, FF25, FF24, FF23, this.f470X[14], 6);
        int FF27 = FF2(FF23, FF26, FF25, FF24, this.f470X[6], 6);
        int FF28 = FF2(FF24, FF27, FF26, FF25, this.f470X[9], 14);
        int FF29 = FF2(FF25, FF28, FF27, FF26, this.f470X[11], 12);
        int FF210 = FF2(FF26, FF29, FF28, FF27, this.f470X[8], 13);
        int FF211 = FF2(FF27, FF210, FF29, FF28, this.f470X[12], 5);
        int FF212 = FF2(FF28, FF211, FF210, FF29, this.f470X[2], 14);
        int FF213 = FF2(FF29, FF212, FF211, FF210, this.f470X[10], 13);
        int FF214 = FF2(FF210, FF213, FF212, FF211, this.f470X[0], 13);
        int FF215 = FF2(FF211, FF214, FF213, FF212, this.f470X[4], 7);
        int FF216 = FF2(FF212, FF215, FF214, FF213, this.f470X[13], 5);
        int FF1 = FF1(FF213, FF216, FF215, FF214, this.f470X[8], 15);
        int FF12 = FF1(FF214, FF1, FF216, FF215, this.f470X[6], 5);
        int FF13 = FF1(FF215, FF12, FF1, FF216, this.f470X[4], 8);
        int FF14 = FF1(FF216, FF13, FF12, FF1, this.f470X[1], 11);
        int FF15 = FF1(FF1, FF14, FF13, FF12, this.f470X[3], 14);
        int FF16 = FF1(FF12, FF15, FF14, FF13, this.f470X[11], 14);
        int FF17 = FF1(FF13, FF16, FF15, FF14, this.f470X[15], 6);
        int FF18 = FF1(FF14, FF17, FF16, FF15, this.f470X[0], 14);
        int FF19 = FF1(FF15, FF18, FF17, FF16, this.f470X[5], 6);
        int FF110 = FF1(FF16, FF19, FF18, FF17, this.f470X[12], 9);
        int FF111 = FF1(FF17, FF110, FF19, FF18, this.f470X[2], 12);
        int FF112 = FF1(FF18, FF111, FF110, FF19, this.f470X[13], 9);
        int FF113 = FF1(FF19, FF112, FF111, FF110, this.f470X[9], 12);
        int FF114 = FF1(FF110, FF113, FF112, FF111, this.f470X[7], 5);
        int FF115 = FF1(FF111, FF114, FF113, FF112, this.f470X[10], 15);
        int FF116 = FF1(FF112, FF115, FF114, FF113, this.f470X[14], 8);
        this.f467H1 = this.f468H2 + m120F414 + FF113;
        this.f468H2 = this.f469H3 + m120F413 + FF116;
        this.f469H3 = this.f466H0 + m120F416 + FF115;
        this.f466H0 = FF114 + m120F415 + this.f467H1;
        this.xOff = 0;
        int i5 = 0;
        while (true) {
            int[] iArr = this.f470X;
            if (i5 == iArr.length) {
                return;
            }
            iArr[i5] = 0;
            i5++;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        int[] iArr = this.f470X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f470X;
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
        this.f466H0 = 1732584193;
        this.f467H1 = -271733879;
        this.f468H2 = -1732584194;
        this.f469H3 = 271733878;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f470X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD128Digest) memoable);
    }
}