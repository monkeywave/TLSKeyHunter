package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class MD4Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;
    private static final int S11 = 3;
    private static final int S12 = 7;
    private static final int S13 = 11;
    private static final int S14 = 19;
    private static final int S21 = 3;
    private static final int S22 = 5;
    private static final int S23 = 9;
    private static final int S24 = 13;
    private static final int S31 = 3;
    private static final int S32 = 9;
    private static final int S33 = 11;
    private static final int S34 = 15;

    /* renamed from: H1 */
    private int f450H1;

    /* renamed from: H2 */
    private int f451H2;

    /* renamed from: H3 */
    private int f452H3;

    /* renamed from: H4 */
    private int f453H4;

    /* renamed from: X */
    private int[] f454X;
    private int xOff;

    public MD4Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public MD4Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f454X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 64, cryptoServicePurpose));
        reset();
    }

    public MD4Digest(MD4Digest mD4Digest) {
        super(mD4Digest.purpose);
        this.f454X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 64, this.purpose));
        copyIn(mD4Digest);
    }

    /* renamed from: F */
    private int m130F(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: G */
    private int m129G(int i, int i2, int i3) {
        return (i & (i2 | i3)) | (i2 & i3);
    }

    /* renamed from: H */
    private int m128H(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    private void copyIn(MD4Digest mD4Digest) {
        super.copyIn((GeneralDigest) mD4Digest);
        this.f450H1 = mD4Digest.f450H1;
        this.f451H2 = mD4Digest.f451H2;
        this.f452H3 = mD4Digest.f452H3;
        this.f453H4 = mD4Digest.f453H4;
        int[] iArr = mD4Digest.f454X;
        System.arraycopy(iArr, 0, this.f454X, 0, iArr.length);
        this.xOff = mD4Digest.xOff;
    }

    private int rotateLeft(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new MD4Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f450H1, bArr, i);
        Pack.intToLittleEndian(this.f451H2, bArr, i + 4);
        Pack.intToLittleEndian(this.f452H3, bArr, i + 8);
        Pack.intToLittleEndian(this.f453H4, bArr, i + 12);
        reset();
        return 16;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "MD4";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f450H1;
        int i2 = this.f451H2;
        int i3 = this.f452H3;
        int i4 = this.f453H4;
        int rotateLeft = rotateLeft(i + m130F(i2, i3, i4) + this.f454X[0], 3);
        int rotateLeft2 = rotateLeft(i4 + m130F(rotateLeft, i2, i3) + this.f454X[1], 7);
        int rotateLeft3 = rotateLeft(i3 + m130F(rotateLeft2, rotateLeft, i2) + this.f454X[2], 11);
        int rotateLeft4 = rotateLeft(i2 + m130F(rotateLeft3, rotateLeft2, rotateLeft) + this.f454X[3], 19);
        int rotateLeft5 = rotateLeft(rotateLeft + m130F(rotateLeft4, rotateLeft3, rotateLeft2) + this.f454X[4], 3);
        int rotateLeft6 = rotateLeft(rotateLeft2 + m130F(rotateLeft5, rotateLeft4, rotateLeft3) + this.f454X[5], 7);
        int rotateLeft7 = rotateLeft(rotateLeft3 + m130F(rotateLeft6, rotateLeft5, rotateLeft4) + this.f454X[6], 11);
        int rotateLeft8 = rotateLeft(rotateLeft4 + m130F(rotateLeft7, rotateLeft6, rotateLeft5) + this.f454X[7], 19);
        int rotateLeft9 = rotateLeft(rotateLeft5 + m130F(rotateLeft8, rotateLeft7, rotateLeft6) + this.f454X[8], 3);
        int rotateLeft10 = rotateLeft(rotateLeft6 + m130F(rotateLeft9, rotateLeft8, rotateLeft7) + this.f454X[9], 7);
        int rotateLeft11 = rotateLeft(rotateLeft7 + m130F(rotateLeft10, rotateLeft9, rotateLeft8) + this.f454X[10], 11);
        int rotateLeft12 = rotateLeft(rotateLeft8 + m130F(rotateLeft11, rotateLeft10, rotateLeft9) + this.f454X[11], 19);
        int rotateLeft13 = rotateLeft(rotateLeft9 + m130F(rotateLeft12, rotateLeft11, rotateLeft10) + this.f454X[12], 3);
        int rotateLeft14 = rotateLeft(rotateLeft10 + m130F(rotateLeft13, rotateLeft12, rotateLeft11) + this.f454X[13], 7);
        int rotateLeft15 = rotateLeft(rotateLeft11 + m130F(rotateLeft14, rotateLeft13, rotateLeft12) + this.f454X[14], 11);
        int rotateLeft16 = rotateLeft(rotateLeft12 + m130F(rotateLeft15, rotateLeft14, rotateLeft13) + this.f454X[15], 19);
        int rotateLeft17 = rotateLeft(rotateLeft13 + m129G(rotateLeft16, rotateLeft15, rotateLeft14) + this.f454X[0] + 1518500249, 3);
        int rotateLeft18 = rotateLeft(rotateLeft14 + m129G(rotateLeft17, rotateLeft16, rotateLeft15) + this.f454X[4] + 1518500249, 5);
        int rotateLeft19 = rotateLeft(rotateLeft15 + m129G(rotateLeft18, rotateLeft17, rotateLeft16) + this.f454X[8] + 1518500249, 9);
        int rotateLeft20 = rotateLeft(rotateLeft16 + m129G(rotateLeft19, rotateLeft18, rotateLeft17) + this.f454X[12] + 1518500249, 13);
        int rotateLeft21 = rotateLeft(rotateLeft17 + m129G(rotateLeft20, rotateLeft19, rotateLeft18) + this.f454X[1] + 1518500249, 3);
        int rotateLeft22 = rotateLeft(rotateLeft18 + m129G(rotateLeft21, rotateLeft20, rotateLeft19) + this.f454X[5] + 1518500249, 5);
        int rotateLeft23 = rotateLeft(rotateLeft19 + m129G(rotateLeft22, rotateLeft21, rotateLeft20) + this.f454X[9] + 1518500249, 9);
        int rotateLeft24 = rotateLeft(rotateLeft20 + m129G(rotateLeft23, rotateLeft22, rotateLeft21) + this.f454X[13] + 1518500249, 13);
        int rotateLeft25 = rotateLeft(rotateLeft21 + m129G(rotateLeft24, rotateLeft23, rotateLeft22) + this.f454X[2] + 1518500249, 3);
        int rotateLeft26 = rotateLeft(rotateLeft22 + m129G(rotateLeft25, rotateLeft24, rotateLeft23) + this.f454X[6] + 1518500249, 5);
        int rotateLeft27 = rotateLeft(rotateLeft23 + m129G(rotateLeft26, rotateLeft25, rotateLeft24) + this.f454X[10] + 1518500249, 9);
        int rotateLeft28 = rotateLeft(rotateLeft24 + m129G(rotateLeft27, rotateLeft26, rotateLeft25) + this.f454X[14] + 1518500249, 13);
        int rotateLeft29 = rotateLeft(rotateLeft25 + m129G(rotateLeft28, rotateLeft27, rotateLeft26) + this.f454X[3] + 1518500249, 3);
        int rotateLeft30 = rotateLeft(rotateLeft26 + m129G(rotateLeft29, rotateLeft28, rotateLeft27) + this.f454X[7] + 1518500249, 5);
        int rotateLeft31 = rotateLeft(rotateLeft27 + m129G(rotateLeft30, rotateLeft29, rotateLeft28) + this.f454X[11] + 1518500249, 9);
        int rotateLeft32 = rotateLeft(rotateLeft28 + m129G(rotateLeft31, rotateLeft30, rotateLeft29) + this.f454X[15] + 1518500249, 13);
        int rotateLeft33 = rotateLeft(rotateLeft29 + m128H(rotateLeft32, rotateLeft31, rotateLeft30) + this.f454X[0] + 1859775393, 3);
        int rotateLeft34 = rotateLeft(rotateLeft30 + m128H(rotateLeft33, rotateLeft32, rotateLeft31) + this.f454X[8] + 1859775393, 9);
        int rotateLeft35 = rotateLeft(rotateLeft31 + m128H(rotateLeft34, rotateLeft33, rotateLeft32) + this.f454X[4] + 1859775393, 11);
        int rotateLeft36 = rotateLeft(rotateLeft32 + m128H(rotateLeft35, rotateLeft34, rotateLeft33) + this.f454X[12] + 1859775393, 15);
        int rotateLeft37 = rotateLeft(rotateLeft33 + m128H(rotateLeft36, rotateLeft35, rotateLeft34) + this.f454X[2] + 1859775393, 3);
        int rotateLeft38 = rotateLeft(rotateLeft34 + m128H(rotateLeft37, rotateLeft36, rotateLeft35) + this.f454X[10] + 1859775393, 9);
        int rotateLeft39 = rotateLeft(rotateLeft35 + m128H(rotateLeft38, rotateLeft37, rotateLeft36) + this.f454X[6] + 1859775393, 11);
        int rotateLeft40 = rotateLeft(rotateLeft36 + m128H(rotateLeft39, rotateLeft38, rotateLeft37) + this.f454X[14] + 1859775393, 15);
        int rotateLeft41 = rotateLeft(rotateLeft37 + m128H(rotateLeft40, rotateLeft39, rotateLeft38) + this.f454X[1] + 1859775393, 3);
        int rotateLeft42 = rotateLeft(rotateLeft38 + m128H(rotateLeft41, rotateLeft40, rotateLeft39) + this.f454X[9] + 1859775393, 9);
        int rotateLeft43 = rotateLeft(rotateLeft39 + m128H(rotateLeft42, rotateLeft41, rotateLeft40) + this.f454X[5] + 1859775393, 11);
        int rotateLeft44 = rotateLeft(rotateLeft40 + m128H(rotateLeft43, rotateLeft42, rotateLeft41) + this.f454X[13] + 1859775393, 15);
        int rotateLeft45 = rotateLeft(rotateLeft41 + m128H(rotateLeft44, rotateLeft43, rotateLeft42) + this.f454X[3] + 1859775393, 3);
        int rotateLeft46 = rotateLeft(rotateLeft42 + m128H(rotateLeft45, rotateLeft44, rotateLeft43) + this.f454X[11] + 1859775393, 9);
        int rotateLeft47 = rotateLeft(rotateLeft43 + m128H(rotateLeft46, rotateLeft45, rotateLeft44) + this.f454X[7] + 1859775393, 11);
        int rotateLeft48 = rotateLeft(rotateLeft44 + m128H(rotateLeft47, rotateLeft46, rotateLeft45) + this.f454X[15] + 1859775393, 15);
        this.f450H1 += rotateLeft45;
        this.f451H2 += rotateLeft48;
        this.f452H3 += rotateLeft47;
        this.f453H4 += rotateLeft46;
        this.xOff = 0;
        int i5 = 0;
        while (true) {
            int[] iArr = this.f454X;
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
        int[] iArr = this.f454X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f454X;
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
        this.f450H1 = 1732584193;
        this.f451H2 = -271733879;
        this.f452H3 = -1732584194;
        this.f453H4 = 271733878;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f454X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((MD4Digest) memoable);
    }
}