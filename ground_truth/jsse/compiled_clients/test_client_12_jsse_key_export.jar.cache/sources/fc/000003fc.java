package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/MD4Digest.class */
public class MD4Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;

    /* renamed from: H1 */
    private int f181H1;

    /* renamed from: H2 */
    private int f182H2;

    /* renamed from: H3 */
    private int f183H3;

    /* renamed from: H4 */
    private int f184H4;

    /* renamed from: X */
    private int[] f185X;
    private int xOff;
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

    public MD4Digest() {
        this.f185X = new int[16];
        reset();
    }

    public MD4Digest(MD4Digest mD4Digest) {
        super(mD4Digest);
        this.f185X = new int[16];
        copyIn(mD4Digest);
    }

    private void copyIn(MD4Digest mD4Digest) {
        super.copyIn((GeneralDigest) mD4Digest);
        this.f181H1 = mD4Digest.f181H1;
        this.f182H2 = mD4Digest.f182H2;
        this.f183H3 = mD4Digest.f183H3;
        this.f184H4 = mD4Digest.f184H4;
        System.arraycopy(mD4Digest.f185X, 0, this.f185X, 0, mD4Digest.f185X.length);
        this.xOff = mD4Digest.xOff;
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
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f185X;
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
        this.f185X[14] = (int) (j & (-1));
        this.f185X[15] = (int) (j >>> 32);
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
        unpackWord(this.f181H1, bArr, i);
        unpackWord(this.f182H2, bArr, i + 4);
        unpackWord(this.f183H3, bArr, i + 8);
        unpackWord(this.f184H4, bArr, i + 12);
        reset();
        return 16;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f181H1 = 1732584193;
        this.f182H2 = -271733879;
        this.f183H3 = -1732584194;
        this.f184H4 = 271733878;
        this.xOff = 0;
        for (int i = 0; i != this.f185X.length; i++) {
            this.f185X[i] = 0;
        }
    }

    private int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    /* renamed from: F */
    private int m110F(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: G */
    private int m109G(int i, int i2, int i3) {
        return (i & i2) | (i & i3) | (i2 & i3);
    }

    /* renamed from: H */
    private int m108H(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f181H1;
        int i2 = this.f182H2;
        int i3 = this.f183H3;
        int i4 = this.f184H4;
        int rotateLeft = rotateLeft(i + m110F(i2, i3, i4) + this.f185X[0], 3);
        int rotateLeft2 = rotateLeft(i4 + m110F(rotateLeft, i2, i3) + this.f185X[1], 7);
        int rotateLeft3 = rotateLeft(i3 + m110F(rotateLeft2, rotateLeft, i2) + this.f185X[2], 11);
        int rotateLeft4 = rotateLeft(i2 + m110F(rotateLeft3, rotateLeft2, rotateLeft) + this.f185X[3], 19);
        int rotateLeft5 = rotateLeft(rotateLeft + m110F(rotateLeft4, rotateLeft3, rotateLeft2) + this.f185X[4], 3);
        int rotateLeft6 = rotateLeft(rotateLeft2 + m110F(rotateLeft5, rotateLeft4, rotateLeft3) + this.f185X[5], 7);
        int rotateLeft7 = rotateLeft(rotateLeft3 + m110F(rotateLeft6, rotateLeft5, rotateLeft4) + this.f185X[6], 11);
        int rotateLeft8 = rotateLeft(rotateLeft4 + m110F(rotateLeft7, rotateLeft6, rotateLeft5) + this.f185X[7], 19);
        int rotateLeft9 = rotateLeft(rotateLeft5 + m110F(rotateLeft8, rotateLeft7, rotateLeft6) + this.f185X[8], 3);
        int rotateLeft10 = rotateLeft(rotateLeft6 + m110F(rotateLeft9, rotateLeft8, rotateLeft7) + this.f185X[9], 7);
        int rotateLeft11 = rotateLeft(rotateLeft7 + m110F(rotateLeft10, rotateLeft9, rotateLeft8) + this.f185X[10], 11);
        int rotateLeft12 = rotateLeft(rotateLeft8 + m110F(rotateLeft11, rotateLeft10, rotateLeft9) + this.f185X[11], 19);
        int rotateLeft13 = rotateLeft(rotateLeft9 + m110F(rotateLeft12, rotateLeft11, rotateLeft10) + this.f185X[12], 3);
        int rotateLeft14 = rotateLeft(rotateLeft10 + m110F(rotateLeft13, rotateLeft12, rotateLeft11) + this.f185X[13], 7);
        int rotateLeft15 = rotateLeft(rotateLeft11 + m110F(rotateLeft14, rotateLeft13, rotateLeft12) + this.f185X[14], 11);
        int rotateLeft16 = rotateLeft(rotateLeft12 + m110F(rotateLeft15, rotateLeft14, rotateLeft13) + this.f185X[15], 19);
        int rotateLeft17 = rotateLeft(rotateLeft13 + m109G(rotateLeft16, rotateLeft15, rotateLeft14) + this.f185X[0] + 1518500249, 3);
        int rotateLeft18 = rotateLeft(rotateLeft14 + m109G(rotateLeft17, rotateLeft16, rotateLeft15) + this.f185X[4] + 1518500249, 5);
        int rotateLeft19 = rotateLeft(rotateLeft15 + m109G(rotateLeft18, rotateLeft17, rotateLeft16) + this.f185X[8] + 1518500249, 9);
        int rotateLeft20 = rotateLeft(rotateLeft16 + m109G(rotateLeft19, rotateLeft18, rotateLeft17) + this.f185X[12] + 1518500249, 13);
        int rotateLeft21 = rotateLeft(rotateLeft17 + m109G(rotateLeft20, rotateLeft19, rotateLeft18) + this.f185X[1] + 1518500249, 3);
        int rotateLeft22 = rotateLeft(rotateLeft18 + m109G(rotateLeft21, rotateLeft20, rotateLeft19) + this.f185X[5] + 1518500249, 5);
        int rotateLeft23 = rotateLeft(rotateLeft19 + m109G(rotateLeft22, rotateLeft21, rotateLeft20) + this.f185X[9] + 1518500249, 9);
        int rotateLeft24 = rotateLeft(rotateLeft20 + m109G(rotateLeft23, rotateLeft22, rotateLeft21) + this.f185X[13] + 1518500249, 13);
        int rotateLeft25 = rotateLeft(rotateLeft21 + m109G(rotateLeft24, rotateLeft23, rotateLeft22) + this.f185X[2] + 1518500249, 3);
        int rotateLeft26 = rotateLeft(rotateLeft22 + m109G(rotateLeft25, rotateLeft24, rotateLeft23) + this.f185X[6] + 1518500249, 5);
        int rotateLeft27 = rotateLeft(rotateLeft23 + m109G(rotateLeft26, rotateLeft25, rotateLeft24) + this.f185X[10] + 1518500249, 9);
        int rotateLeft28 = rotateLeft(rotateLeft24 + m109G(rotateLeft27, rotateLeft26, rotateLeft25) + this.f185X[14] + 1518500249, 13);
        int rotateLeft29 = rotateLeft(rotateLeft25 + m109G(rotateLeft28, rotateLeft27, rotateLeft26) + this.f185X[3] + 1518500249, 3);
        int rotateLeft30 = rotateLeft(rotateLeft26 + m109G(rotateLeft29, rotateLeft28, rotateLeft27) + this.f185X[7] + 1518500249, 5);
        int rotateLeft31 = rotateLeft(rotateLeft27 + m109G(rotateLeft30, rotateLeft29, rotateLeft28) + this.f185X[11] + 1518500249, 9);
        int rotateLeft32 = rotateLeft(rotateLeft28 + m109G(rotateLeft31, rotateLeft30, rotateLeft29) + this.f185X[15] + 1518500249, 13);
        int rotateLeft33 = rotateLeft(rotateLeft29 + m108H(rotateLeft32, rotateLeft31, rotateLeft30) + this.f185X[0] + 1859775393, 3);
        int rotateLeft34 = rotateLeft(rotateLeft30 + m108H(rotateLeft33, rotateLeft32, rotateLeft31) + this.f185X[8] + 1859775393, 9);
        int rotateLeft35 = rotateLeft(rotateLeft31 + m108H(rotateLeft34, rotateLeft33, rotateLeft32) + this.f185X[4] + 1859775393, 11);
        int rotateLeft36 = rotateLeft(rotateLeft32 + m108H(rotateLeft35, rotateLeft34, rotateLeft33) + this.f185X[12] + 1859775393, 15);
        int rotateLeft37 = rotateLeft(rotateLeft33 + m108H(rotateLeft36, rotateLeft35, rotateLeft34) + this.f185X[2] + 1859775393, 3);
        int rotateLeft38 = rotateLeft(rotateLeft34 + m108H(rotateLeft37, rotateLeft36, rotateLeft35) + this.f185X[10] + 1859775393, 9);
        int rotateLeft39 = rotateLeft(rotateLeft35 + m108H(rotateLeft38, rotateLeft37, rotateLeft36) + this.f185X[6] + 1859775393, 11);
        int rotateLeft40 = rotateLeft(rotateLeft36 + m108H(rotateLeft39, rotateLeft38, rotateLeft37) + this.f185X[14] + 1859775393, 15);
        int rotateLeft41 = rotateLeft(rotateLeft37 + m108H(rotateLeft40, rotateLeft39, rotateLeft38) + this.f185X[1] + 1859775393, 3);
        int rotateLeft42 = rotateLeft(rotateLeft38 + m108H(rotateLeft41, rotateLeft40, rotateLeft39) + this.f185X[9] + 1859775393, 9);
        int rotateLeft43 = rotateLeft(rotateLeft39 + m108H(rotateLeft42, rotateLeft41, rotateLeft40) + this.f185X[5] + 1859775393, 11);
        int rotateLeft44 = rotateLeft(rotateLeft40 + m108H(rotateLeft43, rotateLeft42, rotateLeft41) + this.f185X[13] + 1859775393, 15);
        int rotateLeft45 = rotateLeft(rotateLeft41 + m108H(rotateLeft44, rotateLeft43, rotateLeft42) + this.f185X[3] + 1859775393, 3);
        int rotateLeft46 = rotateLeft(rotateLeft42 + m108H(rotateLeft45, rotateLeft44, rotateLeft43) + this.f185X[11] + 1859775393, 9);
        int rotateLeft47 = rotateLeft(rotateLeft43 + m108H(rotateLeft46, rotateLeft45, rotateLeft44) + this.f185X[7] + 1859775393, 11);
        int rotateLeft48 = rotateLeft(rotateLeft44 + m108H(rotateLeft47, rotateLeft46, rotateLeft45) + this.f185X[15] + 1859775393, 15);
        this.f181H1 += rotateLeft45;
        this.f182H2 += rotateLeft48;
        this.f183H3 += rotateLeft47;
        this.f184H4 += rotateLeft46;
        this.xOff = 0;
        for (int i5 = 0; i5 != this.f185X.length; i5++) {
            this.f185X[i5] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new MD4Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((MD4Digest) memoable);
    }
}