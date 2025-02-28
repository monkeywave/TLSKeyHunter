package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class MD5Digest extends GeneralDigest implements EncodableDigest {
    private static final int DIGEST_LENGTH = 16;
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

    /* renamed from: H1 */
    private int f455H1;

    /* renamed from: H2 */
    private int f456H2;

    /* renamed from: H3 */
    private int f457H3;

    /* renamed from: H4 */
    private int f458H4;

    /* renamed from: X */
    private int[] f459X;
    private int xOff;

    public MD5Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public MD5Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f459X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 64, cryptoServicePurpose));
        reset();
    }

    public MD5Digest(MD5Digest mD5Digest) {
        super(mD5Digest);
        this.f459X = new int[16];
        copyIn(mD5Digest);
    }

    public MD5Digest(byte[] bArr) {
        super(bArr);
        this.f459X = new int[16];
        this.f455H1 = Pack.bigEndianToInt(bArr, 16);
        this.f456H2 = Pack.bigEndianToInt(bArr, 20);
        this.f457H3 = Pack.bigEndianToInt(bArr, 24);
        this.f458H4 = Pack.bigEndianToInt(bArr, 28);
        this.xOff = Pack.bigEndianToInt(bArr, 32);
        for (int i = 0; i != this.xOff; i++) {
            this.f459X[i] = Pack.bigEndianToInt(bArr, (i * 4) + 36);
        }
    }

    /* renamed from: F */
    private int m127F(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: G */
    private int m126G(int i, int i2, int i3) {
        return (i & i3) | (i2 & (~i3));
    }

    /* renamed from: H */
    private int m125H(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: K */
    private int m124K(int i, int i2, int i3) {
        return (i | (~i3)) ^ i2;
    }

    private void copyIn(MD5Digest mD5Digest) {
        super.copyIn((GeneralDigest) mD5Digest);
        this.f455H1 = mD5Digest.f455H1;
        this.f456H2 = mD5Digest.f456H2;
        this.f457H3 = mD5Digest.f457H3;
        this.f458H4 = mD5Digest.f458H4;
        int[] iArr = mD5Digest.f459X;
        System.arraycopy(iArr, 0, this.f459X, 0, iArr.length);
        this.xOff = mD5Digest.xOff;
    }

    private int rotateLeft(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new MD5Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f455H1, bArr, i);
        Pack.intToLittleEndian(this.f456H2, bArr, i + 4);
        Pack.intToLittleEndian(this.f457H3, bArr, i + 8);
        Pack.intToLittleEndian(this.f458H4, bArr, i + 12);
        reset();
        return 16;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "MD5";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        int i = this.xOff * 4;
        byte[] bArr = new byte[i + 37];
        super.populateState(bArr);
        Pack.intToBigEndian(this.f455H1, bArr, 16);
        Pack.intToBigEndian(this.f456H2, bArr, 20);
        Pack.intToBigEndian(this.f457H3, bArr, 24);
        Pack.intToBigEndian(this.f458H4, bArr, 28);
        Pack.intToBigEndian(this.xOff, bArr, 32);
        for (int i2 = 0; i2 != this.xOff; i2++) {
            Pack.intToBigEndian(this.f459X[i2], bArr, (i2 * 4) + 36);
        }
        bArr[i + 36] = (byte) this.purpose.ordinal();
        return bArr;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f455H1;
        int i2 = this.f456H2;
        int i3 = this.f457H3;
        int i4 = this.f458H4;
        int rotateLeft = rotateLeft(((i + m127F(i2, i3, i4)) + this.f459X[0]) - 680876936, 7) + i2;
        int rotateLeft2 = rotateLeft(((i4 + m127F(rotateLeft, i2, i3)) + this.f459X[1]) - 389564586, 12) + rotateLeft;
        int rotateLeft3 = rotateLeft(i3 + m127F(rotateLeft2, rotateLeft, i2) + this.f459X[2] + 606105819, 17) + rotateLeft2;
        int rotateLeft4 = rotateLeft(((i2 + m127F(rotateLeft3, rotateLeft2, rotateLeft)) + this.f459X[3]) - 1044525330, 22) + rotateLeft3;
        int rotateLeft5 = rotateLeft(((rotateLeft + m127F(rotateLeft4, rotateLeft3, rotateLeft2)) + this.f459X[4]) - 176418897, 7) + rotateLeft4;
        int rotateLeft6 = rotateLeft(rotateLeft2 + m127F(rotateLeft5, rotateLeft4, rotateLeft3) + this.f459X[5] + 1200080426, 12) + rotateLeft5;
        int rotateLeft7 = rotateLeft(((rotateLeft3 + m127F(rotateLeft6, rotateLeft5, rotateLeft4)) + this.f459X[6]) - 1473231341, 17) + rotateLeft6;
        int rotateLeft8 = rotateLeft(((rotateLeft4 + m127F(rotateLeft7, rotateLeft6, rotateLeft5)) + this.f459X[7]) - 45705983, 22) + rotateLeft7;
        int rotateLeft9 = rotateLeft(rotateLeft5 + m127F(rotateLeft8, rotateLeft7, rotateLeft6) + this.f459X[8] + 1770035416, 7) + rotateLeft8;
        int rotateLeft10 = rotateLeft(((rotateLeft6 + m127F(rotateLeft9, rotateLeft8, rotateLeft7)) + this.f459X[9]) - 1958414417, 12) + rotateLeft9;
        int rotateLeft11 = rotateLeft(((rotateLeft7 + m127F(rotateLeft10, rotateLeft9, rotateLeft8)) + this.f459X[10]) - 42063, 17) + rotateLeft10;
        int rotateLeft12 = rotateLeft(((rotateLeft8 + m127F(rotateLeft11, rotateLeft10, rotateLeft9)) + this.f459X[11]) - 1990404162, 22) + rotateLeft11;
        int rotateLeft13 = rotateLeft(rotateLeft9 + m127F(rotateLeft12, rotateLeft11, rotateLeft10) + this.f459X[12] + 1804603682, 7) + rotateLeft12;
        int rotateLeft14 = rotateLeft(((rotateLeft10 + m127F(rotateLeft13, rotateLeft12, rotateLeft11)) + this.f459X[13]) - 40341101, 12) + rotateLeft13;
        int rotateLeft15 = rotateLeft(((rotateLeft11 + m127F(rotateLeft14, rotateLeft13, rotateLeft12)) + this.f459X[14]) - 1502002290, 17) + rotateLeft14;
        int rotateLeft16 = rotateLeft(rotateLeft12 + m127F(rotateLeft15, rotateLeft14, rotateLeft13) + this.f459X[15] + 1236535329, 22) + rotateLeft15;
        int rotateLeft17 = rotateLeft(((rotateLeft13 + m126G(rotateLeft16, rotateLeft15, rotateLeft14)) + this.f459X[1]) - 165796510, 5) + rotateLeft16;
        int rotateLeft18 = rotateLeft(((rotateLeft14 + m126G(rotateLeft17, rotateLeft16, rotateLeft15)) + this.f459X[6]) - 1069501632, 9) + rotateLeft17;
        int rotateLeft19 = rotateLeft(rotateLeft15 + m126G(rotateLeft18, rotateLeft17, rotateLeft16) + this.f459X[11] + 643717713, 14) + rotateLeft18;
        int rotateLeft20 = rotateLeft(((rotateLeft16 + m126G(rotateLeft19, rotateLeft18, rotateLeft17)) + this.f459X[0]) - 373897302, 20) + rotateLeft19;
        int rotateLeft21 = rotateLeft(((rotateLeft17 + m126G(rotateLeft20, rotateLeft19, rotateLeft18)) + this.f459X[5]) - 701558691, 5) + rotateLeft20;
        int rotateLeft22 = rotateLeft(rotateLeft18 + m126G(rotateLeft21, rotateLeft20, rotateLeft19) + this.f459X[10] + 38016083, 9) + rotateLeft21;
        int rotateLeft23 = rotateLeft(((rotateLeft19 + m126G(rotateLeft22, rotateLeft21, rotateLeft20)) + this.f459X[15]) - 660478335, 14) + rotateLeft22;
        int rotateLeft24 = rotateLeft(((rotateLeft20 + m126G(rotateLeft23, rotateLeft22, rotateLeft21)) + this.f459X[4]) - 405537848, 20) + rotateLeft23;
        int rotateLeft25 = rotateLeft(rotateLeft21 + m126G(rotateLeft24, rotateLeft23, rotateLeft22) + this.f459X[9] + 568446438, 5) + rotateLeft24;
        int rotateLeft26 = rotateLeft(((rotateLeft22 + m126G(rotateLeft25, rotateLeft24, rotateLeft23)) + this.f459X[14]) - 1019803690, 9) + rotateLeft25;
        int rotateLeft27 = rotateLeft(((rotateLeft23 + m126G(rotateLeft26, rotateLeft25, rotateLeft24)) + this.f459X[3]) - 187363961, 14) + rotateLeft26;
        int rotateLeft28 = rotateLeft(rotateLeft24 + m126G(rotateLeft27, rotateLeft26, rotateLeft25) + this.f459X[8] + 1163531501, 20) + rotateLeft27;
        int rotateLeft29 = rotateLeft(((rotateLeft25 + m126G(rotateLeft28, rotateLeft27, rotateLeft26)) + this.f459X[13]) - 1444681467, 5) + rotateLeft28;
        int rotateLeft30 = rotateLeft(((rotateLeft26 + m126G(rotateLeft29, rotateLeft28, rotateLeft27)) + this.f459X[2]) - 51403784, 9) + rotateLeft29;
        int rotateLeft31 = rotateLeft(rotateLeft27 + m126G(rotateLeft30, rotateLeft29, rotateLeft28) + this.f459X[7] + 1735328473, 14) + rotateLeft30;
        int rotateLeft32 = rotateLeft(((rotateLeft28 + m126G(rotateLeft31, rotateLeft30, rotateLeft29)) + this.f459X[12]) - 1926607734, 20) + rotateLeft31;
        int rotateLeft33 = rotateLeft(((rotateLeft29 + m125H(rotateLeft32, rotateLeft31, rotateLeft30)) + this.f459X[5]) - 378558, 4) + rotateLeft32;
        int rotateLeft34 = rotateLeft(((rotateLeft30 + m125H(rotateLeft33, rotateLeft32, rotateLeft31)) + this.f459X[8]) - 2022574463, 11) + rotateLeft33;
        int rotateLeft35 = rotateLeft(rotateLeft31 + m125H(rotateLeft34, rotateLeft33, rotateLeft32) + this.f459X[11] + 1839030562, 16) + rotateLeft34;
        int rotateLeft36 = rotateLeft(((rotateLeft32 + m125H(rotateLeft35, rotateLeft34, rotateLeft33)) + this.f459X[14]) - 35309556, 23) + rotateLeft35;
        int rotateLeft37 = rotateLeft(((rotateLeft33 + m125H(rotateLeft36, rotateLeft35, rotateLeft34)) + this.f459X[1]) - 1530992060, 4) + rotateLeft36;
        int rotateLeft38 = rotateLeft(rotateLeft34 + m125H(rotateLeft37, rotateLeft36, rotateLeft35) + this.f459X[4] + 1272893353, 11) + rotateLeft37;
        int rotateLeft39 = rotateLeft(((rotateLeft35 + m125H(rotateLeft38, rotateLeft37, rotateLeft36)) + this.f459X[7]) - 155497632, 16) + rotateLeft38;
        int rotateLeft40 = rotateLeft(((rotateLeft36 + m125H(rotateLeft39, rotateLeft38, rotateLeft37)) + this.f459X[10]) - 1094730640, 23) + rotateLeft39;
        int rotateLeft41 = rotateLeft(rotateLeft37 + m125H(rotateLeft40, rotateLeft39, rotateLeft38) + this.f459X[13] + 681279174, 4) + rotateLeft40;
        int rotateLeft42 = rotateLeft(((rotateLeft38 + m125H(rotateLeft41, rotateLeft40, rotateLeft39)) + this.f459X[0]) - 358537222, 11) + rotateLeft41;
        int rotateLeft43 = rotateLeft(((rotateLeft39 + m125H(rotateLeft42, rotateLeft41, rotateLeft40)) + this.f459X[3]) - 722521979, 16) + rotateLeft42;
        int rotateLeft44 = rotateLeft(rotateLeft40 + m125H(rotateLeft43, rotateLeft42, rotateLeft41) + this.f459X[6] + 76029189, 23) + rotateLeft43;
        int rotateLeft45 = rotateLeft(((rotateLeft41 + m125H(rotateLeft44, rotateLeft43, rotateLeft42)) + this.f459X[9]) - 640364487, 4) + rotateLeft44;
        int rotateLeft46 = rotateLeft(((rotateLeft42 + m125H(rotateLeft45, rotateLeft44, rotateLeft43)) + this.f459X[12]) - 421815835, 11) + rotateLeft45;
        int rotateLeft47 = rotateLeft(rotateLeft43 + m125H(rotateLeft46, rotateLeft45, rotateLeft44) + this.f459X[15] + 530742520, 16) + rotateLeft46;
        int rotateLeft48 = rotateLeft(((rotateLeft44 + m125H(rotateLeft47, rotateLeft46, rotateLeft45)) + this.f459X[2]) - 995338651, 23) + rotateLeft47;
        int rotateLeft49 = rotateLeft(((rotateLeft45 + m124K(rotateLeft48, rotateLeft47, rotateLeft46)) + this.f459X[0]) - 198630844, 6) + rotateLeft48;
        int rotateLeft50 = rotateLeft(rotateLeft46 + m124K(rotateLeft49, rotateLeft48, rotateLeft47) + this.f459X[7] + 1126891415, 10) + rotateLeft49;
        int rotateLeft51 = rotateLeft(((rotateLeft47 + m124K(rotateLeft50, rotateLeft49, rotateLeft48)) + this.f459X[14]) - 1416354905, 15) + rotateLeft50;
        int rotateLeft52 = rotateLeft(((rotateLeft48 + m124K(rotateLeft51, rotateLeft50, rotateLeft49)) + this.f459X[5]) - 57434055, 21) + rotateLeft51;
        int rotateLeft53 = rotateLeft(rotateLeft49 + m124K(rotateLeft52, rotateLeft51, rotateLeft50) + this.f459X[12] + 1700485571, 6) + rotateLeft52;
        int rotateLeft54 = rotateLeft(((rotateLeft50 + m124K(rotateLeft53, rotateLeft52, rotateLeft51)) + this.f459X[3]) - 1894986606, 10) + rotateLeft53;
        int rotateLeft55 = rotateLeft(((rotateLeft51 + m124K(rotateLeft54, rotateLeft53, rotateLeft52)) + this.f459X[10]) - 1051523, 15) + rotateLeft54;
        int rotateLeft56 = rotateLeft(((rotateLeft52 + m124K(rotateLeft55, rotateLeft54, rotateLeft53)) + this.f459X[1]) - 2054922799, 21) + rotateLeft55;
        int rotateLeft57 = rotateLeft(rotateLeft53 + m124K(rotateLeft56, rotateLeft55, rotateLeft54) + this.f459X[8] + 1873313359, 6) + rotateLeft56;
        int rotateLeft58 = rotateLeft(((rotateLeft54 + m124K(rotateLeft57, rotateLeft56, rotateLeft55)) + this.f459X[15]) - 30611744, 10) + rotateLeft57;
        int rotateLeft59 = rotateLeft(((rotateLeft55 + m124K(rotateLeft58, rotateLeft57, rotateLeft56)) + this.f459X[6]) - 1560198380, 15) + rotateLeft58;
        int rotateLeft60 = rotateLeft(rotateLeft56 + m124K(rotateLeft59, rotateLeft58, rotateLeft57) + this.f459X[13] + 1309151649, 21) + rotateLeft59;
        int rotateLeft61 = rotateLeft(((rotateLeft57 + m124K(rotateLeft60, rotateLeft59, rotateLeft58)) + this.f459X[4]) - 145523070, 6) + rotateLeft60;
        int rotateLeft62 = rotateLeft(((rotateLeft58 + m124K(rotateLeft61, rotateLeft60, rotateLeft59)) + this.f459X[11]) - 1120210379, 10) + rotateLeft61;
        int rotateLeft63 = rotateLeft(rotateLeft59 + m124K(rotateLeft62, rotateLeft61, rotateLeft60) + this.f459X[2] + 718787259, 15) + rotateLeft62;
        this.f455H1 += rotateLeft61;
        this.f456H2 += rotateLeft(((rotateLeft60 + m124K(rotateLeft63, rotateLeft62, rotateLeft61)) + this.f459X[9]) - 343485551, 21) + rotateLeft63;
        this.f457H3 += rotateLeft63;
        this.f458H4 += rotateLeft62;
        this.xOff = 0;
        int i5 = 0;
        while (true) {
            int[] iArr = this.f459X;
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
        int[] iArr = this.f459X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f459X;
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
        this.f455H1 = 1732584193;
        this.f456H2 = -271733879;
        this.f457H3 = -1732584194;
        this.f458H4 = 271733878;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f459X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((MD5Digest) memoable);
    }
}