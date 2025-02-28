package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/RIPEMD320Digest.class */
public class RIPEMD320Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 40;

    /* renamed from: H0 */
    private int f212H0;

    /* renamed from: H1 */
    private int f213H1;

    /* renamed from: H2 */
    private int f214H2;

    /* renamed from: H3 */
    private int f215H3;

    /* renamed from: H4 */
    private int f216H4;

    /* renamed from: H5 */
    private int f217H5;

    /* renamed from: H6 */
    private int f218H6;

    /* renamed from: H7 */
    private int f219H7;

    /* renamed from: H8 */
    private int f220H8;

    /* renamed from: H9 */
    private int f221H9;

    /* renamed from: X */
    private int[] f222X;
    private int xOff;

    public RIPEMD320Digest() {
        this.f222X = new int[16];
        reset();
    }

    public RIPEMD320Digest(RIPEMD320Digest rIPEMD320Digest) {
        super(rIPEMD320Digest);
        this.f222X = new int[16];
        doCopy(rIPEMD320Digest);
    }

    private void doCopy(RIPEMD320Digest rIPEMD320Digest) {
        super.copyIn(rIPEMD320Digest);
        this.f212H0 = rIPEMD320Digest.f212H0;
        this.f213H1 = rIPEMD320Digest.f213H1;
        this.f214H2 = rIPEMD320Digest.f214H2;
        this.f215H3 = rIPEMD320Digest.f215H3;
        this.f216H4 = rIPEMD320Digest.f216H4;
        this.f217H5 = rIPEMD320Digest.f217H5;
        this.f218H6 = rIPEMD320Digest.f218H6;
        this.f219H7 = rIPEMD320Digest.f219H7;
        this.f220H8 = rIPEMD320Digest.f220H8;
        this.f221H9 = rIPEMD320Digest.f221H9;
        System.arraycopy(rIPEMD320Digest.f222X, 0, this.f222X, 0, rIPEMD320Digest.f222X.length);
        this.xOff = rIPEMD320Digest.xOff;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "RIPEMD320";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 40;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f222X;
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
        this.f222X[14] = (int) (j & (-1));
        this.f222X[15] = (int) (j >>> 32);
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
        unpackWord(this.f212H0, bArr, i);
        unpackWord(this.f213H1, bArr, i + 4);
        unpackWord(this.f214H2, bArr, i + 8);
        unpackWord(this.f215H3, bArr, i + 12);
        unpackWord(this.f216H4, bArr, i + 16);
        unpackWord(this.f217H5, bArr, i + 20);
        unpackWord(this.f218H6, bArr, i + 24);
        unpackWord(this.f219H7, bArr, i + 28);
        unpackWord(this.f220H8, bArr, i + 32);
        unpackWord(this.f221H9, bArr, i + 36);
        reset();
        return 40;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f212H0 = 1732584193;
        this.f213H1 = -271733879;
        this.f214H2 = -1732584194;
        this.f215H3 = 271733878;
        this.f216H4 = -1009589776;
        this.f217H5 = 1985229328;
        this.f218H6 = -19088744;
        this.f219H7 = -1985229329;
        this.f220H8 = 19088743;
        this.f221H9 = 1009589775;
        this.xOff = 0;
        for (int i = 0; i != this.f222X.length; i++) {
            this.f222X[i] = 0;
        }
    }

    /* renamed from: RL */
    private int m79RL(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    /* renamed from: f1 */
    private int m78f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m77f2(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: f3 */
    private int m76f3(int i, int i2, int i3) {
        return (i | (i2 ^ (-1))) ^ i3;
    }

    /* renamed from: f4 */
    private int m75f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (i3 ^ (-1)));
    }

    /* renamed from: f5 */
    private int m74f5(int i, int i2, int i3) {
        return i ^ (i2 | (i3 ^ (-1)));
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f212H0;
        int i2 = this.f213H1;
        int i3 = this.f214H2;
        int i4 = this.f215H3;
        int i5 = this.f216H4;
        int i6 = this.f217H5;
        int i7 = this.f218H6;
        int i8 = this.f219H7;
        int i9 = this.f220H8;
        int i10 = this.f221H9;
        int m79RL = m79RL(i + m78f1(i2, i3, i4) + this.f222X[0], 11) + i5;
        int m79RL2 = m79RL(i3, 10);
        int m79RL3 = m79RL(i5 + m78f1(m79RL, i2, m79RL2) + this.f222X[1], 14) + i4;
        int m79RL4 = m79RL(i2, 10);
        int m79RL5 = m79RL(i4 + m78f1(m79RL3, m79RL, m79RL4) + this.f222X[2], 15) + m79RL2;
        int m79RL6 = m79RL(m79RL, 10);
        int m79RL7 = m79RL(m79RL2 + m78f1(m79RL5, m79RL3, m79RL6) + this.f222X[3], 12) + m79RL4;
        int m79RL8 = m79RL(m79RL3, 10);
        int m79RL9 = m79RL(m79RL4 + m78f1(m79RL7, m79RL5, m79RL8) + this.f222X[4], 5) + m79RL6;
        int m79RL10 = m79RL(m79RL5, 10);
        int m79RL11 = m79RL(m79RL6 + m78f1(m79RL9, m79RL7, m79RL10) + this.f222X[5], 8) + m79RL8;
        int m79RL12 = m79RL(m79RL7, 10);
        int m79RL13 = m79RL(m79RL8 + m78f1(m79RL11, m79RL9, m79RL12) + this.f222X[6], 7) + m79RL10;
        int m79RL14 = m79RL(m79RL9, 10);
        int m79RL15 = m79RL(m79RL10 + m78f1(m79RL13, m79RL11, m79RL14) + this.f222X[7], 9) + m79RL12;
        int m79RL16 = m79RL(m79RL11, 10);
        int m79RL17 = m79RL(m79RL12 + m78f1(m79RL15, m79RL13, m79RL16) + this.f222X[8], 11) + m79RL14;
        int m79RL18 = m79RL(m79RL13, 10);
        int m79RL19 = m79RL(m79RL14 + m78f1(m79RL17, m79RL15, m79RL18) + this.f222X[9], 13) + m79RL16;
        int m79RL20 = m79RL(m79RL15, 10);
        int m79RL21 = m79RL(m79RL16 + m78f1(m79RL19, m79RL17, m79RL20) + this.f222X[10], 14) + m79RL18;
        int m79RL22 = m79RL(m79RL17, 10);
        int m79RL23 = m79RL(m79RL18 + m78f1(m79RL21, m79RL19, m79RL22) + this.f222X[11], 15) + m79RL20;
        int m79RL24 = m79RL(m79RL19, 10);
        int m79RL25 = m79RL(m79RL20 + m78f1(m79RL23, m79RL21, m79RL24) + this.f222X[12], 6) + m79RL22;
        int m79RL26 = m79RL(m79RL21, 10);
        int m79RL27 = m79RL(m79RL22 + m78f1(m79RL25, m79RL23, m79RL26) + this.f222X[13], 7) + m79RL24;
        int m79RL28 = m79RL(m79RL23, 10);
        int m79RL29 = m79RL(m79RL24 + m78f1(m79RL27, m79RL25, m79RL28) + this.f222X[14], 9) + m79RL26;
        int m79RL30 = m79RL(m79RL25, 10);
        int m79RL31 = m79RL(m79RL26 + m78f1(m79RL29, m79RL27, m79RL30) + this.f222X[15], 8) + m79RL28;
        int m79RL32 = m79RL(m79RL27, 10);
        int m79RL33 = m79RL(i6 + m74f5(i7, i8, i9) + this.f222X[5] + 1352829926, 8) + i10;
        int m79RL34 = m79RL(i8, 10);
        int m79RL35 = m79RL(i10 + m74f5(m79RL33, i7, m79RL34) + this.f222X[14] + 1352829926, 9) + i9;
        int m79RL36 = m79RL(i7, 10);
        int m79RL37 = m79RL(i9 + m74f5(m79RL35, m79RL33, m79RL36) + this.f222X[7] + 1352829926, 9) + m79RL34;
        int m79RL38 = m79RL(m79RL33, 10);
        int m79RL39 = m79RL(m79RL34 + m74f5(m79RL37, m79RL35, m79RL38) + this.f222X[0] + 1352829926, 11) + m79RL36;
        int m79RL40 = m79RL(m79RL35, 10);
        int m79RL41 = m79RL(m79RL36 + m74f5(m79RL39, m79RL37, m79RL40) + this.f222X[9] + 1352829926, 13) + m79RL38;
        int m79RL42 = m79RL(m79RL37, 10);
        int m79RL43 = m79RL(m79RL38 + m74f5(m79RL41, m79RL39, m79RL42) + this.f222X[2] + 1352829926, 15) + m79RL40;
        int m79RL44 = m79RL(m79RL39, 10);
        int m79RL45 = m79RL(m79RL40 + m74f5(m79RL43, m79RL41, m79RL44) + this.f222X[11] + 1352829926, 15) + m79RL42;
        int m79RL46 = m79RL(m79RL41, 10);
        int m79RL47 = m79RL(m79RL42 + m74f5(m79RL45, m79RL43, m79RL46) + this.f222X[4] + 1352829926, 5) + m79RL44;
        int m79RL48 = m79RL(m79RL43, 10);
        int m79RL49 = m79RL(m79RL44 + m74f5(m79RL47, m79RL45, m79RL48) + this.f222X[13] + 1352829926, 7) + m79RL46;
        int m79RL50 = m79RL(m79RL45, 10);
        int m79RL51 = m79RL(m79RL46 + m74f5(m79RL49, m79RL47, m79RL50) + this.f222X[6] + 1352829926, 7) + m79RL48;
        int m79RL52 = m79RL(m79RL47, 10);
        int m79RL53 = m79RL(m79RL48 + m74f5(m79RL51, m79RL49, m79RL52) + this.f222X[15] + 1352829926, 8) + m79RL50;
        int m79RL54 = m79RL(m79RL49, 10);
        int m79RL55 = m79RL(m79RL50 + m74f5(m79RL53, m79RL51, m79RL54) + this.f222X[8] + 1352829926, 11) + m79RL52;
        int m79RL56 = m79RL(m79RL51, 10);
        int m79RL57 = m79RL(m79RL52 + m74f5(m79RL55, m79RL53, m79RL56) + this.f222X[1] + 1352829926, 14) + m79RL54;
        int m79RL58 = m79RL(m79RL53, 10);
        int m79RL59 = m79RL(m79RL54 + m74f5(m79RL57, m79RL55, m79RL58) + this.f222X[10] + 1352829926, 14) + m79RL56;
        int m79RL60 = m79RL(m79RL55, 10);
        int m79RL61 = m79RL(m79RL56 + m74f5(m79RL59, m79RL57, m79RL60) + this.f222X[3] + 1352829926, 12) + m79RL58;
        int m79RL62 = m79RL(m79RL57, 10);
        int m79RL63 = m79RL(m79RL58 + m74f5(m79RL61, m79RL59, m79RL62) + this.f222X[12] + 1352829926, 6) + m79RL60;
        int m79RL64 = m79RL(m79RL59, 10);
        int m79RL65 = m79RL(m79RL28 + m77f2(m79RL63, m79RL29, m79RL32) + this.f222X[7] + 1518500249, 7) + m79RL30;
        int m79RL66 = m79RL(m79RL29, 10);
        int m79RL67 = m79RL(m79RL30 + m77f2(m79RL65, m79RL63, m79RL66) + this.f222X[4] + 1518500249, 6) + m79RL32;
        int m79RL68 = m79RL(m79RL63, 10);
        int m79RL69 = m79RL(m79RL32 + m77f2(m79RL67, m79RL65, m79RL68) + this.f222X[13] + 1518500249, 8) + m79RL66;
        int m79RL70 = m79RL(m79RL65, 10);
        int m79RL71 = m79RL(m79RL66 + m77f2(m79RL69, m79RL67, m79RL70) + this.f222X[1] + 1518500249, 13) + m79RL68;
        int m79RL72 = m79RL(m79RL67, 10);
        int m79RL73 = m79RL(m79RL68 + m77f2(m79RL71, m79RL69, m79RL72) + this.f222X[10] + 1518500249, 11) + m79RL70;
        int m79RL74 = m79RL(m79RL69, 10);
        int m79RL75 = m79RL(m79RL70 + m77f2(m79RL73, m79RL71, m79RL74) + this.f222X[6] + 1518500249, 9) + m79RL72;
        int m79RL76 = m79RL(m79RL71, 10);
        int m79RL77 = m79RL(m79RL72 + m77f2(m79RL75, m79RL73, m79RL76) + this.f222X[15] + 1518500249, 7) + m79RL74;
        int m79RL78 = m79RL(m79RL73, 10);
        int m79RL79 = m79RL(m79RL74 + m77f2(m79RL77, m79RL75, m79RL78) + this.f222X[3] + 1518500249, 15) + m79RL76;
        int m79RL80 = m79RL(m79RL75, 10);
        int m79RL81 = m79RL(m79RL76 + m77f2(m79RL79, m79RL77, m79RL80) + this.f222X[12] + 1518500249, 7) + m79RL78;
        int m79RL82 = m79RL(m79RL77, 10);
        int m79RL83 = m79RL(m79RL78 + m77f2(m79RL81, m79RL79, m79RL82) + this.f222X[0] + 1518500249, 12) + m79RL80;
        int m79RL84 = m79RL(m79RL79, 10);
        int m79RL85 = m79RL(m79RL80 + m77f2(m79RL83, m79RL81, m79RL84) + this.f222X[9] + 1518500249, 15) + m79RL82;
        int m79RL86 = m79RL(m79RL81, 10);
        int m79RL87 = m79RL(m79RL82 + m77f2(m79RL85, m79RL83, m79RL86) + this.f222X[5] + 1518500249, 9) + m79RL84;
        int m79RL88 = m79RL(m79RL83, 10);
        int m79RL89 = m79RL(m79RL84 + m77f2(m79RL87, m79RL85, m79RL88) + this.f222X[2] + 1518500249, 11) + m79RL86;
        int m79RL90 = m79RL(m79RL85, 10);
        int m79RL91 = m79RL(m79RL86 + m77f2(m79RL89, m79RL87, m79RL90) + this.f222X[14] + 1518500249, 7) + m79RL88;
        int m79RL92 = m79RL(m79RL87, 10);
        int m79RL93 = m79RL(m79RL88 + m77f2(m79RL91, m79RL89, m79RL92) + this.f222X[11] + 1518500249, 13) + m79RL90;
        int m79RL94 = m79RL(m79RL89, 10);
        int m79RL95 = m79RL(m79RL90 + m77f2(m79RL93, m79RL91, m79RL94) + this.f222X[8] + 1518500249, 12) + m79RL92;
        int m79RL96 = m79RL(m79RL91, 10);
        int m79RL97 = m79RL(m79RL60 + m75f4(m79RL31, m79RL61, m79RL64) + this.f222X[6] + 1548603684, 9) + m79RL62;
        int m79RL98 = m79RL(m79RL61, 10);
        int m79RL99 = m79RL(m79RL62 + m75f4(m79RL97, m79RL31, m79RL98) + this.f222X[11] + 1548603684, 13) + m79RL64;
        int m79RL100 = m79RL(m79RL31, 10);
        int m79RL101 = m79RL(m79RL64 + m75f4(m79RL99, m79RL97, m79RL100) + this.f222X[3] + 1548603684, 15) + m79RL98;
        int m79RL102 = m79RL(m79RL97, 10);
        int m79RL103 = m79RL(m79RL98 + m75f4(m79RL101, m79RL99, m79RL102) + this.f222X[7] + 1548603684, 7) + m79RL100;
        int m79RL104 = m79RL(m79RL99, 10);
        int m79RL105 = m79RL(m79RL100 + m75f4(m79RL103, m79RL101, m79RL104) + this.f222X[0] + 1548603684, 12) + m79RL102;
        int m79RL106 = m79RL(m79RL101, 10);
        int m79RL107 = m79RL(m79RL102 + m75f4(m79RL105, m79RL103, m79RL106) + this.f222X[13] + 1548603684, 8) + m79RL104;
        int m79RL108 = m79RL(m79RL103, 10);
        int m79RL109 = m79RL(m79RL104 + m75f4(m79RL107, m79RL105, m79RL108) + this.f222X[5] + 1548603684, 9) + m79RL106;
        int m79RL110 = m79RL(m79RL105, 10);
        int m79RL111 = m79RL(m79RL106 + m75f4(m79RL109, m79RL107, m79RL110) + this.f222X[10] + 1548603684, 11) + m79RL108;
        int m79RL112 = m79RL(m79RL107, 10);
        int m79RL113 = m79RL(m79RL108 + m75f4(m79RL111, m79RL109, m79RL112) + this.f222X[14] + 1548603684, 7) + m79RL110;
        int m79RL114 = m79RL(m79RL109, 10);
        int m79RL115 = m79RL(m79RL110 + m75f4(m79RL113, m79RL111, m79RL114) + this.f222X[15] + 1548603684, 7) + m79RL112;
        int m79RL116 = m79RL(m79RL111, 10);
        int m79RL117 = m79RL(m79RL112 + m75f4(m79RL115, m79RL113, m79RL116) + this.f222X[8] + 1548603684, 12) + m79RL114;
        int m79RL118 = m79RL(m79RL113, 10);
        int m79RL119 = m79RL(m79RL114 + m75f4(m79RL117, m79RL115, m79RL118) + this.f222X[12] + 1548603684, 7) + m79RL116;
        int m79RL120 = m79RL(m79RL115, 10);
        int m79RL121 = m79RL(m79RL116 + m75f4(m79RL119, m79RL117, m79RL120) + this.f222X[4] + 1548603684, 6) + m79RL118;
        int m79RL122 = m79RL(m79RL117, 10);
        int m79RL123 = m79RL(m79RL118 + m75f4(m79RL121, m79RL119, m79RL122) + this.f222X[9] + 1548603684, 15) + m79RL120;
        int m79RL124 = m79RL(m79RL119, 10);
        int m79RL125 = m79RL(m79RL120 + m75f4(m79RL123, m79RL121, m79RL124) + this.f222X[1] + 1548603684, 13) + m79RL122;
        int m79RL126 = m79RL(m79RL121, 10);
        int m79RL127 = m79RL(m79RL122 + m75f4(m79RL125, m79RL123, m79RL126) + this.f222X[2] + 1548603684, 11) + m79RL124;
        int m79RL128 = m79RL(m79RL123, 10);
        int m79RL129 = m79RL(m79RL92 + m76f3(m79RL95, m79RL93, m79RL128) + this.f222X[3] + 1859775393, 11) + m79RL94;
        int m79RL130 = m79RL(m79RL93, 10);
        int m79RL131 = m79RL(m79RL94 + m76f3(m79RL129, m79RL95, m79RL130) + this.f222X[10] + 1859775393, 13) + m79RL128;
        int m79RL132 = m79RL(m79RL95, 10);
        int m79RL133 = m79RL(m79RL128 + m76f3(m79RL131, m79RL129, m79RL132) + this.f222X[14] + 1859775393, 6) + m79RL130;
        int m79RL134 = m79RL(m79RL129, 10);
        int m79RL135 = m79RL(m79RL130 + m76f3(m79RL133, m79RL131, m79RL134) + this.f222X[4] + 1859775393, 7) + m79RL132;
        int m79RL136 = m79RL(m79RL131, 10);
        int m79RL137 = m79RL(m79RL132 + m76f3(m79RL135, m79RL133, m79RL136) + this.f222X[9] + 1859775393, 14) + m79RL134;
        int m79RL138 = m79RL(m79RL133, 10);
        int m79RL139 = m79RL(m79RL134 + m76f3(m79RL137, m79RL135, m79RL138) + this.f222X[15] + 1859775393, 9) + m79RL136;
        int m79RL140 = m79RL(m79RL135, 10);
        int m79RL141 = m79RL(m79RL136 + m76f3(m79RL139, m79RL137, m79RL140) + this.f222X[8] + 1859775393, 13) + m79RL138;
        int m79RL142 = m79RL(m79RL137, 10);
        int m79RL143 = m79RL(m79RL138 + m76f3(m79RL141, m79RL139, m79RL142) + this.f222X[1] + 1859775393, 15) + m79RL140;
        int m79RL144 = m79RL(m79RL139, 10);
        int m79RL145 = m79RL(m79RL140 + m76f3(m79RL143, m79RL141, m79RL144) + this.f222X[2] + 1859775393, 14) + m79RL142;
        int m79RL146 = m79RL(m79RL141, 10);
        int m79RL147 = m79RL(m79RL142 + m76f3(m79RL145, m79RL143, m79RL146) + this.f222X[7] + 1859775393, 8) + m79RL144;
        int m79RL148 = m79RL(m79RL143, 10);
        int m79RL149 = m79RL(m79RL144 + m76f3(m79RL147, m79RL145, m79RL148) + this.f222X[0] + 1859775393, 13) + m79RL146;
        int m79RL150 = m79RL(m79RL145, 10);
        int m79RL151 = m79RL(m79RL146 + m76f3(m79RL149, m79RL147, m79RL150) + this.f222X[6] + 1859775393, 6) + m79RL148;
        int m79RL152 = m79RL(m79RL147, 10);
        int m79RL153 = m79RL(m79RL148 + m76f3(m79RL151, m79RL149, m79RL152) + this.f222X[13] + 1859775393, 5) + m79RL150;
        int m79RL154 = m79RL(m79RL149, 10);
        int m79RL155 = m79RL(m79RL150 + m76f3(m79RL153, m79RL151, m79RL154) + this.f222X[11] + 1859775393, 12) + m79RL152;
        int m79RL156 = m79RL(m79RL151, 10);
        int m79RL157 = m79RL(m79RL152 + m76f3(m79RL155, m79RL153, m79RL156) + this.f222X[5] + 1859775393, 7) + m79RL154;
        int m79RL158 = m79RL(m79RL153, 10);
        int m79RL159 = m79RL(m79RL154 + m76f3(m79RL157, m79RL155, m79RL158) + this.f222X[12] + 1859775393, 5) + m79RL156;
        int m79RL160 = m79RL(m79RL155, 10);
        int m79RL161 = m79RL(m79RL124 + m76f3(m79RL127, m79RL125, m79RL96) + this.f222X[15] + 1836072691, 9) + m79RL126;
        int m79RL162 = m79RL(m79RL125, 10);
        int m79RL163 = m79RL(m79RL126 + m76f3(m79RL161, m79RL127, m79RL162) + this.f222X[5] + 1836072691, 7) + m79RL96;
        int m79RL164 = m79RL(m79RL127, 10);
        int m79RL165 = m79RL(m79RL96 + m76f3(m79RL163, m79RL161, m79RL164) + this.f222X[1] + 1836072691, 15) + m79RL162;
        int m79RL166 = m79RL(m79RL161, 10);
        int m79RL167 = m79RL(m79RL162 + m76f3(m79RL165, m79RL163, m79RL166) + this.f222X[3] + 1836072691, 11) + m79RL164;
        int m79RL168 = m79RL(m79RL163, 10);
        int m79RL169 = m79RL(m79RL164 + m76f3(m79RL167, m79RL165, m79RL168) + this.f222X[7] + 1836072691, 8) + m79RL166;
        int m79RL170 = m79RL(m79RL165, 10);
        int m79RL171 = m79RL(m79RL166 + m76f3(m79RL169, m79RL167, m79RL170) + this.f222X[14] + 1836072691, 6) + m79RL168;
        int m79RL172 = m79RL(m79RL167, 10);
        int m79RL173 = m79RL(m79RL168 + m76f3(m79RL171, m79RL169, m79RL172) + this.f222X[6] + 1836072691, 6) + m79RL170;
        int m79RL174 = m79RL(m79RL169, 10);
        int m79RL175 = m79RL(m79RL170 + m76f3(m79RL173, m79RL171, m79RL174) + this.f222X[9] + 1836072691, 14) + m79RL172;
        int m79RL176 = m79RL(m79RL171, 10);
        int m79RL177 = m79RL(m79RL172 + m76f3(m79RL175, m79RL173, m79RL176) + this.f222X[11] + 1836072691, 12) + m79RL174;
        int m79RL178 = m79RL(m79RL173, 10);
        int m79RL179 = m79RL(m79RL174 + m76f3(m79RL177, m79RL175, m79RL178) + this.f222X[8] + 1836072691, 13) + m79RL176;
        int m79RL180 = m79RL(m79RL175, 10);
        int m79RL181 = m79RL(m79RL176 + m76f3(m79RL179, m79RL177, m79RL180) + this.f222X[12] + 1836072691, 5) + m79RL178;
        int m79RL182 = m79RL(m79RL177, 10);
        int m79RL183 = m79RL(m79RL178 + m76f3(m79RL181, m79RL179, m79RL182) + this.f222X[2] + 1836072691, 14) + m79RL180;
        int m79RL184 = m79RL(m79RL179, 10);
        int m79RL185 = m79RL(m79RL180 + m76f3(m79RL183, m79RL181, m79RL184) + this.f222X[10] + 1836072691, 13) + m79RL182;
        int m79RL186 = m79RL(m79RL181, 10);
        int m79RL187 = m79RL(m79RL182 + m76f3(m79RL185, m79RL183, m79RL186) + this.f222X[0] + 1836072691, 13) + m79RL184;
        int m79RL188 = m79RL(m79RL183, 10);
        int m79RL189 = m79RL(m79RL184 + m76f3(m79RL187, m79RL185, m79RL188) + this.f222X[4] + 1836072691, 7) + m79RL186;
        int m79RL190 = m79RL(m79RL185, 10);
        int m79RL191 = m79RL(m79RL186 + m76f3(m79RL189, m79RL187, m79RL190) + this.f222X[13] + 1836072691, 5) + m79RL188;
        int m79RL192 = m79RL(m79RL187, 10);
        int m79RL193 = m79RL(((m79RL188 + m75f4(m79RL159, m79RL157, m79RL160)) + this.f222X[1]) - 1894007588, 11) + m79RL158;
        int m79RL194 = m79RL(m79RL157, 10);
        int m79RL195 = m79RL(((m79RL158 + m75f4(m79RL193, m79RL159, m79RL194)) + this.f222X[9]) - 1894007588, 12) + m79RL160;
        int m79RL196 = m79RL(m79RL159, 10);
        int m79RL197 = m79RL(((m79RL160 + m75f4(m79RL195, m79RL193, m79RL196)) + this.f222X[11]) - 1894007588, 14) + m79RL194;
        int m79RL198 = m79RL(m79RL193, 10);
        int m79RL199 = m79RL(((m79RL194 + m75f4(m79RL197, m79RL195, m79RL198)) + this.f222X[10]) - 1894007588, 15) + m79RL196;
        int m79RL200 = m79RL(m79RL195, 10);
        int m79RL201 = m79RL(((m79RL196 + m75f4(m79RL199, m79RL197, m79RL200)) + this.f222X[0]) - 1894007588, 14) + m79RL198;
        int m79RL202 = m79RL(m79RL197, 10);
        int m79RL203 = m79RL(((m79RL198 + m75f4(m79RL201, m79RL199, m79RL202)) + this.f222X[8]) - 1894007588, 15) + m79RL200;
        int m79RL204 = m79RL(m79RL199, 10);
        int m79RL205 = m79RL(((m79RL200 + m75f4(m79RL203, m79RL201, m79RL204)) + this.f222X[12]) - 1894007588, 9) + m79RL202;
        int m79RL206 = m79RL(m79RL201, 10);
        int m79RL207 = m79RL(((m79RL202 + m75f4(m79RL205, m79RL203, m79RL206)) + this.f222X[4]) - 1894007588, 8) + m79RL204;
        int m79RL208 = m79RL(m79RL203, 10);
        int m79RL209 = m79RL(((m79RL204 + m75f4(m79RL207, m79RL205, m79RL208)) + this.f222X[13]) - 1894007588, 9) + m79RL206;
        int m79RL210 = m79RL(m79RL205, 10);
        int m79RL211 = m79RL(((m79RL206 + m75f4(m79RL209, m79RL207, m79RL210)) + this.f222X[3]) - 1894007588, 14) + m79RL208;
        int m79RL212 = m79RL(m79RL207, 10);
        int m79RL213 = m79RL(((m79RL208 + m75f4(m79RL211, m79RL209, m79RL212)) + this.f222X[7]) - 1894007588, 5) + m79RL210;
        int m79RL214 = m79RL(m79RL209, 10);
        int m79RL215 = m79RL(((m79RL210 + m75f4(m79RL213, m79RL211, m79RL214)) + this.f222X[15]) - 1894007588, 6) + m79RL212;
        int m79RL216 = m79RL(m79RL211, 10);
        int m79RL217 = m79RL(((m79RL212 + m75f4(m79RL215, m79RL213, m79RL216)) + this.f222X[14]) - 1894007588, 8) + m79RL214;
        int m79RL218 = m79RL(m79RL213, 10);
        int m79RL219 = m79RL(((m79RL214 + m75f4(m79RL217, m79RL215, m79RL218)) + this.f222X[5]) - 1894007588, 6) + m79RL216;
        int m79RL220 = m79RL(m79RL215, 10);
        int m79RL221 = m79RL(((m79RL216 + m75f4(m79RL219, m79RL217, m79RL220)) + this.f222X[6]) - 1894007588, 5) + m79RL218;
        int m79RL222 = m79RL(m79RL217, 10);
        int m79RL223 = m79RL(((m79RL218 + m75f4(m79RL221, m79RL219, m79RL222)) + this.f222X[2]) - 1894007588, 12) + m79RL220;
        int m79RL224 = m79RL(m79RL219, 10);
        int m79RL225 = m79RL(m79RL156 + m77f2(m79RL191, m79RL189, m79RL192) + this.f222X[8] + 2053994217, 15) + m79RL190;
        int m79RL226 = m79RL(m79RL189, 10);
        int m79RL227 = m79RL(m79RL190 + m77f2(m79RL225, m79RL191, m79RL226) + this.f222X[6] + 2053994217, 5) + m79RL192;
        int m79RL228 = m79RL(m79RL191, 10);
        int m79RL229 = m79RL(m79RL192 + m77f2(m79RL227, m79RL225, m79RL228) + this.f222X[4] + 2053994217, 8) + m79RL226;
        int m79RL230 = m79RL(m79RL225, 10);
        int m79RL231 = m79RL(m79RL226 + m77f2(m79RL229, m79RL227, m79RL230) + this.f222X[1] + 2053994217, 11) + m79RL228;
        int m79RL232 = m79RL(m79RL227, 10);
        int m79RL233 = m79RL(m79RL228 + m77f2(m79RL231, m79RL229, m79RL232) + this.f222X[3] + 2053994217, 14) + m79RL230;
        int m79RL234 = m79RL(m79RL229, 10);
        int m79RL235 = m79RL(m79RL230 + m77f2(m79RL233, m79RL231, m79RL234) + this.f222X[11] + 2053994217, 14) + m79RL232;
        int m79RL236 = m79RL(m79RL231, 10);
        int m79RL237 = m79RL(m79RL232 + m77f2(m79RL235, m79RL233, m79RL236) + this.f222X[15] + 2053994217, 6) + m79RL234;
        int m79RL238 = m79RL(m79RL233, 10);
        int m79RL239 = m79RL(m79RL234 + m77f2(m79RL237, m79RL235, m79RL238) + this.f222X[0] + 2053994217, 14) + m79RL236;
        int m79RL240 = m79RL(m79RL235, 10);
        int m79RL241 = m79RL(m79RL236 + m77f2(m79RL239, m79RL237, m79RL240) + this.f222X[5] + 2053994217, 6) + m79RL238;
        int m79RL242 = m79RL(m79RL237, 10);
        int m79RL243 = m79RL(m79RL238 + m77f2(m79RL241, m79RL239, m79RL242) + this.f222X[12] + 2053994217, 9) + m79RL240;
        int m79RL244 = m79RL(m79RL239, 10);
        int m79RL245 = m79RL(m79RL240 + m77f2(m79RL243, m79RL241, m79RL244) + this.f222X[2] + 2053994217, 12) + m79RL242;
        int m79RL246 = m79RL(m79RL241, 10);
        int m79RL247 = m79RL(m79RL242 + m77f2(m79RL245, m79RL243, m79RL246) + this.f222X[13] + 2053994217, 9) + m79RL244;
        int m79RL248 = m79RL(m79RL243, 10);
        int m79RL249 = m79RL(m79RL244 + m77f2(m79RL247, m79RL245, m79RL248) + this.f222X[9] + 2053994217, 12) + m79RL246;
        int m79RL250 = m79RL(m79RL245, 10);
        int m79RL251 = m79RL(m79RL246 + m77f2(m79RL249, m79RL247, m79RL250) + this.f222X[7] + 2053994217, 5) + m79RL248;
        int m79RL252 = m79RL(m79RL247, 10);
        int m79RL253 = m79RL(m79RL248 + m77f2(m79RL251, m79RL249, m79RL252) + this.f222X[10] + 2053994217, 15) + m79RL250;
        int m79RL254 = m79RL(m79RL249, 10);
        int m79RL255 = m79RL(m79RL250 + m77f2(m79RL253, m79RL251, m79RL254) + this.f222X[14] + 2053994217, 8) + m79RL252;
        int m79RL256 = m79RL(m79RL251, 10);
        int m79RL257 = m79RL(((m79RL220 + m74f5(m79RL223, m79RL253, m79RL224)) + this.f222X[4]) - 1454113458, 9) + m79RL222;
        int m79RL258 = m79RL(m79RL253, 10);
        int m79RL259 = m79RL(((m79RL222 + m74f5(m79RL257, m79RL223, m79RL258)) + this.f222X[0]) - 1454113458, 15) + m79RL224;
        int m79RL260 = m79RL(m79RL223, 10);
        int m79RL261 = m79RL(((m79RL224 + m74f5(m79RL259, m79RL257, m79RL260)) + this.f222X[5]) - 1454113458, 5) + m79RL258;
        int m79RL262 = m79RL(m79RL257, 10);
        int m79RL263 = m79RL(((m79RL258 + m74f5(m79RL261, m79RL259, m79RL262)) + this.f222X[9]) - 1454113458, 11) + m79RL260;
        int m79RL264 = m79RL(m79RL259, 10);
        int m79RL265 = m79RL(((m79RL260 + m74f5(m79RL263, m79RL261, m79RL264)) + this.f222X[7]) - 1454113458, 6) + m79RL262;
        int m79RL266 = m79RL(m79RL261, 10);
        int m79RL267 = m79RL(((m79RL262 + m74f5(m79RL265, m79RL263, m79RL266)) + this.f222X[12]) - 1454113458, 8) + m79RL264;
        int m79RL268 = m79RL(m79RL263, 10);
        int m79RL269 = m79RL(((m79RL264 + m74f5(m79RL267, m79RL265, m79RL268)) + this.f222X[2]) - 1454113458, 13) + m79RL266;
        int m79RL270 = m79RL(m79RL265, 10);
        int m79RL271 = m79RL(((m79RL266 + m74f5(m79RL269, m79RL267, m79RL270)) + this.f222X[10]) - 1454113458, 12) + m79RL268;
        int m79RL272 = m79RL(m79RL267, 10);
        int m79RL273 = m79RL(((m79RL268 + m74f5(m79RL271, m79RL269, m79RL272)) + this.f222X[14]) - 1454113458, 5) + m79RL270;
        int m79RL274 = m79RL(m79RL269, 10);
        int m79RL275 = m79RL(((m79RL270 + m74f5(m79RL273, m79RL271, m79RL274)) + this.f222X[1]) - 1454113458, 12) + m79RL272;
        int m79RL276 = m79RL(m79RL271, 10);
        int m79RL277 = m79RL(((m79RL272 + m74f5(m79RL275, m79RL273, m79RL276)) + this.f222X[3]) - 1454113458, 13) + m79RL274;
        int m79RL278 = m79RL(m79RL273, 10);
        int m79RL279 = m79RL(((m79RL274 + m74f5(m79RL277, m79RL275, m79RL278)) + this.f222X[8]) - 1454113458, 14) + m79RL276;
        int m79RL280 = m79RL(m79RL275, 10);
        int m79RL281 = m79RL(((m79RL276 + m74f5(m79RL279, m79RL277, m79RL280)) + this.f222X[11]) - 1454113458, 11) + m79RL278;
        int m79RL282 = m79RL(m79RL277, 10);
        int m79RL283 = m79RL(((m79RL278 + m74f5(m79RL281, m79RL279, m79RL282)) + this.f222X[6]) - 1454113458, 8) + m79RL280;
        int m79RL284 = m79RL(m79RL279, 10);
        int m79RL285 = m79RL(((m79RL280 + m74f5(m79RL283, m79RL281, m79RL284)) + this.f222X[15]) - 1454113458, 5) + m79RL282;
        int m79RL286 = m79RL(m79RL281, 10);
        int m79RL287 = m79RL(((m79RL282 + m74f5(m79RL285, m79RL283, m79RL286)) + this.f222X[13]) - 1454113458, 6) + m79RL284;
        int m79RL288 = m79RL(m79RL283, 10);
        int m79RL289 = m79RL(m79RL252 + m78f1(m79RL255, m79RL221, m79RL256) + this.f222X[12], 8) + m79RL254;
        int m79RL290 = m79RL(m79RL221, 10);
        int m79RL291 = m79RL(m79RL254 + m78f1(m79RL289, m79RL255, m79RL290) + this.f222X[15], 5) + m79RL256;
        int m79RL292 = m79RL(m79RL255, 10);
        int m79RL293 = m79RL(m79RL256 + m78f1(m79RL291, m79RL289, m79RL292) + this.f222X[10], 12) + m79RL290;
        int m79RL294 = m79RL(m79RL289, 10);
        int m79RL295 = m79RL(m79RL290 + m78f1(m79RL293, m79RL291, m79RL294) + this.f222X[4], 9) + m79RL292;
        int m79RL296 = m79RL(m79RL291, 10);
        int m79RL297 = m79RL(m79RL292 + m78f1(m79RL295, m79RL293, m79RL296) + this.f222X[1], 12) + m79RL294;
        int m79RL298 = m79RL(m79RL293, 10);
        int m79RL299 = m79RL(m79RL294 + m78f1(m79RL297, m79RL295, m79RL298) + this.f222X[5], 5) + m79RL296;
        int m79RL300 = m79RL(m79RL295, 10);
        int m79RL301 = m79RL(m79RL296 + m78f1(m79RL299, m79RL297, m79RL300) + this.f222X[8], 14) + m79RL298;
        int m79RL302 = m79RL(m79RL297, 10);
        int m79RL303 = m79RL(m79RL298 + m78f1(m79RL301, m79RL299, m79RL302) + this.f222X[7], 6) + m79RL300;
        int m79RL304 = m79RL(m79RL299, 10);
        int m79RL305 = m79RL(m79RL300 + m78f1(m79RL303, m79RL301, m79RL304) + this.f222X[6], 8) + m79RL302;
        int m79RL306 = m79RL(m79RL301, 10);
        int m79RL307 = m79RL(m79RL302 + m78f1(m79RL305, m79RL303, m79RL306) + this.f222X[2], 13) + m79RL304;
        int m79RL308 = m79RL(m79RL303, 10);
        int m79RL309 = m79RL(m79RL304 + m78f1(m79RL307, m79RL305, m79RL308) + this.f222X[13], 6) + m79RL306;
        int m79RL310 = m79RL(m79RL305, 10);
        int m79RL311 = m79RL(m79RL306 + m78f1(m79RL309, m79RL307, m79RL310) + this.f222X[14], 5) + m79RL308;
        int m79RL312 = m79RL(m79RL307, 10);
        int m79RL313 = m79RL(m79RL308 + m78f1(m79RL311, m79RL309, m79RL312) + this.f222X[0], 15) + m79RL310;
        int m79RL314 = m79RL(m79RL309, 10);
        int m79RL315 = m79RL(m79RL310 + m78f1(m79RL313, m79RL311, m79RL314) + this.f222X[3], 13) + m79RL312;
        int m79RL316 = m79RL(m79RL311, 10);
        int m79RL317 = m79RL(m79RL312 + m78f1(m79RL315, m79RL313, m79RL316) + this.f222X[9], 11) + m79RL314;
        int m79RL318 = m79RL(m79RL313, 10);
        int m79RL319 = m79RL(m79RL314 + m78f1(m79RL317, m79RL315, m79RL318) + this.f222X[11], 11) + m79RL316;
        int m79RL320 = m79RL(m79RL315, 10);
        this.f212H0 += m79RL284;
        this.f213H1 += m79RL287;
        this.f214H2 += m79RL285;
        this.f215H3 += m79RL288;
        this.f216H4 += m79RL318;
        this.f217H5 += m79RL316;
        this.f218H6 += m79RL319;
        this.f219H7 += m79RL317;
        this.f220H8 += m79RL320;
        this.f221H9 += m79RL286;
        this.xOff = 0;
        for (int i11 = 0; i11 != this.f222X.length; i11++) {
            this.f222X[i11] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD320Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        doCopy((RIPEMD320Digest) memoable);
    }
}