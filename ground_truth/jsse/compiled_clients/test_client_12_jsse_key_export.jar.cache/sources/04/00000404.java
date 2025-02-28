package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/RIPEMD160Digest.class */
public class RIPEMD160Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 20;

    /* renamed from: H0 */
    private int f197H0;

    /* renamed from: H1 */
    private int f198H1;

    /* renamed from: H2 */
    private int f199H2;

    /* renamed from: H3 */
    private int f200H3;

    /* renamed from: H4 */
    private int f201H4;

    /* renamed from: X */
    private int[] f202X;
    private int xOff;

    public RIPEMD160Digest() {
        this.f202X = new int[16];
        reset();
    }

    public RIPEMD160Digest(RIPEMD160Digest rIPEMD160Digest) {
        super(rIPEMD160Digest);
        this.f202X = new int[16];
        copyIn(rIPEMD160Digest);
    }

    private void copyIn(RIPEMD160Digest rIPEMD160Digest) {
        super.copyIn((GeneralDigest) rIPEMD160Digest);
        this.f197H0 = rIPEMD160Digest.f197H0;
        this.f198H1 = rIPEMD160Digest.f198H1;
        this.f199H2 = rIPEMD160Digest.f199H2;
        this.f200H3 = rIPEMD160Digest.f200H3;
        this.f201H4 = rIPEMD160Digest.f201H4;
        System.arraycopy(rIPEMD160Digest.f202X, 0, this.f202X, 0, rIPEMD160Digest.f202X.length);
        this.xOff = rIPEMD160Digest.xOff;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "RIPEMD160";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 20;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f202X;
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
        this.f202X[14] = (int) (j & (-1));
        this.f202X[15] = (int) (j >>> 32);
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
        unpackWord(this.f197H0, bArr, i);
        unpackWord(this.f198H1, bArr, i + 4);
        unpackWord(this.f199H2, bArr, i + 8);
        unpackWord(this.f200H3, bArr, i + 12);
        unpackWord(this.f201H4, bArr, i + 16);
        reset();
        return 20;
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f197H0 = 1732584193;
        this.f198H1 = -271733879;
        this.f199H2 = -1732584194;
        this.f200H3 = 271733878;
        this.f201H4 = -1009589776;
        this.xOff = 0;
        for (int i = 0; i != this.f202X.length; i++) {
            this.f202X[i] = 0;
        }
    }

    /* renamed from: RL */
    private int m94RL(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    /* renamed from: f1 */
    private int m93f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m92f2(int i, int i2, int i3) {
        return (i & i2) | ((i ^ (-1)) & i3);
    }

    /* renamed from: f3 */
    private int m91f3(int i, int i2, int i3) {
        return (i | (i2 ^ (-1))) ^ i3;
    }

    /* renamed from: f4 */
    private int m90f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (i3 ^ (-1)));
    }

    /* renamed from: f5 */
    private int m89f5(int i, int i2, int i3) {
        return i ^ (i2 | (i3 ^ (-1)));
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processBlock() {
        int i = this.f197H0;
        int i2 = this.f198H1;
        int i3 = this.f199H2;
        int i4 = this.f200H3;
        int i5 = this.f201H4;
        int m94RL = m94RL(i + m93f1(i2, i3, i4) + this.f202X[0], 11) + i5;
        int m94RL2 = m94RL(i3, 10);
        int m94RL3 = m94RL(i5 + m93f1(m94RL, i2, m94RL2) + this.f202X[1], 14) + i4;
        int m94RL4 = m94RL(i2, 10);
        int m94RL5 = m94RL(i4 + m93f1(m94RL3, m94RL, m94RL4) + this.f202X[2], 15) + m94RL2;
        int m94RL6 = m94RL(m94RL, 10);
        int m94RL7 = m94RL(m94RL2 + m93f1(m94RL5, m94RL3, m94RL6) + this.f202X[3], 12) + m94RL4;
        int m94RL8 = m94RL(m94RL3, 10);
        int m94RL9 = m94RL(m94RL4 + m93f1(m94RL7, m94RL5, m94RL8) + this.f202X[4], 5) + m94RL6;
        int m94RL10 = m94RL(m94RL5, 10);
        int m94RL11 = m94RL(m94RL6 + m93f1(m94RL9, m94RL7, m94RL10) + this.f202X[5], 8) + m94RL8;
        int m94RL12 = m94RL(m94RL7, 10);
        int m94RL13 = m94RL(m94RL8 + m93f1(m94RL11, m94RL9, m94RL12) + this.f202X[6], 7) + m94RL10;
        int m94RL14 = m94RL(m94RL9, 10);
        int m94RL15 = m94RL(m94RL10 + m93f1(m94RL13, m94RL11, m94RL14) + this.f202X[7], 9) + m94RL12;
        int m94RL16 = m94RL(m94RL11, 10);
        int m94RL17 = m94RL(m94RL12 + m93f1(m94RL15, m94RL13, m94RL16) + this.f202X[8], 11) + m94RL14;
        int m94RL18 = m94RL(m94RL13, 10);
        int m94RL19 = m94RL(m94RL14 + m93f1(m94RL17, m94RL15, m94RL18) + this.f202X[9], 13) + m94RL16;
        int m94RL20 = m94RL(m94RL15, 10);
        int m94RL21 = m94RL(m94RL16 + m93f1(m94RL19, m94RL17, m94RL20) + this.f202X[10], 14) + m94RL18;
        int m94RL22 = m94RL(m94RL17, 10);
        int m94RL23 = m94RL(m94RL18 + m93f1(m94RL21, m94RL19, m94RL22) + this.f202X[11], 15) + m94RL20;
        int m94RL24 = m94RL(m94RL19, 10);
        int m94RL25 = m94RL(m94RL20 + m93f1(m94RL23, m94RL21, m94RL24) + this.f202X[12], 6) + m94RL22;
        int m94RL26 = m94RL(m94RL21, 10);
        int m94RL27 = m94RL(m94RL22 + m93f1(m94RL25, m94RL23, m94RL26) + this.f202X[13], 7) + m94RL24;
        int m94RL28 = m94RL(m94RL23, 10);
        int m94RL29 = m94RL(m94RL24 + m93f1(m94RL27, m94RL25, m94RL28) + this.f202X[14], 9) + m94RL26;
        int m94RL30 = m94RL(m94RL25, 10);
        int m94RL31 = m94RL(m94RL26 + m93f1(m94RL29, m94RL27, m94RL30) + this.f202X[15], 8) + m94RL28;
        int m94RL32 = m94RL(m94RL27, 10);
        int m94RL33 = m94RL(i + m89f5(i2, i3, i4) + this.f202X[5] + 1352829926, 8) + i5;
        int m94RL34 = m94RL(i3, 10);
        int m94RL35 = m94RL(i5 + m89f5(m94RL33, i2, m94RL34) + this.f202X[14] + 1352829926, 9) + i4;
        int m94RL36 = m94RL(i2, 10);
        int m94RL37 = m94RL(i4 + m89f5(m94RL35, m94RL33, m94RL36) + this.f202X[7] + 1352829926, 9) + m94RL34;
        int m94RL38 = m94RL(m94RL33, 10);
        int m94RL39 = m94RL(m94RL34 + m89f5(m94RL37, m94RL35, m94RL38) + this.f202X[0] + 1352829926, 11) + m94RL36;
        int m94RL40 = m94RL(m94RL35, 10);
        int m94RL41 = m94RL(m94RL36 + m89f5(m94RL39, m94RL37, m94RL40) + this.f202X[9] + 1352829926, 13) + m94RL38;
        int m94RL42 = m94RL(m94RL37, 10);
        int m94RL43 = m94RL(m94RL38 + m89f5(m94RL41, m94RL39, m94RL42) + this.f202X[2] + 1352829926, 15) + m94RL40;
        int m94RL44 = m94RL(m94RL39, 10);
        int m94RL45 = m94RL(m94RL40 + m89f5(m94RL43, m94RL41, m94RL44) + this.f202X[11] + 1352829926, 15) + m94RL42;
        int m94RL46 = m94RL(m94RL41, 10);
        int m94RL47 = m94RL(m94RL42 + m89f5(m94RL45, m94RL43, m94RL46) + this.f202X[4] + 1352829926, 5) + m94RL44;
        int m94RL48 = m94RL(m94RL43, 10);
        int m94RL49 = m94RL(m94RL44 + m89f5(m94RL47, m94RL45, m94RL48) + this.f202X[13] + 1352829926, 7) + m94RL46;
        int m94RL50 = m94RL(m94RL45, 10);
        int m94RL51 = m94RL(m94RL46 + m89f5(m94RL49, m94RL47, m94RL50) + this.f202X[6] + 1352829926, 7) + m94RL48;
        int m94RL52 = m94RL(m94RL47, 10);
        int m94RL53 = m94RL(m94RL48 + m89f5(m94RL51, m94RL49, m94RL52) + this.f202X[15] + 1352829926, 8) + m94RL50;
        int m94RL54 = m94RL(m94RL49, 10);
        int m94RL55 = m94RL(m94RL50 + m89f5(m94RL53, m94RL51, m94RL54) + this.f202X[8] + 1352829926, 11) + m94RL52;
        int m94RL56 = m94RL(m94RL51, 10);
        int m94RL57 = m94RL(m94RL52 + m89f5(m94RL55, m94RL53, m94RL56) + this.f202X[1] + 1352829926, 14) + m94RL54;
        int m94RL58 = m94RL(m94RL53, 10);
        int m94RL59 = m94RL(m94RL54 + m89f5(m94RL57, m94RL55, m94RL58) + this.f202X[10] + 1352829926, 14) + m94RL56;
        int m94RL60 = m94RL(m94RL55, 10);
        int m94RL61 = m94RL(m94RL56 + m89f5(m94RL59, m94RL57, m94RL60) + this.f202X[3] + 1352829926, 12) + m94RL58;
        int m94RL62 = m94RL(m94RL57, 10);
        int m94RL63 = m94RL(m94RL58 + m89f5(m94RL61, m94RL59, m94RL62) + this.f202X[12] + 1352829926, 6) + m94RL60;
        int m94RL64 = m94RL(m94RL59, 10);
        int m94RL65 = m94RL(m94RL28 + m92f2(m94RL31, m94RL29, m94RL32) + this.f202X[7] + 1518500249, 7) + m94RL30;
        int m94RL66 = m94RL(m94RL29, 10);
        int m94RL67 = m94RL(m94RL30 + m92f2(m94RL65, m94RL31, m94RL66) + this.f202X[4] + 1518500249, 6) + m94RL32;
        int m94RL68 = m94RL(m94RL31, 10);
        int m94RL69 = m94RL(m94RL32 + m92f2(m94RL67, m94RL65, m94RL68) + this.f202X[13] + 1518500249, 8) + m94RL66;
        int m94RL70 = m94RL(m94RL65, 10);
        int m94RL71 = m94RL(m94RL66 + m92f2(m94RL69, m94RL67, m94RL70) + this.f202X[1] + 1518500249, 13) + m94RL68;
        int m94RL72 = m94RL(m94RL67, 10);
        int m94RL73 = m94RL(m94RL68 + m92f2(m94RL71, m94RL69, m94RL72) + this.f202X[10] + 1518500249, 11) + m94RL70;
        int m94RL74 = m94RL(m94RL69, 10);
        int m94RL75 = m94RL(m94RL70 + m92f2(m94RL73, m94RL71, m94RL74) + this.f202X[6] + 1518500249, 9) + m94RL72;
        int m94RL76 = m94RL(m94RL71, 10);
        int m94RL77 = m94RL(m94RL72 + m92f2(m94RL75, m94RL73, m94RL76) + this.f202X[15] + 1518500249, 7) + m94RL74;
        int m94RL78 = m94RL(m94RL73, 10);
        int m94RL79 = m94RL(m94RL74 + m92f2(m94RL77, m94RL75, m94RL78) + this.f202X[3] + 1518500249, 15) + m94RL76;
        int m94RL80 = m94RL(m94RL75, 10);
        int m94RL81 = m94RL(m94RL76 + m92f2(m94RL79, m94RL77, m94RL80) + this.f202X[12] + 1518500249, 7) + m94RL78;
        int m94RL82 = m94RL(m94RL77, 10);
        int m94RL83 = m94RL(m94RL78 + m92f2(m94RL81, m94RL79, m94RL82) + this.f202X[0] + 1518500249, 12) + m94RL80;
        int m94RL84 = m94RL(m94RL79, 10);
        int m94RL85 = m94RL(m94RL80 + m92f2(m94RL83, m94RL81, m94RL84) + this.f202X[9] + 1518500249, 15) + m94RL82;
        int m94RL86 = m94RL(m94RL81, 10);
        int m94RL87 = m94RL(m94RL82 + m92f2(m94RL85, m94RL83, m94RL86) + this.f202X[5] + 1518500249, 9) + m94RL84;
        int m94RL88 = m94RL(m94RL83, 10);
        int m94RL89 = m94RL(m94RL84 + m92f2(m94RL87, m94RL85, m94RL88) + this.f202X[2] + 1518500249, 11) + m94RL86;
        int m94RL90 = m94RL(m94RL85, 10);
        int m94RL91 = m94RL(m94RL86 + m92f2(m94RL89, m94RL87, m94RL90) + this.f202X[14] + 1518500249, 7) + m94RL88;
        int m94RL92 = m94RL(m94RL87, 10);
        int m94RL93 = m94RL(m94RL88 + m92f2(m94RL91, m94RL89, m94RL92) + this.f202X[11] + 1518500249, 13) + m94RL90;
        int m94RL94 = m94RL(m94RL89, 10);
        int m94RL95 = m94RL(m94RL90 + m92f2(m94RL93, m94RL91, m94RL94) + this.f202X[8] + 1518500249, 12) + m94RL92;
        int m94RL96 = m94RL(m94RL91, 10);
        int m94RL97 = m94RL(m94RL60 + m90f4(m94RL63, m94RL61, m94RL64) + this.f202X[6] + 1548603684, 9) + m94RL62;
        int m94RL98 = m94RL(m94RL61, 10);
        int m94RL99 = m94RL(m94RL62 + m90f4(m94RL97, m94RL63, m94RL98) + this.f202X[11] + 1548603684, 13) + m94RL64;
        int m94RL100 = m94RL(m94RL63, 10);
        int m94RL101 = m94RL(m94RL64 + m90f4(m94RL99, m94RL97, m94RL100) + this.f202X[3] + 1548603684, 15) + m94RL98;
        int m94RL102 = m94RL(m94RL97, 10);
        int m94RL103 = m94RL(m94RL98 + m90f4(m94RL101, m94RL99, m94RL102) + this.f202X[7] + 1548603684, 7) + m94RL100;
        int m94RL104 = m94RL(m94RL99, 10);
        int m94RL105 = m94RL(m94RL100 + m90f4(m94RL103, m94RL101, m94RL104) + this.f202X[0] + 1548603684, 12) + m94RL102;
        int m94RL106 = m94RL(m94RL101, 10);
        int m94RL107 = m94RL(m94RL102 + m90f4(m94RL105, m94RL103, m94RL106) + this.f202X[13] + 1548603684, 8) + m94RL104;
        int m94RL108 = m94RL(m94RL103, 10);
        int m94RL109 = m94RL(m94RL104 + m90f4(m94RL107, m94RL105, m94RL108) + this.f202X[5] + 1548603684, 9) + m94RL106;
        int m94RL110 = m94RL(m94RL105, 10);
        int m94RL111 = m94RL(m94RL106 + m90f4(m94RL109, m94RL107, m94RL110) + this.f202X[10] + 1548603684, 11) + m94RL108;
        int m94RL112 = m94RL(m94RL107, 10);
        int m94RL113 = m94RL(m94RL108 + m90f4(m94RL111, m94RL109, m94RL112) + this.f202X[14] + 1548603684, 7) + m94RL110;
        int m94RL114 = m94RL(m94RL109, 10);
        int m94RL115 = m94RL(m94RL110 + m90f4(m94RL113, m94RL111, m94RL114) + this.f202X[15] + 1548603684, 7) + m94RL112;
        int m94RL116 = m94RL(m94RL111, 10);
        int m94RL117 = m94RL(m94RL112 + m90f4(m94RL115, m94RL113, m94RL116) + this.f202X[8] + 1548603684, 12) + m94RL114;
        int m94RL118 = m94RL(m94RL113, 10);
        int m94RL119 = m94RL(m94RL114 + m90f4(m94RL117, m94RL115, m94RL118) + this.f202X[12] + 1548603684, 7) + m94RL116;
        int m94RL120 = m94RL(m94RL115, 10);
        int m94RL121 = m94RL(m94RL116 + m90f4(m94RL119, m94RL117, m94RL120) + this.f202X[4] + 1548603684, 6) + m94RL118;
        int m94RL122 = m94RL(m94RL117, 10);
        int m94RL123 = m94RL(m94RL118 + m90f4(m94RL121, m94RL119, m94RL122) + this.f202X[9] + 1548603684, 15) + m94RL120;
        int m94RL124 = m94RL(m94RL119, 10);
        int m94RL125 = m94RL(m94RL120 + m90f4(m94RL123, m94RL121, m94RL124) + this.f202X[1] + 1548603684, 13) + m94RL122;
        int m94RL126 = m94RL(m94RL121, 10);
        int m94RL127 = m94RL(m94RL122 + m90f4(m94RL125, m94RL123, m94RL126) + this.f202X[2] + 1548603684, 11) + m94RL124;
        int m94RL128 = m94RL(m94RL123, 10);
        int m94RL129 = m94RL(m94RL92 + m91f3(m94RL95, m94RL93, m94RL96) + this.f202X[3] + 1859775393, 11) + m94RL94;
        int m94RL130 = m94RL(m94RL93, 10);
        int m94RL131 = m94RL(m94RL94 + m91f3(m94RL129, m94RL95, m94RL130) + this.f202X[10] + 1859775393, 13) + m94RL96;
        int m94RL132 = m94RL(m94RL95, 10);
        int m94RL133 = m94RL(m94RL96 + m91f3(m94RL131, m94RL129, m94RL132) + this.f202X[14] + 1859775393, 6) + m94RL130;
        int m94RL134 = m94RL(m94RL129, 10);
        int m94RL135 = m94RL(m94RL130 + m91f3(m94RL133, m94RL131, m94RL134) + this.f202X[4] + 1859775393, 7) + m94RL132;
        int m94RL136 = m94RL(m94RL131, 10);
        int m94RL137 = m94RL(m94RL132 + m91f3(m94RL135, m94RL133, m94RL136) + this.f202X[9] + 1859775393, 14) + m94RL134;
        int m94RL138 = m94RL(m94RL133, 10);
        int m94RL139 = m94RL(m94RL134 + m91f3(m94RL137, m94RL135, m94RL138) + this.f202X[15] + 1859775393, 9) + m94RL136;
        int m94RL140 = m94RL(m94RL135, 10);
        int m94RL141 = m94RL(m94RL136 + m91f3(m94RL139, m94RL137, m94RL140) + this.f202X[8] + 1859775393, 13) + m94RL138;
        int m94RL142 = m94RL(m94RL137, 10);
        int m94RL143 = m94RL(m94RL138 + m91f3(m94RL141, m94RL139, m94RL142) + this.f202X[1] + 1859775393, 15) + m94RL140;
        int m94RL144 = m94RL(m94RL139, 10);
        int m94RL145 = m94RL(m94RL140 + m91f3(m94RL143, m94RL141, m94RL144) + this.f202X[2] + 1859775393, 14) + m94RL142;
        int m94RL146 = m94RL(m94RL141, 10);
        int m94RL147 = m94RL(m94RL142 + m91f3(m94RL145, m94RL143, m94RL146) + this.f202X[7] + 1859775393, 8) + m94RL144;
        int m94RL148 = m94RL(m94RL143, 10);
        int m94RL149 = m94RL(m94RL144 + m91f3(m94RL147, m94RL145, m94RL148) + this.f202X[0] + 1859775393, 13) + m94RL146;
        int m94RL150 = m94RL(m94RL145, 10);
        int m94RL151 = m94RL(m94RL146 + m91f3(m94RL149, m94RL147, m94RL150) + this.f202X[6] + 1859775393, 6) + m94RL148;
        int m94RL152 = m94RL(m94RL147, 10);
        int m94RL153 = m94RL(m94RL148 + m91f3(m94RL151, m94RL149, m94RL152) + this.f202X[13] + 1859775393, 5) + m94RL150;
        int m94RL154 = m94RL(m94RL149, 10);
        int m94RL155 = m94RL(m94RL150 + m91f3(m94RL153, m94RL151, m94RL154) + this.f202X[11] + 1859775393, 12) + m94RL152;
        int m94RL156 = m94RL(m94RL151, 10);
        int m94RL157 = m94RL(m94RL152 + m91f3(m94RL155, m94RL153, m94RL156) + this.f202X[5] + 1859775393, 7) + m94RL154;
        int m94RL158 = m94RL(m94RL153, 10);
        int m94RL159 = m94RL(m94RL154 + m91f3(m94RL157, m94RL155, m94RL158) + this.f202X[12] + 1859775393, 5) + m94RL156;
        int m94RL160 = m94RL(m94RL155, 10);
        int m94RL161 = m94RL(m94RL124 + m91f3(m94RL127, m94RL125, m94RL128) + this.f202X[15] + 1836072691, 9) + m94RL126;
        int m94RL162 = m94RL(m94RL125, 10);
        int m94RL163 = m94RL(m94RL126 + m91f3(m94RL161, m94RL127, m94RL162) + this.f202X[5] + 1836072691, 7) + m94RL128;
        int m94RL164 = m94RL(m94RL127, 10);
        int m94RL165 = m94RL(m94RL128 + m91f3(m94RL163, m94RL161, m94RL164) + this.f202X[1] + 1836072691, 15) + m94RL162;
        int m94RL166 = m94RL(m94RL161, 10);
        int m94RL167 = m94RL(m94RL162 + m91f3(m94RL165, m94RL163, m94RL166) + this.f202X[3] + 1836072691, 11) + m94RL164;
        int m94RL168 = m94RL(m94RL163, 10);
        int m94RL169 = m94RL(m94RL164 + m91f3(m94RL167, m94RL165, m94RL168) + this.f202X[7] + 1836072691, 8) + m94RL166;
        int m94RL170 = m94RL(m94RL165, 10);
        int m94RL171 = m94RL(m94RL166 + m91f3(m94RL169, m94RL167, m94RL170) + this.f202X[14] + 1836072691, 6) + m94RL168;
        int m94RL172 = m94RL(m94RL167, 10);
        int m94RL173 = m94RL(m94RL168 + m91f3(m94RL171, m94RL169, m94RL172) + this.f202X[6] + 1836072691, 6) + m94RL170;
        int m94RL174 = m94RL(m94RL169, 10);
        int m94RL175 = m94RL(m94RL170 + m91f3(m94RL173, m94RL171, m94RL174) + this.f202X[9] + 1836072691, 14) + m94RL172;
        int m94RL176 = m94RL(m94RL171, 10);
        int m94RL177 = m94RL(m94RL172 + m91f3(m94RL175, m94RL173, m94RL176) + this.f202X[11] + 1836072691, 12) + m94RL174;
        int m94RL178 = m94RL(m94RL173, 10);
        int m94RL179 = m94RL(m94RL174 + m91f3(m94RL177, m94RL175, m94RL178) + this.f202X[8] + 1836072691, 13) + m94RL176;
        int m94RL180 = m94RL(m94RL175, 10);
        int m94RL181 = m94RL(m94RL176 + m91f3(m94RL179, m94RL177, m94RL180) + this.f202X[12] + 1836072691, 5) + m94RL178;
        int m94RL182 = m94RL(m94RL177, 10);
        int m94RL183 = m94RL(m94RL178 + m91f3(m94RL181, m94RL179, m94RL182) + this.f202X[2] + 1836072691, 14) + m94RL180;
        int m94RL184 = m94RL(m94RL179, 10);
        int m94RL185 = m94RL(m94RL180 + m91f3(m94RL183, m94RL181, m94RL184) + this.f202X[10] + 1836072691, 13) + m94RL182;
        int m94RL186 = m94RL(m94RL181, 10);
        int m94RL187 = m94RL(m94RL182 + m91f3(m94RL185, m94RL183, m94RL186) + this.f202X[0] + 1836072691, 13) + m94RL184;
        int m94RL188 = m94RL(m94RL183, 10);
        int m94RL189 = m94RL(m94RL184 + m91f3(m94RL187, m94RL185, m94RL188) + this.f202X[4] + 1836072691, 7) + m94RL186;
        int m94RL190 = m94RL(m94RL185, 10);
        int m94RL191 = m94RL(m94RL186 + m91f3(m94RL189, m94RL187, m94RL190) + this.f202X[13] + 1836072691, 5) + m94RL188;
        int m94RL192 = m94RL(m94RL187, 10);
        int m94RL193 = m94RL(((m94RL156 + m90f4(m94RL159, m94RL157, m94RL160)) + this.f202X[1]) - 1894007588, 11) + m94RL158;
        int m94RL194 = m94RL(m94RL157, 10);
        int m94RL195 = m94RL(((m94RL158 + m90f4(m94RL193, m94RL159, m94RL194)) + this.f202X[9]) - 1894007588, 12) + m94RL160;
        int m94RL196 = m94RL(m94RL159, 10);
        int m94RL197 = m94RL(((m94RL160 + m90f4(m94RL195, m94RL193, m94RL196)) + this.f202X[11]) - 1894007588, 14) + m94RL194;
        int m94RL198 = m94RL(m94RL193, 10);
        int m94RL199 = m94RL(((m94RL194 + m90f4(m94RL197, m94RL195, m94RL198)) + this.f202X[10]) - 1894007588, 15) + m94RL196;
        int m94RL200 = m94RL(m94RL195, 10);
        int m94RL201 = m94RL(((m94RL196 + m90f4(m94RL199, m94RL197, m94RL200)) + this.f202X[0]) - 1894007588, 14) + m94RL198;
        int m94RL202 = m94RL(m94RL197, 10);
        int m94RL203 = m94RL(((m94RL198 + m90f4(m94RL201, m94RL199, m94RL202)) + this.f202X[8]) - 1894007588, 15) + m94RL200;
        int m94RL204 = m94RL(m94RL199, 10);
        int m94RL205 = m94RL(((m94RL200 + m90f4(m94RL203, m94RL201, m94RL204)) + this.f202X[12]) - 1894007588, 9) + m94RL202;
        int m94RL206 = m94RL(m94RL201, 10);
        int m94RL207 = m94RL(((m94RL202 + m90f4(m94RL205, m94RL203, m94RL206)) + this.f202X[4]) - 1894007588, 8) + m94RL204;
        int m94RL208 = m94RL(m94RL203, 10);
        int m94RL209 = m94RL(((m94RL204 + m90f4(m94RL207, m94RL205, m94RL208)) + this.f202X[13]) - 1894007588, 9) + m94RL206;
        int m94RL210 = m94RL(m94RL205, 10);
        int m94RL211 = m94RL(((m94RL206 + m90f4(m94RL209, m94RL207, m94RL210)) + this.f202X[3]) - 1894007588, 14) + m94RL208;
        int m94RL212 = m94RL(m94RL207, 10);
        int m94RL213 = m94RL(((m94RL208 + m90f4(m94RL211, m94RL209, m94RL212)) + this.f202X[7]) - 1894007588, 5) + m94RL210;
        int m94RL214 = m94RL(m94RL209, 10);
        int m94RL215 = m94RL(((m94RL210 + m90f4(m94RL213, m94RL211, m94RL214)) + this.f202X[15]) - 1894007588, 6) + m94RL212;
        int m94RL216 = m94RL(m94RL211, 10);
        int m94RL217 = m94RL(((m94RL212 + m90f4(m94RL215, m94RL213, m94RL216)) + this.f202X[14]) - 1894007588, 8) + m94RL214;
        int m94RL218 = m94RL(m94RL213, 10);
        int m94RL219 = m94RL(((m94RL214 + m90f4(m94RL217, m94RL215, m94RL218)) + this.f202X[5]) - 1894007588, 6) + m94RL216;
        int m94RL220 = m94RL(m94RL215, 10);
        int m94RL221 = m94RL(((m94RL216 + m90f4(m94RL219, m94RL217, m94RL220)) + this.f202X[6]) - 1894007588, 5) + m94RL218;
        int m94RL222 = m94RL(m94RL217, 10);
        int m94RL223 = m94RL(((m94RL218 + m90f4(m94RL221, m94RL219, m94RL222)) + this.f202X[2]) - 1894007588, 12) + m94RL220;
        int m94RL224 = m94RL(m94RL219, 10);
        int m94RL225 = m94RL(m94RL188 + m92f2(m94RL191, m94RL189, m94RL192) + this.f202X[8] + 2053994217, 15) + m94RL190;
        int m94RL226 = m94RL(m94RL189, 10);
        int m94RL227 = m94RL(m94RL190 + m92f2(m94RL225, m94RL191, m94RL226) + this.f202X[6] + 2053994217, 5) + m94RL192;
        int m94RL228 = m94RL(m94RL191, 10);
        int m94RL229 = m94RL(m94RL192 + m92f2(m94RL227, m94RL225, m94RL228) + this.f202X[4] + 2053994217, 8) + m94RL226;
        int m94RL230 = m94RL(m94RL225, 10);
        int m94RL231 = m94RL(m94RL226 + m92f2(m94RL229, m94RL227, m94RL230) + this.f202X[1] + 2053994217, 11) + m94RL228;
        int m94RL232 = m94RL(m94RL227, 10);
        int m94RL233 = m94RL(m94RL228 + m92f2(m94RL231, m94RL229, m94RL232) + this.f202X[3] + 2053994217, 14) + m94RL230;
        int m94RL234 = m94RL(m94RL229, 10);
        int m94RL235 = m94RL(m94RL230 + m92f2(m94RL233, m94RL231, m94RL234) + this.f202X[11] + 2053994217, 14) + m94RL232;
        int m94RL236 = m94RL(m94RL231, 10);
        int m94RL237 = m94RL(m94RL232 + m92f2(m94RL235, m94RL233, m94RL236) + this.f202X[15] + 2053994217, 6) + m94RL234;
        int m94RL238 = m94RL(m94RL233, 10);
        int m94RL239 = m94RL(m94RL234 + m92f2(m94RL237, m94RL235, m94RL238) + this.f202X[0] + 2053994217, 14) + m94RL236;
        int m94RL240 = m94RL(m94RL235, 10);
        int m94RL241 = m94RL(m94RL236 + m92f2(m94RL239, m94RL237, m94RL240) + this.f202X[5] + 2053994217, 6) + m94RL238;
        int m94RL242 = m94RL(m94RL237, 10);
        int m94RL243 = m94RL(m94RL238 + m92f2(m94RL241, m94RL239, m94RL242) + this.f202X[12] + 2053994217, 9) + m94RL240;
        int m94RL244 = m94RL(m94RL239, 10);
        int m94RL245 = m94RL(m94RL240 + m92f2(m94RL243, m94RL241, m94RL244) + this.f202X[2] + 2053994217, 12) + m94RL242;
        int m94RL246 = m94RL(m94RL241, 10);
        int m94RL247 = m94RL(m94RL242 + m92f2(m94RL245, m94RL243, m94RL246) + this.f202X[13] + 2053994217, 9) + m94RL244;
        int m94RL248 = m94RL(m94RL243, 10);
        int m94RL249 = m94RL(m94RL244 + m92f2(m94RL247, m94RL245, m94RL248) + this.f202X[9] + 2053994217, 12) + m94RL246;
        int m94RL250 = m94RL(m94RL245, 10);
        int m94RL251 = m94RL(m94RL246 + m92f2(m94RL249, m94RL247, m94RL250) + this.f202X[7] + 2053994217, 5) + m94RL248;
        int m94RL252 = m94RL(m94RL247, 10);
        int m94RL253 = m94RL(m94RL248 + m92f2(m94RL251, m94RL249, m94RL252) + this.f202X[10] + 2053994217, 15) + m94RL250;
        int m94RL254 = m94RL(m94RL249, 10);
        int m94RL255 = m94RL(m94RL250 + m92f2(m94RL253, m94RL251, m94RL254) + this.f202X[14] + 2053994217, 8) + m94RL252;
        int m94RL256 = m94RL(m94RL251, 10);
        int m94RL257 = m94RL(((m94RL220 + m89f5(m94RL223, m94RL221, m94RL224)) + this.f202X[4]) - 1454113458, 9) + m94RL222;
        int m94RL258 = m94RL(m94RL221, 10);
        int m94RL259 = m94RL(((m94RL222 + m89f5(m94RL257, m94RL223, m94RL258)) + this.f202X[0]) - 1454113458, 15) + m94RL224;
        int m94RL260 = m94RL(m94RL223, 10);
        int m94RL261 = m94RL(((m94RL224 + m89f5(m94RL259, m94RL257, m94RL260)) + this.f202X[5]) - 1454113458, 5) + m94RL258;
        int m94RL262 = m94RL(m94RL257, 10);
        int m94RL263 = m94RL(((m94RL258 + m89f5(m94RL261, m94RL259, m94RL262)) + this.f202X[9]) - 1454113458, 11) + m94RL260;
        int m94RL264 = m94RL(m94RL259, 10);
        int m94RL265 = m94RL(((m94RL260 + m89f5(m94RL263, m94RL261, m94RL264)) + this.f202X[7]) - 1454113458, 6) + m94RL262;
        int m94RL266 = m94RL(m94RL261, 10);
        int m94RL267 = m94RL(((m94RL262 + m89f5(m94RL265, m94RL263, m94RL266)) + this.f202X[12]) - 1454113458, 8) + m94RL264;
        int m94RL268 = m94RL(m94RL263, 10);
        int m94RL269 = m94RL(((m94RL264 + m89f5(m94RL267, m94RL265, m94RL268)) + this.f202X[2]) - 1454113458, 13) + m94RL266;
        int m94RL270 = m94RL(m94RL265, 10);
        int m94RL271 = m94RL(((m94RL266 + m89f5(m94RL269, m94RL267, m94RL270)) + this.f202X[10]) - 1454113458, 12) + m94RL268;
        int m94RL272 = m94RL(m94RL267, 10);
        int m94RL273 = m94RL(((m94RL268 + m89f5(m94RL271, m94RL269, m94RL272)) + this.f202X[14]) - 1454113458, 5) + m94RL270;
        int m94RL274 = m94RL(m94RL269, 10);
        int m94RL275 = m94RL(((m94RL270 + m89f5(m94RL273, m94RL271, m94RL274)) + this.f202X[1]) - 1454113458, 12) + m94RL272;
        int m94RL276 = m94RL(m94RL271, 10);
        int m94RL277 = m94RL(((m94RL272 + m89f5(m94RL275, m94RL273, m94RL276)) + this.f202X[3]) - 1454113458, 13) + m94RL274;
        int m94RL278 = m94RL(m94RL273, 10);
        int m94RL279 = m94RL(((m94RL274 + m89f5(m94RL277, m94RL275, m94RL278)) + this.f202X[8]) - 1454113458, 14) + m94RL276;
        int m94RL280 = m94RL(m94RL275, 10);
        int m94RL281 = m94RL(((m94RL276 + m89f5(m94RL279, m94RL277, m94RL280)) + this.f202X[11]) - 1454113458, 11) + m94RL278;
        int m94RL282 = m94RL(m94RL277, 10);
        int m94RL283 = m94RL(((m94RL278 + m89f5(m94RL281, m94RL279, m94RL282)) + this.f202X[6]) - 1454113458, 8) + m94RL280;
        int m94RL284 = m94RL(m94RL279, 10);
        int m94RL285 = m94RL(((m94RL280 + m89f5(m94RL283, m94RL281, m94RL284)) + this.f202X[15]) - 1454113458, 5) + m94RL282;
        int m94RL286 = m94RL(m94RL281, 10);
        int m94RL287 = m94RL(((m94RL282 + m89f5(m94RL285, m94RL283, m94RL286)) + this.f202X[13]) - 1454113458, 6) + m94RL284;
        int m94RL288 = m94RL(m94RL283, 10);
        int m94RL289 = m94RL(m94RL252 + m93f1(m94RL255, m94RL253, m94RL256) + this.f202X[12], 8) + m94RL254;
        int m94RL290 = m94RL(m94RL253, 10);
        int m94RL291 = m94RL(m94RL254 + m93f1(m94RL289, m94RL255, m94RL290) + this.f202X[15], 5) + m94RL256;
        int m94RL292 = m94RL(m94RL255, 10);
        int m94RL293 = m94RL(m94RL256 + m93f1(m94RL291, m94RL289, m94RL292) + this.f202X[10], 12) + m94RL290;
        int m94RL294 = m94RL(m94RL289, 10);
        int m94RL295 = m94RL(m94RL290 + m93f1(m94RL293, m94RL291, m94RL294) + this.f202X[4], 9) + m94RL292;
        int m94RL296 = m94RL(m94RL291, 10);
        int m94RL297 = m94RL(m94RL292 + m93f1(m94RL295, m94RL293, m94RL296) + this.f202X[1], 12) + m94RL294;
        int m94RL298 = m94RL(m94RL293, 10);
        int m94RL299 = m94RL(m94RL294 + m93f1(m94RL297, m94RL295, m94RL298) + this.f202X[5], 5) + m94RL296;
        int m94RL300 = m94RL(m94RL295, 10);
        int m94RL301 = m94RL(m94RL296 + m93f1(m94RL299, m94RL297, m94RL300) + this.f202X[8], 14) + m94RL298;
        int m94RL302 = m94RL(m94RL297, 10);
        int m94RL303 = m94RL(m94RL298 + m93f1(m94RL301, m94RL299, m94RL302) + this.f202X[7], 6) + m94RL300;
        int m94RL304 = m94RL(m94RL299, 10);
        int m94RL305 = m94RL(m94RL300 + m93f1(m94RL303, m94RL301, m94RL304) + this.f202X[6], 8) + m94RL302;
        int m94RL306 = m94RL(m94RL301, 10);
        int m94RL307 = m94RL(m94RL302 + m93f1(m94RL305, m94RL303, m94RL306) + this.f202X[2], 13) + m94RL304;
        int m94RL308 = m94RL(m94RL303, 10);
        int m94RL309 = m94RL(m94RL304 + m93f1(m94RL307, m94RL305, m94RL308) + this.f202X[13], 6) + m94RL306;
        int m94RL310 = m94RL(m94RL305, 10);
        int m94RL311 = m94RL(m94RL306 + m93f1(m94RL309, m94RL307, m94RL310) + this.f202X[14], 5) + m94RL308;
        int m94RL312 = m94RL(m94RL307, 10);
        int m94RL313 = m94RL(m94RL308 + m93f1(m94RL311, m94RL309, m94RL312) + this.f202X[0], 15) + m94RL310;
        int m94RL314 = m94RL(m94RL309, 10);
        int m94RL315 = m94RL(m94RL310 + m93f1(m94RL313, m94RL311, m94RL314) + this.f202X[3], 13) + m94RL312;
        int m94RL316 = m94RL(m94RL311, 10);
        int m94RL317 = m94RL(m94RL312 + m93f1(m94RL315, m94RL313, m94RL316) + this.f202X[9], 11) + m94RL314;
        int m94RL318 = m94RL(m94RL313, 10);
        int m94RL319 = m94RL(m94RL314 + m93f1(m94RL317, m94RL315, m94RL318) + this.f202X[11], 11) + m94RL316;
        int m94RL320 = m94RL(m94RL315, 10) + m94RL285 + this.f198H1;
        this.f198H1 = this.f199H2 + m94RL288 + m94RL318;
        this.f199H2 = this.f200H3 + m94RL286 + m94RL316;
        this.f200H3 = this.f201H4 + m94RL284 + m94RL319;
        this.f201H4 = this.f197H0 + m94RL287 + m94RL317;
        this.f197H0 = m94RL320;
        this.xOff = 0;
        for (int i6 = 0; i6 != this.f202X.length; i6++) {
            this.f202X[i6] = 0;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD160Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD160Digest) memoable);
    }
}