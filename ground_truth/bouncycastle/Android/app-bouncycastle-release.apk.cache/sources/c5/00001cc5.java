package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class RIPEMD160Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 20;

    /* renamed from: H0 */
    private int f471H0;

    /* renamed from: H1 */
    private int f472H1;

    /* renamed from: H2 */
    private int f473H2;

    /* renamed from: H3 */
    private int f474H3;

    /* renamed from: H4 */
    private int f475H4;

    /* renamed from: X */
    private int[] f476X;
    private int xOff;

    public RIPEMD160Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public RIPEMD160Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f476X = new int[16];
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset();
    }

    public RIPEMD160Digest(RIPEMD160Digest rIPEMD160Digest) {
        super(rIPEMD160Digest);
        this.f476X = new int[16];
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        copyIn(rIPEMD160Digest);
    }

    /* renamed from: RL */
    private int m114RL(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    private void copyIn(RIPEMD160Digest rIPEMD160Digest) {
        super.copyIn((GeneralDigest) rIPEMD160Digest);
        this.f471H0 = rIPEMD160Digest.f471H0;
        this.f472H1 = rIPEMD160Digest.f472H1;
        this.f473H2 = rIPEMD160Digest.f473H2;
        this.f474H3 = rIPEMD160Digest.f474H3;
        this.f475H4 = rIPEMD160Digest.f475H4;
        int[] iArr = rIPEMD160Digest.f476X;
        System.arraycopy(iArr, 0, this.f476X, 0, iArr.length);
        this.xOff = rIPEMD160Digest.xOff;
    }

    /* renamed from: f1 */
    private int m113f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m112f2(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: f3 */
    private int m111f3(int i, int i2, int i3) {
        return (i | (~i2)) ^ i3;
    }

    /* renamed from: f4 */
    private int m110f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (~i3));
    }

    /* renamed from: f5 */
    private int m109f5(int i, int i2, int i3) {
        return i ^ (i2 | (~i3));
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD160Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, 128, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f471H0, bArr, i);
        Pack.intToLittleEndian(this.f472H1, bArr, i + 4);
        Pack.intToLittleEndian(this.f473H2, bArr, i + 8);
        Pack.intToLittleEndian(this.f474H3, bArr, i + 12);
        Pack.intToLittleEndian(this.f475H4, bArr, i + 16);
        reset();
        return 20;
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
    protected void processBlock() {
        int i = this.f471H0;
        int i2 = this.f472H1;
        int i3 = this.f473H2;
        int i4 = this.f474H3;
        int i5 = this.f475H4;
        int m114RL = m114RL(m113f1(i2, i3, i4) + i + this.f476X[0], 11) + i5;
        int m114RL2 = m114RL(i3, 10);
        int m114RL3 = m114RL(m113f1(m114RL, i2, m114RL2) + i5 + this.f476X[1], 14) + i4;
        int m114RL4 = m114RL(i2, 10);
        int m114RL5 = m114RL(m113f1(m114RL3, m114RL, m114RL4) + i4 + this.f476X[2], 15) + m114RL2;
        int m114RL6 = m114RL(m114RL, 10);
        int m114RL7 = m114RL(m114RL2 + m113f1(m114RL5, m114RL3, m114RL6) + this.f476X[3], 12) + m114RL4;
        int m114RL8 = m114RL(m114RL3, 10);
        int m114RL9 = m114RL(m114RL4 + m113f1(m114RL7, m114RL5, m114RL8) + this.f476X[4], 5) + m114RL6;
        int m114RL10 = m114RL(m114RL5, 10);
        int m114RL11 = m114RL(m114RL6 + m113f1(m114RL9, m114RL7, m114RL10) + this.f476X[5], 8) + m114RL8;
        int m114RL12 = m114RL(m114RL7, 10);
        int m114RL13 = m114RL(m114RL8 + m113f1(m114RL11, m114RL9, m114RL12) + this.f476X[6], 7) + m114RL10;
        int m114RL14 = m114RL(m114RL9, 10);
        int m114RL15 = m114RL(m114RL10 + m113f1(m114RL13, m114RL11, m114RL14) + this.f476X[7], 9) + m114RL12;
        int m114RL16 = m114RL(m114RL11, 10);
        int m114RL17 = m114RL(m114RL12 + m113f1(m114RL15, m114RL13, m114RL16) + this.f476X[8], 11) + m114RL14;
        int m114RL18 = m114RL(m114RL13, 10);
        int m114RL19 = m114RL(m114RL14 + m113f1(m114RL17, m114RL15, m114RL18) + this.f476X[9], 13) + m114RL16;
        int m114RL20 = m114RL(m114RL15, 10);
        int m114RL21 = m114RL(m114RL16 + m113f1(m114RL19, m114RL17, m114RL20) + this.f476X[10], 14) + m114RL18;
        int m114RL22 = m114RL(m114RL17, 10);
        int m114RL23 = m114RL(m114RL18 + m113f1(m114RL21, m114RL19, m114RL22) + this.f476X[11], 15) + m114RL20;
        int m114RL24 = m114RL(m114RL19, 10);
        int m114RL25 = m114RL(m114RL20 + m113f1(m114RL23, m114RL21, m114RL24) + this.f476X[12], 6) + m114RL22;
        int m114RL26 = m114RL(m114RL21, 10);
        int m114RL27 = m114RL(m114RL22 + m113f1(m114RL25, m114RL23, m114RL26) + this.f476X[13], 7) + m114RL24;
        int m114RL28 = m114RL(m114RL23, 10);
        int m114RL29 = m114RL(m114RL24 + m113f1(m114RL27, m114RL25, m114RL28) + this.f476X[14], 9) + m114RL26;
        int m114RL30 = m114RL(m114RL25, 10);
        int m114RL31 = m114RL(m114RL26 + m113f1(m114RL29, m114RL27, m114RL30) + this.f476X[15], 8) + m114RL28;
        int m114RL32 = m114RL(m114RL27, 10);
        int m114RL33 = m114RL(i + m109f5(i2, i3, i4) + this.f476X[5] + 1352829926, 8) + i5;
        int m114RL34 = m114RL(i3, 10);
        int m114RL35 = m114RL(i5 + m109f5(m114RL33, i2, m114RL34) + this.f476X[14] + 1352829926, 9) + i4;
        int m114RL36 = m114RL(i2, 10);
        int m114RL37 = m114RL(i4 + m109f5(m114RL35, m114RL33, m114RL36) + this.f476X[7] + 1352829926, 9) + m114RL34;
        int m114RL38 = m114RL(m114RL33, 10);
        int m114RL39 = m114RL(m114RL34 + m109f5(m114RL37, m114RL35, m114RL38) + this.f476X[0] + 1352829926, 11) + m114RL36;
        int m114RL40 = m114RL(m114RL35, 10);
        int m114RL41 = m114RL(m114RL36 + m109f5(m114RL39, m114RL37, m114RL40) + this.f476X[9] + 1352829926, 13) + m114RL38;
        int m114RL42 = m114RL(m114RL37, 10);
        int m114RL43 = m114RL(m114RL38 + m109f5(m114RL41, m114RL39, m114RL42) + this.f476X[2] + 1352829926, 15) + m114RL40;
        int m114RL44 = m114RL(m114RL39, 10);
        int m114RL45 = m114RL(m114RL40 + m109f5(m114RL43, m114RL41, m114RL44) + this.f476X[11] + 1352829926, 15) + m114RL42;
        int m114RL46 = m114RL(m114RL41, 10);
        int m114RL47 = m114RL(m114RL42 + m109f5(m114RL45, m114RL43, m114RL46) + this.f476X[4] + 1352829926, 5) + m114RL44;
        int m114RL48 = m114RL(m114RL43, 10);
        int m114RL49 = m114RL(m114RL44 + m109f5(m114RL47, m114RL45, m114RL48) + this.f476X[13] + 1352829926, 7) + m114RL46;
        int m114RL50 = m114RL(m114RL45, 10);
        int m114RL51 = m114RL(m114RL46 + m109f5(m114RL49, m114RL47, m114RL50) + this.f476X[6] + 1352829926, 7) + m114RL48;
        int m114RL52 = m114RL(m114RL47, 10);
        int m114RL53 = m114RL(m114RL48 + m109f5(m114RL51, m114RL49, m114RL52) + this.f476X[15] + 1352829926, 8) + m114RL50;
        int m114RL54 = m114RL(m114RL49, 10);
        int m114RL55 = m114RL(m114RL50 + m109f5(m114RL53, m114RL51, m114RL54) + this.f476X[8] + 1352829926, 11) + m114RL52;
        int m114RL56 = m114RL(m114RL51, 10);
        int m114RL57 = m114RL(m114RL52 + m109f5(m114RL55, m114RL53, m114RL56) + this.f476X[1] + 1352829926, 14) + m114RL54;
        int m114RL58 = m114RL(m114RL53, 10);
        int m114RL59 = m114RL(m114RL54 + m109f5(m114RL57, m114RL55, m114RL58) + this.f476X[10] + 1352829926, 14) + m114RL56;
        int m114RL60 = m114RL(m114RL55, 10);
        int m114RL61 = m114RL(m114RL56 + m109f5(m114RL59, m114RL57, m114RL60) + this.f476X[3] + 1352829926, 12) + m114RL58;
        int m114RL62 = m114RL(m114RL57, 10);
        int m114RL63 = m114RL(m114RL58 + m109f5(m114RL61, m114RL59, m114RL62) + this.f476X[12] + 1352829926, 6) + m114RL60;
        int m114RL64 = m114RL(m114RL59, 10);
        int m114RL65 = m114RL(m114RL28 + m112f2(m114RL31, m114RL29, m114RL32) + this.f476X[7] + 1518500249, 7) + m114RL30;
        int m114RL66 = m114RL(m114RL29, 10);
        int m114RL67 = m114RL(m114RL30 + m112f2(m114RL65, m114RL31, m114RL66) + this.f476X[4] + 1518500249, 6) + m114RL32;
        int m114RL68 = m114RL(m114RL31, 10);
        int m114RL69 = m114RL(m114RL32 + m112f2(m114RL67, m114RL65, m114RL68) + this.f476X[13] + 1518500249, 8) + m114RL66;
        int m114RL70 = m114RL(m114RL65, 10);
        int m114RL71 = m114RL(m114RL66 + m112f2(m114RL69, m114RL67, m114RL70) + this.f476X[1] + 1518500249, 13) + m114RL68;
        int m114RL72 = m114RL(m114RL67, 10);
        int m114RL73 = m114RL(m114RL68 + m112f2(m114RL71, m114RL69, m114RL72) + this.f476X[10] + 1518500249, 11) + m114RL70;
        int m114RL74 = m114RL(m114RL69, 10);
        int m114RL75 = m114RL(m114RL70 + m112f2(m114RL73, m114RL71, m114RL74) + this.f476X[6] + 1518500249, 9) + m114RL72;
        int m114RL76 = m114RL(m114RL71, 10);
        int m114RL77 = m114RL(m114RL72 + m112f2(m114RL75, m114RL73, m114RL76) + this.f476X[15] + 1518500249, 7) + m114RL74;
        int m114RL78 = m114RL(m114RL73, 10);
        int m114RL79 = m114RL(m114RL74 + m112f2(m114RL77, m114RL75, m114RL78) + this.f476X[3] + 1518500249, 15) + m114RL76;
        int m114RL80 = m114RL(m114RL75, 10);
        int m114RL81 = m114RL(m114RL76 + m112f2(m114RL79, m114RL77, m114RL80) + this.f476X[12] + 1518500249, 7) + m114RL78;
        int m114RL82 = m114RL(m114RL77, 10);
        int m114RL83 = m114RL(m114RL78 + m112f2(m114RL81, m114RL79, m114RL82) + this.f476X[0] + 1518500249, 12) + m114RL80;
        int m114RL84 = m114RL(m114RL79, 10);
        int m114RL85 = m114RL(m114RL80 + m112f2(m114RL83, m114RL81, m114RL84) + this.f476X[9] + 1518500249, 15) + m114RL82;
        int m114RL86 = m114RL(m114RL81, 10);
        int m114RL87 = m114RL(m114RL82 + m112f2(m114RL85, m114RL83, m114RL86) + this.f476X[5] + 1518500249, 9) + m114RL84;
        int m114RL88 = m114RL(m114RL83, 10);
        int m114RL89 = m114RL(m114RL84 + m112f2(m114RL87, m114RL85, m114RL88) + this.f476X[2] + 1518500249, 11) + m114RL86;
        int m114RL90 = m114RL(m114RL85, 10);
        int m114RL91 = m114RL(m114RL86 + m112f2(m114RL89, m114RL87, m114RL90) + this.f476X[14] + 1518500249, 7) + m114RL88;
        int m114RL92 = m114RL(m114RL87, 10);
        int m114RL93 = m114RL(m114RL88 + m112f2(m114RL91, m114RL89, m114RL92) + this.f476X[11] + 1518500249, 13) + m114RL90;
        int m114RL94 = m114RL(m114RL89, 10);
        int m114RL95 = m114RL(m114RL90 + m112f2(m114RL93, m114RL91, m114RL94) + this.f476X[8] + 1518500249, 12) + m114RL92;
        int m114RL96 = m114RL(m114RL91, 10);
        int m114RL97 = m114RL(m114RL60 + m110f4(m114RL63, m114RL61, m114RL64) + this.f476X[6] + 1548603684, 9) + m114RL62;
        int m114RL98 = m114RL(m114RL61, 10);
        int m114RL99 = m114RL(m114RL62 + m110f4(m114RL97, m114RL63, m114RL98) + this.f476X[11] + 1548603684, 13) + m114RL64;
        int m114RL100 = m114RL(m114RL63, 10);
        int m114RL101 = m114RL(m114RL64 + m110f4(m114RL99, m114RL97, m114RL100) + this.f476X[3] + 1548603684, 15) + m114RL98;
        int m114RL102 = m114RL(m114RL97, 10);
        int m114RL103 = m114RL(m114RL98 + m110f4(m114RL101, m114RL99, m114RL102) + this.f476X[7] + 1548603684, 7) + m114RL100;
        int m114RL104 = m114RL(m114RL99, 10);
        int m114RL105 = m114RL(m114RL100 + m110f4(m114RL103, m114RL101, m114RL104) + this.f476X[0] + 1548603684, 12) + m114RL102;
        int m114RL106 = m114RL(m114RL101, 10);
        int m114RL107 = m114RL(m114RL102 + m110f4(m114RL105, m114RL103, m114RL106) + this.f476X[13] + 1548603684, 8) + m114RL104;
        int m114RL108 = m114RL(m114RL103, 10);
        int m114RL109 = m114RL(m114RL104 + m110f4(m114RL107, m114RL105, m114RL108) + this.f476X[5] + 1548603684, 9) + m114RL106;
        int m114RL110 = m114RL(m114RL105, 10);
        int m114RL111 = m114RL(m114RL106 + m110f4(m114RL109, m114RL107, m114RL110) + this.f476X[10] + 1548603684, 11) + m114RL108;
        int m114RL112 = m114RL(m114RL107, 10);
        int m114RL113 = m114RL(m114RL108 + m110f4(m114RL111, m114RL109, m114RL112) + this.f476X[14] + 1548603684, 7) + m114RL110;
        int m114RL114 = m114RL(m114RL109, 10);
        int m114RL115 = m114RL(m114RL110 + m110f4(m114RL113, m114RL111, m114RL114) + this.f476X[15] + 1548603684, 7) + m114RL112;
        int m114RL116 = m114RL(m114RL111, 10);
        int m114RL117 = m114RL(m114RL112 + m110f4(m114RL115, m114RL113, m114RL116) + this.f476X[8] + 1548603684, 12) + m114RL114;
        int m114RL118 = m114RL(m114RL113, 10);
        int m114RL119 = m114RL(m114RL114 + m110f4(m114RL117, m114RL115, m114RL118) + this.f476X[12] + 1548603684, 7) + m114RL116;
        int m114RL120 = m114RL(m114RL115, 10);
        int m114RL121 = m114RL(m114RL116 + m110f4(m114RL119, m114RL117, m114RL120) + this.f476X[4] + 1548603684, 6) + m114RL118;
        int m114RL122 = m114RL(m114RL117, 10);
        int m114RL123 = m114RL(m114RL118 + m110f4(m114RL121, m114RL119, m114RL122) + this.f476X[9] + 1548603684, 15) + m114RL120;
        int m114RL124 = m114RL(m114RL119, 10);
        int m114RL125 = m114RL(m114RL120 + m110f4(m114RL123, m114RL121, m114RL124) + this.f476X[1] + 1548603684, 13) + m114RL122;
        int m114RL126 = m114RL(m114RL121, 10);
        int m114RL127 = m114RL(m114RL122 + m110f4(m114RL125, m114RL123, m114RL126) + this.f476X[2] + 1548603684, 11) + m114RL124;
        int m114RL128 = m114RL(m114RL123, 10);
        int m114RL129 = m114RL(m114RL92 + m111f3(m114RL95, m114RL93, m114RL96) + this.f476X[3] + 1859775393, 11) + m114RL94;
        int m114RL130 = m114RL(m114RL93, 10);
        int m114RL131 = m114RL(m114RL94 + m111f3(m114RL129, m114RL95, m114RL130) + this.f476X[10] + 1859775393, 13) + m114RL96;
        int m114RL132 = m114RL(m114RL95, 10);
        int m114RL133 = m114RL(m114RL96 + m111f3(m114RL131, m114RL129, m114RL132) + this.f476X[14] + 1859775393, 6) + m114RL130;
        int m114RL134 = m114RL(m114RL129, 10);
        int m114RL135 = m114RL(m114RL130 + m111f3(m114RL133, m114RL131, m114RL134) + this.f476X[4] + 1859775393, 7) + m114RL132;
        int m114RL136 = m114RL(m114RL131, 10);
        int m114RL137 = m114RL(m114RL132 + m111f3(m114RL135, m114RL133, m114RL136) + this.f476X[9] + 1859775393, 14) + m114RL134;
        int m114RL138 = m114RL(m114RL133, 10);
        int m114RL139 = m114RL(m114RL134 + m111f3(m114RL137, m114RL135, m114RL138) + this.f476X[15] + 1859775393, 9) + m114RL136;
        int m114RL140 = m114RL(m114RL135, 10);
        int m114RL141 = m114RL(m114RL136 + m111f3(m114RL139, m114RL137, m114RL140) + this.f476X[8] + 1859775393, 13) + m114RL138;
        int m114RL142 = m114RL(m114RL137, 10);
        int m114RL143 = m114RL(m114RL138 + m111f3(m114RL141, m114RL139, m114RL142) + this.f476X[1] + 1859775393, 15) + m114RL140;
        int m114RL144 = m114RL(m114RL139, 10);
        int m114RL145 = m114RL(m114RL140 + m111f3(m114RL143, m114RL141, m114RL144) + this.f476X[2] + 1859775393, 14) + m114RL142;
        int m114RL146 = m114RL(m114RL141, 10);
        int m114RL147 = m114RL(m114RL142 + m111f3(m114RL145, m114RL143, m114RL146) + this.f476X[7] + 1859775393, 8) + m114RL144;
        int m114RL148 = m114RL(m114RL143, 10);
        int m114RL149 = m114RL(m114RL144 + m111f3(m114RL147, m114RL145, m114RL148) + this.f476X[0] + 1859775393, 13) + m114RL146;
        int m114RL150 = m114RL(m114RL145, 10);
        int m114RL151 = m114RL(m114RL146 + m111f3(m114RL149, m114RL147, m114RL150) + this.f476X[6] + 1859775393, 6) + m114RL148;
        int m114RL152 = m114RL(m114RL147, 10);
        int m114RL153 = m114RL(m114RL148 + m111f3(m114RL151, m114RL149, m114RL152) + this.f476X[13] + 1859775393, 5) + m114RL150;
        int m114RL154 = m114RL(m114RL149, 10);
        int m114RL155 = m114RL(m114RL150 + m111f3(m114RL153, m114RL151, m114RL154) + this.f476X[11] + 1859775393, 12) + m114RL152;
        int m114RL156 = m114RL(m114RL151, 10);
        int m114RL157 = m114RL(m114RL152 + m111f3(m114RL155, m114RL153, m114RL156) + this.f476X[5] + 1859775393, 7) + m114RL154;
        int m114RL158 = m114RL(m114RL153, 10);
        int m114RL159 = m114RL(m114RL154 + m111f3(m114RL157, m114RL155, m114RL158) + this.f476X[12] + 1859775393, 5) + m114RL156;
        int m114RL160 = m114RL(m114RL155, 10);
        int m114RL161 = m114RL(m114RL124 + m111f3(m114RL127, m114RL125, m114RL128) + this.f476X[15] + 1836072691, 9) + m114RL126;
        int m114RL162 = m114RL(m114RL125, 10);
        int m114RL163 = m114RL(m114RL126 + m111f3(m114RL161, m114RL127, m114RL162) + this.f476X[5] + 1836072691, 7) + m114RL128;
        int m114RL164 = m114RL(m114RL127, 10);
        int m114RL165 = m114RL(m114RL128 + m111f3(m114RL163, m114RL161, m114RL164) + this.f476X[1] + 1836072691, 15) + m114RL162;
        int m114RL166 = m114RL(m114RL161, 10);
        int m114RL167 = m114RL(m114RL162 + m111f3(m114RL165, m114RL163, m114RL166) + this.f476X[3] + 1836072691, 11) + m114RL164;
        int m114RL168 = m114RL(m114RL163, 10);
        int m114RL169 = m114RL(m114RL164 + m111f3(m114RL167, m114RL165, m114RL168) + this.f476X[7] + 1836072691, 8) + m114RL166;
        int m114RL170 = m114RL(m114RL165, 10);
        int m114RL171 = m114RL(m114RL166 + m111f3(m114RL169, m114RL167, m114RL170) + this.f476X[14] + 1836072691, 6) + m114RL168;
        int m114RL172 = m114RL(m114RL167, 10);
        int m114RL173 = m114RL(m114RL168 + m111f3(m114RL171, m114RL169, m114RL172) + this.f476X[6] + 1836072691, 6) + m114RL170;
        int m114RL174 = m114RL(m114RL169, 10);
        int m114RL175 = m114RL(m114RL170 + m111f3(m114RL173, m114RL171, m114RL174) + this.f476X[9] + 1836072691, 14) + m114RL172;
        int m114RL176 = m114RL(m114RL171, 10);
        int m114RL177 = m114RL(m114RL172 + m111f3(m114RL175, m114RL173, m114RL176) + this.f476X[11] + 1836072691, 12) + m114RL174;
        int m114RL178 = m114RL(m114RL173, 10);
        int m114RL179 = m114RL(m114RL174 + m111f3(m114RL177, m114RL175, m114RL178) + this.f476X[8] + 1836072691, 13) + m114RL176;
        int m114RL180 = m114RL(m114RL175, 10);
        int m114RL181 = m114RL(m114RL176 + m111f3(m114RL179, m114RL177, m114RL180) + this.f476X[12] + 1836072691, 5) + m114RL178;
        int m114RL182 = m114RL(m114RL177, 10);
        int m114RL183 = m114RL(m114RL178 + m111f3(m114RL181, m114RL179, m114RL182) + this.f476X[2] + 1836072691, 14) + m114RL180;
        int m114RL184 = m114RL(m114RL179, 10);
        int m114RL185 = m114RL(m114RL180 + m111f3(m114RL183, m114RL181, m114RL184) + this.f476X[10] + 1836072691, 13) + m114RL182;
        int m114RL186 = m114RL(m114RL181, 10);
        int m114RL187 = m114RL(m114RL182 + m111f3(m114RL185, m114RL183, m114RL186) + this.f476X[0] + 1836072691, 13) + m114RL184;
        int m114RL188 = m114RL(m114RL183, 10);
        int m114RL189 = m114RL(m114RL184 + m111f3(m114RL187, m114RL185, m114RL188) + this.f476X[4] + 1836072691, 7) + m114RL186;
        int m114RL190 = m114RL(m114RL185, 10);
        int m114RL191 = m114RL(m114RL186 + m111f3(m114RL189, m114RL187, m114RL190) + this.f476X[13] + 1836072691, 5) + m114RL188;
        int m114RL192 = m114RL(m114RL187, 10);
        int m114RL193 = m114RL(((m114RL156 + m110f4(m114RL159, m114RL157, m114RL160)) + this.f476X[1]) - 1894007588, 11) + m114RL158;
        int m114RL194 = m114RL(m114RL157, 10);
        int m114RL195 = m114RL(((m114RL158 + m110f4(m114RL193, m114RL159, m114RL194)) + this.f476X[9]) - 1894007588, 12) + m114RL160;
        int m114RL196 = m114RL(m114RL159, 10);
        int m114RL197 = m114RL(((m114RL160 + m110f4(m114RL195, m114RL193, m114RL196)) + this.f476X[11]) - 1894007588, 14) + m114RL194;
        int m114RL198 = m114RL(m114RL193, 10);
        int m114RL199 = m114RL(((m114RL194 + m110f4(m114RL197, m114RL195, m114RL198)) + this.f476X[10]) - 1894007588, 15) + m114RL196;
        int m114RL200 = m114RL(m114RL195, 10);
        int m114RL201 = m114RL(((m114RL196 + m110f4(m114RL199, m114RL197, m114RL200)) + this.f476X[0]) - 1894007588, 14) + m114RL198;
        int m114RL202 = m114RL(m114RL197, 10);
        int m114RL203 = m114RL(((m114RL198 + m110f4(m114RL201, m114RL199, m114RL202)) + this.f476X[8]) - 1894007588, 15) + m114RL200;
        int m114RL204 = m114RL(m114RL199, 10);
        int m114RL205 = m114RL(((m114RL200 + m110f4(m114RL203, m114RL201, m114RL204)) + this.f476X[12]) - 1894007588, 9) + m114RL202;
        int m114RL206 = m114RL(m114RL201, 10);
        int m114RL207 = m114RL(((m114RL202 + m110f4(m114RL205, m114RL203, m114RL206)) + this.f476X[4]) - 1894007588, 8) + m114RL204;
        int m114RL208 = m114RL(m114RL203, 10);
        int m114RL209 = m114RL(((m114RL204 + m110f4(m114RL207, m114RL205, m114RL208)) + this.f476X[13]) - 1894007588, 9) + m114RL206;
        int m114RL210 = m114RL(m114RL205, 10);
        int m114RL211 = m114RL(((m114RL206 + m110f4(m114RL209, m114RL207, m114RL210)) + this.f476X[3]) - 1894007588, 14) + m114RL208;
        int m114RL212 = m114RL(m114RL207, 10);
        int m114RL213 = m114RL(((m114RL208 + m110f4(m114RL211, m114RL209, m114RL212)) + this.f476X[7]) - 1894007588, 5) + m114RL210;
        int m114RL214 = m114RL(m114RL209, 10);
        int m114RL215 = m114RL(((m114RL210 + m110f4(m114RL213, m114RL211, m114RL214)) + this.f476X[15]) - 1894007588, 6) + m114RL212;
        int m114RL216 = m114RL(m114RL211, 10);
        int m114RL217 = m114RL(((m114RL212 + m110f4(m114RL215, m114RL213, m114RL216)) + this.f476X[14]) - 1894007588, 8) + m114RL214;
        int m114RL218 = m114RL(m114RL213, 10);
        int m114RL219 = m114RL(((m114RL214 + m110f4(m114RL217, m114RL215, m114RL218)) + this.f476X[5]) - 1894007588, 6) + m114RL216;
        int m114RL220 = m114RL(m114RL215, 10);
        int m114RL221 = m114RL(((m114RL216 + m110f4(m114RL219, m114RL217, m114RL220)) + this.f476X[6]) - 1894007588, 5) + m114RL218;
        int m114RL222 = m114RL(m114RL217, 10);
        int m114RL223 = m114RL(((m114RL218 + m110f4(m114RL221, m114RL219, m114RL222)) + this.f476X[2]) - 1894007588, 12) + m114RL220;
        int m114RL224 = m114RL(m114RL219, 10);
        int m114RL225 = m114RL(m114RL188 + m112f2(m114RL191, m114RL189, m114RL192) + this.f476X[8] + 2053994217, 15) + m114RL190;
        int m114RL226 = m114RL(m114RL189, 10);
        int m114RL227 = m114RL(m114RL190 + m112f2(m114RL225, m114RL191, m114RL226) + this.f476X[6] + 2053994217, 5) + m114RL192;
        int m114RL228 = m114RL(m114RL191, 10);
        int m114RL229 = m114RL(m114RL192 + m112f2(m114RL227, m114RL225, m114RL228) + this.f476X[4] + 2053994217, 8) + m114RL226;
        int m114RL230 = m114RL(m114RL225, 10);
        int m114RL231 = m114RL(m114RL226 + m112f2(m114RL229, m114RL227, m114RL230) + this.f476X[1] + 2053994217, 11) + m114RL228;
        int m114RL232 = m114RL(m114RL227, 10);
        int m114RL233 = m114RL(m114RL228 + m112f2(m114RL231, m114RL229, m114RL232) + this.f476X[3] + 2053994217, 14) + m114RL230;
        int m114RL234 = m114RL(m114RL229, 10);
        int m114RL235 = m114RL(m114RL230 + m112f2(m114RL233, m114RL231, m114RL234) + this.f476X[11] + 2053994217, 14) + m114RL232;
        int m114RL236 = m114RL(m114RL231, 10);
        int m114RL237 = m114RL(m114RL232 + m112f2(m114RL235, m114RL233, m114RL236) + this.f476X[15] + 2053994217, 6) + m114RL234;
        int m114RL238 = m114RL(m114RL233, 10);
        int m114RL239 = m114RL(m114RL234 + m112f2(m114RL237, m114RL235, m114RL238) + this.f476X[0] + 2053994217, 14) + m114RL236;
        int m114RL240 = m114RL(m114RL235, 10);
        int m114RL241 = m114RL(m114RL236 + m112f2(m114RL239, m114RL237, m114RL240) + this.f476X[5] + 2053994217, 6) + m114RL238;
        int m114RL242 = m114RL(m114RL237, 10);
        int m114RL243 = m114RL(m114RL238 + m112f2(m114RL241, m114RL239, m114RL242) + this.f476X[12] + 2053994217, 9) + m114RL240;
        int m114RL244 = m114RL(m114RL239, 10);
        int m114RL245 = m114RL(m114RL240 + m112f2(m114RL243, m114RL241, m114RL244) + this.f476X[2] + 2053994217, 12) + m114RL242;
        int m114RL246 = m114RL(m114RL241, 10);
        int m114RL247 = m114RL(m114RL242 + m112f2(m114RL245, m114RL243, m114RL246) + this.f476X[13] + 2053994217, 9) + m114RL244;
        int m114RL248 = m114RL(m114RL243, 10);
        int m114RL249 = m114RL(m114RL244 + m112f2(m114RL247, m114RL245, m114RL248) + this.f476X[9] + 2053994217, 12) + m114RL246;
        int m114RL250 = m114RL(m114RL245, 10);
        int m114RL251 = m114RL(m114RL246 + m112f2(m114RL249, m114RL247, m114RL250) + this.f476X[7] + 2053994217, 5) + m114RL248;
        int m114RL252 = m114RL(m114RL247, 10);
        int m114RL253 = m114RL(m114RL248 + m112f2(m114RL251, m114RL249, m114RL252) + this.f476X[10] + 2053994217, 15) + m114RL250;
        int m114RL254 = m114RL(m114RL249, 10);
        int m114RL255 = m114RL(m114RL250 + m112f2(m114RL253, m114RL251, m114RL254) + this.f476X[14] + 2053994217, 8) + m114RL252;
        int m114RL256 = m114RL(m114RL251, 10);
        int m114RL257 = m114RL(((m114RL220 + m109f5(m114RL223, m114RL221, m114RL224)) + this.f476X[4]) - 1454113458, 9) + m114RL222;
        int m114RL258 = m114RL(m114RL221, 10);
        int m114RL259 = m114RL(((m114RL222 + m109f5(m114RL257, m114RL223, m114RL258)) + this.f476X[0]) - 1454113458, 15) + m114RL224;
        int m114RL260 = m114RL(m114RL223, 10);
        int m114RL261 = m114RL(((m114RL224 + m109f5(m114RL259, m114RL257, m114RL260)) + this.f476X[5]) - 1454113458, 5) + m114RL258;
        int m114RL262 = m114RL(m114RL257, 10);
        int m114RL263 = m114RL(((m114RL258 + m109f5(m114RL261, m114RL259, m114RL262)) + this.f476X[9]) - 1454113458, 11) + m114RL260;
        int m114RL264 = m114RL(m114RL259, 10);
        int m114RL265 = m114RL(((m114RL260 + m109f5(m114RL263, m114RL261, m114RL264)) + this.f476X[7]) - 1454113458, 6) + m114RL262;
        int m114RL266 = m114RL(m114RL261, 10);
        int m114RL267 = m114RL(((m114RL262 + m109f5(m114RL265, m114RL263, m114RL266)) + this.f476X[12]) - 1454113458, 8) + m114RL264;
        int m114RL268 = m114RL(m114RL263, 10);
        int m114RL269 = m114RL(((m114RL264 + m109f5(m114RL267, m114RL265, m114RL268)) + this.f476X[2]) - 1454113458, 13) + m114RL266;
        int m114RL270 = m114RL(m114RL265, 10);
        int m114RL271 = m114RL(((m114RL266 + m109f5(m114RL269, m114RL267, m114RL270)) + this.f476X[10]) - 1454113458, 12) + m114RL268;
        int m114RL272 = m114RL(m114RL267, 10);
        int m114RL273 = m114RL(((m114RL268 + m109f5(m114RL271, m114RL269, m114RL272)) + this.f476X[14]) - 1454113458, 5) + m114RL270;
        int m114RL274 = m114RL(m114RL269, 10);
        int m114RL275 = m114RL(((m114RL270 + m109f5(m114RL273, m114RL271, m114RL274)) + this.f476X[1]) - 1454113458, 12) + m114RL272;
        int m114RL276 = m114RL(m114RL271, 10);
        int m114RL277 = m114RL(((m114RL272 + m109f5(m114RL275, m114RL273, m114RL276)) + this.f476X[3]) - 1454113458, 13) + m114RL274;
        int m114RL278 = m114RL(m114RL273, 10);
        int m114RL279 = m114RL(((m114RL274 + m109f5(m114RL277, m114RL275, m114RL278)) + this.f476X[8]) - 1454113458, 14) + m114RL276;
        int m114RL280 = m114RL(m114RL275, 10);
        int m114RL281 = m114RL(((m114RL276 + m109f5(m114RL279, m114RL277, m114RL280)) + this.f476X[11]) - 1454113458, 11) + m114RL278;
        int m114RL282 = m114RL(m114RL277, 10);
        int m114RL283 = m114RL(((m114RL278 + m109f5(m114RL281, m114RL279, m114RL282)) + this.f476X[6]) - 1454113458, 8) + m114RL280;
        int m114RL284 = m114RL(m114RL279, 10);
        int m114RL285 = m114RL(((m114RL280 + m109f5(m114RL283, m114RL281, m114RL284)) + this.f476X[15]) - 1454113458, 5) + m114RL282;
        int m114RL286 = m114RL(m114RL281, 10);
        int m114RL287 = m114RL(m114RL283, 10);
        int m114RL288 = m114RL(m114RL252 + m113f1(m114RL255, m114RL253, m114RL256) + this.f476X[12], 8) + m114RL254;
        int m114RL289 = m114RL(m114RL253, 10);
        int m114RL290 = m114RL(m114RL254 + m113f1(m114RL288, m114RL255, m114RL289) + this.f476X[15], 5) + m114RL256;
        int m114RL291 = m114RL(m114RL255, 10);
        int m114RL292 = m114RL(m114RL256 + m113f1(m114RL290, m114RL288, m114RL291) + this.f476X[10], 12) + m114RL289;
        int m114RL293 = m114RL(m114RL288, 10);
        int m114RL294 = m114RL(m114RL289 + m113f1(m114RL292, m114RL290, m114RL293) + this.f476X[4], 9) + m114RL291;
        int m114RL295 = m114RL(m114RL290, 10);
        int m114RL296 = m114RL(m114RL291 + m113f1(m114RL294, m114RL292, m114RL295) + this.f476X[1], 12) + m114RL293;
        int m114RL297 = m114RL(m114RL292, 10);
        int m114RL298 = m114RL(m114RL293 + m113f1(m114RL296, m114RL294, m114RL297) + this.f476X[5], 5) + m114RL295;
        int m114RL299 = m114RL(m114RL294, 10);
        int m114RL300 = m114RL(m114RL295 + m113f1(m114RL298, m114RL296, m114RL299) + this.f476X[8], 14) + m114RL297;
        int m114RL301 = m114RL(m114RL296, 10);
        int m114RL302 = m114RL(m114RL297 + m113f1(m114RL300, m114RL298, m114RL301) + this.f476X[7], 6) + m114RL299;
        int m114RL303 = m114RL(m114RL298, 10);
        int m114RL304 = m114RL(m114RL299 + m113f1(m114RL302, m114RL300, m114RL303) + this.f476X[6], 8) + m114RL301;
        int m114RL305 = m114RL(m114RL300, 10);
        int m114RL306 = m114RL(m114RL301 + m113f1(m114RL304, m114RL302, m114RL305) + this.f476X[2], 13) + m114RL303;
        int m114RL307 = m114RL(m114RL302, 10);
        int m114RL308 = m114RL(m114RL303 + m113f1(m114RL306, m114RL304, m114RL307) + this.f476X[13], 6) + m114RL305;
        int m114RL309 = m114RL(m114RL304, 10);
        int m114RL310 = m114RL(m114RL305 + m113f1(m114RL308, m114RL306, m114RL309) + this.f476X[14], 5) + m114RL307;
        int m114RL311 = m114RL(m114RL306, 10);
        int m114RL312 = m114RL(m114RL307 + m113f1(m114RL310, m114RL308, m114RL311) + this.f476X[0], 15) + m114RL309;
        int m114RL313 = m114RL(m114RL308, 10);
        int m114RL314 = m114RL(m114RL309 + m113f1(m114RL312, m114RL310, m114RL313) + this.f476X[3], 13) + m114RL311;
        int m114RL315 = m114RL(m114RL310, 10);
        int m114RL316 = m114RL(m114RL311 + m113f1(m114RL314, m114RL312, m114RL315) + this.f476X[9], 11) + m114RL313;
        int m114RL317 = m114RL(m114RL312, 10);
        int m114RL318 = m114RL(m114RL313 + m113f1(m114RL316, m114RL314, m114RL317) + this.f476X[11], 11) + m114RL315;
        this.f472H1 = this.f473H2 + m114RL287 + m114RL317;
        this.f473H2 = this.f474H3 + m114RL286 + m114RL315;
        this.f474H3 = this.f475H4 + m114RL284 + m114RL318;
        this.f475H4 = this.f471H0 + m114RL(((m114RL282 + m109f5(m114RL285, m114RL283, m114RL286)) + this.f476X[13]) - 1454113458, 6) + m114RL284 + m114RL316;
        this.f471H0 = m114RL(m114RL314, 10) + m114RL285 + this.f472H1;
        this.xOff = 0;
        int i6 = 0;
        while (true) {
            int[] iArr = this.f476X;
            if (i6 == iArr.length) {
                return;
            }
            iArr[i6] = 0;
            i6++;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        int[] iArr = this.f476X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f476X;
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
        this.f471H0 = 1732584193;
        this.f472H1 = -271733879;
        this.f473H2 = -1732584194;
        this.f474H3 = 271733878;
        this.f475H4 = -1009589776;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f476X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((RIPEMD160Digest) memoable);
    }
}