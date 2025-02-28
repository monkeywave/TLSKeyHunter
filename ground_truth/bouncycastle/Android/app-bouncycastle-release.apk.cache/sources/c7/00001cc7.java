package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class RIPEMD320Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 40;

    /* renamed from: H0 */
    private int f486H0;

    /* renamed from: H1 */
    private int f487H1;

    /* renamed from: H2 */
    private int f488H2;

    /* renamed from: H3 */
    private int f489H3;

    /* renamed from: H4 */
    private int f490H4;

    /* renamed from: H5 */
    private int f491H5;

    /* renamed from: H6 */
    private int f492H6;

    /* renamed from: H7 */
    private int f493H7;

    /* renamed from: H8 */
    private int f494H8;

    /* renamed from: H9 */
    private int f495H9;

    /* renamed from: X */
    private int[] f496X;
    private int xOff;

    public RIPEMD320Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public RIPEMD320Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        this.f496X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, cryptoServicePurpose));
        reset();
    }

    public RIPEMD320Digest(RIPEMD320Digest rIPEMD320Digest) {
        super(rIPEMD320Digest.purpose);
        this.f496X = new int[16];
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, 128, this.purpose));
        doCopy(rIPEMD320Digest);
    }

    /* renamed from: RL */
    private int m99RL(int i, int i2) {
        return (i >>> (32 - i2)) | (i << i2);
    }

    private void doCopy(RIPEMD320Digest rIPEMD320Digest) {
        super.copyIn(rIPEMD320Digest);
        this.f486H0 = rIPEMD320Digest.f486H0;
        this.f487H1 = rIPEMD320Digest.f487H1;
        this.f488H2 = rIPEMD320Digest.f488H2;
        this.f489H3 = rIPEMD320Digest.f489H3;
        this.f490H4 = rIPEMD320Digest.f490H4;
        this.f491H5 = rIPEMD320Digest.f491H5;
        this.f492H6 = rIPEMD320Digest.f492H6;
        this.f493H7 = rIPEMD320Digest.f493H7;
        this.f494H8 = rIPEMD320Digest.f494H8;
        this.f495H9 = rIPEMD320Digest.f495H9;
        int[] iArr = rIPEMD320Digest.f496X;
        System.arraycopy(iArr, 0, this.f496X, 0, iArr.length);
        this.xOff = rIPEMD320Digest.xOff;
    }

    /* renamed from: f1 */
    private int m98f1(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: f2 */
    private int m97f2(int i, int i2, int i3) {
        return ((~i) & i3) | (i2 & i);
    }

    /* renamed from: f3 */
    private int m96f3(int i, int i2, int i3) {
        return (i | (~i2)) ^ i3;
    }

    /* renamed from: f4 */
    private int m95f4(int i, int i2, int i3) {
        return (i & i3) | (i2 & (~i3));
    }

    /* renamed from: f5 */
    private int m94f5(int i, int i2, int i3) {
        return i ^ (i2 | (~i3));
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new RIPEMD320Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.intToLittleEndian(this.f486H0, bArr, i);
        Pack.intToLittleEndian(this.f487H1, bArr, i + 4);
        Pack.intToLittleEndian(this.f488H2, bArr, i + 8);
        Pack.intToLittleEndian(this.f489H3, bArr, i + 12);
        Pack.intToLittleEndian(this.f490H4, bArr, i + 16);
        Pack.intToLittleEndian(this.f491H5, bArr, i + 20);
        Pack.intToLittleEndian(this.f492H6, bArr, i + 24);
        Pack.intToLittleEndian(this.f493H7, bArr, i + 28);
        Pack.intToLittleEndian(this.f494H8, bArr, i + 32);
        Pack.intToLittleEndian(this.f495H9, bArr, i + 36);
        reset();
        return 40;
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
    protected void processBlock() {
        int i = this.f486H0;
        int i2 = this.f487H1;
        int i3 = this.f488H2;
        int i4 = this.f489H3;
        int i5 = this.f490H4;
        int i6 = this.f491H5;
        int i7 = this.f492H6;
        int i8 = this.f493H7;
        int i9 = this.f494H8;
        int i10 = this.f495H9;
        int m99RL = m99RL(i + m98f1(i2, i3, i4) + this.f496X[0], 11) + i5;
        int m99RL2 = m99RL(i3, 10);
        int m99RL3 = m99RL(i5 + m98f1(m99RL, i2, m99RL2) + this.f496X[1], 14) + i4;
        int m99RL4 = m99RL(i2, 10);
        int m99RL5 = m99RL(i4 + m98f1(m99RL3, m99RL, m99RL4) + this.f496X[2], 15) + m99RL2;
        int m99RL6 = m99RL(m99RL, 10);
        int m99RL7 = m99RL(m99RL2 + m98f1(m99RL5, m99RL3, m99RL6) + this.f496X[3], 12) + m99RL4;
        int m99RL8 = m99RL(m99RL3, 10);
        int m99RL9 = m99RL(m99RL4 + m98f1(m99RL7, m99RL5, m99RL8) + this.f496X[4], 5) + m99RL6;
        int m99RL10 = m99RL(m99RL5, 10);
        int m99RL11 = m99RL(m99RL6 + m98f1(m99RL9, m99RL7, m99RL10) + this.f496X[5], 8) + m99RL8;
        int m99RL12 = m99RL(m99RL7, 10);
        int m99RL13 = m99RL(m99RL8 + m98f1(m99RL11, m99RL9, m99RL12) + this.f496X[6], 7) + m99RL10;
        int m99RL14 = m99RL(m99RL9, 10);
        int m99RL15 = m99RL(m99RL10 + m98f1(m99RL13, m99RL11, m99RL14) + this.f496X[7], 9) + m99RL12;
        int m99RL16 = m99RL(m99RL11, 10);
        int m99RL17 = m99RL(m99RL12 + m98f1(m99RL15, m99RL13, m99RL16) + this.f496X[8], 11) + m99RL14;
        int m99RL18 = m99RL(m99RL13, 10);
        int m99RL19 = m99RL(m99RL14 + m98f1(m99RL17, m99RL15, m99RL18) + this.f496X[9], 13) + m99RL16;
        int m99RL20 = m99RL(m99RL15, 10);
        int m99RL21 = m99RL(m99RL16 + m98f1(m99RL19, m99RL17, m99RL20) + this.f496X[10], 14) + m99RL18;
        int m99RL22 = m99RL(m99RL17, 10);
        int m99RL23 = m99RL(m99RL18 + m98f1(m99RL21, m99RL19, m99RL22) + this.f496X[11], 15) + m99RL20;
        int m99RL24 = m99RL(m99RL19, 10);
        int m99RL25 = m99RL(m99RL20 + m98f1(m99RL23, m99RL21, m99RL24) + this.f496X[12], 6) + m99RL22;
        int m99RL26 = m99RL(m99RL21, 10);
        int m99RL27 = m99RL(m99RL22 + m98f1(m99RL25, m99RL23, m99RL26) + this.f496X[13], 7) + m99RL24;
        int m99RL28 = m99RL(m99RL23, 10);
        int m99RL29 = m99RL(m99RL24 + m98f1(m99RL27, m99RL25, m99RL28) + this.f496X[14], 9) + m99RL26;
        int m99RL30 = m99RL(m99RL25, 10);
        int m99RL31 = m99RL(m99RL26 + m98f1(m99RL29, m99RL27, m99RL30) + this.f496X[15], 8) + m99RL28;
        int m99RL32 = m99RL(m99RL27, 10);
        int m99RL33 = m99RL(i6 + m94f5(i7, i8, i9) + this.f496X[5] + 1352829926, 8) + i10;
        int m99RL34 = m99RL(i8, 10);
        int m99RL35 = m99RL(i10 + m94f5(m99RL33, i7, m99RL34) + this.f496X[14] + 1352829926, 9) + i9;
        int m99RL36 = m99RL(i7, 10);
        int m99RL37 = m99RL(i9 + m94f5(m99RL35, m99RL33, m99RL36) + this.f496X[7] + 1352829926, 9) + m99RL34;
        int m99RL38 = m99RL(m99RL33, 10);
        int m99RL39 = m99RL(m99RL34 + m94f5(m99RL37, m99RL35, m99RL38) + this.f496X[0] + 1352829926, 11) + m99RL36;
        int m99RL40 = m99RL(m99RL35, 10);
        int m99RL41 = m99RL(m99RL36 + m94f5(m99RL39, m99RL37, m99RL40) + this.f496X[9] + 1352829926, 13) + m99RL38;
        int m99RL42 = m99RL(m99RL37, 10);
        int m99RL43 = m99RL(m99RL38 + m94f5(m99RL41, m99RL39, m99RL42) + this.f496X[2] + 1352829926, 15) + m99RL40;
        int m99RL44 = m99RL(m99RL39, 10);
        int m99RL45 = m99RL(m99RL40 + m94f5(m99RL43, m99RL41, m99RL44) + this.f496X[11] + 1352829926, 15) + m99RL42;
        int m99RL46 = m99RL(m99RL41, 10);
        int m99RL47 = m99RL(m99RL42 + m94f5(m99RL45, m99RL43, m99RL46) + this.f496X[4] + 1352829926, 5) + m99RL44;
        int m99RL48 = m99RL(m99RL43, 10);
        int m99RL49 = m99RL(m99RL44 + m94f5(m99RL47, m99RL45, m99RL48) + this.f496X[13] + 1352829926, 7) + m99RL46;
        int m99RL50 = m99RL(m99RL45, 10);
        int m99RL51 = m99RL(m99RL46 + m94f5(m99RL49, m99RL47, m99RL50) + this.f496X[6] + 1352829926, 7) + m99RL48;
        int m99RL52 = m99RL(m99RL47, 10);
        int m99RL53 = m99RL(m99RL48 + m94f5(m99RL51, m99RL49, m99RL52) + this.f496X[15] + 1352829926, 8) + m99RL50;
        int m99RL54 = m99RL(m99RL49, 10);
        int m99RL55 = m99RL(m99RL50 + m94f5(m99RL53, m99RL51, m99RL54) + this.f496X[8] + 1352829926, 11) + m99RL52;
        int m99RL56 = m99RL(m99RL51, 10);
        int m99RL57 = m99RL(m99RL52 + m94f5(m99RL55, m99RL53, m99RL56) + this.f496X[1] + 1352829926, 14) + m99RL54;
        int m99RL58 = m99RL(m99RL53, 10);
        int m99RL59 = m99RL(m99RL54 + m94f5(m99RL57, m99RL55, m99RL58) + this.f496X[10] + 1352829926, 14) + m99RL56;
        int m99RL60 = m99RL(m99RL55, 10);
        int m99RL61 = m99RL(m99RL56 + m94f5(m99RL59, m99RL57, m99RL60) + this.f496X[3] + 1352829926, 12) + m99RL58;
        int m99RL62 = m99RL(m99RL57, 10);
        int m99RL63 = m99RL(m99RL58 + m94f5(m99RL61, m99RL59, m99RL62) + this.f496X[12] + 1352829926, 6) + m99RL60;
        int m99RL64 = m99RL(m99RL59, 10);
        int m99RL65 = m99RL(m99RL28 + m97f2(m99RL63, m99RL29, m99RL32) + this.f496X[7] + 1518500249, 7) + m99RL30;
        int m99RL66 = m99RL(m99RL29, 10);
        int m99RL67 = m99RL(m99RL30 + m97f2(m99RL65, m99RL63, m99RL66) + this.f496X[4] + 1518500249, 6) + m99RL32;
        int m99RL68 = m99RL(m99RL63, 10);
        int m99RL69 = m99RL(m99RL32 + m97f2(m99RL67, m99RL65, m99RL68) + this.f496X[13] + 1518500249, 8) + m99RL66;
        int m99RL70 = m99RL(m99RL65, 10);
        int m99RL71 = m99RL(m99RL66 + m97f2(m99RL69, m99RL67, m99RL70) + this.f496X[1] + 1518500249, 13) + m99RL68;
        int m99RL72 = m99RL(m99RL67, 10);
        int m99RL73 = m99RL(m99RL68 + m97f2(m99RL71, m99RL69, m99RL72) + this.f496X[10] + 1518500249, 11) + m99RL70;
        int m99RL74 = m99RL(m99RL69, 10);
        int m99RL75 = m99RL(m99RL70 + m97f2(m99RL73, m99RL71, m99RL74) + this.f496X[6] + 1518500249, 9) + m99RL72;
        int m99RL76 = m99RL(m99RL71, 10);
        int m99RL77 = m99RL(m99RL72 + m97f2(m99RL75, m99RL73, m99RL76) + this.f496X[15] + 1518500249, 7) + m99RL74;
        int m99RL78 = m99RL(m99RL73, 10);
        int m99RL79 = m99RL(m99RL74 + m97f2(m99RL77, m99RL75, m99RL78) + this.f496X[3] + 1518500249, 15) + m99RL76;
        int m99RL80 = m99RL(m99RL75, 10);
        int m99RL81 = m99RL(m99RL76 + m97f2(m99RL79, m99RL77, m99RL80) + this.f496X[12] + 1518500249, 7) + m99RL78;
        int m99RL82 = m99RL(m99RL77, 10);
        int m99RL83 = m99RL(m99RL78 + m97f2(m99RL81, m99RL79, m99RL82) + this.f496X[0] + 1518500249, 12) + m99RL80;
        int m99RL84 = m99RL(m99RL79, 10);
        int m99RL85 = m99RL(m99RL80 + m97f2(m99RL83, m99RL81, m99RL84) + this.f496X[9] + 1518500249, 15) + m99RL82;
        int m99RL86 = m99RL(m99RL81, 10);
        int m99RL87 = m99RL(m99RL82 + m97f2(m99RL85, m99RL83, m99RL86) + this.f496X[5] + 1518500249, 9) + m99RL84;
        int m99RL88 = m99RL(m99RL83, 10);
        int m99RL89 = m99RL(m99RL84 + m97f2(m99RL87, m99RL85, m99RL88) + this.f496X[2] + 1518500249, 11) + m99RL86;
        int m99RL90 = m99RL(m99RL85, 10);
        int m99RL91 = m99RL(m99RL86 + m97f2(m99RL89, m99RL87, m99RL90) + this.f496X[14] + 1518500249, 7) + m99RL88;
        int m99RL92 = m99RL(m99RL87, 10);
        int m99RL93 = m99RL(m99RL88 + m97f2(m99RL91, m99RL89, m99RL92) + this.f496X[11] + 1518500249, 13) + m99RL90;
        int m99RL94 = m99RL(m99RL89, 10);
        int m99RL95 = m99RL(m99RL90 + m97f2(m99RL93, m99RL91, m99RL94) + this.f496X[8] + 1518500249, 12) + m99RL92;
        int m99RL96 = m99RL(m99RL91, 10);
        int m99RL97 = m99RL(m99RL60 + m95f4(m99RL31, m99RL61, m99RL64) + this.f496X[6] + 1548603684, 9) + m99RL62;
        int m99RL98 = m99RL(m99RL61, 10);
        int m99RL99 = m99RL(m99RL62 + m95f4(m99RL97, m99RL31, m99RL98) + this.f496X[11] + 1548603684, 13) + m99RL64;
        int m99RL100 = m99RL(m99RL31, 10);
        int m99RL101 = m99RL(m99RL64 + m95f4(m99RL99, m99RL97, m99RL100) + this.f496X[3] + 1548603684, 15) + m99RL98;
        int m99RL102 = m99RL(m99RL97, 10);
        int m99RL103 = m99RL(m99RL98 + m95f4(m99RL101, m99RL99, m99RL102) + this.f496X[7] + 1548603684, 7) + m99RL100;
        int m99RL104 = m99RL(m99RL99, 10);
        int m99RL105 = m99RL(m99RL100 + m95f4(m99RL103, m99RL101, m99RL104) + this.f496X[0] + 1548603684, 12) + m99RL102;
        int m99RL106 = m99RL(m99RL101, 10);
        int m99RL107 = m99RL(m99RL102 + m95f4(m99RL105, m99RL103, m99RL106) + this.f496X[13] + 1548603684, 8) + m99RL104;
        int m99RL108 = m99RL(m99RL103, 10);
        int m99RL109 = m99RL(m99RL104 + m95f4(m99RL107, m99RL105, m99RL108) + this.f496X[5] + 1548603684, 9) + m99RL106;
        int m99RL110 = m99RL(m99RL105, 10);
        int m99RL111 = m99RL(m99RL106 + m95f4(m99RL109, m99RL107, m99RL110) + this.f496X[10] + 1548603684, 11) + m99RL108;
        int m99RL112 = m99RL(m99RL107, 10);
        int m99RL113 = m99RL(m99RL108 + m95f4(m99RL111, m99RL109, m99RL112) + this.f496X[14] + 1548603684, 7) + m99RL110;
        int m99RL114 = m99RL(m99RL109, 10);
        int m99RL115 = m99RL(m99RL110 + m95f4(m99RL113, m99RL111, m99RL114) + this.f496X[15] + 1548603684, 7) + m99RL112;
        int m99RL116 = m99RL(m99RL111, 10);
        int m99RL117 = m99RL(m99RL112 + m95f4(m99RL115, m99RL113, m99RL116) + this.f496X[8] + 1548603684, 12) + m99RL114;
        int m99RL118 = m99RL(m99RL113, 10);
        int m99RL119 = m99RL(m99RL114 + m95f4(m99RL117, m99RL115, m99RL118) + this.f496X[12] + 1548603684, 7) + m99RL116;
        int m99RL120 = m99RL(m99RL115, 10);
        int m99RL121 = m99RL(m99RL116 + m95f4(m99RL119, m99RL117, m99RL120) + this.f496X[4] + 1548603684, 6) + m99RL118;
        int m99RL122 = m99RL(m99RL117, 10);
        int m99RL123 = m99RL(m99RL118 + m95f4(m99RL121, m99RL119, m99RL122) + this.f496X[9] + 1548603684, 15) + m99RL120;
        int m99RL124 = m99RL(m99RL119, 10);
        int m99RL125 = m99RL(m99RL120 + m95f4(m99RL123, m99RL121, m99RL124) + this.f496X[1] + 1548603684, 13) + m99RL122;
        int m99RL126 = m99RL(m99RL121, 10);
        int m99RL127 = m99RL(m99RL122 + m95f4(m99RL125, m99RL123, m99RL126) + this.f496X[2] + 1548603684, 11) + m99RL124;
        int m99RL128 = m99RL(m99RL123, 10);
        int m99RL129 = m99RL(m99RL92 + m96f3(m99RL95, m99RL93, m99RL128) + this.f496X[3] + 1859775393, 11) + m99RL94;
        int m99RL130 = m99RL(m99RL93, 10);
        int m99RL131 = m99RL(m99RL94 + m96f3(m99RL129, m99RL95, m99RL130) + this.f496X[10] + 1859775393, 13) + m99RL128;
        int m99RL132 = m99RL(m99RL95, 10);
        int m99RL133 = m99RL(m99RL128 + m96f3(m99RL131, m99RL129, m99RL132) + this.f496X[14] + 1859775393, 6) + m99RL130;
        int m99RL134 = m99RL(m99RL129, 10);
        int m99RL135 = m99RL(m99RL130 + m96f3(m99RL133, m99RL131, m99RL134) + this.f496X[4] + 1859775393, 7) + m99RL132;
        int m99RL136 = m99RL(m99RL131, 10);
        int m99RL137 = m99RL(m99RL132 + m96f3(m99RL135, m99RL133, m99RL136) + this.f496X[9] + 1859775393, 14) + m99RL134;
        int m99RL138 = m99RL(m99RL133, 10);
        int m99RL139 = m99RL(m99RL134 + m96f3(m99RL137, m99RL135, m99RL138) + this.f496X[15] + 1859775393, 9) + m99RL136;
        int m99RL140 = m99RL(m99RL135, 10);
        int m99RL141 = m99RL(m99RL136 + m96f3(m99RL139, m99RL137, m99RL140) + this.f496X[8] + 1859775393, 13) + m99RL138;
        int m99RL142 = m99RL(m99RL137, 10);
        int m99RL143 = m99RL(m99RL138 + m96f3(m99RL141, m99RL139, m99RL142) + this.f496X[1] + 1859775393, 15) + m99RL140;
        int m99RL144 = m99RL(m99RL139, 10);
        int m99RL145 = m99RL(m99RL140 + m96f3(m99RL143, m99RL141, m99RL144) + this.f496X[2] + 1859775393, 14) + m99RL142;
        int m99RL146 = m99RL(m99RL141, 10);
        int m99RL147 = m99RL(m99RL142 + m96f3(m99RL145, m99RL143, m99RL146) + this.f496X[7] + 1859775393, 8) + m99RL144;
        int m99RL148 = m99RL(m99RL143, 10);
        int m99RL149 = m99RL(m99RL144 + m96f3(m99RL147, m99RL145, m99RL148) + this.f496X[0] + 1859775393, 13) + m99RL146;
        int m99RL150 = m99RL(m99RL145, 10);
        int m99RL151 = m99RL(m99RL146 + m96f3(m99RL149, m99RL147, m99RL150) + this.f496X[6] + 1859775393, 6) + m99RL148;
        int m99RL152 = m99RL(m99RL147, 10);
        int m99RL153 = m99RL(m99RL148 + m96f3(m99RL151, m99RL149, m99RL152) + this.f496X[13] + 1859775393, 5) + m99RL150;
        int m99RL154 = m99RL(m99RL149, 10);
        int m99RL155 = m99RL(m99RL150 + m96f3(m99RL153, m99RL151, m99RL154) + this.f496X[11] + 1859775393, 12) + m99RL152;
        int m99RL156 = m99RL(m99RL151, 10);
        int m99RL157 = m99RL(m99RL152 + m96f3(m99RL155, m99RL153, m99RL156) + this.f496X[5] + 1859775393, 7) + m99RL154;
        int m99RL158 = m99RL(m99RL153, 10);
        int m99RL159 = m99RL(m99RL154 + m96f3(m99RL157, m99RL155, m99RL158) + this.f496X[12] + 1859775393, 5) + m99RL156;
        int m99RL160 = m99RL(m99RL155, 10);
        int m99RL161 = m99RL(m99RL124 + m96f3(m99RL127, m99RL125, m99RL96) + this.f496X[15] + 1836072691, 9) + m99RL126;
        int m99RL162 = m99RL(m99RL125, 10);
        int m99RL163 = m99RL(m99RL126 + m96f3(m99RL161, m99RL127, m99RL162) + this.f496X[5] + 1836072691, 7) + m99RL96;
        int m99RL164 = m99RL(m99RL127, 10);
        int m99RL165 = m99RL(m99RL96 + m96f3(m99RL163, m99RL161, m99RL164) + this.f496X[1] + 1836072691, 15) + m99RL162;
        int m99RL166 = m99RL(m99RL161, 10);
        int m99RL167 = m99RL(m99RL162 + m96f3(m99RL165, m99RL163, m99RL166) + this.f496X[3] + 1836072691, 11) + m99RL164;
        int m99RL168 = m99RL(m99RL163, 10);
        int m99RL169 = m99RL(m99RL164 + m96f3(m99RL167, m99RL165, m99RL168) + this.f496X[7] + 1836072691, 8) + m99RL166;
        int m99RL170 = m99RL(m99RL165, 10);
        int m99RL171 = m99RL(m99RL166 + m96f3(m99RL169, m99RL167, m99RL170) + this.f496X[14] + 1836072691, 6) + m99RL168;
        int m99RL172 = m99RL(m99RL167, 10);
        int m99RL173 = m99RL(m99RL168 + m96f3(m99RL171, m99RL169, m99RL172) + this.f496X[6] + 1836072691, 6) + m99RL170;
        int m99RL174 = m99RL(m99RL169, 10);
        int m99RL175 = m99RL(m99RL170 + m96f3(m99RL173, m99RL171, m99RL174) + this.f496X[9] + 1836072691, 14) + m99RL172;
        int m99RL176 = m99RL(m99RL171, 10);
        int m99RL177 = m99RL(m99RL172 + m96f3(m99RL175, m99RL173, m99RL176) + this.f496X[11] + 1836072691, 12) + m99RL174;
        int m99RL178 = m99RL(m99RL173, 10);
        int m99RL179 = m99RL(m99RL174 + m96f3(m99RL177, m99RL175, m99RL178) + this.f496X[8] + 1836072691, 13) + m99RL176;
        int m99RL180 = m99RL(m99RL175, 10);
        int m99RL181 = m99RL(m99RL176 + m96f3(m99RL179, m99RL177, m99RL180) + this.f496X[12] + 1836072691, 5) + m99RL178;
        int m99RL182 = m99RL(m99RL177, 10);
        int m99RL183 = m99RL(m99RL178 + m96f3(m99RL181, m99RL179, m99RL182) + this.f496X[2] + 1836072691, 14) + m99RL180;
        int m99RL184 = m99RL(m99RL179, 10);
        int m99RL185 = m99RL(m99RL180 + m96f3(m99RL183, m99RL181, m99RL184) + this.f496X[10] + 1836072691, 13) + m99RL182;
        int m99RL186 = m99RL(m99RL181, 10);
        int m99RL187 = m99RL(m99RL182 + m96f3(m99RL185, m99RL183, m99RL186) + this.f496X[0] + 1836072691, 13) + m99RL184;
        int m99RL188 = m99RL(m99RL183, 10);
        int m99RL189 = m99RL(m99RL184 + m96f3(m99RL187, m99RL185, m99RL188) + this.f496X[4] + 1836072691, 7) + m99RL186;
        int m99RL190 = m99RL(m99RL185, 10);
        int m99RL191 = m99RL(m99RL186 + m96f3(m99RL189, m99RL187, m99RL190) + this.f496X[13] + 1836072691, 5) + m99RL188;
        int m99RL192 = m99RL(m99RL187, 10);
        int m99RL193 = m99RL(((m99RL188 + m95f4(m99RL159, m99RL157, m99RL160)) + this.f496X[1]) - 1894007588, 11) + m99RL158;
        int m99RL194 = m99RL(m99RL157, 10);
        int m99RL195 = m99RL(((m99RL158 + m95f4(m99RL193, m99RL159, m99RL194)) + this.f496X[9]) - 1894007588, 12) + m99RL160;
        int m99RL196 = m99RL(m99RL159, 10);
        int m99RL197 = m99RL(((m99RL160 + m95f4(m99RL195, m99RL193, m99RL196)) + this.f496X[11]) - 1894007588, 14) + m99RL194;
        int m99RL198 = m99RL(m99RL193, 10);
        int m99RL199 = m99RL(((m99RL194 + m95f4(m99RL197, m99RL195, m99RL198)) + this.f496X[10]) - 1894007588, 15) + m99RL196;
        int m99RL200 = m99RL(m99RL195, 10);
        int m99RL201 = m99RL(((m99RL196 + m95f4(m99RL199, m99RL197, m99RL200)) + this.f496X[0]) - 1894007588, 14) + m99RL198;
        int m99RL202 = m99RL(m99RL197, 10);
        int m99RL203 = m99RL(((m99RL198 + m95f4(m99RL201, m99RL199, m99RL202)) + this.f496X[8]) - 1894007588, 15) + m99RL200;
        int m99RL204 = m99RL(m99RL199, 10);
        int m99RL205 = m99RL(((m99RL200 + m95f4(m99RL203, m99RL201, m99RL204)) + this.f496X[12]) - 1894007588, 9) + m99RL202;
        int m99RL206 = m99RL(m99RL201, 10);
        int m99RL207 = m99RL(((m99RL202 + m95f4(m99RL205, m99RL203, m99RL206)) + this.f496X[4]) - 1894007588, 8) + m99RL204;
        int m99RL208 = m99RL(m99RL203, 10);
        int m99RL209 = m99RL(((m99RL204 + m95f4(m99RL207, m99RL205, m99RL208)) + this.f496X[13]) - 1894007588, 9) + m99RL206;
        int m99RL210 = m99RL(m99RL205, 10);
        int m99RL211 = m99RL(((m99RL206 + m95f4(m99RL209, m99RL207, m99RL210)) + this.f496X[3]) - 1894007588, 14) + m99RL208;
        int m99RL212 = m99RL(m99RL207, 10);
        int m99RL213 = m99RL(((m99RL208 + m95f4(m99RL211, m99RL209, m99RL212)) + this.f496X[7]) - 1894007588, 5) + m99RL210;
        int m99RL214 = m99RL(m99RL209, 10);
        int m99RL215 = m99RL(((m99RL210 + m95f4(m99RL213, m99RL211, m99RL214)) + this.f496X[15]) - 1894007588, 6) + m99RL212;
        int m99RL216 = m99RL(m99RL211, 10);
        int m99RL217 = m99RL(((m99RL212 + m95f4(m99RL215, m99RL213, m99RL216)) + this.f496X[14]) - 1894007588, 8) + m99RL214;
        int m99RL218 = m99RL(m99RL213, 10);
        int m99RL219 = m99RL(((m99RL214 + m95f4(m99RL217, m99RL215, m99RL218)) + this.f496X[5]) - 1894007588, 6) + m99RL216;
        int m99RL220 = m99RL(m99RL215, 10);
        int m99RL221 = m99RL(((m99RL216 + m95f4(m99RL219, m99RL217, m99RL220)) + this.f496X[6]) - 1894007588, 5) + m99RL218;
        int m99RL222 = m99RL(m99RL217, 10);
        int m99RL223 = m99RL(((m99RL218 + m95f4(m99RL221, m99RL219, m99RL222)) + this.f496X[2]) - 1894007588, 12) + m99RL220;
        int m99RL224 = m99RL(m99RL219, 10);
        int m99RL225 = m99RL(m99RL156 + m97f2(m99RL191, m99RL189, m99RL192) + this.f496X[8] + 2053994217, 15) + m99RL190;
        int m99RL226 = m99RL(m99RL189, 10);
        int m99RL227 = m99RL(m99RL190 + m97f2(m99RL225, m99RL191, m99RL226) + this.f496X[6] + 2053994217, 5) + m99RL192;
        int m99RL228 = m99RL(m99RL191, 10);
        int m99RL229 = m99RL(m99RL192 + m97f2(m99RL227, m99RL225, m99RL228) + this.f496X[4] + 2053994217, 8) + m99RL226;
        int m99RL230 = m99RL(m99RL225, 10);
        int m99RL231 = m99RL(m99RL226 + m97f2(m99RL229, m99RL227, m99RL230) + this.f496X[1] + 2053994217, 11) + m99RL228;
        int m99RL232 = m99RL(m99RL227, 10);
        int m99RL233 = m99RL(m99RL228 + m97f2(m99RL231, m99RL229, m99RL232) + this.f496X[3] + 2053994217, 14) + m99RL230;
        int m99RL234 = m99RL(m99RL229, 10);
        int m99RL235 = m99RL(m99RL230 + m97f2(m99RL233, m99RL231, m99RL234) + this.f496X[11] + 2053994217, 14) + m99RL232;
        int m99RL236 = m99RL(m99RL231, 10);
        int m99RL237 = m99RL(m99RL232 + m97f2(m99RL235, m99RL233, m99RL236) + this.f496X[15] + 2053994217, 6) + m99RL234;
        int m99RL238 = m99RL(m99RL233, 10);
        int m99RL239 = m99RL(m99RL234 + m97f2(m99RL237, m99RL235, m99RL238) + this.f496X[0] + 2053994217, 14) + m99RL236;
        int m99RL240 = m99RL(m99RL235, 10);
        int m99RL241 = m99RL(m99RL236 + m97f2(m99RL239, m99RL237, m99RL240) + this.f496X[5] + 2053994217, 6) + m99RL238;
        int m99RL242 = m99RL(m99RL237, 10);
        int m99RL243 = m99RL(m99RL238 + m97f2(m99RL241, m99RL239, m99RL242) + this.f496X[12] + 2053994217, 9) + m99RL240;
        int m99RL244 = m99RL(m99RL239, 10);
        int m99RL245 = m99RL(m99RL240 + m97f2(m99RL243, m99RL241, m99RL244) + this.f496X[2] + 2053994217, 12) + m99RL242;
        int m99RL246 = m99RL(m99RL241, 10);
        int m99RL247 = m99RL(m99RL242 + m97f2(m99RL245, m99RL243, m99RL246) + this.f496X[13] + 2053994217, 9) + m99RL244;
        int m99RL248 = m99RL(m99RL243, 10);
        int m99RL249 = m99RL(m99RL244 + m97f2(m99RL247, m99RL245, m99RL248) + this.f496X[9] + 2053994217, 12) + m99RL246;
        int m99RL250 = m99RL(m99RL245, 10);
        int m99RL251 = m99RL(m99RL246 + m97f2(m99RL249, m99RL247, m99RL250) + this.f496X[7] + 2053994217, 5) + m99RL248;
        int m99RL252 = m99RL(m99RL247, 10);
        int m99RL253 = m99RL(m99RL248 + m97f2(m99RL251, m99RL249, m99RL252) + this.f496X[10] + 2053994217, 15) + m99RL250;
        int m99RL254 = m99RL(m99RL249, 10);
        int m99RL255 = m99RL(m99RL250 + m97f2(m99RL253, m99RL251, m99RL254) + this.f496X[14] + 2053994217, 8) + m99RL252;
        int m99RL256 = m99RL(m99RL251, 10);
        int m99RL257 = m99RL(((m99RL220 + m94f5(m99RL223, m99RL253, m99RL224)) + this.f496X[4]) - 1454113458, 9) + m99RL222;
        int m99RL258 = m99RL(m99RL253, 10);
        int m99RL259 = m99RL(((m99RL222 + m94f5(m99RL257, m99RL223, m99RL258)) + this.f496X[0]) - 1454113458, 15) + m99RL224;
        int m99RL260 = m99RL(m99RL223, 10);
        int m99RL261 = m99RL(((m99RL224 + m94f5(m99RL259, m99RL257, m99RL260)) + this.f496X[5]) - 1454113458, 5) + m99RL258;
        int m99RL262 = m99RL(m99RL257, 10);
        int m99RL263 = m99RL(((m99RL258 + m94f5(m99RL261, m99RL259, m99RL262)) + this.f496X[9]) - 1454113458, 11) + m99RL260;
        int m99RL264 = m99RL(m99RL259, 10);
        int m99RL265 = m99RL(((m99RL260 + m94f5(m99RL263, m99RL261, m99RL264)) + this.f496X[7]) - 1454113458, 6) + m99RL262;
        int m99RL266 = m99RL(m99RL261, 10);
        int m99RL267 = m99RL(((m99RL262 + m94f5(m99RL265, m99RL263, m99RL266)) + this.f496X[12]) - 1454113458, 8) + m99RL264;
        int m99RL268 = m99RL(m99RL263, 10);
        int m99RL269 = m99RL(((m99RL264 + m94f5(m99RL267, m99RL265, m99RL268)) + this.f496X[2]) - 1454113458, 13) + m99RL266;
        int m99RL270 = m99RL(m99RL265, 10);
        int m99RL271 = m99RL(((m99RL266 + m94f5(m99RL269, m99RL267, m99RL270)) + this.f496X[10]) - 1454113458, 12) + m99RL268;
        int m99RL272 = m99RL(m99RL267, 10);
        int m99RL273 = m99RL(((m99RL268 + m94f5(m99RL271, m99RL269, m99RL272)) + this.f496X[14]) - 1454113458, 5) + m99RL270;
        int m99RL274 = m99RL(m99RL269, 10);
        int m99RL275 = m99RL(((m99RL270 + m94f5(m99RL273, m99RL271, m99RL274)) + this.f496X[1]) - 1454113458, 12) + m99RL272;
        int m99RL276 = m99RL(m99RL271, 10);
        int m99RL277 = m99RL(((m99RL272 + m94f5(m99RL275, m99RL273, m99RL276)) + this.f496X[3]) - 1454113458, 13) + m99RL274;
        int m99RL278 = m99RL(m99RL273, 10);
        int m99RL279 = m99RL(((m99RL274 + m94f5(m99RL277, m99RL275, m99RL278)) + this.f496X[8]) - 1454113458, 14) + m99RL276;
        int m99RL280 = m99RL(m99RL275, 10);
        int m99RL281 = m99RL(((m99RL276 + m94f5(m99RL279, m99RL277, m99RL280)) + this.f496X[11]) - 1454113458, 11) + m99RL278;
        int m99RL282 = m99RL(m99RL277, 10);
        int m99RL283 = m99RL(((m99RL278 + m94f5(m99RL281, m99RL279, m99RL282)) + this.f496X[6]) - 1454113458, 8) + m99RL280;
        int m99RL284 = m99RL(m99RL279, 10);
        int m99RL285 = m99RL(((m99RL280 + m94f5(m99RL283, m99RL281, m99RL284)) + this.f496X[15]) - 1454113458, 5) + m99RL282;
        int m99RL286 = m99RL(m99RL281, 10);
        int m99RL287 = m99RL(((m99RL282 + m94f5(m99RL285, m99RL283, m99RL286)) + this.f496X[13]) - 1454113458, 6) + m99RL284;
        int m99RL288 = m99RL(m99RL283, 10);
        int m99RL289 = m99RL(m99RL252 + m98f1(m99RL255, m99RL221, m99RL256) + this.f496X[12], 8) + m99RL254;
        int m99RL290 = m99RL(m99RL221, 10);
        int m99RL291 = m99RL(m99RL254 + m98f1(m99RL289, m99RL255, m99RL290) + this.f496X[15], 5) + m99RL256;
        int m99RL292 = m99RL(m99RL255, 10);
        int m99RL293 = m99RL(m99RL256 + m98f1(m99RL291, m99RL289, m99RL292) + this.f496X[10], 12) + m99RL290;
        int m99RL294 = m99RL(m99RL289, 10);
        int m99RL295 = m99RL(m99RL290 + m98f1(m99RL293, m99RL291, m99RL294) + this.f496X[4], 9) + m99RL292;
        int m99RL296 = m99RL(m99RL291, 10);
        int m99RL297 = m99RL(m99RL292 + m98f1(m99RL295, m99RL293, m99RL296) + this.f496X[1], 12) + m99RL294;
        int m99RL298 = m99RL(m99RL293, 10);
        int m99RL299 = m99RL(m99RL294 + m98f1(m99RL297, m99RL295, m99RL298) + this.f496X[5], 5) + m99RL296;
        int m99RL300 = m99RL(m99RL295, 10);
        int m99RL301 = m99RL(m99RL296 + m98f1(m99RL299, m99RL297, m99RL300) + this.f496X[8], 14) + m99RL298;
        int m99RL302 = m99RL(m99RL297, 10);
        int m99RL303 = m99RL(m99RL298 + m98f1(m99RL301, m99RL299, m99RL302) + this.f496X[7], 6) + m99RL300;
        int m99RL304 = m99RL(m99RL299, 10);
        int m99RL305 = m99RL(m99RL300 + m98f1(m99RL303, m99RL301, m99RL304) + this.f496X[6], 8) + m99RL302;
        int m99RL306 = m99RL(m99RL301, 10);
        int m99RL307 = m99RL(m99RL302 + m98f1(m99RL305, m99RL303, m99RL306) + this.f496X[2], 13) + m99RL304;
        int m99RL308 = m99RL(m99RL303, 10);
        int m99RL309 = m99RL(m99RL304 + m98f1(m99RL307, m99RL305, m99RL308) + this.f496X[13], 6) + m99RL306;
        int m99RL310 = m99RL(m99RL305, 10);
        int m99RL311 = m99RL(m99RL306 + m98f1(m99RL309, m99RL307, m99RL310) + this.f496X[14], 5) + m99RL308;
        int m99RL312 = m99RL(m99RL307, 10);
        int m99RL313 = m99RL(m99RL308 + m98f1(m99RL311, m99RL309, m99RL312) + this.f496X[0], 15) + m99RL310;
        int m99RL314 = m99RL(m99RL309, 10);
        int m99RL315 = m99RL(m99RL310 + m98f1(m99RL313, m99RL311, m99RL314) + this.f496X[3], 13) + m99RL312;
        int m99RL316 = m99RL(m99RL311, 10);
        int m99RL317 = m99RL(m99RL312 + m98f1(m99RL315, m99RL313, m99RL316) + this.f496X[9], 11) + m99RL314;
        int m99RL318 = m99RL(m99RL313, 10);
        int m99RL319 = m99RL(m99RL314 + m98f1(m99RL317, m99RL315, m99RL318) + this.f496X[11], 11) + m99RL316;
        int m99RL320 = m99RL(m99RL315, 10);
        this.f486H0 += m99RL284;
        this.f487H1 += m99RL287;
        this.f488H2 += m99RL285;
        this.f489H3 += m99RL288;
        this.f490H4 += m99RL318;
        this.f491H5 += m99RL316;
        this.f492H6 += m99RL319;
        this.f493H7 += m99RL317;
        this.f494H8 += m99RL320;
        this.f495H9 += m99RL286;
        this.xOff = 0;
        int i11 = 0;
        while (true) {
            int[] iArr = this.f496X;
            if (i11 == iArr.length) {
                return;
            }
            iArr[i11] = 0;
            i11++;
        }
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        int[] iArr = this.f496X;
        iArr[14] = (int) j;
        iArr[15] = (int) (j >>> 32);
    }

    @Override // org.bouncycastle.crypto.digests.GeneralDigest
    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f496X;
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
        this.f486H0 = 1732584193;
        this.f487H1 = -271733879;
        this.f488H2 = -1732584194;
        this.f489H3 = 271733878;
        this.f490H4 = -1009589776;
        this.f491H5 = 1985229328;
        this.f492H6 = -19088744;
        this.f493H7 = -1985229329;
        this.f494H8 = 19088743;
        this.f495H9 = 1009589775;
        this.xOff = 0;
        int i = 0;
        while (true) {
            int[] iArr = this.f496X;
            if (i == iArr.length) {
                return;
            }
            iArr[i] = 0;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        doCopy((RIPEMD320Digest) memoable);
    }
}