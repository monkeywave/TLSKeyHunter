package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;
import org.openjsse.sun.security.ssl.Record;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/Poly1305.class */
public class Poly1305 implements Mac {
    private static final int BLOCK_SIZE = 16;
    private final BlockCipher cipher;
    private final byte[] singleByte;

    /* renamed from: r0 */
    private int f417r0;

    /* renamed from: r1 */
    private int f418r1;

    /* renamed from: r2 */
    private int f419r2;

    /* renamed from: r3 */
    private int f420r3;

    /* renamed from: r4 */
    private int f421r4;

    /* renamed from: s1 */
    private int f422s1;

    /* renamed from: s2 */
    private int f423s2;

    /* renamed from: s3 */
    private int f424s3;

    /* renamed from: s4 */
    private int f425s4;

    /* renamed from: k0 */
    private int f426k0;

    /* renamed from: k1 */
    private int f427k1;

    /* renamed from: k2 */
    private int f428k2;

    /* renamed from: k3 */
    private int f429k3;
    private final byte[] currentBlock;
    private int currentBlockOffset;

    /* renamed from: h0 */
    private int f430h0;

    /* renamed from: h1 */
    private int f431h1;

    /* renamed from: h2 */
    private int f432h2;

    /* renamed from: h3 */
    private int f433h3;

    /* renamed from: h4 */
    private int f434h4;

    public Poly1305() {
        this.singleByte = new byte[1];
        this.currentBlock = new byte[16];
        this.currentBlockOffset = 0;
        this.cipher = null;
    }

    public Poly1305(BlockCipher blockCipher) {
        this.singleByte = new byte[1];
        this.currentBlock = new byte[16];
        this.currentBlockOffset = 0;
        if (blockCipher.getBlockSize() != 16) {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit block cipher.");
        }
        this.cipher = blockCipher;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] bArr = null;
        if (this.cipher != null) {
            if (!(cipherParameters instanceof ParametersWithIV)) {
                throw new IllegalArgumentException("Poly1305 requires an IV when used with a block cipher.");
            }
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            bArr = parametersWithIV.getIV();
            cipherParameters = parametersWithIV.getParameters();
        }
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("Poly1305 requires a key.");
        }
        setKey(((KeyParameter) cipherParameters).getKey(), bArr);
        reset();
    }

    private void setKey(byte[] bArr, byte[] bArr2) {
        byte[] bArr3;
        int i;
        if (bArr.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }
        if (this.cipher != null && (bArr2 == null || bArr2.length != 16)) {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit IV.");
        }
        int littleEndianToInt = Pack.littleEndianToInt(bArr, 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, 8);
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, 12);
        this.f417r0 = littleEndianToInt & 67108863;
        this.f418r1 = ((littleEndianToInt >>> 26) | (littleEndianToInt2 << 6)) & 67108611;
        this.f419r2 = ((littleEndianToInt2 >>> 20) | (littleEndianToInt3 << 12)) & 67092735;
        this.f420r3 = ((littleEndianToInt3 >>> 14) | (littleEndianToInt4 << 18)) & 66076671;
        this.f421r4 = (littleEndianToInt4 >>> 8) & 1048575;
        this.f422s1 = this.f418r1 * 5;
        this.f423s2 = this.f419r2 * 5;
        this.f424s3 = this.f420r3 * 5;
        this.f425s4 = this.f421r4 * 5;
        if (this.cipher == null) {
            bArr3 = bArr;
            i = 16;
        } else {
            bArr3 = new byte[16];
            i = 0;
            this.cipher.init(true, new KeyParameter(bArr, 16, 16));
            this.cipher.processBlock(bArr2, 0, bArr3, 0);
        }
        this.f426k0 = Pack.littleEndianToInt(bArr3, i + 0);
        this.f427k1 = Pack.littleEndianToInt(bArr3, i + 4);
        this.f428k2 = Pack.littleEndianToInt(bArr3, i + 8);
        this.f429k3 = Pack.littleEndianToInt(bArr3, i + 12);
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return this.cipher == null ? "Poly1305" : "Poly1305-" + this.cipher.getAlgorithmName();
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        this.singleByte[0] = b;
        update(this.singleByte, 0, 1);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        int i3 = 0;
        while (i2 > i3) {
            if (this.currentBlockOffset == 16) {
                processBlock();
                this.currentBlockOffset = 0;
            }
            int min = Math.min(i2 - i3, 16 - this.currentBlockOffset);
            System.arraycopy(bArr, i3 + i, this.currentBlock, this.currentBlockOffset, min);
            i3 += min;
            this.currentBlockOffset += min;
        }
    }

    private void processBlock() {
        if (this.currentBlockOffset < 16) {
            this.currentBlock[this.currentBlockOffset] = 1;
            for (int i = this.currentBlockOffset + 1; i < 16; i++) {
                this.currentBlock[i] = 0;
            }
        }
        long littleEndianToInt = 4294967295L & Pack.littleEndianToInt(this.currentBlock, 0);
        long littleEndianToInt2 = 4294967295L & Pack.littleEndianToInt(this.currentBlock, 4);
        long littleEndianToInt3 = 4294967295L & Pack.littleEndianToInt(this.currentBlock, 8);
        long littleEndianToInt4 = 4294967295L & Pack.littleEndianToInt(this.currentBlock, 12);
        this.f430h0 = (int) (this.f430h0 + (littleEndianToInt & 67108863));
        this.f431h1 = (int) (this.f431h1 + ((((littleEndianToInt2 << 32) | littleEndianToInt) >>> 26) & 67108863));
        this.f432h2 = (int) (this.f432h2 + ((((littleEndianToInt3 << 32) | littleEndianToInt2) >>> 20) & 67108863));
        this.f433h3 = (int) (this.f433h3 + ((((littleEndianToInt4 << 32) | littleEndianToInt3) >>> 14) & 67108863));
        this.f434h4 = (int) (this.f434h4 + (littleEndianToInt4 >>> 8));
        if (this.currentBlockOffset == 16) {
            this.f434h4 += Record.OVERFLOW_OF_INT24;
        }
        long mul32x32_64 = mul32x32_64(this.f430h0, this.f417r0) + mul32x32_64(this.f431h1, this.f425s4) + mul32x32_64(this.f432h2, this.f424s3) + mul32x32_64(this.f433h3, this.f423s2) + mul32x32_64(this.f434h4, this.f422s1);
        long mul32x32_642 = mul32x32_64(this.f430h0, this.f418r1) + mul32x32_64(this.f431h1, this.f417r0) + mul32x32_64(this.f432h2, this.f425s4) + mul32x32_64(this.f433h3, this.f424s3) + mul32x32_64(this.f434h4, this.f423s2);
        long mul32x32_643 = mul32x32_64(this.f430h0, this.f419r2) + mul32x32_64(this.f431h1, this.f418r1) + mul32x32_64(this.f432h2, this.f417r0) + mul32x32_64(this.f433h3, this.f425s4) + mul32x32_64(this.f434h4, this.f424s3);
        long mul32x32_644 = mul32x32_64(this.f430h0, this.f420r3) + mul32x32_64(this.f431h1, this.f419r2) + mul32x32_64(this.f432h2, this.f418r1) + mul32x32_64(this.f433h3, this.f417r0) + mul32x32_64(this.f434h4, this.f425s4);
        long mul32x32_645 = mul32x32_64(this.f430h0, this.f421r4) + mul32x32_64(this.f431h1, this.f420r3) + mul32x32_64(this.f432h2, this.f419r2) + mul32x32_64(this.f433h3, this.f418r1) + mul32x32_64(this.f434h4, this.f417r0);
        this.f430h0 = ((int) mul32x32_64) & 67108863;
        long j = mul32x32_642 + (mul32x32_64 >>> 26);
        this.f431h1 = ((int) j) & 67108863;
        long j2 = mul32x32_643 + (j >>> 26);
        this.f432h2 = ((int) j2) & 67108863;
        long j3 = mul32x32_644 + (j2 >>> 26);
        this.f433h3 = ((int) j3) & 67108863;
        long j4 = mul32x32_645 + (j3 >>> 26);
        this.f434h4 = ((int) j4) & 67108863;
        this.f430h0 += ((int) (j4 >>> 26)) * 5;
        this.f431h1 += this.f430h0 >>> 26;
        this.f430h0 &= 67108863;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        if (i + 16 > bArr.length) {
            throw new OutputLengthException("Output buffer is too short.");
        }
        if (this.currentBlockOffset > 0) {
            processBlock();
        }
        this.f431h1 += this.f430h0 >>> 26;
        this.f430h0 &= 67108863;
        this.f432h2 += this.f431h1 >>> 26;
        this.f431h1 &= 67108863;
        this.f433h3 += this.f432h2 >>> 26;
        this.f432h2 &= 67108863;
        this.f434h4 += this.f433h3 >>> 26;
        this.f433h3 &= 67108863;
        this.f430h0 += (this.f434h4 >>> 26) * 5;
        this.f434h4 &= 67108863;
        this.f431h1 += this.f430h0 >>> 26;
        this.f430h0 &= 67108863;
        int i2 = this.f430h0 + 5;
        int i3 = i2 >>> 26;
        int i4 = i2 & 67108863;
        int i5 = this.f431h1 + i3;
        int i6 = i5 >>> 26;
        int i7 = i5 & 67108863;
        int i8 = this.f432h2 + i6;
        int i9 = i8 >>> 26;
        int i10 = i8 & 67108863;
        int i11 = this.f433h3 + i9;
        int i12 = i11 >>> 26;
        int i13 = i11 & 67108863;
        int i14 = (this.f434h4 + i12) - 67108864;
        int i15 = (i14 >>> 31) - 1;
        int i16 = i15 ^ (-1);
        this.f430h0 = (this.f430h0 & i16) | (i4 & i15);
        this.f431h1 = (this.f431h1 & i16) | (i7 & i15);
        this.f432h2 = (this.f432h2 & i16) | (i10 & i15);
        this.f433h3 = (this.f433h3 & i16) | (i13 & i15);
        this.f434h4 = (this.f434h4 & i16) | (i14 & i15);
        long j = ((this.f430h0 | (this.f431h1 << 26)) & 4294967295L) + (4294967295L & this.f426k0);
        Pack.intToLittleEndian((int) j, bArr, i);
        long j2 = (((this.f431h1 >>> 6) | (this.f432h2 << 20)) & 4294967295L) + (4294967295L & this.f427k1) + (j >>> 32);
        Pack.intToLittleEndian((int) j2, bArr, i + 4);
        long j3 = (((this.f432h2 >>> 12) | (this.f433h3 << 14)) & 4294967295L) + (4294967295L & this.f428k2) + (j2 >>> 32);
        Pack.intToLittleEndian((int) j3, bArr, i + 8);
        Pack.intToLittleEndian((int) ((((this.f433h3 >>> 18) | (this.f434h4 << 8)) & 4294967295L) + (4294967295L & this.f429k3) + (j3 >>> 32)), bArr, i + 12);
        reset();
        return 16;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        this.currentBlockOffset = 0;
        this.f434h4 = 0;
        this.f433h3 = 0;
        this.f432h2 = 0;
        this.f431h1 = 0;
        this.f430h0 = 0;
    }

    private static final long mul32x32_64(int i, int i2) {
        return (i & 4294967295L) * i2;
    }
}