package org.bouncycastle.crypto.macs;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class Poly1305 implements Mac {
    private static final int BLOCK_SIZE = 16;
    private final BlockCipher cipher;
    private final byte[] currentBlock;
    private int currentBlockOffset;

    /* renamed from: h0 */
    private int f735h0;

    /* renamed from: h1 */
    private int f736h1;

    /* renamed from: h2 */
    private int f737h2;

    /* renamed from: h3 */
    private int f738h3;

    /* renamed from: h4 */
    private int f739h4;

    /* renamed from: k0 */
    private int f740k0;

    /* renamed from: k1 */
    private int f741k1;

    /* renamed from: k2 */
    private int f742k2;

    /* renamed from: k3 */
    private int f743k3;

    /* renamed from: r0 */
    private int f744r0;

    /* renamed from: r1 */
    private int f745r1;

    /* renamed from: r2 */
    private int f746r2;

    /* renamed from: r3 */
    private int f747r3;

    /* renamed from: r4 */
    private int f748r4;

    /* renamed from: s1 */
    private int f749s1;

    /* renamed from: s2 */
    private int f750s2;

    /* renamed from: s3 */
    private int f751s3;

    /* renamed from: s4 */
    private int f752s4;
    private final byte[] singleByte;

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

    private static final long mul32x32_64(int i, int i2) {
        return (i & BodyPartID.bodyIdMax) * i2;
    }

    private void processBlock() {
        int i = this.currentBlockOffset;
        if (i < 16) {
            this.currentBlock[i] = 1;
            for (int i2 = i + 1; i2 < 16; i2++) {
                this.currentBlock[i2] = 0;
            }
        }
        long littleEndianToInt = Pack.littleEndianToInt(this.currentBlock, 0);
        long j = littleEndianToInt & BodyPartID.bodyIdMax;
        long littleEndianToInt2 = Pack.littleEndianToInt(this.currentBlock, 4) & BodyPartID.bodyIdMax;
        long littleEndianToInt3 = Pack.littleEndianToInt(this.currentBlock, 8) & BodyPartID.bodyIdMax;
        long littleEndianToInt4 = BodyPartID.bodyIdMax & Pack.littleEndianToInt(this.currentBlock, 12);
        int i3 = (int) (this.f735h0 + (littleEndianToInt & 67108863));
        this.f735h0 = i3;
        this.f736h1 = (int) (this.f736h1 + ((((littleEndianToInt2 << 32) | j) >>> 26) & 67108863));
        this.f737h2 = (int) (this.f737h2 + (((littleEndianToInt2 | (littleEndianToInt3 << 32)) >>> 20) & 67108863));
        this.f738h3 = (int) (this.f738h3 + ((((littleEndianToInt4 << 32) | littleEndianToInt3) >>> 14) & 67108863));
        int i4 = (int) (this.f739h4 + (littleEndianToInt4 >>> 8));
        this.f739h4 = i4;
        if (this.currentBlockOffset == 16) {
            this.f739h4 = i4 + 16777216;
        }
        long mul32x32_64 = mul32x32_64(i3, this.f744r0) + mul32x32_64(this.f736h1, this.f752s4) + mul32x32_64(this.f737h2, this.f751s3) + mul32x32_64(this.f738h3, this.f750s2) + mul32x32_64(this.f739h4, this.f749s1);
        long mul32x32_642 = mul32x32_64(this.f735h0, this.f745r1) + mul32x32_64(this.f736h1, this.f744r0) + mul32x32_64(this.f737h2, this.f752s4) + mul32x32_64(this.f738h3, this.f751s3) + mul32x32_64(this.f739h4, this.f750s2);
        long mul32x32_643 = mul32x32_64(this.f735h0, this.f746r2) + mul32x32_64(this.f736h1, this.f745r1) + mul32x32_64(this.f737h2, this.f744r0) + mul32x32_64(this.f738h3, this.f752s4) + mul32x32_64(this.f739h4, this.f751s3);
        long mul32x32_644 = mul32x32_64(this.f735h0, this.f747r3) + mul32x32_64(this.f736h1, this.f746r2) + mul32x32_64(this.f737h2, this.f745r1) + mul32x32_64(this.f738h3, this.f744r0) + mul32x32_64(this.f739h4, this.f752s4);
        long j2 = mul32x32_642 + (mul32x32_64 >>> 26);
        long j3 = mul32x32_643 + (j2 >>> 26);
        this.f737h2 = ((int) j3) & 67108863;
        long j4 = mul32x32_644 + (j3 >>> 26);
        this.f738h3 = ((int) j4) & 67108863;
        long mul32x32_645 = mul32x32_64(this.f735h0, this.f748r4) + mul32x32_64(this.f736h1, this.f747r3) + mul32x32_64(this.f737h2, this.f746r2) + mul32x32_64(this.f738h3, this.f745r1) + mul32x32_64(this.f739h4, this.f744r0) + (j4 >>> 26);
        this.f739h4 = ((int) mul32x32_645) & 67108863;
        int i5 = (((int) mul32x32_64) & 67108863) + (((int) (mul32x32_645 >>> 26)) * 5);
        this.f736h1 = (((int) j2) & 67108863) + (i5 >>> 26);
        this.f735h0 = i5 & 67108863;
    }

    private void setKey(byte[] bArr, byte[] bArr2) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }
        int i = 16;
        if (this.cipher != null && (bArr2 == null || bArr2.length != 16)) {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit IV.");
        }
        int littleEndianToInt = Pack.littleEndianToInt(bArr, 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, 8);
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, 12);
        this.f744r0 = 67108863 & littleEndianToInt;
        int i2 = ((littleEndianToInt >>> 26) | (littleEndianToInt2 << 6)) & 67108611;
        this.f745r1 = i2;
        int i3 = ((littleEndianToInt2 >>> 20) | (littleEndianToInt3 << 12)) & 67092735;
        this.f746r2 = i3;
        int i4 = ((littleEndianToInt3 >>> 14) | (littleEndianToInt4 << 18)) & 66076671;
        this.f747r3 = i4;
        int i5 = (littleEndianToInt4 >>> 8) & 1048575;
        this.f748r4 = i5;
        this.f749s1 = i2 * 5;
        this.f750s2 = i3 * 5;
        this.f751s3 = i4 * 5;
        this.f752s4 = i5 * 5;
        BlockCipher blockCipher = this.cipher;
        if (blockCipher != null) {
            byte[] bArr3 = new byte[16];
            blockCipher.init(true, new KeyParameter(bArr, 16, 16));
            this.cipher.processBlock(bArr2, 0, bArr3, 0);
            i = 0;
            bArr = bArr3;
        }
        this.f740k0 = Pack.littleEndianToInt(bArr, i);
        this.f741k1 = Pack.littleEndianToInt(bArr, i + 4);
        this.f742k2 = Pack.littleEndianToInt(bArr, i + 8);
        this.f743k3 = Pack.littleEndianToInt(bArr, i + 12);
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        if (i + 16 <= bArr.length) {
            if (this.currentBlockOffset > 0) {
                processBlock();
            }
            int i7 = this.f736h1;
            int i8 = this.f735h0;
            int i9 = i7 + (i8 >>> 26);
            int i10 = this.f737h2 + (i9 >>> 26);
            int i11 = this.f738h3 + (i10 >>> 26);
            int i12 = i10 & 67108863;
            int i13 = this.f739h4 + (i11 >>> 26);
            int i14 = i11 & 67108863;
            int i15 = (i8 & 67108863) + ((i13 >>> 26) * 5);
            int i16 = i13 & 67108863;
            int i17 = (i9 & 67108863) + (i15 >>> 26);
            int i18 = i15 & 67108863;
            int i19 = i18 + 5;
            int i20 = (i19 >>> 26) + i17;
            int i21 = (i20 >>> 26) + i12;
            int i22 = (i21 >>> 26) + i14;
            int i23 = 67108863 & i22;
            int i24 = ((i22 >>> 26) + i16) - 67108864;
            int i25 = (i24 >>> 31) - 1;
            int i26 = ~i25;
            this.f735h0 = (i18 & i26) | (i19 & 67108863 & i25);
            this.f736h1 = (i17 & i26) | (i20 & 67108863 & i25);
            this.f737h2 = (i12 & i26) | (i21 & 67108863 & i25);
            this.f738h3 = (i23 & i25) | (i14 & i26);
            this.f739h4 = (i16 & i26) | (i24 & i25);
            long j = ((i2 | (i3 << 26)) & BodyPartID.bodyIdMax) + (this.f740k0 & BodyPartID.bodyIdMax);
            long j2 = (((i3 >>> 6) | (i4 << 20)) & BodyPartID.bodyIdMax) + (this.f741k1 & BodyPartID.bodyIdMax);
            long j3 = (((i4 >>> 12) | (i5 << 14)) & BodyPartID.bodyIdMax) + (this.f742k2 & BodyPartID.bodyIdMax);
            Pack.intToLittleEndian((int) j, bArr, i);
            long j4 = j2 + (j >>> 32);
            Pack.intToLittleEndian((int) j4, bArr, i + 4);
            long j5 = j3 + (j4 >>> 32);
            Pack.intToLittleEndian((int) j5, bArr, i + 8);
            Pack.intToLittleEndian((int) ((((i5 >>> 18) | (i6 << 8)) & BodyPartID.bodyIdMax) + (BodyPartID.bodyIdMax & this.f743k3) + (j5 >>> 32)), bArr, i + 12);
            reset();
            return 16;
        }
        throw new OutputLengthException("Output buffer is too short.");
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
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] bArr;
        if (this.cipher == null) {
            bArr = null;
        } else if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("Poly1305 requires an IV when used with a block cipher.");
        } else {
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

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        this.currentBlockOffset = 0;
        this.f739h4 = 0;
        this.f738h3 = 0;
        this.f737h2 = 0;
        this.f736h1 = 0;
        this.f735h0 = 0;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        byte[] bArr = this.singleByte;
        bArr[0] = b;
        update(bArr, 0, 1);
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
}