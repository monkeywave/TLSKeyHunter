package org.bouncycastle.crypto.digests;

import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.math.Primes;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/WhirlpoolDigest.class */
public final class WhirlpoolDigest implements ExtendedDigest, Memoable {
    private static final int BYTE_LENGTH = 64;
    private static final int DIGEST_LENGTH_BYTES = 64;
    private static final int ROUNDS = 10;
    private static final int REDUCTION_POLYNOMIAL = 285;
    private final long[] _rc;
    private static final int BITCOUNT_ARRAY_SIZE = 32;
    private byte[] _buffer;
    private int _bufferPos;
    private short[] _bitCount;
    private long[] _hash;

    /* renamed from: _K */
    private long[] f272_K;

    /* renamed from: _L */
    private long[] f273_L;
    private long[] _block;
    private long[] _state;
    private static final int[] SBOX = {24, 35, Opcode.IFNULL, 232, Opcode.I2D, Opcode.INVOKESTATIC, 1, 79, 54, Opcode.IF_ACMPNE, 210, 245, Opcode.LSHL, Opcode.DDIV, Opcode.I2B, 82, 96, 188, Opcode.IFLT, Opcode.D2I, Opcode.IF_ICMPGT, 12, Opcode.LSHR, 53, 29, BERTags.FLAGS, 215, Opcode.MONITORENTER, 46, 75, 254, 87, 21, Opcode.DNEG, 55, 229, Opcode.IF_ICMPEQ, 240, 74, 218, 88, Opcode.JSR_W, 41, 10, Opcode.RETURN, Opcode.IF_ICMPNE, Opcode.DMUL, Opcode.I2L, Opcode.ANEWARRAY, 93, 16, 244, 203, 62, 5, Opcode.DSUB, 228, 39, 65, Opcode.F2I, Opcode.GOTO, Opcode.LUSHR, Opcode.FCMPL, 216, 251, 238, Opcode.IUSHR, Opcode.FSUB, 221, 23, 71, Opcode.IFLE, 202, 45, Opcode.ATHROW, 7, Opcode.LRETURN, 90, Opcode.LXOR, 51, 99, 2, Opcode.TABLESWITCH, Opcode.LREM, 200, 25, 73, 217, 242, 227, 91, Opcode.L2I, Opcode.IFNE, 38, 50, Opcode.ARETURN, 233, 15, 213, 128, Opcode.ARRAYLENGTH, 205, 52, 72, GF2Field.MASK, Opcode.ISHR, Opcode.D2F, 95, 32, Opcode.IMUL, 26, Opcode.FRETURN, Opcode.GETFIELD, 84, Opcode.I2S, 34, 100, 241, Opcode.DREM, 18, 64, 8, Opcode.MONITOREXIT, 236, 219, Opcode.IF_ICMPLT, Opcode.F2D, 61, Opcode.DCMPL, 0, 207, 43, Opcode.FNEG, Opcode.IXOR, 214, 27, Opcode.PUTFIELD, Opcode.DRETURN, Opcode.FMUL, 80, 69, 243, 48, 239, 63, 85, Opcode.IF_ICMPGE, 234, Opcode.LSUB, Opcode.INVOKEDYNAMIC, 47, 192, 222, 28, 253, 77, Opcode.I2C, Opcode.LNEG, 6, Opcode.L2D, Opcode.GETSTATIC, 230, 14, 31, 98, 212, Opcode.JSR, Opcode.FCMPG, 249, Opcode.MULTIANEWARRAY, 37, 89, Opcode.IINC, 114, 57, 76, 94, Opcode.ISHL, 56, Opcode.F2L, 209, Opcode.IF_ACMPEQ, 226, 97, Opcode.PUTSTATIC, 33, Opcode.IFGE, 30, 67, Opcode.IFNONNULL, 252, 4, 81, Opcode.IFEQ, Opcode.LDIV, 13, 250, 223, Opcode.IAND, 36, 59, Opcode.LOOKUPSWITCH, 206, 17, Opcode.D2L, 78, Opcode.INVOKESPECIAL, 235, 60, Opcode.LOR, Opcode.LCMP, 247, Opcode.INVOKEINTERFACE, 19, 44, Primes.SMALL_FACTOR_LIMIT, 231, Opcode.FDIV, Opcode.WIDE, 3, 86, 68, Opcode.LAND, Opcode.RET, 42, Opcode.NEW, Opcode.INSTANCEOF, 83, 220, 11, Opcode.IFGT, Opcode.IDIV, 49, Opcode.INEG, 246, 70, Opcode.IRETURN, Opcode.L2F, 20, 225, 22, 58, Opcode.LMUL, 9, Opcode.IREM, Opcode.INVOKEVIRTUAL, 208, 237, 204, 66, Opcode.DCMPG, Opcode.IF_ICMPLE, 40, 92, 248, Opcode.I2F};

    /* renamed from: C0 */
    private static final long[] f264C0 = new long[256];

    /* renamed from: C1 */
    private static final long[] f265C1 = new long[256];

    /* renamed from: C2 */
    private static final long[] f266C2 = new long[256];

    /* renamed from: C3 */
    private static final long[] f267C3 = new long[256];

    /* renamed from: C4 */
    private static final long[] f268C4 = new long[256];

    /* renamed from: C5 */
    private static final long[] f269C5 = new long[256];

    /* renamed from: C6 */
    private static final long[] f270C6 = new long[256];

    /* renamed from: C7 */
    private static final long[] f271C7 = new long[256];
    private static final short[] EIGHT = new short[32];

    public WhirlpoolDigest() {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this.f272_K = new long[8];
        this.f273_L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        for (int i = 0; i < 256; i++) {
            int i2 = SBOX[i];
            int maskWithReductionPolynomial = maskWithReductionPolynomial(i2 << 1);
            int maskWithReductionPolynomial2 = maskWithReductionPolynomial(maskWithReductionPolynomial << 1);
            int i3 = maskWithReductionPolynomial2 ^ i2;
            int maskWithReductionPolynomial3 = maskWithReductionPolynomial(maskWithReductionPolynomial2 << 1);
            int i4 = maskWithReductionPolynomial3 ^ i2;
            f264C0[i] = packIntoLong(i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4);
            f265C1[i] = packIntoLong(i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial);
            f266C2[i] = packIntoLong(maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3);
            f267C3[i] = packIntoLong(i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3);
            f268C4[i] = packIntoLong(maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2);
            f269C5[i] = packIntoLong(i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2);
            f270C6[i] = packIntoLong(maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2);
            f271C7[i] = packIntoLong(i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2);
        }
        this._rc[0] = 0;
        for (int i5 = 1; i5 <= 10; i5++) {
            int i6 = 8 * (i5 - 1);
            this._rc[i5] = (((((((f264C0[i6] & (-72057594037927936L)) ^ (f265C1[i6 + 1] & 71776119061217280L)) ^ (f266C2[i6 + 2] & 280375465082880L)) ^ (f267C3[i6 + 3] & 1095216660480L)) ^ (f268C4[i6 + 4] & 4278190080L)) ^ (f269C5[i6 + 5] & 16711680)) ^ (f270C6[i6 + 6] & 65280)) ^ (f271C7[i6 + 7] & 255);
        }
    }

    private long packIntoLong(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        return (((((((i << 56) ^ (i2 << 48)) ^ (i3 << 40)) ^ (i4 << 32)) ^ (i5 << 24)) ^ (i6 << 16)) ^ (i7 << 8)) ^ i8;
    }

    private int maskWithReductionPolynomial(int i) {
        int i2 = i;
        if (i2 >= 256) {
            i2 ^= REDUCTION_POLYNOMIAL;
        }
        return i2;
    }

    public WhirlpoolDigest(WhirlpoolDigest whirlpoolDigest) {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this.f272_K = new long[8];
        this.f273_L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        reset(whirlpoolDigest);
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "Whirlpool";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 64;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        for (int i2 = 0; i2 < 8; i2++) {
            convertLongToByteArray(this._hash[i2], bArr, i + (i2 * 8));
        }
        reset();
        return getDigestSize();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this._bufferPos = 0;
        Arrays.fill(this._bitCount, (short) 0);
        Arrays.fill(this._buffer, (byte) 0);
        Arrays.fill(this._hash, 0L);
        Arrays.fill(this.f272_K, 0L);
        Arrays.fill(this.f273_L, 0L);
        Arrays.fill(this._block, 0L);
        Arrays.fill(this._state, 0L);
    }

    private void processFilledBuffer(byte[] bArr, int i) {
        for (int i2 = 0; i2 < this._state.length; i2++) {
            this._block[i2] = bytesToLongFromBuffer(this._buffer, i2 * 8);
        }
        processBlock();
        this._bufferPos = 0;
        Arrays.fill(this._buffer, (byte) 0);
    }

    private long bytesToLongFromBuffer(byte[] bArr, int i) {
        return ((bArr[i + 0] & 255) << 56) | ((bArr[i + 1] & 255) << 48) | ((bArr[i + 2] & 255) << 40) | ((bArr[i + 3] & 255) << 32) | ((bArr[i + 4] & 255) << 24) | ((bArr[i + 5] & 255) << 16) | ((bArr[i + 6] & 255) << 8) | (bArr[i + 7] & 255);
    }

    private void convertLongToByteArray(long j, byte[] bArr, int i) {
        for (int i2 = 0; i2 < 8; i2++) {
            bArr[i + i2] = (byte) ((j >> (56 - (i2 * 8))) & 255);
        }
    }

    /*  JADX ERROR: Method load error
        jadx.core.utils.exceptions.DecodeException: Load method exception: JavaClassParseException: Unknown opcode: 0x5e in method: org.bouncycastle.crypto.digests.WhirlpoolDigest.processBlock():void, file: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/WhirlpoolDigest.class
        	at jadx.core.dex.nodes.MethodNode.load(MethodNode.java:158)
        	at jadx.core.dex.nodes.ClassNode.load(ClassNode.java:409)
        	at jadx.core.ProcessClass.process(ProcessClass.java:67)
        	at jadx.core.ProcessClass.generateCode(ProcessClass.java:115)
        	at jadx.core.dex.nodes.ClassNode.decompile(ClassNode.java:383)
        	at jadx.core.dex.nodes.ClassNode.decompile(ClassNode.java:307)
        Caused by: jadx.plugins.input.java.utils.JavaClassParseException: Unknown opcode: 0x5e
        	at jadx.plugins.input.java.data.code.JavaCodeReader.visitInstructions(JavaCodeReader.java:71)
        	at jadx.core.dex.instructions.InsnDecoder.process(InsnDecoder.java:48)
        	at jadx.core.dex.nodes.MethodNode.load(MethodNode.java:148)
        	... 5 more
        */
    protected void processBlock() {
        /*
        // Can't load method instructions: Load method exception: JavaClassParseException: Unknown opcode: 0x5e in method: org.bouncycastle.crypto.digests.WhirlpoolDigest.processBlock():void, file: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/WhirlpoolDigest.class
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.digests.WhirlpoolDigest.processBlock():void");
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this._buffer[this._bufferPos] = b;
        this._bufferPos++;
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        increment();
    }

    private void increment() {
        int i = 0;
        for (int length = this._bitCount.length - 1; length >= 0; length--) {
            int i2 = (this._bitCount[length] & 255) + EIGHT[length] + i;
            i = i2 >>> 8;
            this._bitCount[length] = (short) (i2 & GF2Field.MASK);
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }

    private void finish() {
        byte[] copyBitLength = copyBitLength();
        byte[] bArr = this._buffer;
        int i = this._bufferPos;
        this._bufferPos = i + 1;
        bArr[i] = (byte) (bArr[i] | 128);
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        if (this._bufferPos > 32) {
            while (this._bufferPos != 0) {
                update((byte) 0);
            }
        }
        while (this._bufferPos <= 32) {
            update((byte) 0);
        }
        System.arraycopy(copyBitLength, 0, this._buffer, 32, copyBitLength.length);
        processFilledBuffer(this._buffer, 0);
    }

    private byte[] copyBitLength() {
        byte[] bArr = new byte[32];
        for (int i = 0; i < bArr.length; i++) {
            bArr[i] = (byte) (this._bitCount[i] & 255);
        }
        return bArr;
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new WhirlpoolDigest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        WhirlpoolDigest whirlpoolDigest = (WhirlpoolDigest) memoable;
        System.arraycopy(whirlpoolDigest._rc, 0, this._rc, 0, this._rc.length);
        System.arraycopy(whirlpoolDigest._buffer, 0, this._buffer, 0, this._buffer.length);
        this._bufferPos = whirlpoolDigest._bufferPos;
        System.arraycopy(whirlpoolDigest._bitCount, 0, this._bitCount, 0, this._bitCount.length);
        System.arraycopy(whirlpoolDigest._hash, 0, this._hash, 0, this._hash.length);
        System.arraycopy(whirlpoolDigest.f272_K, 0, this.f272_K, 0, this.f272_K.length);
        System.arraycopy(whirlpoolDigest.f273_L, 0, this.f273_L, 0, this.f273_L.length);
        System.arraycopy(whirlpoolDigest._block, 0, this._block, 0, this._block.length);
        System.arraycopy(whirlpoolDigest._state, 0, this._state, 0, this._state.length);
    }

    static {
        EIGHT[31] = 8;
    }
}