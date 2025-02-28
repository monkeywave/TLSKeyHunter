package org.bouncycastle.crypto.digests;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.location.LocationRequestCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.math.Primes;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public final class WhirlpoolDigest implements ExtendedDigest, Memoable {
    private static final int BITCOUNT_ARRAY_SIZE = 32;
    private static final int BYTE_LENGTH = 64;
    private static final int DIGEST_LENGTH_BYTES = 64;
    private static final short[] EIGHT;
    private static final int REDUCTION_POLYNOMIAL = 285;
    private static final int ROUNDS = 10;

    /* renamed from: _K */
    private long[] f547_K;

    /* renamed from: _L */
    private long[] f548_L;
    private short[] _bitCount;
    private long[] _block;
    private byte[] _buffer;
    private int _bufferPos;
    private long[] _hash;
    private final long[] _rc;
    private long[] _state;
    private final CryptoServicePurpose purpose;
    private static final int[] SBOX = {24, 35, CipherSuite.TLS_SM4_GCM_SM3, 232, CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256, 1, 79, 54, CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256, 210, 245, 121, 111, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA, 82, 96, 188, CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, 12, 123, 53, 29, BERTags.FLAGS, 215, CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, 46, 75, 254, 87, 21, 119, 55, 229, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 240, 74, 218, 88, 201, 41, 10, CipherSuite.TLS_PSK_WITH_NULL_SHA384, CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256, 93, 16, 244, 203, 62, 5, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 228, 39, 65, CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, 125, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, 216, 251, 238, 124, LocationRequestCompat.QUALITY_BALANCED_POWER_ACCURACY, 221, 23, 71, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 202, 45, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256, 7, CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384, 90, 131, 51, 99, 2, CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, 113, 200, 25, 73, 217, 242, 227, 91, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, 38, 50, CipherSuite.TLS_PSK_WITH_NULL_SHA256, 233, 15, 213, 128, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, 205, 52, 72, 255, 122, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA, 95, 32, 104, 26, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256, 84, CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA, 34, 100, 241, 115, 18, 64, 8, CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256, 236, 219, CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, 61, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, 0, 207, 43, 118, 130, 214, 27, CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, 80, 69, 243, 48, 239, 63, 85, CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, 234, TypedValues.TYPE_TARGET, CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, 47, 192, 222, 28, 253, 77, CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA, 117, 6, CipherSuite.TLS_PSK_WITH_RC4_128_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 230, 14, 31, 98, 212, CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, 249, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256, 37, 89, CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, 114, 57, 76, 94, 120, 56, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA, 209, CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384, 226, 97, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, 33, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, 30, 67, CipherSuite.TLS_SM4_CCM_SM3, 252, 4, 81, CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA, 109, 13, ItemTouchHelper.Callback.DEFAULT_SWIPE_ANIMATION_DURATION, 223, 126, 36, 59, CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, 206, 17, CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA, 78, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384, 235, 60, 129, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA, 247, CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384, 19, 44, Primes.SMALL_FACTOR_LIMIT, 231, 110, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, 3, 86, 68, 127, CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384, 42, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256, 83, 220, 11, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, 108, 49, 116, 246, 70, CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA, 20, 225, 22, 58, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, 9, 112, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, 208, 237, 204, 66, CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA, CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, 40, 92, 248, CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA};

    /* renamed from: C0 */
    private static final long[] f539C0 = new long[256];

    /* renamed from: C1 */
    private static final long[] f540C1 = new long[256];

    /* renamed from: C2 */
    private static final long[] f541C2 = new long[256];

    /* renamed from: C3 */
    private static final long[] f542C3 = new long[256];

    /* renamed from: C4 */
    private static final long[] f543C4 = new long[256];

    /* renamed from: C5 */
    private static final long[] f544C5 = new long[256];

    /* renamed from: C6 */
    private static final long[] f545C6 = new long[256];

    /* renamed from: C7 */
    private static final long[] f546C7 = new long[256];

    static {
        short[] sArr = new short[32];
        EIGHT = sArr;
        sArr[31] = 8;
        for (int i = 0; i < 256; i++) {
            int i2 = SBOX[i];
            int mulX = mulX(i2);
            int mulX2 = mulX(mulX);
            int i3 = mulX2 ^ i2;
            int mulX3 = mulX(mulX2);
            int i4 = mulX3 ^ i2;
            f539C0[i] = packIntoLong(i2, i2, mulX2, i2, mulX3, i3, mulX, i4);
            f540C1[i] = packIntoLong(i4, i2, i2, mulX2, i2, mulX3, i3, mulX);
            f541C2[i] = packIntoLong(mulX, i4, i2, i2, mulX2, i2, mulX3, i3);
            f542C3[i] = packIntoLong(i3, mulX, i4, i2, i2, mulX2, i2, mulX3);
            f543C4[i] = packIntoLong(mulX3, i3, mulX, i4, i2, i2, mulX2, i2);
            f544C5[i] = packIntoLong(i2, mulX3, i3, mulX, i4, i2, i2, mulX2);
            f545C6[i] = packIntoLong(mulX2, i2, mulX3, i3, mulX, i4, i2, i2);
            f546C7[i] = packIntoLong(i2, mulX2, i2, mulX3, i3, mulX, i4, i2);
        }
    }

    public WhirlpoolDigest() {
        this(CryptoServicePurpose.ANY);
    }

    public WhirlpoolDigest(CryptoServicePurpose cryptoServicePurpose) {
        long[] jArr = new long[11];
        this._rc = jArr;
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this.f547_K = new long[8];
        this.f548_L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        jArr[0] = 0;
        for (int i = 1; i <= 10; i++) {
            int i2 = (i - 1) * 8;
            this._rc[i] = (((((((f539C0[i2] & (-72057594037927936L)) ^ (f540C1[i2 + 1] & 71776119061217280L)) ^ (f541C2[i2 + 2] & 280375465082880L)) ^ (f542C3[i2 + 3] & 1095216660480L)) ^ (f543C4[i2 + 4] & 4278190080L)) ^ (f544C5[i2 + 5] & 16711680)) ^ (f545C6[i2 + 6] & 65280)) ^ (f546C7[i2 + 7] & 255);
        }
        this.purpose = cryptoServicePurpose;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize(), cryptoServicePurpose));
    }

    public WhirlpoolDigest(WhirlpoolDigest whirlpoolDigest) {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this.f547_K = new long[8];
        this.f548_L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        CryptoServicePurpose cryptoServicePurpose = whirlpoolDigest.purpose;
        this.purpose = cryptoServicePurpose;
        reset(whirlpoolDigest);
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize(), cryptoServicePurpose));
    }

    private byte[] copyBitLength() {
        byte[] bArr = new byte[32];
        for (int i = 0; i < 32; i++) {
            bArr[i] = (byte) (this._bitCount[i] & 255);
        }
        return bArr;
    }

    private void finish() {
        byte[] copyBitLength = copyBitLength();
        byte[] bArr = this._buffer;
        int i = this._bufferPos;
        bArr[i] = (byte) (bArr[i] | ByteCompanionObject.MIN_VALUE);
        int i2 = i + 1;
        this._bufferPos = i2;
        if (i2 == bArr.length) {
            processFilledBuffer(bArr, 0);
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

    private void increment() {
        int i = 0;
        for (int length = this._bitCount.length - 1; length >= 0; length--) {
            short[] sArr = this._bitCount;
            int i2 = (sArr[length] & 255) + EIGHT[length] + i;
            i = i2 >>> 8;
            sArr[length] = (short) (i2 & 255);
        }
    }

    private static int mulX(int i) {
        return ((-(i >>> 7)) & REDUCTION_POLYNOMIAL) ^ (i << 1);
    }

    private static long packIntoLong(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        return (((((((i2 << 48) ^ (i << 56)) ^ (i3 << 40)) ^ (i4 << 32)) ^ (i5 << 24)) ^ (i6 << 16)) ^ (i7 << 8)) ^ i8;
    }

    private void processFilledBuffer(byte[] bArr, int i) {
        Pack.bigEndianToLong(this._buffer, 0, this._block);
        processBlock();
        this._bufferPos = 0;
        Arrays.fill(this._buffer, (byte) 0);
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new WhirlpoolDigest(this);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.longToBigEndian(this._hash, bArr, i);
        reset();
        return getDigestSize();
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "Whirlpool";
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 64;
    }

    protected void processBlock() {
        long[] jArr;
        for (int i = 0; i < 8; i++) {
            long[] jArr2 = this._state;
            long j = this._block[i];
            long[] jArr3 = this.f547_K;
            long j2 = this._hash[i];
            jArr3[i] = j2;
            jArr2[i] = j ^ j2;
        }
        int i2 = 1;
        while (i2 <= 10) {
            int i3 = 0;
            while (i3 < 8) {
                long[] jArr4 = this.f548_L;
                jArr4[i3] = 0;
                long[] jArr5 = f539C0;
                long[] jArr6 = this.f547_K;
                long j3 = jArr5[((int) (jArr6[i3 & 7] >>> 56)) & 255];
                jArr4[i3] = j3;
                long j4 = f540C1[((int) (jArr6[(i3 - 1) & 7] >>> 48)) & 255] ^ j3;
                jArr4[i3] = j4;
                long j5 = j4 ^ f541C2[((int) (jArr6[(i3 - 2) & 7] >>> 40)) & 255];
                jArr4[i3] = j5;
                long j6 = j5 ^ f542C3[((int) (jArr6[(i3 - 3) & 7] >>> 32)) & 255];
                jArr4[i3] = j6;
                long j7 = j6 ^ f543C4[((int) (jArr6[(i3 - 4) & 7] >>> 24)) & 255];
                jArr4[i3] = j7;
                long j8 = j7 ^ f544C5[((int) (jArr6[(i3 - 5) & 7] >>> 16)) & 255];
                jArr4[i3] = j8;
                long j9 = j8 ^ f545C6[((int) (jArr6[(i3 - 6) & 7] >>> 8)) & 255];
                jArr4[i3] = j9;
                jArr4[i3] = j9 ^ f546C7[((int) jArr6[(i3 - 7) & 7]) & 255];
                i3++;
                i2 = i2;
            }
            int i4 = i2;
            long[] jArr7 = this.f548_L;
            long[] jArr8 = this.f547_K;
            System.arraycopy(jArr7, 0, jArr8, 0, jArr8.length);
            long[] jArr9 = this.f547_K;
            jArr9[0] = jArr9[0] ^ this._rc[i4];
            int i5 = 0;
            while (true) {
                jArr = this.f548_L;
                if (i5 < 8) {
                    long j10 = this.f547_K[i5];
                    jArr[i5] = j10;
                    long[] jArr10 = f539C0;
                    long[] jArr11 = this._state;
                    long j11 = jArr10[((int) (jArr11[i5 & 7] >>> 56)) & 255] ^ j10;
                    jArr[i5] = j11;
                    long j12 = j11 ^ f540C1[((int) (jArr11[(i5 - 1) & 7] >>> 48)) & 255];
                    jArr[i5] = j12;
                    long j13 = j12 ^ f541C2[((int) (jArr11[(i5 - 2) & 7] >>> 40)) & 255];
                    jArr[i5] = j13;
                    long j14 = j13 ^ f542C3[((int) (jArr11[(i5 - 3) & 7] >>> 32)) & 255];
                    jArr[i5] = j14;
                    long j15 = j14 ^ f543C4[((int) (jArr11[(i5 - 4) & 7] >>> 24)) & 255];
                    jArr[i5] = j15;
                    long j16 = j15 ^ f544C5[((int) (jArr11[(i5 - 5) & 7] >>> 16)) & 255];
                    jArr[i5] = j16;
                    long j17 = j16 ^ f545C6[((int) (jArr11[(i5 - 6) & 7] >>> 8)) & 255];
                    jArr[i5] = j17;
                    jArr[i5] = j17 ^ f546C7[((int) jArr11[(i5 - 7) & 7]) & 255];
                    i5++;
                }
            }
            long[] jArr12 = this._state;
            System.arraycopy(jArr, 0, jArr12, 0, jArr12.length);
            i2 = i4 + 1;
        }
        for (int i6 = 0; i6 < 8; i6++) {
            long[] jArr13 = this._hash;
            jArr13[i6] = jArr13[i6] ^ (this._state[i6] ^ this._block[i6]);
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this._bufferPos = 0;
        Arrays.fill(this._bitCount, (short) 0);
        Arrays.fill(this._buffer, (byte) 0);
        Arrays.fill(this._hash, 0L);
        Arrays.fill(this.f547_K, 0L);
        Arrays.fill(this.f548_L, 0L);
        Arrays.fill(this._block, 0L);
        Arrays.fill(this._state, 0L);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        WhirlpoolDigest whirlpoolDigest = (WhirlpoolDigest) memoable;
        long[] jArr = whirlpoolDigest._rc;
        long[] jArr2 = this._rc;
        System.arraycopy(jArr, 0, jArr2, 0, jArr2.length);
        byte[] bArr = whirlpoolDigest._buffer;
        byte[] bArr2 = this._buffer;
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
        this._bufferPos = whirlpoolDigest._bufferPos;
        short[] sArr = whirlpoolDigest._bitCount;
        short[] sArr2 = this._bitCount;
        System.arraycopy(sArr, 0, sArr2, 0, sArr2.length);
        long[] jArr3 = whirlpoolDigest._hash;
        long[] jArr4 = this._hash;
        System.arraycopy(jArr3, 0, jArr4, 0, jArr4.length);
        long[] jArr5 = whirlpoolDigest.f547_K;
        long[] jArr6 = this.f547_K;
        System.arraycopy(jArr5, 0, jArr6, 0, jArr6.length);
        long[] jArr7 = whirlpoolDigest.f548_L;
        long[] jArr8 = this.f548_L;
        System.arraycopy(jArr7, 0, jArr8, 0, jArr8.length);
        long[] jArr9 = whirlpoolDigest._block;
        long[] jArr10 = this._block;
        System.arraycopy(jArr9, 0, jArr10, 0, jArr10.length);
        long[] jArr11 = whirlpoolDigest._state;
        long[] jArr12 = this._state;
        System.arraycopy(jArr11, 0, jArr12, 0, jArr12.length);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this._buffer;
        int i = this._bufferPos;
        bArr[i] = b;
        int i2 = i + 1;
        this._bufferPos = i2;
        if (i2 == bArr.length) {
            processFilledBuffer(bArr, 0);
        }
        increment();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }
}