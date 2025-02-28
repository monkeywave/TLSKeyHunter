package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/Blake2sDigest.class */
public class Blake2sDigest implements ExtendedDigest {
    private static final int[] blake2s_IV = {1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225};
    private static final byte[][] blake2s_sigma = {new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, new byte[]{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, new byte[]{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, new byte[]{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, new byte[]{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, new byte[]{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, new byte[]{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, new byte[]{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, new byte[]{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, new byte[]{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
    private static final int ROUNDS = 10;
    private static final int BLOCK_LENGTH_BYTES = 64;
    private int digestLength;
    private int keyLength;
    private byte[] salt;
    private byte[] personalization;
    private byte[] key;
    private int fanout;
    private int depth;
    private int leafLength;
    private long nodeOffset;
    private int nodeDepth;
    private int innerHashLength;
    private byte[] buffer;
    private int bufferPos;
    private int[] internalState;
    private int[] chainValue;

    /* renamed from: t0 */
    private int f134t0;

    /* renamed from: t1 */
    private int f135t1;

    /* renamed from: f0 */
    private int f136f0;

    public Blake2sDigest() {
        this(256);
    }

    public Blake2sDigest(Blake2sDigest blake2sDigest) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        this.bufferPos = blake2sDigest.bufferPos;
        this.buffer = Arrays.clone(blake2sDigest.buffer);
        this.keyLength = blake2sDigest.keyLength;
        this.key = Arrays.clone(blake2sDigest.key);
        this.digestLength = blake2sDigest.digestLength;
        this.internalState = Arrays.clone(this.internalState);
        this.chainValue = Arrays.clone(blake2sDigest.chainValue);
        this.f134t0 = blake2sDigest.f134t0;
        this.f135t1 = blake2sDigest.f135t1;
        this.f136f0 = blake2sDigest.f136f0;
        this.salt = Arrays.clone(blake2sDigest.salt);
        this.personalization = Arrays.clone(blake2sDigest.personalization);
        this.fanout = blake2sDigest.fanout;
        this.depth = blake2sDigest.depth;
        this.leafLength = blake2sDigest.leafLength;
        this.nodeOffset = blake2sDigest.nodeOffset;
        this.nodeDepth = blake2sDigest.nodeDepth;
        this.innerHashLength = blake2sDigest.innerHashLength;
    }

    public Blake2sDigest(int i) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        if (i < 8 || i > 256 || i % 8 != 0) {
            throw new IllegalArgumentException("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256");
        }
        this.digestLength = i / 8;
        init(null, null, null);
    }

    public Blake2sDigest(byte[] bArr) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        init(null, null, bArr);
    }

    public Blake2sDigest(byte[] bArr, int i, byte[] bArr2, byte[] bArr3) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        if (i < 1 || i > 32) {
            throw new IllegalArgumentException("Invalid digest length (required: 1 - 32)");
        }
        this.digestLength = i;
        init(bArr2, bArr3, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Blake2sDigest(int i, byte[] bArr, byte[] bArr2, byte[] bArr3, long j) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        this.digestLength = i;
        this.nodeOffset = j;
        init(bArr2, bArr3, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Blake2sDigest(int i, int i2, long j) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0L;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.f136f0 = 0;
        this.digestLength = i;
        this.nodeOffset = j;
        this.fanout = 0;
        this.depth = 0;
        this.leafLength = i2;
        this.innerHashLength = i2;
        this.nodeDepth = 0;
        init(null, null, null);
    }

    private void init(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this.buffer = new byte[64];
        if (bArr3 != null && bArr3.length > 0) {
            if (bArr3.length > 32) {
                throw new IllegalArgumentException("Keys > 32 bytes are not supported");
            }
            this.key = new byte[bArr3.length];
            System.arraycopy(bArr3, 0, this.key, 0, bArr3.length);
            this.keyLength = bArr3.length;
            System.arraycopy(bArr3, 0, this.buffer, 0, bArr3.length);
            this.bufferPos = 64;
        }
        if (this.chainValue == null) {
            this.chainValue = new int[8];
            this.chainValue[0] = blake2s_IV[0] ^ ((this.digestLength | (this.keyLength << 8)) | ((this.fanout << 16) | (this.depth << 24)));
            this.chainValue[1] = blake2s_IV[1] ^ this.leafLength;
            int i = (int) (this.nodeOffset >> 32);
            this.chainValue[2] = blake2s_IV[2] ^ ((int) this.nodeOffset);
            this.chainValue[3] = blake2s_IV[3] ^ ((i | (this.nodeDepth << 16)) | (this.innerHashLength << 24));
            this.chainValue[4] = blake2s_IV[4];
            this.chainValue[5] = blake2s_IV[5];
            if (bArr != null) {
                if (bArr.length != 8) {
                    throw new IllegalArgumentException("Salt length must be exactly 8 bytes");
                }
                this.salt = new byte[8];
                System.arraycopy(bArr, 0, this.salt, 0, bArr.length);
                int[] iArr = this.chainValue;
                iArr[4] = iArr[4] ^ Pack.littleEndianToInt(bArr, 0);
                int[] iArr2 = this.chainValue;
                iArr2[5] = iArr2[5] ^ Pack.littleEndianToInt(bArr, 4);
            }
            this.chainValue[6] = blake2s_IV[6];
            this.chainValue[7] = blake2s_IV[7];
            if (bArr2 != null) {
                if (bArr2.length != 8) {
                    throw new IllegalArgumentException("Personalization length must be exactly 8 bytes");
                }
                this.personalization = new byte[8];
                System.arraycopy(bArr2, 0, this.personalization, 0, bArr2.length);
                int[] iArr3 = this.chainValue;
                iArr3[6] = iArr3[6] ^ Pack.littleEndianToInt(bArr2, 0);
                int[] iArr4 = this.chainValue;
                iArr4[7] = iArr4[7] ^ Pack.littleEndianToInt(bArr2, 4);
            }
        }
    }

    private void initializeInternalState() {
        System.arraycopy(this.chainValue, 0, this.internalState, 0, this.chainValue.length);
        System.arraycopy(blake2s_IV, 0, this.internalState, this.chainValue.length, 4);
        this.internalState[12] = this.f134t0 ^ blake2s_IV[4];
        this.internalState[13] = this.f135t1 ^ blake2s_IV[5];
        this.internalState[14] = this.f136f0 ^ blake2s_IV[6];
        this.internalState[15] = blake2s_IV[7];
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        if (64 - this.bufferPos != 0) {
            this.buffer[this.bufferPos] = b;
            this.bufferPos++;
            return;
        }
        this.f134t0 += 64;
        if (this.f134t0 == 0) {
            this.f135t1++;
        }
        compress(this.buffer, 0);
        Arrays.fill(this.buffer, (byte) 0);
        this.buffer[0] = b;
        this.bufferPos = 1;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        if (bArr == null || i2 == 0) {
            return;
        }
        int i3 = 0;
        if (this.bufferPos != 0) {
            i3 = 64 - this.bufferPos;
            if (i3 >= i2) {
                System.arraycopy(bArr, i, this.buffer, this.bufferPos, i2);
                this.bufferPos += i2;
                return;
            }
            System.arraycopy(bArr, i, this.buffer, this.bufferPos, i3);
            this.f134t0 += 64;
            if (this.f134t0 == 0) {
                this.f135t1++;
            }
            compress(this.buffer, 0);
            this.bufferPos = 0;
            Arrays.fill(this.buffer, (byte) 0);
        }
        int i4 = (i + i2) - 64;
        int i5 = i + i3;
        while (i5 < i4) {
            this.f134t0 += 64;
            if (this.f134t0 == 0) {
                this.f135t1++;
            }
            compress(bArr, i5);
            i5 += 64;
        }
        System.arraycopy(bArr, i5, this.buffer, 0, (i + i2) - i5);
        this.bufferPos += (i + i2) - i5;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        this.f136f0 = -1;
        this.f134t0 += this.bufferPos;
        if (this.f134t0 < 0 && this.bufferPos > (-this.f134t0)) {
            this.f135t1++;
        }
        compress(this.buffer, 0);
        Arrays.fill(this.buffer, (byte) 0);
        Arrays.fill(this.internalState, 0);
        for (int i2 = 0; i2 < this.chainValue.length && i2 * 4 < this.digestLength; i2++) {
            byte[] intToLittleEndian = Pack.intToLittleEndian(this.chainValue[i2]);
            if (i2 * 4 < this.digestLength - 4) {
                System.arraycopy(intToLittleEndian, 0, bArr, i + (i2 * 4), 4);
            } else {
                System.arraycopy(intToLittleEndian, 0, bArr, i + (i2 * 4), this.digestLength - (i2 * 4));
            }
        }
        Arrays.fill(this.chainValue, 0);
        reset();
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.bufferPos = 0;
        this.f136f0 = 0;
        this.f134t0 = 0;
        this.f135t1 = 0;
        this.chainValue = null;
        Arrays.fill(this.buffer, (byte) 0);
        if (this.key != null) {
            System.arraycopy(this.key, 0, this.buffer, 0, this.key.length);
            this.bufferPos = 64;
        }
        init(this.salt, this.personalization, this.key);
    }

    private void compress(byte[] bArr, int i) {
        initializeInternalState();
        int[] iArr = new int[16];
        for (int i2 = 0; i2 < 16; i2++) {
            iArr[i2] = Pack.littleEndianToInt(bArr, i + (i2 * 4));
        }
        for (int i3 = 0; i3 < 10; i3++) {
            m120G(iArr[blake2s_sigma[i3][0]], iArr[blake2s_sigma[i3][1]], 0, 4, 8, 12);
            m120G(iArr[blake2s_sigma[i3][2]], iArr[blake2s_sigma[i3][3]], 1, 5, 9, 13);
            m120G(iArr[blake2s_sigma[i3][4]], iArr[blake2s_sigma[i3][5]], 2, 6, 10, 14);
            m120G(iArr[blake2s_sigma[i3][6]], iArr[blake2s_sigma[i3][7]], 3, 7, 11, 15);
            m120G(iArr[blake2s_sigma[i3][8]], iArr[blake2s_sigma[i3][9]], 0, 5, 10, 15);
            m120G(iArr[blake2s_sigma[i3][10]], iArr[blake2s_sigma[i3][11]], 1, 6, 11, 12);
            m120G(iArr[blake2s_sigma[i3][12]], iArr[blake2s_sigma[i3][13]], 2, 7, 8, 13);
            m120G(iArr[blake2s_sigma[i3][14]], iArr[blake2s_sigma[i3][15]], 3, 4, 9, 14);
        }
        for (int i4 = 0; i4 < this.chainValue.length; i4++) {
            this.chainValue[i4] = (this.chainValue[i4] ^ this.internalState[i4]) ^ this.internalState[i4 + 8];
        }
    }

    /* renamed from: G */
    private void m120G(int i, int i2, int i3, int i4, int i5, int i6) {
        this.internalState[i3] = this.internalState[i3] + this.internalState[i4] + i;
        this.internalState[i6] = rotr32(this.internalState[i6] ^ this.internalState[i3], 16);
        this.internalState[i5] = this.internalState[i5] + this.internalState[i6];
        this.internalState[i4] = rotr32(this.internalState[i4] ^ this.internalState[i5], 12);
        this.internalState[i3] = this.internalState[i3] + this.internalState[i4] + i2;
        this.internalState[i6] = rotr32(this.internalState[i6] ^ this.internalState[i3], 8);
        this.internalState[i5] = this.internalState[i5] + this.internalState[i6];
        this.internalState[i4] = rotr32(this.internalState[i4] ^ this.internalState[i5], 7);
    }

    private int rotr32(int i, int i2) {
        return (i >>> i2) | (i << (32 - i2));
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE2s";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    public void clearKey() {
        if (this.key != null) {
            Arrays.fill(this.key, (byte) 0);
            Arrays.fill(this.buffer, (byte) 0);
        }
    }

    public void clearSalt() {
        if (this.salt != null) {
            Arrays.fill(this.salt, (byte) 0);
        }
    }
}