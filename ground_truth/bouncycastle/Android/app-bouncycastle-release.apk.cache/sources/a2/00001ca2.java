package org.bouncycastle.crypto.digests;

import java.lang.reflect.Array;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class Blake2spDigest implements ExtendedDigest {
    private int depth;
    private int digestLength;
    private int fanout;
    private long innerHashLength;
    private Blake2sDigest root;
    private int bufferPos = 0;
    private int keyLength = 0;
    private int nodeOffset = 0;

    /* renamed from: S */
    private Blake2sDigest[] f396S = new Blake2sDigest[8];
    private byte[] salt = null;
    private byte[] key = null;
    private final int BLAKE2S_BLOCKBYTES = 64;
    private final int BLAKE2S_KEYBYTES = 32;
    private final int BLAKE2S_OUTBYTES = 32;
    private final int PARALLELISM_DEGREE = 8;
    private final byte[] singleByte = new byte[1];
    private byte[] param = new byte[32];
    private byte[] buffer = new byte[512];

    public Blake2spDigest(byte[] bArr) {
        init(bArr);
    }

    private void init(byte[] bArr) {
        int i;
        if (bArr != null && bArr.length > 0) {
            int length = bArr.length;
            this.keyLength = length;
            if (length > 32) {
                throw new IllegalArgumentException("Keys > 32 bytes are not supported");
            }
            this.key = Arrays.clone(bArr);
        }
        this.bufferPos = 0;
        this.digestLength = 32;
        this.fanout = 8;
        this.depth = 2;
        this.innerHashLength = 32L;
        byte[] bArr2 = this.param;
        bArr2[0] = (byte) 32;
        bArr2[1] = (byte) this.keyLength;
        bArr2[2] = (byte) 8;
        bArr2[3] = (byte) 2;
        Pack.intToLittleEndian(0, bArr2, 8);
        byte[] bArr3 = this.param;
        bArr3[14] = 1;
        bArr3[15] = (byte) this.innerHashLength;
        this.root = new Blake2sDigest((byte[]) null, this.param);
        Pack.intToLittleEndian(this.nodeOffset, this.param, 8);
        this.param[14] = 0;
        for (int i2 = 0; i2 < 8; i2++) {
            Pack.intToLittleEndian(i2, this.param, 8);
            this.f396S[i2] = new Blake2sDigest((byte[]) null, this.param);
        }
        this.root.setAsLastNode();
        this.f396S[7].setAsLastNode();
        if (bArr == null || (i = this.keyLength) <= 0) {
            return;
        }
        byte[] bArr4 = new byte[64];
        System.arraycopy(bArr, 0, bArr4, 0, i);
        for (int i3 = 0; i3 < 8; i3++) {
            this.f396S[i3].update(bArr4, 0, 64);
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        byte[][] bArr2 = (byte[][]) Array.newInstance(Byte.TYPE, 8, 32);
        for (int i2 = 0; i2 < 8; i2++) {
            int i3 = this.bufferPos;
            int i4 = i2 * 64;
            if (i3 > i4) {
                int i5 = i3 - i4;
                if (i5 > 64) {
                    i5 = 64;
                }
                this.f396S[i2].update(this.buffer, i4, i5);
            }
            this.f396S[i2].doFinal(bArr2[i2], 0);
        }
        for (int i6 = 0; i6 < 8; i6++) {
            this.root.update(bArr2[i6], 0, 32);
        }
        int doFinal = this.root.doFinal(bArr, i);
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE2sp";
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.bufferPos = 0;
        this.digestLength = 32;
        this.root.reset();
        for (int i = 0; i < 8; i++) {
            this.f396S[i].reset();
        }
        this.root.setAsLastNode();
        this.f396S[7].setAsLastNode();
        byte[] bArr = this.key;
        if (bArr != null) {
            byte[] bArr2 = new byte[64];
            System.arraycopy(bArr, 0, bArr2, 0, this.keyLength);
            for (int i2 = 0; i2 < 8; i2++) {
                this.f396S[i2].update(bArr2, 0, 64);
            }
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.singleByte;
        bArr[0] = b;
        update(bArr, 0, 1);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        int i3 = this.bufferPos;
        int i4 = 512 - i3;
        if (i3 != 0 && i2 >= i4) {
            System.arraycopy(bArr, i, this.buffer, i3, i4);
            for (int i5 = 0; i5 < 8; i5++) {
                this.f396S[i5].update(this.buffer, i5 * 64, 64);
            }
            i += i4;
            i2 -= i4;
            i3 = 0;
        }
        for (int i6 = 0; i6 < 8; i6++) {
            int i7 = (i6 * 64) + i;
            for (int i8 = i2; i8 >= 512; i8 -= 512) {
                this.f396S[i6].update(bArr, i7, 64);
                i7 += 512;
            }
        }
        int i9 = i2 % 512;
        int i10 = i + (i2 - i9);
        if (i9 > 0) {
            System.arraycopy(bArr, i10, this.buffer, i3, i9);
        }
        this.bufferPos = i3 + i9;
    }
}