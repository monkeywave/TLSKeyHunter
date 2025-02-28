package org.bouncycastle.crypto.digests;

import java.lang.reflect.Array;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class Blake2bpDigest implements ExtendedDigest {
    private int depth;
    private int digestLength;
    private int fanout;
    private long innerHashLength;
    private Blake2bDigest root;
    private int bufferPos = 0;
    private int keyLength = 0;
    private int nodeOffset = 0;

    /* renamed from: S */
    private Blake2bDigest[] f391S = new Blake2bDigest[4];
    private byte[] salt = null;
    private byte[] key = null;
    private final int BLAKE2B_BLOCKBYTES = 128;
    private final int BLAKE2B_KEYBYTES = 64;
    private final int BLAKE2B_OUTBYTES = 64;
    private final int PARALLELISM_DEGREE = 4;
    private final byte[] singleByte = new byte[1];
    private byte[] param = new byte[64];
    private byte[] buffer = new byte[512];

    public Blake2bpDigest(byte[] bArr) {
        init(bArr);
    }

    private void init(byte[] bArr) {
        int i;
        if (bArr != null && bArr.length > 0) {
            int length = bArr.length;
            this.keyLength = length;
            if (length > 64) {
                throw new IllegalArgumentException("Keys > 64 bytes are not supported");
            }
            this.key = Arrays.clone(bArr);
        }
        this.bufferPos = 0;
        this.digestLength = 64;
        this.fanout = 4;
        this.depth = 2;
        this.innerHashLength = 64L;
        byte[] bArr2 = this.param;
        bArr2[0] = (byte) 64;
        bArr2[1] = (byte) this.keyLength;
        bArr2[2] = (byte) 4;
        bArr2[3] = (byte) 2;
        bArr2[16] = 1;
        bArr2[17] = (byte) 64;
        this.root = new Blake2bDigest((byte[]) null, this.param);
        Pack.intToLittleEndian(this.nodeOffset, this.param, 8);
        this.param[16] = 0;
        for (int i2 = 0; i2 < 4; i2++) {
            Pack.intToLittleEndian(i2, this.param, 8);
            this.f391S[i2] = new Blake2bDigest((byte[]) null, this.param);
        }
        this.root.setAsLastNode();
        this.f391S[3].setAsLastNode();
        if (bArr == null || (i = this.keyLength) <= 0) {
            return;
        }
        byte[] bArr3 = new byte[128];
        System.arraycopy(bArr, 0, bArr3, 0, i);
        for (int i3 = 0; i3 < 4; i3++) {
            this.f391S[i3].update(bArr3, 0, 128);
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        byte[][] bArr2 = (byte[][]) Array.newInstance(Byte.TYPE, 4, 64);
        for (int i2 = 0; i2 < 4; i2++) {
            int i3 = this.bufferPos;
            int i4 = i2 * 128;
            if (i3 > i4) {
                int i5 = i3 - i4;
                if (i5 > 128) {
                    i5 = 128;
                }
                this.f391S[i2].update(this.buffer, i4, i5);
            }
            this.f391S[i2].doFinal(bArr2[i2], 0);
        }
        for (int i6 = 0; i6 < 4; i6++) {
            this.root.update(bArr2[i6], 0, 64);
        }
        int doFinal = this.root.doFinal(bArr, i);
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE2bp";
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 0;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.bufferPos = 0;
        this.digestLength = 64;
        this.root.reset();
        for (int i = 0; i < 4; i++) {
            this.f391S[i].reset();
        }
        this.root.setAsLastNode();
        this.f391S[3].setAsLastNode();
        byte[] bArr = this.key;
        if (bArr != null) {
            byte[] bArr2 = new byte[128];
            System.arraycopy(bArr, 0, bArr2, 0, this.keyLength);
            for (int i2 = 0; i2 < 4; i2++) {
                this.f391S[i2].update(bArr2, 0, 128);
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
        int i4 = 1024 - i3;
        if (i3 != 0 && i2 >= i4) {
            System.arraycopy(bArr, i, this.buffer, i3, i4);
            for (int i5 = 0; i5 < 4; i5++) {
                this.f391S[i5].update(this.buffer, i5 * 128, 128);
            }
            i += i4;
            i2 -= i4;
            i3 = 0;
        }
        for (int i6 = 0; i6 < 4; i6++) {
            int i7 = (i6 * 128) + i;
            for (int i8 = i2; i8 >= 512; i8 -= 512) {
                this.f391S[i6].update(bArr, i7, 128);
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