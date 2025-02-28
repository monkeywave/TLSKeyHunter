package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/GeneralDigest.class */
public abstract class GeneralDigest implements ExtendedDigest, Memoable {
    private static final int BYTE_LENGTH = 64;
    private final byte[] xBuf;
    private int xBufOff;
    private long byteCount;

    /* JADX INFO: Access modifiers changed from: protected */
    public GeneralDigest() {
        this.xBuf = new byte[4];
        this.xBufOff = 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public GeneralDigest(GeneralDigest generalDigest) {
        this.xBuf = new byte[4];
        copyIn(generalDigest);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public GeneralDigest(byte[] bArr) {
        this.xBuf = new byte[4];
        System.arraycopy(bArr, 0, this.xBuf, 0, this.xBuf.length);
        this.xBufOff = Pack.bigEndianToInt(bArr, 4);
        this.byteCount = Pack.bigEndianToLong(bArr, 8);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void copyIn(GeneralDigest generalDigest) {
        System.arraycopy(generalDigest.xBuf, 0, this.xBuf, 0, generalDigest.xBuf.length);
        this.xBufOff = generalDigest.xBufOff;
        this.byteCount = generalDigest.byteCount;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = b;
        if (this.xBufOff == this.xBuf.length) {
            processWord(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        int max = Math.max(0, i2);
        int i3 = 0;
        if (this.xBufOff != 0) {
            while (true) {
                if (i3 >= max) {
                    break;
                }
                byte[] bArr2 = this.xBuf;
                int i4 = this.xBufOff;
                this.xBufOff = i4 + 1;
                int i5 = i3;
                i3++;
                bArr2[i4] = bArr[i + i5];
                if (this.xBufOff == 4) {
                    processWord(this.xBuf, 0);
                    this.xBufOff = 0;
                    break;
                }
            }
        }
        int i6 = ((max - i3) & (-4)) + i3;
        while (i3 < i6) {
            processWord(bArr, i + i3);
            i3 += 4;
        }
        while (i3 < max) {
            byte[] bArr3 = this.xBuf;
            int i7 = this.xBufOff;
            this.xBufOff = i7 + 1;
            int i8 = i3;
            i3++;
            bArr3[i7] = bArr[i + i8];
        }
        this.byteCount += max;
    }

    public void finish() {
        long j = this.byteCount << 3;
        update(Byte.MIN_VALUE);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processLength(j);
        processBlock();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.byteCount = 0L;
        this.xBufOff = 0;
        for (int i = 0; i < this.xBuf.length; i++) {
            this.xBuf[i] = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void populateState(byte[] bArr) {
        System.arraycopy(this.xBuf, 0, bArr, 0, this.xBufOff);
        Pack.intToBigEndian(this.xBufOff, bArr, 4);
        Pack.longToBigEndian(this.byteCount, bArr, 8);
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    protected abstract void processWord(byte[] bArr, int i);

    protected abstract void processLength(long j);

    protected abstract void processBlock();
}