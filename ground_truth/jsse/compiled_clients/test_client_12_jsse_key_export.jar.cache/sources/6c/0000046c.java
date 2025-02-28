package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/HC256Engine.class */
public class HC256Engine implements StreamCipher {
    private byte[] key;

    /* renamed from: iv */
    private byte[] f344iv;
    private boolean initialised;

    /* renamed from: p */
    private int[] f342p = new int[1024];

    /* renamed from: q */
    private int[] f343q = new int[1024];
    private int cnt = 0;
    private byte[] buf = new byte[4];
    private int idx = 0;

    private int step() {
        int i;
        int i2 = this.cnt & 1023;
        if (this.cnt < 1024) {
            int i3 = this.f342p[(i2 - 3) & 1023];
            int i4 = this.f342p[(i2 - 1023) & 1023];
            int[] iArr = this.f342p;
            iArr[i2] = iArr[i2] + this.f342p[(i2 - 10) & 1023] + (rotateRight(i3, 10) ^ rotateRight(i4, 23)) + this.f343q[(i3 ^ i4) & 1023];
            int i5 = this.f342p[(i2 - 12) & 1023];
            i = (((this.f343q[i5 & GF2Field.MASK] + this.f343q[((i5 >> 8) & GF2Field.MASK) + 256]) + this.f343q[((i5 >> 16) & GF2Field.MASK) + 512]) + this.f343q[((i5 >> 24) & GF2Field.MASK) + 768]) ^ this.f342p[i2];
        } else {
            int i6 = this.f343q[(i2 - 3) & 1023];
            int i7 = this.f343q[(i2 - 1023) & 1023];
            int[] iArr2 = this.f343q;
            iArr2[i2] = iArr2[i2] + this.f343q[(i2 - 10) & 1023] + (rotateRight(i6, 10) ^ rotateRight(i7, 23)) + this.f342p[(i6 ^ i7) & 1023];
            int i8 = this.f343q[(i2 - 12) & 1023];
            i = (((this.f342p[i8 & GF2Field.MASK] + this.f342p[((i8 >> 8) & GF2Field.MASK) + 256]) + this.f342p[((i8 >> 16) & GF2Field.MASK) + 512]) + this.f342p[((i8 >> 24) & GF2Field.MASK) + 768]) ^ this.f343q[i2];
        }
        this.cnt = (this.cnt + 1) & 2047;
        return i;
    }

    private void init() {
        if (this.key.length != 32 && this.key.length != 16) {
            throw new IllegalArgumentException("The key must be 128/256 bits long");
        }
        if (this.f344iv.length < 16) {
            throw new IllegalArgumentException("The IV must be at least 128 bits long");
        }
        if (this.key.length != 32) {
            byte[] bArr = new byte[32];
            System.arraycopy(this.key, 0, bArr, 0, this.key.length);
            System.arraycopy(this.key, 0, bArr, 16, this.key.length);
            this.key = bArr;
        }
        if (this.f344iv.length < 32) {
            byte[] bArr2 = new byte[32];
            System.arraycopy(this.f344iv, 0, bArr2, 0, this.f344iv.length);
            System.arraycopy(this.f344iv, 0, bArr2, this.f344iv.length, bArr2.length - this.f344iv.length);
            this.f344iv = bArr2;
        }
        this.idx = 0;
        this.cnt = 0;
        int[] iArr = new int[2560];
        for (int i = 0; i < 32; i++) {
            int i2 = i >> 2;
            iArr[i2] = iArr[i2] | ((this.key[i] & 255) << (8 * (i & 3)));
        }
        for (int i3 = 0; i3 < 32; i3++) {
            int i4 = (i3 >> 2) + 8;
            iArr[i4] = iArr[i4] | ((this.f344iv[i3] & 255) << (8 * (i3 & 3)));
        }
        for (int i5 = 16; i5 < 2560; i5++) {
            int i6 = iArr[i5 - 2];
            int i7 = iArr[i5 - 15];
            iArr[i5] = ((rotateRight(i6, 17) ^ rotateRight(i6, 19)) ^ (i6 >>> 10)) + iArr[i5 - 7] + ((rotateRight(i7, 7) ^ rotateRight(i7, 18)) ^ (i7 >>> 3)) + iArr[i5 - 16] + i5;
        }
        System.arraycopy(iArr, 512, this.f342p, 0, 1024);
        System.arraycopy(iArr, 1536, this.f343q, 0, 1024);
        for (int i8 = 0; i8 < 4096; i8++) {
            step();
        }
        this.cnt = 0;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "HC-256";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        CipherParameters cipherParameters2 = cipherParameters;
        if (cipherParameters instanceof ParametersWithIV) {
            this.f344iv = ((ParametersWithIV) cipherParameters).getIV();
            cipherParameters2 = ((ParametersWithIV) cipherParameters).getParameters();
        } else {
            this.f344iv = new byte[0];
        }
        if (!(cipherParameters2 instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to HC256 init - " + cipherParameters.getClass().getName());
        }
        this.key = ((KeyParameter) cipherParameters2).getKey();
        init();
        this.initialised = true;
    }

    private byte getByte() {
        if (this.idx == 0) {
            int step = step();
            this.buf[0] = (byte) (step & GF2Field.MASK);
            int i = step >> 8;
            this.buf[1] = (byte) (i & GF2Field.MASK);
            int i2 = i >> 8;
            this.buf[2] = (byte) (i2 & GF2Field.MASK);
            this.buf[3] = (byte) ((i2 >> 8) & GF2Field.MASK);
        }
        byte b = this.buf[this.idx];
        this.idx = (this.idx + 1) & 3;
        return b;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (this.initialised) {
            if (i + i2 > bArr.length) {
                throw new DataLengthException("input buffer too short");
            }
            if (i3 + i2 > bArr2.length) {
                throw new OutputLengthException("output buffer too short");
            }
            for (int i4 = 0; i4 < i2; i4++) {
                bArr2[i3 + i4] = (byte) (bArr[i + i4] ^ getByte());
            }
            return i2;
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        init();
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        return (byte) (b ^ getByte());
    }

    private static int rotateRight(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }
}