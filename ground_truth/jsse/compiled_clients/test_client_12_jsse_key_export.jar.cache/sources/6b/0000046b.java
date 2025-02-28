package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/HC128Engine.class */
public class HC128Engine implements StreamCipher {
    private byte[] key;

    /* renamed from: iv */
    private byte[] f341iv;
    private boolean initialised;

    /* renamed from: p */
    private int[] f339p = new int[512];

    /* renamed from: q */
    private int[] f340q = new int[512];
    private int cnt = 0;
    private byte[] buf = new byte[4];
    private int idx = 0;

    /* renamed from: f1 */
    private static int m52f1(int i) {
        return (rotateRight(i, 7) ^ rotateRight(i, 18)) ^ (i >>> 3);
    }

    /* renamed from: f2 */
    private static int m51f2(int i) {
        return (rotateRight(i, 17) ^ rotateRight(i, 19)) ^ (i >>> 10);
    }

    /* renamed from: g1 */
    private int m50g1(int i, int i2, int i3) {
        return (rotateRight(i, 10) ^ rotateRight(i3, 23)) + rotateRight(i2, 8);
    }

    /* renamed from: g2 */
    private int m49g2(int i, int i2, int i3) {
        return (rotateLeft(i, 10) ^ rotateLeft(i3, 23)) + rotateLeft(i2, 8);
    }

    private static int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    private static int rotateRight(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    /* renamed from: h1 */
    private int m48h1(int i) {
        return this.f340q[i & GF2Field.MASK] + this.f340q[((i >> 16) & GF2Field.MASK) + 256];
    }

    /* renamed from: h2 */
    private int m47h2(int i) {
        return this.f339p[i & GF2Field.MASK] + this.f339p[((i >> 16) & GF2Field.MASK) + 256];
    }

    private static int mod1024(int i) {
        return i & 1023;
    }

    private static int mod512(int i) {
        return i & 511;
    }

    private static int dim(int i, int i2) {
        return mod512(i - i2);
    }

    private int step() {
        int m47h2;
        int mod512 = mod512(this.cnt);
        if (this.cnt < 512) {
            int[] iArr = this.f339p;
            iArr[mod512] = iArr[mod512] + m50g1(this.f339p[dim(mod512, 3)], this.f339p[dim(mod512, 10)], this.f339p[dim(mod512, 511)]);
            m47h2 = m48h1(this.f339p[dim(mod512, 12)]) ^ this.f339p[mod512];
        } else {
            int[] iArr2 = this.f340q;
            iArr2[mod512] = iArr2[mod512] + m49g2(this.f340q[dim(mod512, 3)], this.f340q[dim(mod512, 10)], this.f340q[dim(mod512, 511)]);
            m47h2 = m47h2(this.f340q[dim(mod512, 12)]) ^ this.f340q[mod512];
        }
        this.cnt = mod1024(this.cnt + 1);
        return m47h2;
    }

    private void init() {
        if (this.key.length != 16) {
            throw new IllegalArgumentException("The key must be 128 bits long");
        }
        this.idx = 0;
        this.cnt = 0;
        int[] iArr = new int[1280];
        for (int i = 0; i < 16; i++) {
            int i2 = i >> 2;
            iArr[i2] = iArr[i2] | ((this.key[i] & 255) << (8 * (i & 3)));
        }
        System.arraycopy(iArr, 0, iArr, 4, 4);
        for (int i3 = 0; i3 < this.f341iv.length && i3 < 16; i3++) {
            int i4 = (i3 >> 2) + 8;
            iArr[i4] = iArr[i4] | ((this.f341iv[i3] & 255) << (8 * (i3 & 3)));
        }
        System.arraycopy(iArr, 8, iArr, 12, 4);
        for (int i5 = 16; i5 < 1280; i5++) {
            iArr[i5] = m51f2(iArr[i5 - 2]) + iArr[i5 - 7] + m52f1(iArr[i5 - 15]) + iArr[i5 - 16] + i5;
        }
        System.arraycopy(iArr, 256, this.f339p, 0, 512);
        System.arraycopy(iArr, 768, this.f340q, 0, 512);
        for (int i6 = 0; i6 < 512; i6++) {
            this.f339p[i6] = step();
        }
        for (int i7 = 0; i7 < 512; i7++) {
            this.f340q[i7] = step();
        }
        this.cnt = 0;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "HC-128";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        CipherParameters cipherParameters2 = cipherParameters;
        if (cipherParameters instanceof ParametersWithIV) {
            this.f341iv = ((ParametersWithIV) cipherParameters).getIV();
            cipherParameters2 = ((ParametersWithIV) cipherParameters).getParameters();
        } else {
            this.f341iv = new byte[0];
        }
        if (!(cipherParameters2 instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to HC128 init - " + cipherParameters.getClass().getName());
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
}