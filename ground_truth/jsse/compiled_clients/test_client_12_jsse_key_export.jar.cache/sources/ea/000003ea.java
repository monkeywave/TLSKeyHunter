package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/GOST3411Digest.class */
public class GOST3411Digest implements ExtendedDigest, Memoable {
    private static final int DIGEST_LENGTH = 32;

    /* renamed from: H */
    private byte[] f143H;

    /* renamed from: L */
    private byte[] f144L;

    /* renamed from: M */
    private byte[] f145M;
    private byte[] Sum;

    /* renamed from: C */
    private byte[][] f146C;
    private byte[] xBuf;
    private int xBufOff;
    private long byteCount;
    private BlockCipher cipher;
    private byte[] sBox;

    /* renamed from: K */
    private byte[] f147K;

    /* renamed from: a */
    byte[] f148a;

    /* renamed from: wS */
    short[] f149wS;
    short[] w_S;

    /* renamed from: S */
    byte[] f150S;

    /* renamed from: U */
    byte[] f151U;

    /* renamed from: V */
    byte[] f152V;

    /* renamed from: W */
    byte[] f153W;

    /* renamed from: C2 */
    private static final byte[] f154C2 = {0, -1, 0, -1, 0, -1, 0, -1, -1, 0, -1, 0, -1, 0, -1, 0, 0, -1, -1, 0, -1, 0, 0, -1, -1, 0, 0, 0, -1, -1, 0, -1};

    public GOST3411Digest() {
        this.f143H = new byte[32];
        this.f144L = new byte[32];
        this.f145M = new byte[32];
        this.Sum = new byte[32];
        this.f146C = new byte[4][32];
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f147K = new byte[32];
        this.f148a = new byte[8];
        this.f149wS = new short[16];
        this.w_S = new short[16];
        this.f150S = new byte[32];
        this.f151U = new byte[32];
        this.f152V = new byte[32];
        this.f153W = new byte[32];
        this.sBox = GOST28147Engine.getSBox("D-A");
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(byte[] bArr) {
        this.f143H = new byte[32];
        this.f144L = new byte[32];
        this.f145M = new byte[32];
        this.Sum = new byte[32];
        this.f146C = new byte[4][32];
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f147K = new byte[32];
        this.f148a = new byte[8];
        this.f149wS = new short[16];
        this.w_S = new short[16];
        this.f150S = new byte[32];
        this.f151U = new byte[32];
        this.f152V = new byte[32];
        this.f153W = new byte[32];
        this.sBox = Arrays.clone(bArr);
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(GOST3411Digest gOST3411Digest) {
        this.f143H = new byte[32];
        this.f144L = new byte[32];
        this.f145M = new byte[32];
        this.Sum = new byte[32];
        this.f146C = new byte[4][32];
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f147K = new byte[32];
        this.f148a = new byte[8];
        this.f149wS = new short[16];
        this.w_S = new short[16];
        this.f150S = new byte[32];
        this.f151U = new byte[32];
        this.f152V = new byte[32];
        this.f153W = new byte[32];
        reset(gOST3411Digest);
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "GOST3411";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = b;
        if (this.xBufOff == this.xBuf.length) {
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        while (this.xBufOff != 0 && i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
        while (i2 > this.xBuf.length) {
            System.arraycopy(bArr, i, this.xBuf, 0, this.xBuf.length);
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            i += this.xBuf.length;
            i2 -= this.xBuf.length;
            this.byteCount += this.xBuf.length;
        }
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }

    /* renamed from: P */
    private byte[] m115P(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            this.f147K[4 * i] = bArr[i];
            this.f147K[1 + (4 * i)] = bArr[8 + i];
            this.f147K[2 + (4 * i)] = bArr[16 + i];
            this.f147K[3 + (4 * i)] = bArr[24 + i];
        }
        return this.f147K;
    }

    /* renamed from: A */
    private byte[] m117A(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            this.f148a[i] = (byte) (bArr[i] ^ bArr[i + 8]);
        }
        System.arraycopy(bArr, 8, bArr, 0, 24);
        System.arraycopy(this.f148a, 0, bArr, 24, 8);
        return bArr;
    }

    /* renamed from: E */
    private void m116E(byte[] bArr, byte[] bArr2, int i, byte[] bArr3, int i2) {
        this.cipher.init(true, new KeyParameter(bArr));
        this.cipher.processBlock(bArr3, i2, bArr2, i);
    }

    /* renamed from: fw */
    private void m114fw(byte[] bArr) {
        cpyBytesToShort(bArr, this.f149wS);
        this.w_S[15] = (short) (((((this.f149wS[0] ^ this.f149wS[1]) ^ this.f149wS[2]) ^ this.f149wS[3]) ^ this.f149wS[12]) ^ this.f149wS[15]);
        System.arraycopy(this.f149wS, 1, this.w_S, 0, 15);
        cpyShortToBytes(this.w_S, bArr);
    }

    protected void processBlock(byte[] bArr, int i) {
        System.arraycopy(bArr, i, this.f145M, 0, 32);
        System.arraycopy(this.f143H, 0, this.f151U, 0, 32);
        System.arraycopy(this.f145M, 0, this.f152V, 0, 32);
        for (int i2 = 0; i2 < 32; i2++) {
            this.f153W[i2] = (byte) (this.f151U[i2] ^ this.f152V[i2]);
        }
        m116E(m115P(this.f153W), this.f150S, 0, this.f143H, 0);
        for (int i3 = 1; i3 < 4; i3++) {
            byte[] m117A = m117A(this.f151U);
            for (int i4 = 0; i4 < 32; i4++) {
                this.f151U[i4] = (byte) (m117A[i4] ^ this.f146C[i3][i4]);
            }
            this.f152V = m117A(m117A(this.f152V));
            for (int i5 = 0; i5 < 32; i5++) {
                this.f153W[i5] = (byte) (this.f151U[i5] ^ this.f152V[i5]);
            }
            m116E(m115P(this.f153W), this.f150S, i3 * 8, this.f143H, i3 * 8);
        }
        for (int i6 = 0; i6 < 12; i6++) {
            m114fw(this.f150S);
        }
        for (int i7 = 0; i7 < 32; i7++) {
            this.f150S[i7] = (byte) (this.f150S[i7] ^ this.f145M[i7]);
        }
        m114fw(this.f150S);
        for (int i8 = 0; i8 < 32; i8++) {
            this.f150S[i8] = (byte) (this.f143H[i8] ^ this.f150S[i8]);
        }
        for (int i9 = 0; i9 < 61; i9++) {
            m114fw(this.f150S);
        }
        System.arraycopy(this.f150S, 0, this.f143H, 0, this.f143H.length);
    }

    private void finish() {
        Pack.longToLittleEndian(this.byteCount * 8, this.f144L, 0);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processBlock(this.f144L, 0);
        processBlock(this.Sum, 0);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        System.arraycopy(this.f143H, 0, bArr, i, this.f143H.length);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.byteCount = 0L;
        this.xBufOff = 0;
        for (int i = 0; i < this.f143H.length; i++) {
            this.f143H[i] = 0;
        }
        for (int i2 = 0; i2 < this.f144L.length; i2++) {
            this.f144L[i2] = 0;
        }
        for (int i3 = 0; i3 < this.f145M.length; i3++) {
            this.f145M[i3] = 0;
        }
        for (int i4 = 0; i4 < this.f146C[1].length; i4++) {
            this.f146C[1][i4] = 0;
        }
        for (int i5 = 0; i5 < this.f146C[3].length; i5++) {
            this.f146C[3][i5] = 0;
        }
        for (int i6 = 0; i6 < this.Sum.length; i6++) {
            this.Sum[i6] = 0;
        }
        for (int i7 = 0; i7 < this.xBuf.length; i7++) {
            this.xBuf[i7] = 0;
        }
        System.arraycopy(f154C2, 0, this.f146C[2], 0, f154C2.length);
    }

    private void sumByteArray(byte[] bArr) {
        int i = 0;
        for (int i2 = 0; i2 != this.Sum.length; i2++) {
            int i3 = (this.Sum[i2] & 255) + (bArr[i2] & 255) + i;
            this.Sum[i2] = (byte) i3;
            i = i3 >>> 8;
        }
    }

    private void cpyBytesToShort(byte[] bArr, short[] sArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            sArr[i] = (short) (((bArr[(i * 2) + 1] << 8) & 65280) | (bArr[i * 2] & 255));
        }
    }

    private void cpyShortToBytes(short[] sArr, byte[] bArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            bArr[(i * 2) + 1] = (byte) (sArr[i] >> 8);
            bArr[i * 2] = (byte) sArr[i];
        }
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 32;
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new GOST3411Digest(this);
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        GOST3411Digest gOST3411Digest = (GOST3411Digest) memoable;
        this.sBox = gOST3411Digest.sBox;
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
        System.arraycopy(gOST3411Digest.f143H, 0, this.f143H, 0, gOST3411Digest.f143H.length);
        System.arraycopy(gOST3411Digest.f144L, 0, this.f144L, 0, gOST3411Digest.f144L.length);
        System.arraycopy(gOST3411Digest.f145M, 0, this.f145M, 0, gOST3411Digest.f145M.length);
        System.arraycopy(gOST3411Digest.Sum, 0, this.Sum, 0, gOST3411Digest.Sum.length);
        System.arraycopy(gOST3411Digest.f146C[1], 0, this.f146C[1], 0, gOST3411Digest.f146C[1].length);
        System.arraycopy(gOST3411Digest.f146C[2], 0, this.f146C[2], 0, gOST3411Digest.f146C[2].length);
        System.arraycopy(gOST3411Digest.f146C[3], 0, this.f146C[3], 0, gOST3411Digest.f146C[3].length);
        System.arraycopy(gOST3411Digest.xBuf, 0, this.xBuf, 0, gOST3411Digest.xBuf.length);
        this.xBufOff = gOST3411Digest.xBufOff;
        this.byteCount = gOST3411Digest.byteCount;
    }
}