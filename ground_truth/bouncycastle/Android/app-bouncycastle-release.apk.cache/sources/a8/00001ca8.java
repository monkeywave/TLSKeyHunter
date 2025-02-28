package org.bouncycastle.crypto.digests;

import androidx.core.view.MotionEventCompat;
import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class GOST3411Digest implements ExtendedDigest, Memoable {

    /* renamed from: C2 */
    private static final byte[] f403C2 = {0, -1, 0, -1, 0, -1, 0, -1, -1, 0, -1, 0, -1, 0, -1, 0, 0, -1, -1, 0, -1, 0, 0, -1, -1, 0, 0, 0, -1, -1, 0, -1};
    private static final int DIGEST_LENGTH = 32;

    /* renamed from: C */
    private byte[][] f404C;

    /* renamed from: H */
    private byte[] f405H;

    /* renamed from: K */
    private byte[] f406K;

    /* renamed from: L */
    private byte[] f407L;

    /* renamed from: M */
    private byte[] f408M;

    /* renamed from: S */
    byte[] f409S;
    private byte[] Sum;

    /* renamed from: U */
    byte[] f410U;

    /* renamed from: V */
    byte[] f411V;

    /* renamed from: W */
    byte[] f412W;

    /* renamed from: a */
    byte[] f413a;
    private long byteCount;
    private BlockCipher cipher;
    private final CryptoServicePurpose purpose;
    private byte[] sBox;

    /* renamed from: wS */
    short[] f414wS;
    short[] w_S;
    private byte[] xBuf;
    private int xBufOff;

    public GOST3411Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public GOST3411Digest(CryptoServicePurpose cryptoServicePurpose) {
        this.f405H = new byte[32];
        this.f407L = new byte[32];
        this.f408M = new byte[32];
        this.Sum = new byte[32];
        this.f404C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f406K = new byte[32];
        this.f413a = new byte[8];
        this.f414wS = new short[16];
        this.w_S = new short[16];
        this.f409S = new byte[32];
        this.f410U = new byte[32];
        this.f411V = new byte[32];
        this.f412W = new byte[32];
        this.purpose = cryptoServicePurpose;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        this.sBox = GOST28147Engine.getSBox("D-A");
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(GOST3411Digest gOST3411Digest) {
        this.f405H = new byte[32];
        this.f407L = new byte[32];
        this.f408M = new byte[32];
        this.Sum = new byte[32];
        this.f404C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f406K = new byte[32];
        this.f413a = new byte[8];
        this.f414wS = new short[16];
        this.w_S = new short[16];
        this.f409S = new byte[32];
        this.f410U = new byte[32];
        this.f411V = new byte[32];
        this.f412W = new byte[32];
        this.purpose = gOST3411Digest.purpose;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset(gOST3411Digest);
    }

    public GOST3411Digest(byte[] bArr) {
        this(bArr, CryptoServicePurpose.ANY);
    }

    public GOST3411Digest(byte[] bArr, CryptoServicePurpose cryptoServicePurpose) {
        this.f405H = new byte[32];
        this.f407L = new byte[32];
        this.f408M = new byte[32];
        this.Sum = new byte[32];
        this.f404C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f406K = new byte[32];
        this.f413a = new byte[8];
        this.f414wS = new short[16];
        this.w_S = new short[16];
        this.f409S = new byte[32];
        this.f410U = new byte[32];
        this.f411V = new byte[32];
        this.f412W = new byte[32];
        this.purpose = cryptoServicePurpose;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        this.sBox = Arrays.clone(bArr);
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    /* renamed from: A */
    private byte[] m137A(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            this.f413a[i] = (byte) (bArr[i] ^ bArr[i + 8]);
        }
        System.arraycopy(bArr, 8, bArr, 0, 24);
        System.arraycopy(this.f413a, 0, bArr, 24, 8);
        return bArr;
    }

    /* renamed from: E */
    private void m136E(byte[] bArr, byte[] bArr2, int i, byte[] bArr3, int i2) {
        this.cipher.init(true, new KeyParameter(bArr));
        this.cipher.processBlock(bArr3, i2, bArr2, i);
    }

    /* renamed from: P */
    private byte[] m135P(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            byte[] bArr2 = this.f406K;
            int i2 = i * 4;
            bArr2[i2] = bArr[i];
            bArr2[i2 + 1] = bArr[i + 8];
            bArr2[i2 + 2] = bArr[i + 16];
            bArr2[i2 + 3] = bArr[i + 24];
        }
        return this.f406K;
    }

    private void cpyBytesToShort(byte[] bArr, short[] sArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            int i2 = i * 2;
            sArr[i] = (short) ((bArr[i2] & UByte.MAX_VALUE) | ((bArr[i2 + 1] << 8) & MotionEventCompat.ACTION_POINTER_INDEX_MASK));
        }
    }

    private void cpyShortToBytes(short[] sArr, byte[] bArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            int i2 = i * 2;
            short s = sArr[i];
            bArr[i2 + 1] = (byte) (s >> 8);
            bArr[i2] = (byte) s;
        }
    }

    private void finish() {
        Pack.longToLittleEndian(this.byteCount * 8, this.f407L, 0);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processBlock(this.f407L, 0);
        processBlock(this.Sum, 0);
    }

    /* renamed from: fw */
    private void m134fw(byte[] bArr) {
        cpyBytesToShort(bArr, this.f414wS);
        short[] sArr = this.w_S;
        short[] sArr2 = this.f414wS;
        sArr[15] = (short) (((((sArr2[0] ^ sArr2[1]) ^ sArr2[2]) ^ sArr2[3]) ^ sArr2[12]) ^ sArr2[15]);
        System.arraycopy(sArr2, 1, sArr, 0, 15);
        cpyShortToBytes(this.w_S, bArr);
    }

    private void sumByteArray(byte[] bArr) {
        int i = 0;
        int i2 = 0;
        while (true) {
            byte[] bArr2 = this.Sum;
            if (i == bArr2.length) {
                return;
            }
            int i3 = (bArr2[i] & UByte.MAX_VALUE) + (bArr[i] & UByte.MAX_VALUE) + i2;
            bArr2[i] = (byte) i3;
            i2 = i3 >>> 8;
            i++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new GOST3411Digest(this);
    }

    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, 256, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        byte[] bArr2 = this.f405H;
        System.arraycopy(bArr2, 0, bArr, i, bArr2.length);
        reset();
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "GOST3411";
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    protected void processBlock(byte[] bArr, int i) {
        System.arraycopy(bArr, i, this.f408M, 0, 32);
        System.arraycopy(this.f405H, 0, this.f410U, 0, 32);
        System.arraycopy(this.f408M, 0, this.f411V, 0, 32);
        for (int i2 = 0; i2 < 32; i2++) {
            this.f412W[i2] = (byte) (this.f410U[i2] ^ this.f411V[i2]);
        }
        m136E(m135P(this.f412W), this.f409S, 0, this.f405H, 0);
        for (int i3 = 1; i3 < 4; i3++) {
            byte[] m137A = m137A(this.f410U);
            for (int i4 = 0; i4 < 32; i4++) {
                this.f410U[i4] = (byte) (m137A[i4] ^ this.f404C[i3][i4]);
            }
            this.f411V = m137A(m137A(this.f411V));
            for (int i5 = 0; i5 < 32; i5++) {
                this.f412W[i5] = (byte) (this.f410U[i5] ^ this.f411V[i5]);
            }
            int i6 = i3 * 8;
            m136E(m135P(this.f412W), this.f409S, i6, this.f405H, i6);
        }
        for (int i7 = 0; i7 < 12; i7++) {
            m134fw(this.f409S);
        }
        for (int i8 = 0; i8 < 32; i8++) {
            byte[] bArr2 = this.f409S;
            bArr2[i8] = (byte) (bArr2[i8] ^ this.f408M[i8]);
        }
        m134fw(this.f409S);
        for (int i9 = 0; i9 < 32; i9++) {
            byte[] bArr3 = this.f409S;
            bArr3[i9] = (byte) (this.f405H[i9] ^ bArr3[i9]);
        }
        for (int i10 = 0; i10 < 61; i10++) {
            m134fw(this.f409S);
        }
        byte[] bArr4 = this.f409S;
        byte[] bArr5 = this.f405H;
        System.arraycopy(bArr4, 0, bArr5, 0, bArr5.length);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.byteCount = 0L;
        this.xBufOff = 0;
        int i = 0;
        while (true) {
            byte[] bArr = this.f405H;
            if (i >= bArr.length) {
                break;
            }
            bArr[i] = 0;
            i++;
        }
        int i2 = 0;
        while (true) {
            byte[] bArr2 = this.f407L;
            if (i2 >= bArr2.length) {
                break;
            }
            bArr2[i2] = 0;
            i2++;
        }
        int i3 = 0;
        while (true) {
            byte[] bArr3 = this.f408M;
            if (i3 >= bArr3.length) {
                break;
            }
            bArr3[i3] = 0;
            i3++;
        }
        int i4 = 0;
        while (true) {
            byte[] bArr4 = this.f404C[1];
            if (i4 >= bArr4.length) {
                break;
            }
            bArr4[i4] = 0;
            i4++;
        }
        int i5 = 0;
        while (true) {
            byte[] bArr5 = this.f404C[3];
            if (i5 >= bArr5.length) {
                break;
            }
            bArr5[i5] = 0;
            i5++;
        }
        int i6 = 0;
        while (true) {
            byte[] bArr6 = this.Sum;
            if (i6 >= bArr6.length) {
                break;
            }
            bArr6[i6] = 0;
            i6++;
        }
        int i7 = 0;
        while (true) {
            byte[] bArr7 = this.xBuf;
            if (i7 >= bArr7.length) {
                byte[] bArr8 = f403C2;
                System.arraycopy(bArr8, 0, this.f404C[2], 0, bArr8.length);
                return;
            }
            bArr7[i7] = 0;
            i7++;
        }
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        GOST3411Digest gOST3411Digest = (GOST3411Digest) memoable;
        this.sBox = gOST3411Digest.sBox;
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
        byte[] bArr = gOST3411Digest.f405H;
        System.arraycopy(bArr, 0, this.f405H, 0, bArr.length);
        byte[] bArr2 = gOST3411Digest.f407L;
        System.arraycopy(bArr2, 0, this.f407L, 0, bArr2.length);
        byte[] bArr3 = gOST3411Digest.f408M;
        System.arraycopy(bArr3, 0, this.f408M, 0, bArr3.length);
        byte[] bArr4 = gOST3411Digest.Sum;
        System.arraycopy(bArr4, 0, this.Sum, 0, bArr4.length);
        byte[] bArr5 = gOST3411Digest.f404C[1];
        System.arraycopy(bArr5, 0, this.f404C[1], 0, bArr5.length);
        byte[] bArr6 = gOST3411Digest.f404C[2];
        System.arraycopy(bArr6, 0, this.f404C[2], 0, bArr6.length);
        byte[] bArr7 = gOST3411Digest.f404C[3];
        System.arraycopy(bArr7, 0, this.f404C[3], 0, bArr7.length);
        byte[] bArr8 = gOST3411Digest.xBuf;
        System.arraycopy(bArr8, 0, this.xBuf, 0, bArr8.length);
        this.xBufOff = gOST3411Digest.xBufOff;
        this.byteCount = gOST3411Digest.byteCount;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        int i2 = i + 1;
        this.xBufOff = i2;
        bArr[i] = b;
        if (i2 == bArr.length) {
            sumByteArray(bArr);
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
        while (true) {
            byte[] bArr2 = this.xBuf;
            if (i2 < bArr2.length) {
                break;
            }
            System.arraycopy(bArr, i, bArr2, 0, bArr2.length);
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            byte[] bArr3 = this.xBuf;
            i += bArr3.length;
            i2 -= bArr3.length;
            this.byteCount += bArr3.length;
        }
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }
}