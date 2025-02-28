package org.bouncycastle.pqc.math.ntru;

import kotlin.UByte;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes2.dex */
public abstract class Polynomial {
    public short[] coeffs;
    protected NTRUParameterSet params;

    public Polynomial(NTRUParameterSet nTRUParameterSet) {
        this.coeffs = new short[nTRUParameterSet.m1n()];
        this.params = nTRUParameterSet;
    }

    static short bothNegativeMask(short s, short s2) {
        return (short) ((s & s2) >>> 15);
    }

    static byte mod3(byte b) {
        return (byte) ((b & UByte.MAX_VALUE) % 3);
    }

    static short mod3(short s) {
        return (short) ((s & 65535) % 3);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int modQ(int i, int i2) {
        return i % i2;
    }

    private void r2InvToRqInv(Polynomial polynomial, Polynomial polynomial2, Polynomial polynomial3, Polynomial polynomial4, Polynomial polynomial5) {
        int length = this.coeffs.length;
        for (int i = 0; i < length; i++) {
            polynomial3.coeffs[i] = (short) (-polynomial2.coeffs[i]);
        }
        for (int i2 = 0; i2 < length; i2++) {
            this.coeffs[i2] = polynomial.coeffs[i2];
        }
        polynomial4.rqMul(this, polynomial3);
        short[] sArr = polynomial4.coeffs;
        sArr[0] = (short) (sArr[0] + 2);
        polynomial5.rqMul(polynomial4, this);
        polynomial4.rqMul(polynomial5, polynomial3);
        short[] sArr2 = polynomial4.coeffs;
        sArr2[0] = (short) (sArr2[0] + 2);
        rqMul(polynomial4, polynomial5);
        polynomial4.rqMul(this, polynomial3);
        short[] sArr3 = polynomial4.coeffs;
        sArr3[0] = (short) (sArr3[0] + 2);
        polynomial5.rqMul(polynomial4, this);
        polynomial4.rqMul(polynomial5, polynomial3);
        short[] sArr4 = polynomial4.coeffs;
        sArr4[0] = (short) (sArr4[0] + 2);
        rqMul(polynomial4, polynomial5);
    }

    public abstract void lift(Polynomial polynomial);

    public void mod3PhiN() {
        int m1n = this.params.m1n();
        for (int i = 0; i < m1n; i++) {
            short[] sArr = this.coeffs;
            sArr[i] = mod3((short) (sArr[i] + (sArr[m1n - 1] * 2)));
        }
    }

    public void modQPhiN() {
        int m1n = this.params.m1n();
        for (int i = 0; i < m1n; i++) {
            short[] sArr = this.coeffs;
            sArr[i] = (short) (sArr[i] - sArr[m1n - 1]);
        }
    }

    public void r2Inv(Polynomial polynomial) {
        r2Inv(polynomial, this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial());
    }

    void r2Inv(Polynomial polynomial, Polynomial polynomial2, Polynomial polynomial3, Polynomial polynomial4, Polynomial polynomial5) {
        int i;
        int length = this.coeffs.length;
        short s = 0;
        polynomial5.coeffs[0] = 1;
        for (int i2 = 0; i2 < length; i2++) {
            polynomial2.coeffs[i2] = 1;
        }
        int i3 = 0;
        while (true) {
            i = length - 1;
            if (i3 >= i) {
                break;
            }
            short[] sArr = polynomial.coeffs;
            polynomial3.coeffs[(length - 2) - i3] = (short) ((sArr[i] ^ sArr[i3]) & 1);
            i3++;
        }
        polynomial3.coeffs[i] = 0;
        int i4 = 0;
        short s2 = 1;
        for (short s3 = 1; i4 < (i * 2) - s3; s3 = 1) {
            for (int i5 = i; i5 > 0; i5--) {
                short[] sArr2 = polynomial4.coeffs;
                sArr2[i5] = sArr2[i5 - 1];
            }
            polynomial4.coeffs[s] = s;
            short s4 = polynomial3.coeffs[s];
            short s5 = (short) (polynomial2.coeffs[s] & s4);
            int i6 = -s2;
            short bothNegativeMask = bothNegativeMask((short) i6, (short) (-s4));
            s2 = (short) (((short) (s2 ^ ((i6 ^ s2) & bothNegativeMask))) + s3);
            for (int i7 = s; i7 < length; i7++) {
                short[] sArr3 = polynomial2.coeffs;
                short s6 = sArr3[i7];
                short[] sArr4 = polynomial3.coeffs;
                short s7 = (short) (bothNegativeMask & (s6 ^ sArr4[i7]));
                sArr3[i7] = (short) (s6 ^ s7);
                sArr4[i7] = (short) (s7 ^ sArr4[i7]);
                short[] sArr5 = polynomial4.coeffs;
                short s8 = sArr5[i7];
                short[] sArr6 = polynomial5.coeffs;
                short s9 = (short) ((sArr6[i7] ^ s8) & bothNegativeMask);
                sArr5[i7] = (short) (s8 ^ s9);
                sArr6[i7] = (short) (sArr6[i7] ^ s9);
            }
            for (int i8 = 0; i8 < length; i8++) {
                short[] sArr7 = polynomial3.coeffs;
                sArr7[i8] = (short) (sArr7[i8] ^ (polynomial2.coeffs[i8] & s5));
            }
            for (int i9 = 0; i9 < length; i9++) {
                short[] sArr8 = polynomial5.coeffs;
                sArr8[i9] = (short) (sArr8[i9] ^ (polynomial4.coeffs[i9] & s5));
            }
            int i10 = 0;
            while (i10 < i) {
                short[] sArr9 = polynomial3.coeffs;
                int i11 = i10 + 1;
                sArr9[i10] = sArr9[i11];
                i10 = i11;
            }
            polynomial3.coeffs[i] = 0;
            i4++;
            s = 0;
        }
        int i12 = 0;
        while (true) {
            short[] sArr10 = this.coeffs;
            if (i12 >= i) {
                sArr10[i] = 0;
                return;
            } else {
                sArr10[i12] = polynomial4.coeffs[(length - 2) - i12];
                i12++;
            }
        }
    }

    public void rqInv(Polynomial polynomial) {
        rqInv(polynomial, this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial());
    }

    void rqInv(Polynomial polynomial, Polynomial polynomial2, Polynomial polynomial3, Polynomial polynomial4, Polynomial polynomial5) {
        polynomial2.r2Inv(polynomial);
        r2InvToRqInv(polynomial2, polynomial, polynomial3, polynomial4, polynomial5);
    }

    public void rqMul(Polynomial polynomial, Polynomial polynomial2) {
        int i;
        int length = this.coeffs.length;
        int i2 = 0;
        while (i2 < length) {
            this.coeffs[i2] = 0;
            for (int i3 = 1; i3 < length - i2; i3++) {
                short[] sArr = this.coeffs;
                sArr[i2] = (short) (sArr[i2] + (polynomial.coeffs[i2 + i3] * polynomial2.coeffs[length - i3]));
            }
            int i4 = 0;
            while (true) {
                i = i2 + 1;
                if (i4 < i) {
                    short[] sArr2 = this.coeffs;
                    sArr2[i2] = (short) (sArr2[i2] + (polynomial.coeffs[i2 - i4] * polynomial2.coeffs[i4]));
                    i4++;
                }
            }
            i2 = i;
        }
    }

    public void rqSumZeroFromBytes(byte[] bArr) {
        int length = this.coeffs.length;
        sqFromBytes(bArr);
        int i = length - 1;
        this.coeffs[i] = 0;
        for (int i2 = 0; i2 < this.params.packDegree(); i2++) {
            short[] sArr = this.coeffs;
            sArr[i] = (short) (sArr[i] - sArr[i2]);
        }
    }

    public byte[] rqSumZeroToBytes(int i) {
        return sqToBytes(i);
    }

    public void rqToS3(Polynomial polynomial) {
        int length = this.coeffs.length;
        for (int i = 0; i < length; i++) {
            this.coeffs[i] = (short) modQ(polynomial.coeffs[i] & 65535, this.params.m0q());
            short[] sArr = this.coeffs;
            sArr[i] = (short) (sArr[i] + (((short) (this.coeffs[i] >>> (this.params.logQ() - 1))) << (1 - (this.params.logQ() & 1))));
        }
        mod3PhiN();
    }

    public void s3FromBytes(byte[] bArr) {
        int length = this.coeffs.length;
        for (int i = 0; i < this.params.packDegree() / 5; i++) {
            byte b = bArr[i];
            short[] sArr = this.coeffs;
            int i2 = i * 5;
            sArr[i2] = b;
            int i3 = b & UByte.MAX_VALUE;
            sArr[i2 + 1] = (short) ((i3 * CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384) >>> 9);
            sArr[i2 + 2] = (short) ((i3 * 57) >>> 9);
            sArr[i2 + 3] = (short) ((i3 * 19) >>> 9);
            sArr[i2 + 4] = (short) ((i3 * 203) >>> 14);
        }
        if (this.params.packDegree() > (this.params.packDegree() / 5) * 5) {
            int packDegree = this.params.packDegree() / 5;
            byte b2 = bArr[packDegree];
            int i4 = 0;
            while (true) {
                int i5 = (packDegree * 5) + i4;
                if (i5 >= this.params.packDegree()) {
                    break;
                }
                this.coeffs[i5] = b2;
                b2 = (byte) (((b2 & UByte.MAX_VALUE) * CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384) >> 9);
                i4++;
            }
        }
        this.coeffs[length - 1] = 0;
        mod3PhiN();
    }

    public void s3Inv(Polynomial polynomial) {
        s3Inv(polynomial, this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial(), this.params.createPolynomial());
    }

    void s3Inv(Polynomial polynomial, Polynomial polynomial2, Polynomial polynomial3, Polynomial polynomial4, Polynomial polynomial5) {
        int i;
        short[] sArr;
        short[] sArr2;
        int length = this.coeffs.length;
        short s = 0;
        polynomial5.coeffs[0] = 1;
        for (int i2 = 0; i2 < length; i2++) {
            polynomial2.coeffs[i2] = 1;
        }
        int i3 = 0;
        while (true) {
            i = length - 1;
            if (i3 >= i) {
                break;
            }
            short[] sArr3 = polynomial.coeffs;
            polynomial3.coeffs[(length - 2) - i3] = mod3((short) ((sArr3[i3] & 3) + ((sArr3[i] & 3) * 2)));
            i3++;
        }
        polynomial3.coeffs[i] = 0;
        int i4 = 0;
        short s2 = 1;
        for (short s3 = 1; i4 < (i * 2) - s3; s3 = 1) {
            for (int i5 = i; i5 > 0; i5--) {
                short[] sArr4 = polynomial4.coeffs;
                sArr4[i5] = sArr4[i5 - 1];
            }
            polynomial4.coeffs[s] = s;
            short mod3 = mod3((byte) (polynomial3.coeffs[s] * 2 * polynomial2.coeffs[s]));
            int i6 = -s2;
            short bothNegativeMask = bothNegativeMask((short) i6, (short) (-polynomial3.coeffs[s]));
            s2 = (short) (((short) (s2 ^ ((i6 ^ s2) & bothNegativeMask))) + s3);
            for (int i7 = s; i7 < length; i7++) {
                short[] sArr5 = polynomial2.coeffs;
                short s4 = sArr5[i7];
                short[] sArr6 = polynomial3.coeffs;
                short s5 = (short) (bothNegativeMask & (s4 ^ sArr6[i7]));
                sArr5[i7] = (short) (s4 ^ s5);
                sArr6[i7] = (short) (s5 ^ sArr6[i7]);
                short[] sArr7 = polynomial4.coeffs;
                short s6 = sArr7[i7];
                short[] sArr8 = polynomial5.coeffs;
                short s7 = (short) ((sArr8[i7] ^ s6) & bothNegativeMask);
                sArr7[i7] = (short) (s6 ^ s7);
                sArr8[i7] = (short) (sArr8[i7] ^ s7);
            }
            for (int i8 = 0; i8 < length; i8++) {
                polynomial3.coeffs[i8] = mod3((byte) (sArr2[i8] + (polynomial2.coeffs[i8] * mod3)));
            }
            for (int i9 = 0; i9 < length; i9++) {
                polynomial5.coeffs[i9] = mod3((byte) (sArr[i9] + (polynomial4.coeffs[i9] * mod3)));
            }
            int i10 = 0;
            while (i10 < i) {
                short[] sArr9 = polynomial3.coeffs;
                int i11 = i10 + 1;
                sArr9[i10] = sArr9[i11];
                i10 = i11;
            }
            polynomial3.coeffs[i] = 0;
            i4++;
            s = 0;
        }
        short s8 = polynomial2.coeffs[s];
        for (int i12 = 0; i12 < i; i12++) {
            this.coeffs[i12] = mod3((byte) (polynomial4.coeffs[(length - 2) - i12] * s8));
        }
        this.coeffs[i] = 0;
    }

    public void s3Mul(Polynomial polynomial, Polynomial polynomial2) {
        rqMul(polynomial, polynomial2);
        mod3PhiN();
    }

    public byte[] s3ToBytes(int i) {
        byte[] bArr = new byte[i];
        byte b = 0;
        for (int i2 = 0; i2 < this.params.packDegree() / 5; i2++) {
            short[] sArr = this.coeffs;
            int i3 = i2 * 5;
            bArr[i2] = (byte) (((((byte) (((((byte) (((((byte) (((((byte) (sArr[i3 + 4] & 255)) * 3) + sArr[i3 + 3]) & 255)) * 3) + sArr[i3 + 2]) & 255)) * 3) + sArr[i3 + 1]) & 255)) * 3) + sArr[i3]) & 255);
        }
        if (this.params.packDegree() > (this.params.packDegree() / 5) * 5) {
            int packDegree = this.params.packDegree() / 5;
            int i4 = packDegree * 5;
            for (int packDegree2 = (this.params.packDegree() - i4) - 1; packDegree2 >= 0; packDegree2--) {
                b = (byte) (((b * 3) + this.coeffs[i4 + packDegree2]) & 255);
            }
            bArr[packDegree] = b;
        }
        return bArr;
    }

    public abstract void sqFromBytes(byte[] bArr);

    public void sqMul(Polynomial polynomial, Polynomial polynomial2) {
        rqMul(polynomial, polynomial2);
        modQPhiN();
    }

    public abstract byte[] sqToBytes(int i);

    public void trinaryZqToZ3() {
        int length = this.coeffs.length;
        for (int i = 0; i < length; i++) {
            short[] sArr = this.coeffs;
            sArr[i] = (short) modQ(sArr[i] & 65535, this.params.m0q());
            short[] sArr2 = this.coeffs;
            short s = sArr2[i];
            sArr2[i] = (short) ((s ^ (s >>> (this.params.logQ() - 1))) & 3);
        }
    }

    public void z3ToZq() {
        int length = this.coeffs.length;
        for (int i = 0; i < length; i++) {
            short[] sArr = this.coeffs;
            short s = sArr[i];
            sArr[i] = (short) (s | ((-(s >>> 1)) & (this.params.m0q() - 1)));
        }
    }
}