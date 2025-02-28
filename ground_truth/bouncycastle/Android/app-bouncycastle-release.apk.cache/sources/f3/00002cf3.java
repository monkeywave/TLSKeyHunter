package org.bouncycastle.pqc.math.ntru;

import kotlin.UByte;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;

/* loaded from: classes2.dex */
public class HRSSPolynomial extends Polynomial {
    public HRSSPolynomial(NTRUHRSSParameterSet nTRUHRSSParameterSet) {
        super(nTRUHRSSParameterSet);
    }

    @Override // org.bouncycastle.pqc.math.ntru.Polynomial
    public void lift(Polynomial polynomial) {
        int length = this.coeffs.length;
        Polynomial createPolynomial = this.params.createPolynomial();
        short s = (short) (3 - (length % 3));
        short[] sArr = createPolynomial.coeffs;
        int i = 0;
        int i2 = 2 - s;
        short s2 = polynomial.coeffs[1];
        sArr[0] = (short) ((polynomial.coeffs[0] * i2) + (polynomial.coeffs[2] * s));
        short[] sArr2 = createPolynomial.coeffs;
        short s3 = polynomial.coeffs[2];
        sArr2[1] = (short) (polynomial.coeffs[1] * i2);
        createPolynomial.coeffs[2] = (short) (polynomial.coeffs[2] * i2);
        short s4 = 0;
        for (int i3 = 3; i3 < length; i3++) {
            short[] sArr3 = createPolynomial.coeffs;
            sArr3[0] = (short) (sArr3[0] + (polynomial.coeffs[i3] * ((s * 2) + s4)));
            short[] sArr4 = createPolynomial.coeffs;
            int i4 = s4 + s;
            sArr4[1] = (short) (sArr4[1] + (polynomial.coeffs[i3] * i4));
            short[] sArr5 = createPolynomial.coeffs;
            sArr5[2] = (short) (sArr5[2] + (polynomial.coeffs[i3] * s4));
            s4 = (short) (i4 % 3);
        }
        short[] sArr6 = createPolynomial.coeffs;
        int i5 = s + s4;
        sArr6[1] = (short) (sArr6[1] + (polynomial.coeffs[0] * i5));
        short[] sArr7 = createPolynomial.coeffs;
        sArr7[2] = (short) (sArr7[2] + (polynomial.coeffs[0] * s4));
        short[] sArr8 = createPolynomial.coeffs;
        sArr8[2] = (short) (sArr8[2] + (polynomial.coeffs[1] * i5));
        for (int i6 = 3; i6 < length; i6++) {
            createPolynomial.coeffs[i6] = (short) (createPolynomial.coeffs[i6 - 3] + ((polynomial.coeffs[i6] + polynomial.coeffs[i6 - 1] + polynomial.coeffs[i6 - 2]) * 2));
        }
        createPolynomial.mod3PhiN();
        createPolynomial.z3ToZq();
        this.coeffs[0] = (short) (-createPolynomial.coeffs[0]);
        while (i < length - 1) {
            int i7 = i + 1;
            this.coeffs[i7] = (short) (createPolynomial.coeffs[i] - createPolynomial.coeffs[i7]);
            i = i7;
        }
    }

    @Override // org.bouncycastle.pqc.math.ntru.Polynomial
    public void sqFromBytes(byte[] bArr) {
        int i = 0;
        while (i < this.params.packDegree() / 8) {
            int i2 = i * 8;
            int i3 = i * 13;
            int i4 = i3 + 1;
            this.coeffs[i2] = (short) ((bArr[i3] & UByte.MAX_VALUE) | ((((short) (bArr[i4] & UByte.MAX_VALUE)) & 31) << 8));
            int i5 = i3 + 3;
            this.coeffs[i2 + 1] = (short) (((bArr[i4] & UByte.MAX_VALUE) >>> 5) | (((short) (bArr[i3 + 2] & UByte.MAX_VALUE)) << 3) | ((((short) (bArr[i5] & UByte.MAX_VALUE)) & 3) << 11));
            int i6 = i3 + 4;
            this.coeffs[i2 + 2] = (short) (((bArr[i5] & UByte.MAX_VALUE) >>> 2) | ((((short) (bArr[i6] & UByte.MAX_VALUE)) & 127) << 6));
            int i7 = ((bArr[i6] & UByte.MAX_VALUE) >>> 7) | (((short) (bArr[i3 + 5] & UByte.MAX_VALUE)) << 1);
            int i8 = i3 + 6;
            this.coeffs[i2 + 3] = (short) (i7 | ((((short) (bArr[i8] & UByte.MAX_VALUE)) & 15) << 9));
            int i9 = i3 + 8;
            this.coeffs[i2 + 4] = (short) ((((short) (bArr[i3 + 7] & UByte.MAX_VALUE)) << 4) | ((bArr[i8] & UByte.MAX_VALUE) >>> 4) | ((((short) (bArr[i9] & UByte.MAX_VALUE)) & 1) << 12));
            int i10 = i3 + 9;
            this.coeffs[i2 + 5] = (short) (((bArr[i9] & UByte.MAX_VALUE) >>> 1) | ((((short) (bArr[i10] & UByte.MAX_VALUE)) & 63) << 7));
            int i11 = i3 + 11;
            this.coeffs[i2 + 6] = (short) ((((short) (bArr[i3 + 10] & UByte.MAX_VALUE)) << 2) | ((bArr[i10] & UByte.MAX_VALUE) >>> 6) | ((((short) (bArr[i11] & UByte.MAX_VALUE)) & 7) << 10));
            this.coeffs[i2 + 7] = (short) (((bArr[i11] & UByte.MAX_VALUE) >>> 3) | (((short) (bArr[i3 + 12] & UByte.MAX_VALUE)) << 5));
            i++;
        }
        int packDegree = this.params.packDegree() & 7;
        if (packDegree == 2) {
            int i12 = i * 8;
            int i13 = i * 13;
            int i14 = i13 + 1;
            this.coeffs[i12] = (short) ((bArr[i13] & UByte.MAX_VALUE) | ((((short) (bArr[i14] & UByte.MAX_VALUE)) & 31) << 8));
            this.coeffs[i12 + 1] = (short) (((((short) (bArr[i13 + 3] & UByte.MAX_VALUE)) & 3) << 11) | ((bArr[i14] & UByte.MAX_VALUE) >>> 5) | (((short) (bArr[i13 + 2] & UByte.MAX_VALUE)) << 3));
        } else if (packDegree == 4) {
            int i15 = i * 8;
            int i16 = i * 13;
            int i17 = i16 + 1;
            this.coeffs[i15] = (short) ((bArr[i16] & UByte.MAX_VALUE) | ((((short) (bArr[i17] & UByte.MAX_VALUE)) & 31) << 8));
            int i18 = i16 + 3;
            this.coeffs[i15 + 1] = (short) (((bArr[i17] & UByte.MAX_VALUE) >>> 5) | (((short) (bArr[i16 + 2] & UByte.MAX_VALUE)) << 3) | ((((short) (bArr[i18] & UByte.MAX_VALUE)) & 3) << 11));
            int i19 = i16 + 4;
            this.coeffs[i15 + 2] = (short) (((bArr[i18] & UByte.MAX_VALUE) >>> 2) | ((((short) (bArr[i19] & UByte.MAX_VALUE)) & 127) << 6));
            this.coeffs[i15 + 3] = (short) (((((short) (bArr[i16 + 6] & UByte.MAX_VALUE)) & 15) << 9) | ((bArr[i19] & UByte.MAX_VALUE) >>> 7) | (((short) (bArr[i16 + 5] & UByte.MAX_VALUE)) << 1));
        }
        this.coeffs[this.params.m1n() - 1] = 0;
    }

    @Override // org.bouncycastle.pqc.math.ntru.Polynomial
    public byte[] sqToBytes(int i) {
        byte[] bArr = new byte[i];
        short[] sArr = new short[8];
        int i2 = 0;
        while (true) {
            short s = 65535;
            if (i2 >= this.params.packDegree() / 8) {
                break;
            }
            int i3 = 0;
            while (i3 < 8) {
                sArr[i3] = (short) modQ(this.coeffs[(i2 * 8) + i3] & s, this.params.m0q());
                i3++;
                s = 65535;
            }
            int i4 = i2 * 13;
            short s2 = sArr[0];
            bArr[i4] = (byte) (s2 & 255);
            short s3 = sArr[1];
            bArr[i4 + 1] = (byte) ((s2 >>> 8) | ((s3 & 7) << 5));
            bArr[i4 + 2] = (byte) ((s3 >>> 3) & 255);
            int i5 = s3 >>> 11;
            short s4 = sArr[2];
            bArr[i4 + 3] = (byte) (((s4 & 63) << 2) | i5);
            short s5 = sArr[3];
            bArr[i4 + 4] = (byte) ((s4 >>> 6) | ((s5 & 1) << 7));
            bArr[i4 + 5] = (byte) ((s5 >>> 1) & 255);
            int i6 = s5 >>> 9;
            short s6 = sArr[4];
            bArr[i4 + 6] = (byte) (((s6 & 15) << 4) | i6);
            bArr[i4 + 7] = (byte) ((s6 >>> 4) & 255);
            short s7 = sArr[5];
            bArr[i4 + 8] = (byte) ((s6 >>> 12) | ((s7 & 127) << 1));
            int i7 = s7 >>> 7;
            short s8 = sArr[6];
            bArr[i4 + 9] = (byte) (((s8 & 3) << 6) | i7);
            bArr[i4 + 10] = (byte) ((s8 >>> 2) & 255);
            short s9 = sArr[7];
            bArr[i4 + 11] = (byte) ((s8 >>> 10) | ((s9 & 31) << 3));
            bArr[i4 + 12] = (byte) (s9 >>> 5);
            i2++;
        }
        int i8 = 0;
        while (true) {
            int i9 = i2 * 8;
            if (i8 >= this.params.packDegree() - i9) {
                break;
            }
            sArr[i8] = (short) modQ(this.coeffs[i9 + i8] & 65535, this.params.m0q());
            i8++;
        }
        while (i8 < 8) {
            sArr[i8] = 0;
            i8++;
        }
        int packDegree = this.params.packDegree() - ((this.params.packDegree() / 8) * 8);
        if (packDegree != 2) {
            if (packDegree == 4) {
                int i10 = i2 * 13;
                short s10 = sArr[0];
                bArr[i10] = (byte) (s10 & 255);
                short s11 = sArr[1];
                bArr[i10 + 1] = (byte) ((s10 >>> 8) | ((s11 & 7) << 5));
                bArr[i10 + 2] = (byte) ((s11 >>> 3) & 255);
                int i11 = s11 >>> 11;
                short s12 = sArr[2];
                bArr[i10 + 3] = (byte) (i11 | ((s12 & 63) << 2));
                int i12 = s12 >>> 6;
                short s13 = sArr[3];
                bArr[i10 + 4] = (byte) (((s13 & 1) << 7) | i12);
                bArr[i10 + 5] = (byte) ((s13 >>> 1) & 255);
                bArr[i10 + 6] = (byte) ((s13 >>> 9) | ((sArr[4] & 15) << 4));
            }
            return bArr;
        }
        int i13 = i2 * 13;
        short s14 = sArr[0];
        bArr[i13] = (byte) (s14 & 255);
        int i14 = s14 >>> 8;
        short s15 = sArr[1];
        bArr[i13 + 1] = (byte) (i14 | ((s15 & 7) << 5));
        bArr[i13 + 2] = (byte) ((s15 >>> 3) & 255);
        bArr[i13 + 3] = (byte) ((s15 >>> 11) | ((sArr[2] & 63) << 2));
        return bArr;
    }
}