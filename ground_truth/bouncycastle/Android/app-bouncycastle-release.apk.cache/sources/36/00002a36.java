package org.bouncycastle.pqc.crypto.ntru;

import kotlin.UByte;
import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.HRSSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class NTRUSampling {
    private final NTRUParameterSet params;

    public NTRUSampling(NTRUParameterSet nTRUParameterSet) {
        this.params = nTRUParameterSet;
    }

    private static int mod3(int i) {
        return i % 3;
    }

    public PolynomialPair sampleFg(byte[] bArr) {
        NTRUParameterSet nTRUParameterSet = this.params;
        if (nTRUParameterSet instanceof NTRUHRSSParameterSet) {
            return new PolynomialPair(sampleIidPlus(Arrays.copyOfRange(bArr, 0, nTRUParameterSet.sampleIidBytes())), sampleIidPlus(Arrays.copyOfRange(bArr, this.params.sampleIidBytes(), bArr.length)));
        }
        if (nTRUParameterSet instanceof NTRUHPSParameterSet) {
            return new PolynomialPair((HPSPolynomial) sampleIid(Arrays.copyOfRange(bArr, 0, nTRUParameterSet.sampleIidBytes())), sampleFixedType(Arrays.copyOfRange(bArr, this.params.sampleIidBytes(), bArr.length)));
        }
        throw new IllegalArgumentException("Invalid polynomial type");
    }

    public HPSPolynomial sampleFixedType(byte[] bArr) {
        int i;
        int i2;
        int m1n = this.params.m1n();
        int weight = ((NTRUHPSParameterSet) this.params).weight();
        HPSPolynomial hPSPolynomial = new HPSPolynomial((NTRUHPSParameterSet) this.params);
        int i3 = m1n - 1;
        int[] iArr = new int[i3];
        int i4 = 0;
        while (true) {
            i = i3 / 4;
            if (i4 >= i) {
                break;
            }
            int i5 = i4 * 4;
            int i6 = i4 * 15;
            iArr[i5] = ((bArr[i6] & UByte.MAX_VALUE) << 2) + ((bArr[i6 + 1] & UByte.MAX_VALUE) << 10) + ((bArr[i6 + 2] & UByte.MAX_VALUE) << 18) + ((bArr[i6 + 3] & UByte.MAX_VALUE) << 26);
            iArr[i5 + 1] = ((bArr[(i4 * 3) + 15] & 192) >> 4) + ((bArr[i6 + 4] & UByte.MAX_VALUE) << 4) + ((bArr[i6 + 5] & UByte.MAX_VALUE) << 12) + ((bArr[i6 + 6] & UByte.MAX_VALUE) << 20) + ((bArr[i6 + 7] & UByte.MAX_VALUE) << 28);
            int i7 = ((bArr[(i4 * 7) + 15] & 240) >> 2) + ((bArr[i6 + 8] & UByte.MAX_VALUE) << 6) + ((bArr[i6 + 9] & UByte.MAX_VALUE) << 14) + ((bArr[i6 + 10] & UByte.MAX_VALUE) << 22);
            byte b = bArr[i6 + 11];
            iArr[i5 + 2] = i7 + ((b & UByte.MAX_VALUE) << 30);
            iArr[i5 + 3] = (b & 252) + ((bArr[i6 + 12] & UByte.MAX_VALUE) << 8) + ((bArr[i6 + 13] & UByte.MAX_VALUE) << 16) + ((bArr[i6 + 14] & UByte.MAX_VALUE) << 24);
            i4++;
        }
        int i8 = i * 4;
        if (i3 > i8) {
            int i9 = i * 15;
            iArr[i8] = ((bArr[i9] & UByte.MAX_VALUE) << 2) + ((bArr[i9 + 1] & UByte.MAX_VALUE) << 10) + ((bArr[i9 + 2] & UByte.MAX_VALUE) << 18) + ((bArr[i9 + 3] & UByte.MAX_VALUE) << 26);
            iArr[i8 + 1] = ((bArr[(i * 3) + 15] & 192) >> 4) + ((bArr[i9 + 4] & UByte.MAX_VALUE) << 4) + ((bArr[i9 + 5] & UByte.MAX_VALUE) << 12) + ((bArr[i9 + 6] & UByte.MAX_VALUE) << 20) + ((bArr[i9 + 7] & UByte.MAX_VALUE) << 28);
        }
        int i10 = 0;
        while (true) {
            i2 = weight / 2;
            if (i10 >= i2) {
                break;
            }
            iArr[i10] = iArr[i10] | 1;
            i10++;
        }
        while (i2 < weight) {
            iArr[i2] = iArr[i2] | 2;
            i2++;
        }
        java.util.Arrays.sort(iArr);
        for (int i11 = 0; i11 < i3; i11++) {
            hPSPolynomial.coeffs[i11] = (short) (iArr[i11] & 3);
        }
        hPSPolynomial.coeffs[i3] = 0;
        return hPSPolynomial;
    }

    public Polynomial sampleIid(byte[] bArr) {
        Polynomial createPolynomial = this.params.createPolynomial();
        for (int i = 0; i < this.params.m1n() - 1; i++) {
            createPolynomial.coeffs[i] = (short) mod3(bArr[i] & UByte.MAX_VALUE);
        }
        createPolynomial.coeffs[this.params.m1n() - 1] = 0;
        return createPolynomial;
    }

    public HRSSPolynomial sampleIidPlus(byte[] bArr) {
        int i;
        int m1n = this.params.m1n();
        HRSSPolynomial hRSSPolynomial = (HRSSPolynomial) sampleIid(bArr);
        int i2 = 0;
        while (true) {
            i = m1n - 1;
            if (i2 >= i) {
                break;
            }
            hRSSPolynomial.coeffs[i2] = (short) (hRSSPolynomial.coeffs[i2] | (-(hRSSPolynomial.coeffs[i2] >>> 1)));
            i2++;
        }
        int i3 = 0;
        short s = 0;
        while (i3 < i) {
            int i4 = i3 + 1;
            s = (short) (s + ((short) (hRSSPolynomial.coeffs[i4] * hRSSPolynomial.coeffs[i3])));
            i3 = i4;
        }
        short s2 = (short) ((-((s & 65535) >>> 15)) | 1);
        for (int i5 = 0; i5 < i; i5 += 2) {
            hRSSPolynomial.coeffs[i5] = (short) (hRSSPolynomial.coeffs[i5] * s2);
        }
        for (int i6 = 0; i6 < i; i6++) {
            hRSSPolynomial.coeffs[i6] = (short) (((hRSSPolynomial.coeffs[i6] & 65535) ^ ((hRSSPolynomial.coeffs[i6] & 65535) >>> 15)) & 3);
        }
        return hRSSPolynomial;
    }

    public PolynomialPair sampleRm(byte[] bArr) {
        NTRUParameterSet nTRUParameterSet = this.params;
        if (nTRUParameterSet instanceof NTRUHRSSParameterSet) {
            return new PolynomialPair((HRSSPolynomial) sampleIid(Arrays.copyOfRange(bArr, 0, nTRUParameterSet.sampleIidBytes())), (HRSSPolynomial) sampleIid(Arrays.copyOfRange(bArr, this.params.sampleIidBytes(), bArr.length)));
        }
        if (nTRUParameterSet instanceof NTRUHPSParameterSet) {
            return new PolynomialPair((HPSPolynomial) sampleIid(Arrays.copyOfRange(bArr, 0, nTRUParameterSet.sampleIidBytes())), sampleFixedType(Arrays.copyOfRange(bArr, this.params.sampleIidBytes(), bArr.length)));
        }
        throw new IllegalArgumentException("Invalid polynomial type");
    }
}