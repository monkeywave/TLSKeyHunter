package org.bouncycastle.pqc.math.ntru;

import kotlin.UByte;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;

/* loaded from: classes2.dex */
public class HRSS1373Polynomial extends HRSSPolynomial {

    /* renamed from: K */
    private static final int f1541K = 86;

    /* renamed from: L */
    private static final int f1542L = 1376;

    /* renamed from: M */
    private static final int f1543M = 344;

    public HRSS1373Polynomial(NTRUHRSSParameterSet nTRUHRSSParameterSet) {
        super(nTRUHRSSParameterSet);
    }

    @Override // org.bouncycastle.pqc.math.ntru.HRSSPolynomial, org.bouncycastle.pqc.math.ntru.Polynomial
    public void sqFromBytes(byte[] bArr) {
        int i = 0;
        while (i < this.params.packDegree() / 4) {
            int i2 = i * 4;
            int i3 = i * 7;
            int i4 = i3 + 1;
            this.coeffs[i2] = (short) ((bArr[i3] & UByte.MAX_VALUE) | ((((short) (bArr[i4] & UByte.MAX_VALUE)) & 63) << 8));
            int i5 = i3 + 3;
            this.coeffs[i2 + 1] = (short) (((bArr[i4] & UByte.MAX_VALUE) >>> 6) | (((short) (bArr[i3 + 2] & UByte.MAX_VALUE)) << 2) | (((short) (bArr[i5] & 15)) << 10));
            int i6 = ((bArr[i5] & UByte.MAX_VALUE) >>> 4) | ((((short) (bArr[i3 + 4] & UByte.MAX_VALUE)) & 255) << 4);
            int i7 = i3 + 5;
            this.coeffs[i2 + 2] = (short) (i6 | (((short) (bArr[i7] & 3)) << 12));
            this.coeffs[i2 + 3] = (short) (((bArr[i7] & UByte.MAX_VALUE) >>> 2) | (((short) (bArr[i3 + 6] & UByte.MAX_VALUE)) << 6));
            i++;
        }
        if (this.params.packDegree() % 4 == 2) {
            int i8 = i * 4;
            int i9 = i * 7;
            int i10 = i9 + 1;
            this.coeffs[i8] = (short) (bArr[i9] | ((bArr[i10] & 63) << 8));
            this.coeffs[i8 + 1] = (short) (((bArr[i9 + 3] & 15) << 10) | (bArr[i9 + 2] << 2) | (bArr[i10] >>> 6));
        }
        this.coeffs[this.params.m1n() - 1] = 0;
    }

    @Override // org.bouncycastle.pqc.math.ntru.HRSSPolynomial, org.bouncycastle.pqc.math.ntru.Polynomial
    public byte[] sqToBytes(int i) {
        byte[] bArr = new byte[i];
        short[] sArr = new short[4];
        int i2 = 0;
        while (i2 < this.params.packDegree() / 4) {
            for (int i3 = 0; i3 < 4; i3++) {
                sArr[i3] = (short) modQ(this.coeffs[(i2 * 4) + i3] & 65535, this.params.m0q());
            }
            int i4 = i2 * 7;
            short s = sArr[0];
            bArr[i4] = (byte) (s & 255);
            short s2 = sArr[1];
            bArr[i4 + 1] = (byte) ((s >>> 8) | ((s2 & 3) << 6));
            bArr[i4 + 2] = (byte) ((s2 >>> 2) & 255);
            short s3 = sArr[2];
            bArr[i4 + 3] = (byte) ((s2 >>> 10) | ((s3 & 15) << 4));
            bArr[i4 + 4] = (byte) ((s3 >>> 4) & 255);
            short s4 = sArr[3];
            bArr[i4 + 5] = (byte) ((s3 >>> 12) | ((s4 & 63) << 2));
            bArr[i4 + 6] = (byte) (s4 >>> 6);
            i2++;
        }
        if (this.params.packDegree() % 4 == 2) {
            sArr[0] = (short) modQ(this.coeffs[this.params.packDegree() - 2] & 65535, this.params.m0q());
            short modQ = (short) modQ(this.coeffs[this.params.packDegree() - 1] & 65535, this.params.m0q());
            sArr[1] = modQ;
            int i5 = i2 * 7;
            short s5 = sArr[0];
            bArr[i5] = (byte) (s5 & 255);
            bArr[i5 + 1] = (byte) ((s5 >>> 8) | ((modQ & 3) << 6));
            bArr[i5 + 2] = (byte) ((modQ >>> 2) & 255);
            bArr[i5 + 3] = (byte) (modQ >>> 10);
        }
        return bArr;
    }
}