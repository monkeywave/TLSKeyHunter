package org.bouncycastle.pqc.crypto.mlkem;

import kotlin.UByte;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Poly {
    private MLKEMEngine engine;
    private int eta1;
    private int polyCompressedBytes;
    private Symmetric symmetric;
    private short[] coeffs = new short[256];
    private int eta2 = MLKEMEngine.getKyberEta2();

    public Poly(MLKEMEngine mLKEMEngine) {
        this.engine = mLKEMEngine;
        this.polyCompressedBytes = mLKEMEngine.getKyberPolyCompressedBytes();
        this.eta1 = mLKEMEngine.getKyberEta1();
        this.symmetric = mLKEMEngine.getSymmetric();
    }

    public static void baseMultMontgomery(Poly poly, Poly poly2, Poly poly3) {
        for (int i = 0; i < 64; i++) {
            int i2 = i * 4;
            int i3 = i2 + 1;
            int i4 = i + 64;
            Ntt.baseMult(poly, i2, poly2.getCoeffIndex(i2), poly2.getCoeffIndex(i3), poly3.getCoeffIndex(i2), poly3.getCoeffIndex(i3), Ntt.nttZetas[i4]);
            int i5 = i2 + 2;
            int i6 = i2 + 3;
            Ntt.baseMult(poly, i5, poly2.getCoeffIndex(i5), poly2.getCoeffIndex(i6), poly3.getCoeffIndex(i5), poly3.getCoeffIndex(i6), (short) (Ntt.nttZetas[i4] * (-1)));
        }
    }

    public void addCoeffs(Poly poly) {
        for (int i = 0; i < 256; i++) {
            setCoeffIndex(i, (short) (getCoeffIndex(i) + poly.getCoeffIndex(i)));
        }
    }

    public byte[] compressPoly() {
        int i = 8;
        byte[] bArr = new byte[8];
        byte[] bArr2 = new byte[this.polyCompressedBytes];
        conditionalSubQ();
        int i2 = this.polyCompressedBytes;
        if (i2 == 128) {
            int i3 = 0;
            int i4 = 0;
            while (i3 < 32) {
                int i5 = 0;
                while (i5 < i) {
                    bArr[i5] = (byte) (((((getCoeffIndex((i3 * 8) + i5) << 4) + 1665) * 80635) >> 28) & 15);
                    i5++;
                    i = 8;
                }
                bArr2[i4] = (byte) (bArr[0] | (bArr[1] << 4));
                bArr2[i4 + 1] = (byte) (bArr[2] | (bArr[3] << 4));
                bArr2[i4 + 2] = (byte) (bArr[4] | (bArr[5] << 4));
                bArr2[i4 + 3] = (byte) (bArr[6] | (bArr[7] << 4));
                i4 += 4;
                i3++;
                i = 8;
            }
        } else if (i2 != 160) {
            throw new RuntimeException("PolyCompressedBytes is neither 128 or 160!");
        } else {
            int i6 = 0;
            int i7 = 0;
            for (int i8 = 32; i6 < i8; i8 = 32) {
                for (int i9 = 0; i9 < 8; i9++) {
                    bArr[i9] = (byte) (((((getCoeffIndex((i6 * 8) + i9) << 5) + 1664) * 40318) >> 27) & 31);
                }
                bArr2[i7] = (byte) (bArr[0] | (bArr[1] << 5));
                bArr2[i7 + 1] = (byte) ((bArr[1] >> 3) | (bArr[2] << 2) | (bArr[3] << 7));
                bArr2[i7 + 2] = (byte) ((bArr[3] >> 1) | (bArr[4] << 4));
                bArr2[i7 + 3] = (byte) ((bArr[4] >> 4) | (bArr[5] << 1) | (bArr[6] << 6));
                bArr2[i7 + 4] = (byte) ((bArr[6] >> 2) | (bArr[7] << 3));
                i7 += 5;
                i6++;
            }
        }
        return bArr2;
    }

    public void conditionalSubQ() {
        for (int i = 0; i < 256; i++) {
            setCoeffIndex(i, Reduce.conditionalSubQ(getCoeffIndex(i)));
        }
    }

    public void convertToMont() {
        for (int i = 0; i < 256; i++) {
            setCoeffIndex(i, Reduce.montgomeryReduce(getCoeffIndex(i) * 1353));
        }
    }

    public void decompressPoly(byte[] bArr) {
        int i = 4;
        int i2 = 1;
        if (this.engine.getKyberPolyCompressedBytes() == 128) {
            int i3 = 0;
            for (int i4 = 0; i4 < 128; i4++) {
                int i5 = i4 * 2;
                setCoeffIndex(i5, (short) (((((short) (bArr[i3] & 15)) * 3329) + 8) >> 4));
                setCoeffIndex(i5 + 1, (short) (((((short) ((bArr[i3] & UByte.MAX_VALUE) >> 4)) * 3329) + 8) >> 4));
                i3++;
            }
        } else if (this.engine.getKyberPolyCompressedBytes() != 160) {
            throw new RuntimeException("PolyCompressedBytes is neither 128 or 160!");
        } else {
            int i6 = 0;
            int i7 = 0;
            while (i6 < 32) {
                byte b = bArr[i7];
                byte b2 = bArr[i7 + 1];
                byte b3 = bArr[i7 + 2];
                byte b4 = bArr[i7 + 3];
                int i8 = (b4 & UByte.MAX_VALUE) << i;
                byte b5 = bArr[i7 + 4];
                byte[] bArr2 = {(byte) (b & UByte.MAX_VALUE), (byte) (((b & UByte.MAX_VALUE) >> 5) | ((b2 & UByte.MAX_VALUE) << 3)), (byte) ((b2 & UByte.MAX_VALUE) >> 2), (byte) (((b2 & UByte.MAX_VALUE) >> 7) | ((b3 & UByte.MAX_VALUE) << i2)), (byte) (i8 | ((b3 & UByte.MAX_VALUE) >> i)), (byte) ((b4 & UByte.MAX_VALUE) >> i2), (byte) (((b5 & UByte.MAX_VALUE) << 2) | ((b4 & UByte.MAX_VALUE) >> 6)), (byte) ((b5 & UByte.MAX_VALUE) >> 3)};
                i7 += 5;
                for (int i9 = 0; i9 < 8; i9++) {
                    setCoeffIndex((i6 * 8) + i9, (short) ((((bArr2[i9] & 31) * MLKEMEngine.KyberQ) + 16) >> 5));
                }
                i6++;
                i = 4;
                i2 = 1;
            }
        }
    }

    public void fromBytes(byte[] bArr) {
        for (int i = 0; i < 128; i++) {
            int i2 = i * 2;
            int i3 = i * 3;
            int i4 = i3 + 1;
            setCoeffIndex(i2, (short) (((bArr[i3] & UByte.MAX_VALUE) | ((bArr[i4] & UByte.MAX_VALUE) << 8)) & 4095));
            setCoeffIndex(i2 + 1, (short) ((((bArr[i4] & UByte.MAX_VALUE) >> 4) | ((bArr[i3 + 2] & UByte.MAX_VALUE) << 4)) & 4095));
        }
    }

    public void fromMsg(byte[] bArr) {
        if (bArr.length != 32) {
            throw new RuntimeException("KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!");
        }
        for (int i = 0; i < 32; i++) {
            for (int i2 = 0; i2 < 8; i2++) {
                setCoeffIndex((i * 8) + i2, (short) (((short) (((short) (((bArr[i] & UByte.MAX_VALUE) >> i2) & 1)) * (-1))) & 1665));
            }
        }
    }

    public short getCoeffIndex(int i) {
        return this.coeffs[i];
    }

    public short[] getCoeffs() {
        return this.coeffs;
    }

    public void getEta1Noise(byte[] bArr, byte b) {
        byte[] bArr2 = new byte[(this.eta1 * 256) / 4];
        this.symmetric.prf(bArr2, bArr, b);
        CBD.mlkemCBD(this, bArr2, this.eta1);
    }

    public void getEta2Noise(byte[] bArr, byte b) {
        byte[] bArr2 = new byte[(this.eta2 * 256) / 4];
        this.symmetric.prf(bArr2, bArr, b);
        CBD.mlkemCBD(this, bArr2, this.eta2);
    }

    public void polyInverseNttToMont() {
        setCoeffs(Ntt.invNtt(getCoeffs()));
    }

    public void polyNtt() {
        setCoeffs(Ntt.ntt(getCoeffs()));
        reduce();
    }

    public void polySubtract(Poly poly) {
        for (int i = 0; i < 256; i++) {
            setCoeffIndex(i, (short) (poly.getCoeffIndex(i) - getCoeffIndex(i)));
        }
    }

    public void reduce() {
        for (int i = 0; i < 256; i++) {
            setCoeffIndex(i, Reduce.barretReduce(getCoeffIndex(i)));
        }
    }

    public void setCoeffIndex(int i, short s) {
        this.coeffs[i] = s;
    }

    public void setCoeffs(short[] sArr) {
        this.coeffs = sArr;
    }

    public byte[] toBytes() {
        byte[] bArr = new byte[MLKEMEngine.KyberPolyBytes];
        conditionalSubQ();
        for (int i = 0; i < 128; i++) {
            int i2 = i * 2;
            short coeffIndex = getCoeffIndex(i2);
            short coeffIndex2 = getCoeffIndex(i2 + 1);
            int i3 = i * 3;
            bArr[i3] = (byte) coeffIndex;
            bArr[i3 + 1] = (byte) ((coeffIndex >> 8) | (coeffIndex2 << 4));
            bArr[i3 + 2] = (byte) (coeffIndex2 >> 4);
        }
        return bArr;
    }

    public byte[] toMsg() {
        byte[] bArr = new byte[MLKEMEngine.getKyberIndCpaMsgBytes()];
        conditionalSubQ();
        for (int i = 0; i < 32; i++) {
            bArr[i] = 0;
            for (int i2 = 0; i2 < 8; i2++) {
                short coeffIndex = getCoeffIndex((i * 8) + i2);
                bArr[i] = (byte) (((byte) ((((coeffIndex - 2497) & (832 - coeffIndex)) >>> 31) << i2)) | bArr[i]);
            }
        }
        return bArr;
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer("[");
        int i = 0;
        while (true) {
            short[] sArr = this.coeffs;
            if (i >= sArr.length) {
                stringBuffer.append("]");
                return stringBuffer.toString();
            }
            stringBuffer.append((int) sArr[i]);
            if (i != this.coeffs.length - 1) {
                stringBuffer.append(", ");
            }
            i++;
        }
    }
}