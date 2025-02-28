package org.bouncycastle.pqc.crypto.mlkem;

import kotlin.UByte;
import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class PolyVec {
    private MLKEMEngine engine;
    private int kyberK;
    private int polyVecBytes;
    Poly[] vec;

    public PolyVec() throws Exception {
        throw new Exception("Requires Parameter");
    }

    public PolyVec(MLKEMEngine mLKEMEngine) {
        this.engine = mLKEMEngine;
        this.kyberK = mLKEMEngine.getKyberK();
        this.polyVecBytes = mLKEMEngine.getKyberPolyVecBytes();
        this.vec = new Poly[this.kyberK];
        for (int i = 0; i < this.kyberK; i++) {
            this.vec[i] = new Poly(mLKEMEngine);
        }
    }

    public static void pointwiseAccountMontgomery(Poly poly, PolyVec polyVec, PolyVec polyVec2, MLKEMEngine mLKEMEngine) {
        Poly poly2 = new Poly(mLKEMEngine);
        Poly.baseMultMontgomery(poly, polyVec.getVectorIndex(0), polyVec2.getVectorIndex(0));
        for (int i = 1; i < mLKEMEngine.getKyberK(); i++) {
            Poly.baseMultMontgomery(poly2, polyVec.getVectorIndex(i), polyVec2.getVectorIndex(i));
            poly.addCoeffs(poly2);
        }
        poly.reduce();
    }

    public void addPoly(PolyVec polyVec) {
        for (int i = 0; i < this.kyberK; i++) {
            getVectorIndex(i).addCoeffs(polyVec.getVectorIndex(i));
        }
    }

    public byte[] compressPolyVec() {
        conditionalSubQ();
        byte[] bArr = new byte[this.engine.getKyberPolyVecCompressedBytes()];
        int i = 32;
        int i2 = 4;
        if (this.engine.getKyberPolyVecCompressedBytes() == this.kyberK * 320) {
            short[] sArr = new short[4];
            int i3 = 0;
            int i4 = 0;
            while (i3 < this.kyberK) {
                int i5 = 0;
                while (i5 < 64) {
                    int i6 = 0;
                    while (i6 < i2) {
                        sArr[i6] = (short) (((((getVectorIndex(i3).getCoeffIndex((i5 * 4) + i6) << 10) + 1665) * 1290167) >> 32) & 1023);
                        i6++;
                        i2 = 4;
                    }
                    short s = sArr[0];
                    bArr[i4] = (byte) s;
                    short s2 = sArr[1];
                    bArr[i4 + 1] = (byte) ((s >> 8) | (s2 << 2));
                    short s3 = sArr[2];
                    bArr[i4 + 2] = (byte) ((s2 >> 6) | (s3 << 4));
                    int i7 = s3 >> 4;
                    short s4 = sArr[3];
                    bArr[i4 + 3] = (byte) ((s4 << 6) | i7);
                    bArr[i4 + 4] = (byte) (s4 >> 2);
                    i4 += 5;
                    i5++;
                    i2 = 4;
                }
                i3++;
                i2 = 4;
            }
        } else if (this.engine.getKyberPolyVecCompressedBytes() != this.kyberK * 352) {
            throw new RuntimeException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        } else {
            short[] sArr2 = new short[8];
            int i8 = 0;
            int i9 = 0;
            while (i8 < this.kyberK) {
                int i10 = 0;
                while (i10 < i) {
                    for (int i11 = 0; i11 < 8; i11++) {
                        sArr2[i11] = (short) (((((getVectorIndex(i8).getCoeffIndex((i10 * 8) + i11) << 11) + 1664) * 645084) >> 31) & 2047);
                    }
                    short s5 = sArr2[0];
                    bArr[i9] = (byte) s5;
                    short s6 = sArr2[1];
                    bArr[i9 + 1] = (byte) ((s5 >> 8) | (s6 << 3));
                    short s7 = sArr2[2];
                    bArr[i9 + 2] = (byte) ((s6 >> 5) | (s7 << 6));
                    bArr[i9 + 3] = (byte) (s7 >> 2);
                    int i12 = s7 >> 10;
                    short s8 = sArr2[3];
                    bArr[i9 + 4] = (byte) (i12 | (s8 << 1));
                    short s9 = sArr2[4];
                    bArr[i9 + 5] = (byte) ((s8 >> 7) | (s9 << 4));
                    short s10 = sArr2[5];
                    bArr[i9 + 6] = (byte) ((s9 >> 4) | (s10 << 7));
                    bArr[i9 + 7] = (byte) (s10 >> 1);
                    int i13 = s10 >> 9;
                    short s11 = sArr2[6];
                    bArr[i9 + 8] = (byte) (i13 | (s11 << 2));
                    int i14 = s11 >> 6;
                    short s12 = sArr2[7];
                    bArr[i9 + 9] = (byte) (i14 | (s12 << 5));
                    bArr[i9 + 10] = (byte) (s12 >> 3);
                    i9 += 11;
                    i10++;
                    i = 32;
                }
                i8++;
                i = 32;
            }
        }
        return bArr;
    }

    public void conditionalSubQ() {
        for (int i = 0; i < this.kyberK; i++) {
            getVectorIndex(i).conditionalSubQ();
        }
    }

    public void decompressPolyVec(byte[] bArr) {
        int i = 3;
        short s = 6;
        short s2 = 8;
        short s3 = 2;
        short s4 = 4;
        int i2 = 0;
        if (this.engine.getKyberPolyVecCompressedBytes() == this.kyberK * 320) {
            int i3 = 0;
            for (int i4 = 0; i4 < this.kyberK; i4++) {
                for (int i5 = 0; i5 < 64; i5++) {
                    int i6 = bArr[i3] & UByte.MAX_VALUE;
                    byte b = bArr[i3 + 1];
                    byte b2 = bArr[i3 + 2];
                    byte b3 = bArr[i3 + 3];
                    short[] sArr = {(short) (i6 | ((short) ((b & UByte.MAX_VALUE) << 8))), (short) (((b & UByte.MAX_VALUE) >> 2) | ((short) ((b2 & UByte.MAX_VALUE) << 6))), (short) (((b2 & UByte.MAX_VALUE) >> 4) | ((short) ((b3 & UByte.MAX_VALUE) << 4))), (short) (((b3 & UByte.MAX_VALUE) >> 6) | ((short) ((bArr[i3 + 4] & UByte.MAX_VALUE) << 2)))};
                    i3 += 5;
                    for (int i7 = 0; i7 < 4; i7++) {
                        this.vec[i4].setCoeffIndex((i5 * 4) + i7, (short) ((((sArr[i7] & 1023) * MLKEMEngine.KyberQ) + 512) >> 10));
                    }
                }
            }
        } else if (this.engine.getKyberPolyVecCompressedBytes() != this.kyberK * 352) {
            throw new RuntimeException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        } else {
            int i8 = 0;
            int i9 = 0;
            while (i8 < this.kyberK) {
                int i10 = i2;
                while (i10 < 32) {
                    int i11 = bArr[i9] & UByte.MAX_VALUE;
                    byte b4 = bArr[i9 + 1];
                    byte b5 = bArr[i9 + 2];
                    int i12 = ((b5 & UByte.MAX_VALUE) >> s) | (((short) (bArr[i9 + 3] & UByte.MAX_VALUE)) << s3);
                    byte b6 = bArr[i9 + 4];
                    byte b7 = bArr[i9 + 5];
                    int i13 = ((short) (b7 & UByte.MAX_VALUE)) << 7;
                    byte b8 = bArr[i9 + 6];
                    int i14 = ((short) (b8 & UByte.MAX_VALUE)) << s4;
                    int i15 = ((b8 & UByte.MAX_VALUE) >> 7) | (((short) (bArr[i9 + 7] & UByte.MAX_VALUE)) << 1);
                    byte b9 = bArr[i9 + 8];
                    int i16 = (b9 & UByte.MAX_VALUE) >> s3;
                    byte b10 = bArr[i9 + 9];
                    short[] sArr2 = {(short) (i11 | (((short) (b4 & UByte.MAX_VALUE)) << s2)), (short) (((b4 & UByte.MAX_VALUE) >> i) | (((short) (b5 & UByte.MAX_VALUE)) << 5)), (short) (((short) ((b6 & UByte.MAX_VALUE) << 10)) | i12), (short) (i13 | ((b6 & UByte.MAX_VALUE) >> 1)), (short) (i14 | ((b7 & UByte.MAX_VALUE) >> s4)), (short) (((short) ((b9 & UByte.MAX_VALUE) << 9)) | i15), (short) ((((short) (b10 & UByte.MAX_VALUE)) << s) | i16), (short) (((b10 & UByte.MAX_VALUE) >> 5) | (((short) (bArr[i9 + 10] & UByte.MAX_VALUE)) << 3))};
                    i9 += 11;
                    for (int i17 = 0; i17 < 8; i17++) {
                        this.vec[i8].setCoeffIndex((i10 * 8) + i17, (short) ((((sArr2[i17] & 2047) * MLKEMEngine.KyberQ) + 1024) >> 11));
                    }
                    i10++;
                    s = 6;
                    s3 = 2;
                    i2 = 0;
                    i = 3;
                    s4 = 4;
                    s2 = 8;
                }
                i8++;
                i = i;
                s4 = s4;
                s2 = s2;
            }
        }
    }

    public void fromBytes(byte[] bArr) {
        int i = 0;
        while (i < this.kyberK) {
            Poly vectorIndex = getVectorIndex(i);
            int i2 = i * MLKEMEngine.KyberPolyBytes;
            i++;
            vectorIndex.fromBytes(Arrays.copyOfRange(bArr, i2, i * MLKEMEngine.KyberPolyBytes));
        }
    }

    public Poly getVectorIndex(int i) {
        return this.vec[i];
    }

    public void polyVecInverseNttToMont() {
        for (int i = 0; i < this.kyberK; i++) {
            getVectorIndex(i).polyInverseNttToMont();
        }
    }

    public void polyVecNtt() {
        for (int i = 0; i < this.kyberK; i++) {
            getVectorIndex(i).polyNtt();
        }
    }

    public void reducePoly() {
        for (int i = 0; i < this.kyberK; i++) {
            getVectorIndex(i).reduce();
        }
    }

    public byte[] toBytes() {
        byte[] bArr = new byte[this.polyVecBytes];
        for (int i = 0; i < this.kyberK; i++) {
            System.arraycopy(this.vec[i].toBytes(), 0, bArr, i * MLKEMEngine.KyberPolyBytes, MLKEMEngine.KyberPolyBytes);
        }
        return bArr;
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer("[");
        for (int i = 0; i < this.kyberK; i++) {
            stringBuffer.append(this.vec[i].toString());
            if (i != this.kyberK - 1) {
                stringBuffer.append(", ");
            }
        }
        stringBuffer.append("]");
        return stringBuffer.toString();
    }
}