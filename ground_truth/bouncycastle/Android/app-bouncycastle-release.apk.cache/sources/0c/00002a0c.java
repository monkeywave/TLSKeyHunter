package org.bouncycastle.pqc.crypto.mlkem;

import kotlin.UByte;
import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class MLKEMIndCpa {
    public final int KyberGenerateMatrixNBlocks;
    private MLKEMEngine engine;
    private int eta1;
    private int indCpaBytes;
    private int indCpaPublicKeyBytes;
    private int kyberK;
    private int polyCompressedBytes;
    private int polyVecBytes;
    private int polyVecCompressedBytes;
    private Symmetric symmetric;

    public MLKEMIndCpa(MLKEMEngine mLKEMEngine) {
        this.engine = mLKEMEngine;
        this.kyberK = mLKEMEngine.getKyberK();
        this.eta1 = mLKEMEngine.getKyberEta1();
        this.indCpaPublicKeyBytes = mLKEMEngine.getKyberPublicKeyBytes();
        this.polyVecBytes = mLKEMEngine.getKyberPolyVecBytes();
        this.indCpaBytes = mLKEMEngine.getKyberIndCpaBytes();
        this.polyVecCompressedBytes = mLKEMEngine.getKyberPolyVecCompressedBytes();
        this.polyCompressedBytes = mLKEMEngine.getKyberPolyCompressedBytes();
        Symmetric symmetric = mLKEMEngine.getSymmetric();
        this.symmetric = symmetric;
        this.KyberGenerateMatrixNBlocks = (symmetric.xofBlockBytes + 472) / this.symmetric.xofBlockBytes;
    }

    private byte[] packCipherText(PolyVec polyVec, Poly poly) {
        byte[] bArr = new byte[this.indCpaBytes];
        System.arraycopy(polyVec.compressPolyVec(), 0, bArr, 0, this.polyVecCompressedBytes);
        System.arraycopy(poly.compressPoly(), 0, bArr, this.polyVecCompressedBytes, this.polyCompressedBytes);
        return bArr;
    }

    private static int rejectionSampling(Poly poly, int i, int i2, byte[] bArr, int i3) {
        int i4 = 0;
        int i5 = 0;
        while (i4 < i2) {
            int i6 = i5 + 3;
            if (i6 > i3) {
                break;
            }
            byte b = bArr[i5 + 1];
            short s = (short) ((((short) (bArr[i5] & UByte.MAX_VALUE)) | (((short) (b & UByte.MAX_VALUE)) << 8)) & 4095);
            short s2 = (short) (((((short) (bArr[i5 + 2] & UByte.MAX_VALUE)) << 4) | (((short) (b & UByte.MAX_VALUE)) >> 4)) & 4095);
            if (s < 3329) {
                poly.setCoeffIndex(i + i4, s);
                i4++;
            }
            if (i4 < i2 && s2 < 3329) {
                poly.setCoeffIndex(i + i4, s2);
                i4++;
            }
            i5 = i6;
        }
        return i4;
    }

    private void unpackCipherText(PolyVec polyVec, Poly poly, byte[] bArr) {
        polyVec.decompressPolyVec(Arrays.copyOfRange(bArr, 0, this.engine.getKyberPolyVecCompressedBytes()));
        poly.decompressPoly(Arrays.copyOfRange(bArr, this.engine.getKyberPolyVecCompressedBytes(), bArr.length));
    }

    public byte[] decrypt(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[MLKEMEngine.getKyberIndCpaMsgBytes()];
        PolyVec polyVec = new PolyVec(this.engine);
        PolyVec polyVec2 = new PolyVec(this.engine);
        Poly poly = new Poly(this.engine);
        Poly poly2 = new Poly(this.engine);
        unpackCipherText(polyVec, poly, bArr2);
        unpackSecretKey(polyVec2, bArr);
        polyVec.polyVecNtt();
        PolyVec.pointwiseAccountMontgomery(poly2, polyVec2, polyVec, this.engine);
        poly2.polyInverseNttToMont();
        poly2.polySubtract(poly);
        poly2.reduce();
        return poly2.toMsg();
    }

    public byte[] encrypt(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        PolyVec polyVec = new PolyVec(this.engine);
        PolyVec polyVec2 = new PolyVec(this.engine);
        PolyVec polyVec3 = new PolyVec(this.engine);
        PolyVec polyVec4 = new PolyVec(this.engine);
        PolyVec[] polyVecArr = new PolyVec[this.engine.getKyberK()];
        Poly poly = new Poly(this.engine);
        Poly poly2 = new Poly(this.engine);
        Poly poly3 = new Poly(this.engine);
        byte[] unpackPublicKey = unpackPublicKey(polyVec2, bArr);
        poly3.fromMsg(bArr2);
        for (int i = 0; i < this.kyberK; i++) {
            polyVecArr[i] = new PolyVec(this.engine);
        }
        generateMatrix(polyVecArr, unpackPublicKey, true);
        byte b = 0;
        for (int i2 = 0; i2 < this.kyberK; i2++) {
            polyVec.getVectorIndex(i2).getEta1Noise(bArr3, b);
            b = (byte) (b + 1);
        }
        for (int i3 = 0; i3 < this.kyberK; i3++) {
            polyVec3.getVectorIndex(i3).getEta2Noise(bArr3, b);
            b = (byte) (b + 1);
        }
        poly.getEta2Noise(bArr3, b);
        polyVec.polyVecNtt();
        for (int i4 = 0; i4 < this.kyberK; i4++) {
            PolyVec.pointwiseAccountMontgomery(polyVec4.getVectorIndex(i4), polyVecArr[i4], polyVec, this.engine);
        }
        PolyVec.pointwiseAccountMontgomery(poly2, polyVec2, polyVec, this.engine);
        polyVec4.polyVecInverseNttToMont();
        poly2.polyInverseNttToMont();
        polyVec4.addPoly(polyVec3);
        poly2.addCoeffs(poly);
        poly2.addCoeffs(poly3);
        polyVec4.reducePoly();
        poly2.reduce();
        return packCipherText(polyVec4, poly2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[][] generateKeyPair(byte[] bArr) {
        PolyVec polyVec = new PolyVec(this.engine);
        PolyVec polyVec2 = new PolyVec(this.engine);
        PolyVec polyVec3 = new PolyVec(this.engine);
        byte[] bArr2 = new byte[64];
        this.symmetric.hash_g(bArr2, Arrays.concatenate(bArr, new byte[]{(byte) this.kyberK}));
        byte[] bArr3 = new byte[32];
        byte[] bArr4 = new byte[32];
        System.arraycopy(bArr2, 0, bArr3, 0, 32);
        System.arraycopy(bArr2, 32, bArr4, 0, 32);
        PolyVec[] polyVecArr = new PolyVec[this.kyberK];
        for (int i = 0; i < this.kyberK; i++) {
            polyVecArr[i] = new PolyVec(this.engine);
        }
        generateMatrix(polyVecArr, bArr3, false);
        byte b = 0;
        for (int i2 = 0; i2 < this.kyberK; i2++) {
            polyVec.getVectorIndex(i2).getEta1Noise(bArr4, b);
            b = (byte) (b + 1);
        }
        for (int i3 = 0; i3 < this.kyberK; i3++) {
            polyVec3.getVectorIndex(i3).getEta1Noise(bArr4, b);
            b = (byte) (b + 1);
        }
        polyVec.polyVecNtt();
        polyVec3.polyVecNtt();
        for (int i4 = 0; i4 < this.kyberK; i4++) {
            PolyVec.pointwiseAccountMontgomery(polyVec2.getVectorIndex(i4), polyVecArr[i4], polyVec, this.engine);
            polyVec2.getVectorIndex(i4).convertToMont();
        }
        polyVec2.addPoly(polyVec3);
        polyVec2.reducePoly();
        return new byte[][]{packPublicKey(polyVec2, bArr3), packSecretKey(polyVec)};
    }

    public void generateMatrix(PolyVec[] polyVecArr, byte[] bArr, boolean z) {
        byte b;
        byte b2;
        byte[] bArr2 = new byte[(this.KyberGenerateMatrixNBlocks * this.symmetric.xofBlockBytes) + 2];
        for (int i = 0; i < this.kyberK; i++) {
            for (int i2 = 0; i2 < this.kyberK; i2++) {
                Symmetric symmetric = this.symmetric;
                if (z) {
                    b = (byte) i;
                    b2 = (byte) i2;
                } else {
                    b = (byte) i2;
                    b2 = (byte) i;
                }
                symmetric.xofAbsorb(bArr, b, b2);
                Symmetric symmetric2 = this.symmetric;
                symmetric2.xofSqueezeBlocks(bArr2, 0, symmetric2.xofBlockBytes * this.KyberGenerateMatrixNBlocks);
                int i3 = this.KyberGenerateMatrixNBlocks * this.symmetric.xofBlockBytes;
                int rejectionSampling = rejectionSampling(polyVecArr[i].getVectorIndex(i2), 0, 256, bArr2, i3);
                while (rejectionSampling < 256) {
                    int i4 = i3 % 3;
                    for (int i5 = 0; i5 < i4; i5++) {
                        bArr2[i5] = bArr2[(i3 - i4) + i5];
                    }
                    Symmetric symmetric3 = this.symmetric;
                    symmetric3.xofSqueezeBlocks(bArr2, i4, symmetric3.xofBlockBytes * 2);
                    i3 = this.symmetric.xofBlockBytes + i4;
                    rejectionSampling += rejectionSampling(polyVecArr[i].getVectorIndex(i2), rejectionSampling, 256 - rejectionSampling, bArr2, i3);
                }
            }
        }
    }

    public byte[] packPublicKey(PolyVec polyVec, byte[] bArr) {
        byte[] bArr2 = new byte[this.indCpaPublicKeyBytes];
        System.arraycopy(polyVec.toBytes(), 0, bArr2, 0, this.polyVecBytes);
        System.arraycopy(bArr, 0, bArr2, this.polyVecBytes, 32);
        return bArr2;
    }

    public byte[] packSecretKey(PolyVec polyVec) {
        return polyVec.toBytes();
    }

    public byte[] unpackPublicKey(PolyVec polyVec, byte[] bArr) {
        byte[] bArr2 = new byte[32];
        polyVec.fromBytes(bArr);
        System.arraycopy(bArr, this.polyVecBytes, bArr2, 0, 32);
        return bArr2;
    }

    public void unpackSecretKey(PolyVec polyVec, byte[] bArr) {
        polyVec.fromBytes(bArr);
    }
}