package org.bouncycastle.pqc.crypto.picnic;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Properties;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class LowmcConstants {
    protected KMatrices KMatrix;
    protected KMatrices KMatrix_full;
    protected KMatrices KMatrix_inv;
    protected KMatrices LMatrix;
    protected KMatrices LMatrix_full;
    protected KMatrices LMatrix_inv;
    protected KMatrices RConstants;
    protected KMatrices RConstants_full;
    protected int[] keyMatrices;
    protected int[] keyMatrices_full;
    protected int[] keyMatrices_inv;
    protected int[] linearMatrices;
    protected int[] linearMatrices_full;
    protected int[] linearMatrices_inv;
    protected int[] roundConstants;
    protected int[] roundConstants_full;

    private KMatricesWithPointer GET_MAT(KMatrices kMatrices, int i) {
        KMatricesWithPointer kMatricesWithPointer = new KMatricesWithPointer(kMatrices);
        kMatricesWithPointer.setMatrixPointer(i * kMatricesWithPointer.getSize());
        return kMatricesWithPointer;
    }

    static int[] ReadFromProperty(Properties properties, String str, int i) {
        byte[] decode = Hex.decode(removeCommas(properties.getProperty(str)));
        int[] iArr = new int[i];
        for (int i2 = 0; i2 < decode.length / 4; i2++) {
            iArr[i2] = Pack.littleEndianToInt(decode, i2 * 4);
        }
        return iArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int[] readArray(DataInputStream dataInputStream) throws IOException {
        int readInt = dataInputStream.readInt();
        int[] iArr = new int[readInt];
        for (int i = 0; i != readInt; i++) {
            iArr[i] = dataInputStream.readInt();
        }
        return iArr;
    }

    private static byte[] removeCommas(String str) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = 0; i != str.length(); i++) {
            if (str.charAt(i) != ',') {
                byteArrayOutputStream.write(str.charAt(i));
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x001f, code lost:
        if (r3.numRounds == 4) goto L9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer KMatrix(org.bouncycastle.pqc.crypto.picnic.PicnicEngine r3, int r4) {
        /*
            r2 = this;
            int r0 = r3.stateSizeBits
            r1 = 128(0x80, float:1.8E-43)
            if (r0 != r1) goto Ld
        L6:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.KMatrix
        L8:
            org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer r3 = r2.GET_MAT(r3, r4)
            return r3
        Ld:
            int r0 = r3.stateSizeBits
            r1 = 129(0x81, float:1.81E-43)
            if (r0 != r1) goto L16
        L13:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.KMatrix_full
            goto L8
        L16:
            int r0 = r3.stateSizeBits
            r1 = 192(0xc0, float:2.69E-43)
            if (r0 != r1) goto L22
            int r3 = r3.numRounds
            r0 = 4
            if (r3 != r0) goto L6
            goto L13
        L22:
            int r0 = r3.stateSizeBits
            r1 = 255(0xff, float:3.57E-43)
            if (r0 != r1) goto L29
            goto L13
        L29:
            int r3 = r3.stateSizeBits
            r0 = 256(0x100, float:3.59E-43)
            if (r3 != r0) goto L30
            goto L6
        L30:
            r3 = 0
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.picnic.LowmcConstants.KMatrix(org.bouncycastle.pqc.crypto.picnic.PicnicEngine, int):org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public KMatricesWithPointer KMatrixInv(PicnicEngine picnicEngine) {
        if (picnicEngine.stateSizeBits == 129 || ((picnicEngine.stateSizeBits == 192 && picnicEngine.numRounds == 4) || picnicEngine.stateSizeBits == 255)) {
            return GET_MAT(this.KMatrix_inv, 0);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x001f, code lost:
        if (r3.numRounds == 4) goto L9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer LMatrix(org.bouncycastle.pqc.crypto.picnic.PicnicEngine r3, int r4) {
        /*
            r2 = this;
            int r0 = r3.stateSizeBits
            r1 = 128(0x80, float:1.8E-43)
            if (r0 != r1) goto Ld
        L6:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.LMatrix
        L8:
            org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer r3 = r2.GET_MAT(r3, r4)
            return r3
        Ld:
            int r0 = r3.stateSizeBits
            r1 = 129(0x81, float:1.81E-43)
            if (r0 != r1) goto L16
        L13:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.LMatrix_full
            goto L8
        L16:
            int r0 = r3.stateSizeBits
            r1 = 192(0xc0, float:2.69E-43)
            if (r0 != r1) goto L22
            int r3 = r3.numRounds
            r0 = 4
            if (r3 != r0) goto L6
            goto L13
        L22:
            int r0 = r3.stateSizeBits
            r1 = 255(0xff, float:3.57E-43)
            if (r0 != r1) goto L29
            goto L13
        L29:
            int r3 = r3.stateSizeBits
            r0 = 256(0x100, float:3.59E-43)
            if (r3 != r0) goto L30
            goto L6
        L30:
            r3 = 0
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.picnic.LowmcConstants.LMatrix(org.bouncycastle.pqc.crypto.picnic.PicnicEngine, int):org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public KMatricesWithPointer LMatrixInv(PicnicEngine picnicEngine, int i) {
        if (picnicEngine.stateSizeBits == 129 || ((picnicEngine.stateSizeBits == 192 && picnicEngine.numRounds == 4) || picnicEngine.stateSizeBits == 255)) {
            return GET_MAT(this.LMatrix_inv, i);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x001f, code lost:
        if (r3.numRounds == 4) goto L9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer RConstant(org.bouncycastle.pqc.crypto.picnic.PicnicEngine r3, int r4) {
        /*
            r2 = this;
            int r0 = r3.stateSizeBits
            r1 = 128(0x80, float:1.8E-43)
            if (r0 != r1) goto Ld
        L6:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.RConstants
        L8:
            org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer r3 = r2.GET_MAT(r3, r4)
            return r3
        Ld:
            int r0 = r3.stateSizeBits
            r1 = 129(0x81, float:1.81E-43)
            if (r0 != r1) goto L16
        L13:
            org.bouncycastle.pqc.crypto.picnic.KMatrices r3 = r2.RConstants_full
            goto L8
        L16:
            int r0 = r3.stateSizeBits
            r1 = 192(0xc0, float:2.69E-43)
            if (r0 != r1) goto L22
            int r3 = r3.numRounds
            r0 = 4
            if (r3 != r0) goto L6
            goto L13
        L22:
            int r0 = r3.stateSizeBits
            r1 = 255(0xff, float:3.57E-43)
            if (r0 != r1) goto L29
            goto L13
        L29:
            int r3 = r3.stateSizeBits
            r0 = 256(0x100, float:3.59E-43)
            if (r3 != r0) goto L30
            goto L6
        L30:
            r3 = 0
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.picnic.LowmcConstants.RConstant(org.bouncycastle.pqc.crypto.picnic.PicnicEngine, int):org.bouncycastle.pqc.crypto.picnic.KMatricesWithPointer");
    }
}