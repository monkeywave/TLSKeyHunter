package org.bouncycastle.pqc.crypto.picnic;

import java.lang.reflect.Array;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Tape {
    private PicnicEngine engine;
    int nTapes;
    int pos = 0;
    byte[][] tapes;

    public Tape(PicnicEngine picnicEngine) {
        this.engine = picnicEngine;
        this.tapes = (byte[][]) Array.newInstance(Byte.TYPE, picnicEngine.numMPCParties, picnicEngine.andSizeBytes * 2);
        this.nTapes = picnicEngine.numMPCParties;
    }

    private void tapesToParityBits(int[] iArr, int i) {
        for (int i2 = 0; i2 < i; i2++) {
            Utils.setBitInWordArray(iArr, i2, Utils.parity16(tapesToWord()));
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void computeAuxTape(byte[] bArr) {
        int[] iArr = new int[16];
        int[] iArr2 = new int[16];
        int[] iArr3 = new int[16];
        int[] iArr4 = new int[16];
        int[] iArr5 = new int[16];
        iArr5[this.engine.stateSizeWords - 1] = 0;
        tapesToParityBits(iArr5, this.engine.stateSizeBits);
        KMatricesWithPointer KMatrixInv = this.engine.lowmcConstants.KMatrixInv(this.engine);
        this.engine.matrix_mul(iArr4, iArr5, KMatrixInv.getData(), KMatrixInv.getMatrixPointer());
        if (bArr != null) {
            Pack.intToLittleEndian(iArr4, 0, this.engine.stateSizeWords, bArr, 0);
        }
        for (int i = this.engine.numRounds; i > 0; i--) {
            KMatricesWithPointer KMatrix = this.engine.lowmcConstants.KMatrix(this.engine, i);
            this.engine.matrix_mul(iArr, iArr4, KMatrix.getData(), KMatrix.getMatrixPointer());
            this.engine.xor_array(iArr2, iArr2, iArr, 0);
            int i2 = i - 1;
            KMatricesWithPointer LMatrixInv = this.engine.lowmcConstants.LMatrixInv(this.engine, i2);
            this.engine.matrix_mul(iArr3, iArr2, LMatrixInv.getData(), LMatrixInv.getMatrixPointer());
            if (i == 1) {
                System.arraycopy(iArr5, 0, iArr2, 0, 16);
            } else {
                this.pos = this.engine.stateSizeBits * 2 * i2;
                tapesToParityBits(iArr2, this.engine.stateSizeBits);
            }
            this.pos = (this.engine.stateSizeBits * 2 * i2) + this.engine.stateSizeBits;
            this.engine.aux_mpc_sbox(iArr2, iArr3, this);
        }
        this.pos = 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setAuxBits(byte[] bArr) {
        int i = this.engine.numMPCParties - 1;
        int i2 = this.engine.stateSizeBits;
        int i3 = 0;
        for (int i4 = 0; i4 < this.engine.numRounds; i4++) {
            int i5 = 0;
            while (i5 < i2) {
                Utils.setBit(this.tapes[i], (i2 * 2 * i4) + i2 + i5, Utils.getBit(bArr, i3));
                i5++;
                i3++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int tapesToWord() {
        int i = this.pos;
        int i2 = i >>> 3;
        int i3 = (i & 7) ^ 7;
        int i4 = 1 << i3;
        byte[][] bArr = this.tapes;
        int i5 = bArr[7][i2] & i4;
        int i6 = (bArr[15][i2] & i4) << 8;
        this.pos = i + 1;
        return (i6 | ((((((((i5 | ((((((((bArr[0][i2] & i4) << 7) | ((bArr[1][i2] & i4) << 6)) | ((bArr[2][i2] & i4) << 5)) | ((bArr[3][i2] & i4) << 4)) | ((bArr[4][i2] & i4) << 3)) | ((bArr[5][i2] & i4) << 2)) | ((bArr[6][i2] & i4) << 1))) | ((bArr[8][i2] & i4) << 15)) | ((bArr[9][i2] & i4) << 14)) | ((bArr[10][i2] & i4) << 13)) | ((bArr[11][i2] & i4) << 12)) | ((bArr[12][i2] & i4) << 11)) | ((bArr[13][i2] & i4) << 10)) | ((bArr[14][i2] & i4) << 9))) >>> i3;
    }
}