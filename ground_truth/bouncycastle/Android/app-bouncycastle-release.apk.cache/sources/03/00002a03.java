package org.bouncycastle.pqc.crypto.mldsa;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class PolyVecMatrix {
    private final int dilithiumK;
    private final int dilithiumL;
    private final PolyVecL[] mat;

    public PolyVecMatrix(MLDSAEngine mLDSAEngine) {
        int dilithiumK = mLDSAEngine.getDilithiumK();
        this.dilithiumK = dilithiumK;
        this.dilithiumL = mLDSAEngine.getDilithiumL();
        this.mat = new PolyVecL[dilithiumK];
        for (int i = 0; i < this.dilithiumK; i++) {
            this.mat[i] = new PolyVecL(mLDSAEngine);
        }
    }

    private String addString() {
        String str = "[";
        int i = 0;
        while (i < this.dilithiumK) {
            String str2 = (str + "Outer Matrix " + i + " [") + this.mat[i].toString();
            str = (i == this.dilithiumK + (-1) ? new StringBuilder().append(str2).append("]\n") : new StringBuilder().append(str2).append("],\n")).toString();
            i++;
        }
        return str + "]\n";
    }

    public void expandMatrix(byte[] bArr) {
        for (int i = 0; i < this.dilithiumK; i++) {
            for (int i2 = 0; i2 < this.dilithiumL; i2++) {
                this.mat[i].getVectorIndex(i2).uniformBlocks(bArr, (short) ((i << 8) + i2));
            }
        }
    }

    public void pointwiseMontgomery(PolyVecK polyVecK, PolyVecL polyVecL) {
        for (int i = 0; i < this.dilithiumK; i++) {
            polyVecK.getVectorIndex(i).pointwiseAccountMontgomery(this.mat[i], polyVecL);
        }
    }

    public String toString(String str) {
        return str.concat(": \n" + addString());
    }
}