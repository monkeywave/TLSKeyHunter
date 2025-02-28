package org.bouncycastle.pqc.crypto.crystals.dilithium;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class PolyVecK {
    private int dilithiumK;
    private int dilithiumL;
    private DilithiumEngine engine;
    private int mode;
    private int polyVecBytes;
    Poly[] vec;

    public PolyVecK() throws Exception {
        throw new Exception("Requires Parameter");
    }

    public PolyVecK(DilithiumEngine dilithiumEngine) {
        this.engine = dilithiumEngine;
        this.mode = dilithiumEngine.getDilithiumMode();
        this.dilithiumK = dilithiumEngine.getDilithiumK();
        this.dilithiumL = dilithiumEngine.getDilithiumL();
        this.vec = new Poly[this.dilithiumK];
        for (int i = 0; i < this.dilithiumK; i++) {
            this.vec[i] = new Poly(dilithiumEngine);
        }
    }

    public void addPolyVecK(PolyVecK polyVecK) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).addPoly(polyVecK.getVectorIndex(i));
        }
    }

    public boolean checkNorm(int i) {
        for (int i2 = 0; i2 < this.dilithiumK; i2++) {
            if (getVectorIndex(i2).checkNorm(i)) {
                return true;
            }
        }
        return false;
    }

    public void conditionalAddQ() {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).conditionalAddQ();
        }
    }

    public void decompose(PolyVecK polyVecK) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).decompose(polyVecK.getVectorIndex(i));
        }
    }

    public Poly getVectorIndex(int i) {
        return this.vec[i];
    }

    public void invNttToMont() {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).invNttToMont();
        }
    }

    public int makeHint(PolyVecK polyVecK, PolyVecK polyVecK2) {
        int i = 0;
        for (int i2 = 0; i2 < this.dilithiumK; i2++) {
            i += getVectorIndex(i2).polyMakeHint(polyVecK.getVectorIndex(i2), polyVecK2.getVectorIndex(i2));
        }
        return i;
    }

    public byte[] packW1() {
        byte[] bArr = new byte[this.dilithiumK * this.engine.getDilithiumPolyW1PackedBytes()];
        for (int i = 0; i < this.dilithiumK; i++) {
            System.arraycopy(getVectorIndex(i).w1Pack(), 0, bArr, this.engine.getDilithiumPolyW1PackedBytes() * i, this.engine.getDilithiumPolyW1PackedBytes());
        }
        return bArr;
    }

    public void pointwisePolyMontgomery(Poly poly, PolyVecK polyVecK) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).pointwiseMontgomery(poly, polyVecK.getVectorIndex(i));
        }
    }

    public void polyVecNtt() {
        for (int i = 0; i < this.dilithiumK; i++) {
            this.vec[i].polyNtt();
        }
    }

    public void power2Round(PolyVecK polyVecK) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).power2Round(polyVecK.getVectorIndex(i));
        }
    }

    public void reduce() {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).reduce();
        }
    }

    public void setVectorIndex(int i, Poly poly) {
        this.vec[i] = poly;
    }

    public void shiftLeft() {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).shiftLeft();
        }
    }

    public void subtract(PolyVecK polyVecK) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).subtract(polyVecK.getVectorIndex(i));
        }
    }

    public String toString() {
        String str = "[";
        for (int i = 0; i < this.dilithiumK; i++) {
            str = str + i + " " + getVectorIndex(i).toString();
            if (i != this.dilithiumK - 1) {
                str = str + ",\n";
            }
        }
        return str + "]";
    }

    public String toString(String str) {
        return str + ": " + toString();
    }

    public void uniformEta(byte[] bArr, short s) {
        int i = 0;
        while (i < this.dilithiumK) {
            getVectorIndex(i).uniformEta(bArr, s);
            i++;
            s = (short) (s + 1);
        }
    }

    public void useHint(PolyVecK polyVecK, PolyVecK polyVecK2) {
        for (int i = 0; i < this.dilithiumK; i++) {
            getVectorIndex(i).polyUseHint(polyVecK.getVectorIndex(i), polyVecK2.getVectorIndex(i));
        }
    }
}