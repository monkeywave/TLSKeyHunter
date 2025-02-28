package org.bouncycastle.pqc.crypto.rainbow.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/util/ComputeInField.class */
public class ComputeInField {

    /* renamed from: A */
    private short[][] f908A;

    /* renamed from: x */
    short[] f909x;

    public short[] solveEquation(short[][] sArr, short[] sArr2) {
        if (sArr.length != sArr2.length) {
            return null;
        }
        try {
            this.f908A = new short[sArr.length][sArr.length + 1];
            this.f909x = new short[sArr.length];
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr[0].length; i2++) {
                    this.f908A[i][i2] = sArr[i][i2];
                }
            }
            for (int i3 = 0; i3 < sArr2.length; i3++) {
                this.f908A[i3][sArr2.length] = GF2Field.addElem(sArr2[i3], this.f908A[i3][sArr2.length]);
            }
            computeZerosUnder(false);
            substitute();
            return this.f909x;
        } catch (RuntimeException e) {
            return null;
        }
    }

    public short[][] inverse(short[][] sArr) {
        try {
            this.f908A = new short[sArr.length][2 * sArr.length];
            if (sArr.length != sArr[0].length) {
                throw new RuntimeException("The matrix is not invertible. Please choose another one!");
            }
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr.length; i2++) {
                    this.f908A[i][i2] = sArr[i][i2];
                }
                for (int length = sArr.length; length < 2 * sArr.length; length++) {
                    this.f908A[i][length] = 0;
                }
                this.f908A[i][i + this.f908A.length] = 1;
            }
            computeZerosUnder(true);
            for (int i3 = 0; i3 < this.f908A.length; i3++) {
                short invElem = GF2Field.invElem(this.f908A[i3][i3]);
                for (int i4 = i3; i4 < 2 * this.f908A.length; i4++) {
                    this.f908A[i3][i4] = GF2Field.multElem(this.f908A[i3][i4], invElem);
                }
            }
            computeZerosAbove();
            short[][] sArr2 = new short[this.f908A.length][this.f908A.length];
            for (int i5 = 0; i5 < this.f908A.length; i5++) {
                for (int length2 = this.f908A.length; length2 < 2 * this.f908A.length; length2++) {
                    sArr2[i5][length2 - this.f908A.length] = this.f908A[i5][length2];
                }
            }
            return sArr2;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void computeZerosUnder(boolean z) throws RuntimeException {
        int length = z ? 2 * this.f908A.length : this.f908A.length + 1;
        for (int i = 0; i < this.f908A.length - 1; i++) {
            for (int i2 = i + 1; i2 < this.f908A.length; i2++) {
                short s = this.f908A[i2][i];
                short invElem = GF2Field.invElem(this.f908A[i][i]);
                if (invElem == 0) {
                    throw new IllegalStateException("Matrix not invertible! We have to choose another one!");
                }
                for (int i3 = i; i3 < length; i3++) {
                    this.f908A[i2][i3] = GF2Field.addElem(this.f908A[i2][i3], GF2Field.multElem(s, GF2Field.multElem(this.f908A[i][i3], invElem)));
                }
            }
        }
    }

    private void computeZerosAbove() throws RuntimeException {
        for (int length = this.f908A.length - 1; length > 0; length--) {
            for (int i = length - 1; i >= 0; i--) {
                short s = this.f908A[i][length];
                short invElem = GF2Field.invElem(this.f908A[length][length]);
                if (invElem == 0) {
                    throw new RuntimeException("The matrix is not invertible");
                }
                for (int i2 = length; i2 < 2 * this.f908A.length; i2++) {
                    this.f908A[i][i2] = GF2Field.addElem(this.f908A[i][i2], GF2Field.multElem(s, GF2Field.multElem(this.f908A[length][i2], invElem)));
                }
            }
        }
    }

    private void substitute() throws IllegalStateException {
        short invElem = GF2Field.invElem(this.f908A[this.f908A.length - 1][this.f908A.length - 1]);
        if (invElem == 0) {
            throw new IllegalStateException("The equation system is not solvable");
        }
        this.f909x[this.f908A.length - 1] = GF2Field.multElem(this.f908A[this.f908A.length - 1][this.f908A.length], invElem);
        for (int length = this.f908A.length - 2; length >= 0; length--) {
            short s = this.f908A[length][this.f908A.length];
            for (int length2 = this.f908A.length - 1; length2 > length; length2--) {
                s = GF2Field.addElem(s, GF2Field.multElem(this.f908A[length][length2], this.f909x[length2]));
            }
            short invElem2 = GF2Field.invElem(this.f908A[length][length]);
            if (invElem2 == 0) {
                throw new IllegalStateException("Not solvable equation system");
            }
            this.f909x[length] = GF2Field.multElem(s, invElem2);
        }
    }

    public short[][] multiplyMatrix(short[][] sArr, short[][] sArr2) throws RuntimeException {
        if (sArr[0].length != sArr2.length) {
            throw new RuntimeException("Multiplication is not possible!");
        }
        this.f908A = new short[sArr.length][sArr2[0].length];
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr2.length; i2++) {
                for (int i3 = 0; i3 < sArr2[0].length; i3++) {
                    this.f908A[i][i3] = GF2Field.addElem(this.f908A[i][i3], GF2Field.multElem(sArr[i][i2], sArr2[i2][i3]));
                }
            }
        }
        return this.f908A;
    }

    public short[] multiplyMatrix(short[][] sArr, short[] sArr2) throws RuntimeException {
        if (sArr[0].length != sArr2.length) {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short[] sArr3 = new short[sArr.length];
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr2.length; i2++) {
                sArr3[i] = GF2Field.addElem(sArr3[i], GF2Field.multElem(sArr[i][i2], sArr2[i2]));
            }
        }
        return sArr3;
    }

    public short[] addVect(short[] sArr, short[] sArr2) {
        if (sArr.length != sArr2.length) {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short[] sArr3 = new short[sArr.length];
        for (int i = 0; i < sArr3.length; i++) {
            sArr3[i] = GF2Field.addElem(sArr[i], sArr2[i]);
        }
        return sArr3;
    }

    public short[][] multVects(short[] sArr, short[] sArr2) {
        if (sArr.length != sArr2.length) {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short[][] sArr3 = new short[sArr.length][sArr2.length];
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr2.length; i2++) {
                sArr3[i][i2] = GF2Field.multElem(sArr[i], sArr2[i2]);
            }
        }
        return sArr3;
    }

    public short[] multVect(short s, short[] sArr) {
        short[] sArr2 = new short[sArr.length];
        for (int i = 0; i < sArr2.length; i++) {
            sArr2[i] = GF2Field.multElem(s, sArr[i]);
        }
        return sArr2;
    }

    public short[][] multMatrix(short s, short[][] sArr) {
        short[][] sArr2 = new short[sArr.length][sArr[0].length];
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr[0].length; i2++) {
                sArr2[i][i2] = GF2Field.multElem(s, sArr[i][i2]);
            }
        }
        return sArr2;
    }

    public short[][] addSquareMatrix(short[][] sArr, short[][] sArr2) {
        if (sArr.length == sArr2.length && sArr[0].length == sArr2[0].length) {
            short[][] sArr3 = new short[sArr.length][sArr.length];
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    sArr3[i][i2] = GF2Field.addElem(sArr[i][i2], sArr2[i][i2]);
                }
            }
            return sArr3;
        }
        throw new RuntimeException("Addition is not possible!");
    }
}