package org.bouncycastle.pqc.legacy.math.linearalgebra;

import java.security.SecureRandom;

/* loaded from: classes2.dex */
public abstract class GF2nField {
    protected GF2Polynomial fieldPolynomial;
    protected java.util.Vector fields;
    protected int mDegree;
    protected java.util.Vector matrices;
    protected final SecureRandom random;

    /* JADX INFO: Access modifiers changed from: protected */
    public GF2nField(SecureRandom secureRandom) {
        this.random = secureRandom;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void computeCOBMatrix(GF2nField gF2nField);

    protected abstract void computeFieldPolynomial();

    public final GF2nElement convert(GF2nElement gF2nElement, GF2nField gF2nField) throws RuntimeException {
        if (gF2nField == this || this.fieldPolynomial.equals(gF2nField.fieldPolynomial)) {
            return (GF2nElement) gF2nElement.clone();
        }
        if (this.mDegree == gF2nField.mDegree) {
            int indexOf = this.fields.indexOf(gF2nField);
            if (indexOf == -1) {
                computeCOBMatrix(gF2nField);
                indexOf = this.fields.indexOf(gF2nField);
            }
            GF2Polynomial[] gF2PolynomialArr = (GF2Polynomial[]) this.matrices.elementAt(indexOf);
            GF2nElement gF2nElement2 = (GF2nElement) gF2nElement.clone();
            if (gF2nElement2 instanceof GF2nONBElement) {
                ((GF2nONBElement) gF2nElement2).reverseOrder();
            }
            GF2Polynomial gF2Polynomial = new GF2Polynomial(this.mDegree, gF2nElement2.toFlexiBigInt());
            gF2Polynomial.expandN(this.mDegree);
            GF2Polynomial gF2Polynomial2 = new GF2Polynomial(this.mDegree);
            for (int i = 0; i < this.mDegree; i++) {
                if (gF2Polynomial.vectorMult(gF2PolynomialArr[i])) {
                    gF2Polynomial2.setBit((this.mDegree - 1) - i);
                }
            }
            if (gF2nField instanceof GF2nPolynomialField) {
                return new GF2nPolynomialElement((GF2nPolynomialField) gF2nField, gF2Polynomial2);
            }
            if (gF2nField instanceof GF2nONBField) {
                GF2nONBElement gF2nONBElement = new GF2nONBElement((GF2nONBField) gF2nField, gF2Polynomial2.toFlexiBigInt());
                gF2nONBElement.reverseOrder();
                return gF2nONBElement;
            }
            throw new RuntimeException("GF2nField.convert: B1 must be an instance of GF2nPolynomialField or GF2nONBField!");
        }
        throw new RuntimeException("GF2nField.convert: B1 has a different degree and thus cannot be coverted to!");
    }

    public final boolean equals(Object obj) {
        if (obj == null || !(obj instanceof GF2nField)) {
            return false;
        }
        GF2nField gF2nField = (GF2nField) obj;
        if (gF2nField.mDegree == this.mDegree && this.fieldPolynomial.equals(gF2nField.fieldPolynomial)) {
            if (!(this instanceof GF2nPolynomialField) || (gF2nField instanceof GF2nPolynomialField)) {
                return !(this instanceof GF2nONBField) || (gF2nField instanceof GF2nONBField);
            }
            return false;
        }
        return false;
    }

    public final int getDegree() {
        return this.mDegree;
    }

    public final GF2Polynomial getFieldPolynomial() {
        if (this.fieldPolynomial == null) {
            computeFieldPolynomial();
        }
        return new GF2Polynomial(this.fieldPolynomial);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract GF2nElement getRandomRoot(GF2Polynomial gF2Polynomial);

    public int hashCode() {
        return this.mDegree + this.fieldPolynomial.hashCode();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final GF2Polynomial[] invertMatrix(GF2Polynomial[] gF2PolynomialArr) {
        GF2Polynomial[] gF2PolynomialArr2 = new GF2Polynomial[gF2PolynomialArr.length];
        GF2Polynomial[] gF2PolynomialArr3 = new GF2Polynomial[gF2PolynomialArr.length];
        int i = 0;
        for (int i2 = 0; i2 < this.mDegree; i2++) {
            gF2PolynomialArr2[i2] = new GF2Polynomial(gF2PolynomialArr[i2]);
            GF2Polynomial gF2Polynomial = new GF2Polynomial(this.mDegree);
            gF2PolynomialArr3[i2] = gF2Polynomial;
            gF2Polynomial.setBit((this.mDegree - 1) - i2);
        }
        while (true) {
            int i3 = this.mDegree;
            if (i >= i3 - 1) {
                for (int i4 = i3 - 1; i4 > 0; i4--) {
                    for (int i5 = i4 - 1; i5 >= 0; i5--) {
                        if (gF2PolynomialArr2[i5].testBit((this.mDegree - 1) - i4)) {
                            gF2PolynomialArr2[i5].addToThis(gF2PolynomialArr2[i4]);
                            gF2PolynomialArr3[i5].addToThis(gF2PolynomialArr3[i4]);
                        }
                    }
                }
                return gF2PolynomialArr3;
            }
            int i6 = i;
            while (true) {
                int i7 = this.mDegree;
                if (i6 >= i7 || gF2PolynomialArr2[i6].testBit((i7 - 1) - i)) {
                    break;
                }
                i6++;
            }
            if (i6 >= this.mDegree) {
                throw new RuntimeException("GF2nField.invertMatrix: Matrix cannot be inverted!");
            }
            if (i != i6) {
                GF2Polynomial gF2Polynomial2 = gF2PolynomialArr2[i];
                gF2PolynomialArr2[i] = gF2PolynomialArr2[i6];
                gF2PolynomialArr2[i6] = gF2Polynomial2;
                GF2Polynomial gF2Polynomial3 = gF2PolynomialArr3[i];
                gF2PolynomialArr3[i] = gF2PolynomialArr3[i6];
                gF2PolynomialArr3[i6] = gF2Polynomial3;
            }
            int i8 = i + 1;
            int i9 = i8;
            while (true) {
                int i10 = this.mDegree;
                if (i9 < i10) {
                    if (gF2PolynomialArr2[i9].testBit((i10 - 1) - i)) {
                        gF2PolynomialArr2[i9].addToThis(gF2PolynomialArr2[i]);
                        gF2PolynomialArr3[i9].addToThis(gF2PolynomialArr3[i]);
                    }
                    i9++;
                }
            }
            i = i8;
        }
    }
}