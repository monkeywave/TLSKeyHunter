package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat448;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT409FieldElement */
/* loaded from: classes2.dex */
public class SecT409FieldElement extends ECFieldElement.AbstractF2m {

    /* renamed from: x */
    protected long[] f1097x;

    public SecT409FieldElement() {
        this.f1097x = Nat448.create64();
    }

    public SecT409FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > 409) {
            throw new IllegalArgumentException("x value invalid for SecT409FieldElement");
        }
        this.f1097x = SecT409Field.fromBigInteger(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecT409FieldElement(long[] jArr) {
        this.f1097x = jArr;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        long[] create64 = Nat448.create64();
        SecT409Field.add(this.f1097x, ((SecT409FieldElement) eCFieldElement).f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] create64 = Nat448.create64();
        SecT409Field.addOne(this.f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        return multiply(eCFieldElement.invert());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecT409FieldElement) {
            return Nat448.eq64(this.f1097x, ((SecT409FieldElement) obj).f1097x);
        }
        return false;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public String getFieldName() {
        return "SecT409Field";
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public int getFieldSize() {
        return 409;
    }

    public int getK1() {
        return 87;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    public int getM() {
        return 409;
    }

    public int getRepresentation() {
        return 2;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] create64 = Nat448.create64();
        SecT409Field.halfTrace(this.f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    public int hashCode() {
        return Arrays.hashCode(this.f1097x, 0, 7) ^ 4090087;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement invert() {
        long[] create64 = Nat448.create64();
        SecT409Field.invert(this.f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isOne() {
        return Nat448.isOne64(this.f1097x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isZero() {
        return Nat448.isZero64(this.f1097x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        long[] create64 = Nat448.create64();
        SecT409Field.multiply(this.f1097x, ((SecT409FieldElement) eCFieldElement).f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        long[] jArr = this.f1097x;
        long[] jArr2 = ((SecT409FieldElement) eCFieldElement).f1097x;
        long[] jArr3 = ((SecT409FieldElement) eCFieldElement2).f1097x;
        long[] jArr4 = ((SecT409FieldElement) eCFieldElement3).f1097x;
        long[] create64 = Nat.create64(13);
        SecT409Field.multiplyAddToExt(jArr, jArr2, create64);
        SecT409Field.multiplyAddToExt(jArr3, jArr4, create64);
        long[] create642 = Nat448.create64();
        SecT409Field.reduce(create64, create642);
        return new SecT409FieldElement(create642);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement negate() {
        return this;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] create64 = Nat448.create64();
        SecT409Field.sqrt(this.f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement square() {
        long[] create64 = Nat448.create64();
        SecT409Field.square(this.f1097x, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return squarePlusProduct(eCFieldElement, eCFieldElement2);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        long[] jArr = this.f1097x;
        long[] jArr2 = ((SecT409FieldElement) eCFieldElement).f1097x;
        long[] jArr3 = ((SecT409FieldElement) eCFieldElement2).f1097x;
        long[] create64 = Nat.create64(13);
        SecT409Field.squareAddToExt(jArr, create64);
        SecT409Field.multiplyAddToExt(jArr2, jArr3, create64);
        long[] create642 = Nat448.create64();
        SecT409Field.reduce(create64, create642);
        return new SecT409FieldElement(create642);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squarePow(int i) {
        if (i < 1) {
            return this;
        }
        long[] create64 = Nat448.create64();
        SecT409Field.squareN(this.f1097x, i, create64);
        return new SecT409FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        return add(eCFieldElement);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean testBitZero() {
        return (this.f1097x[0] & 1) != 0;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat448.toBigInteger64(this.f1097x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT409Field.trace(this.f1097x);
    }
}