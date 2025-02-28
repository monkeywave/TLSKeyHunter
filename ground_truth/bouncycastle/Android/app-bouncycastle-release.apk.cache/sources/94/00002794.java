package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat320;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT283FieldElement */
/* loaded from: classes2.dex */
public class SecT283FieldElement extends ECFieldElement.AbstractF2m {

    /* renamed from: x */
    protected long[] f1096x;

    public SecT283FieldElement() {
        this.f1096x = Nat320.create64();
    }

    public SecT283FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > 283) {
            throw new IllegalArgumentException("x value invalid for SecT283FieldElement");
        }
        this.f1096x = SecT283Field.fromBigInteger(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecT283FieldElement(long[] jArr) {
        this.f1096x = jArr;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        long[] create64 = Nat320.create64();
        SecT283Field.add(this.f1096x, ((SecT283FieldElement) eCFieldElement).f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] create64 = Nat320.create64();
        SecT283Field.addOne(this.f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        return multiply(eCFieldElement.invert());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecT283FieldElement) {
            return Nat320.eq64(this.f1096x, ((SecT283FieldElement) obj).f1096x);
        }
        return false;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public String getFieldName() {
        return "SecT283Field";
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public int getFieldSize() {
        return 283;
    }

    public int getK1() {
        return 5;
    }

    public int getK2() {
        return 7;
    }

    public int getK3() {
        return 12;
    }

    public int getM() {
        return 283;
    }

    public int getRepresentation() {
        return 3;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] create64 = Nat320.create64();
        SecT283Field.halfTrace(this.f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    public int hashCode() {
        return Arrays.hashCode(this.f1096x, 0, 5) ^ 2831275;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement invert() {
        long[] create64 = Nat320.create64();
        SecT283Field.invert(this.f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isOne() {
        return Nat320.isOne64(this.f1096x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isZero() {
        return Nat320.isZero64(this.f1096x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        long[] create64 = Nat320.create64();
        SecT283Field.multiply(this.f1096x, ((SecT283FieldElement) eCFieldElement).f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        long[] jArr = this.f1096x;
        long[] jArr2 = ((SecT283FieldElement) eCFieldElement).f1096x;
        long[] jArr3 = ((SecT283FieldElement) eCFieldElement2).f1096x;
        long[] jArr4 = ((SecT283FieldElement) eCFieldElement3).f1096x;
        long[] create64 = Nat.create64(9);
        SecT283Field.multiplyAddToExt(jArr, jArr2, create64);
        SecT283Field.multiplyAddToExt(jArr3, jArr4, create64);
        long[] create642 = Nat320.create64();
        SecT283Field.reduce(create64, create642);
        return new SecT283FieldElement(create642);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement negate() {
        return this;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] create64 = Nat320.create64();
        SecT283Field.sqrt(this.f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement square() {
        long[] create64 = Nat320.create64();
        SecT283Field.square(this.f1096x, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return squarePlusProduct(eCFieldElement, eCFieldElement2);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        long[] jArr = this.f1096x;
        long[] jArr2 = ((SecT283FieldElement) eCFieldElement).f1096x;
        long[] jArr3 = ((SecT283FieldElement) eCFieldElement2).f1096x;
        long[] create64 = Nat.create64(9);
        SecT283Field.squareAddToExt(jArr, create64);
        SecT283Field.multiplyAddToExt(jArr2, jArr3, create64);
        long[] create642 = Nat320.create64();
        SecT283Field.reduce(create64, create642);
        return new SecT283FieldElement(create642);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement squarePow(int i) {
        if (i < 1) {
            return this;
        }
        long[] create64 = Nat320.create64();
        SecT283Field.squareN(this.f1096x, i, create64);
        return new SecT283FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        return add(eCFieldElement);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean testBitZero() {
        return (this.f1096x[0] & 1) != 0;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat320.toBigInteger64(this.f1096x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT283Field.trace(this.f1096x);
    }
}