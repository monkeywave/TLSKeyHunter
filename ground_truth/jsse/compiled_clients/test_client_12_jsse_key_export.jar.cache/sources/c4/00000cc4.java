package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT233FieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT233FieldElement.class */
public class SecT233FieldElement extends ECFieldElement.AbstractF2m {

    /* renamed from: x */
    protected long[] f755x;

    public SecT233FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > 233) {
            throw new IllegalArgumentException("x value invalid for SecT233FieldElement");
        }
        this.f755x = SecT233Field.fromBigInteger(bigInteger);
    }

    public SecT233FieldElement() {
        this.f755x = Nat256.create64();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecT233FieldElement(long[] jArr) {
        this.f755x = jArr;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne64(this.f755x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero64(this.f755x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean testBitZero() {
        return (this.f755x[0] & 1) != 0;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger64(this.f755x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public String getFieldName() {
        return "SecT233Field";
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public int getFieldSize() {
        return 233;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        long[] create64 = Nat256.create64();
        SecT233Field.add(this.f755x, ((SecT233FieldElement) eCFieldElement).f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] create64 = Nat256.create64();
        SecT233Field.addOne(this.f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        return add(eCFieldElement);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        long[] create64 = Nat256.create64();
        SecT233Field.multiply(this.f755x, ((SecT233FieldElement) eCFieldElement).f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        long[] jArr = this.f755x;
        long[] jArr2 = ((SecT233FieldElement) eCFieldElement).f755x;
        long[] jArr3 = ((SecT233FieldElement) eCFieldElement2).f755x;
        long[] jArr4 = ((SecT233FieldElement) eCFieldElement3).f755x;
        long[] createExt64 = Nat256.createExt64();
        SecT233Field.multiplyAddToExt(jArr, jArr2, createExt64);
        SecT233Field.multiplyAddToExt(jArr3, jArr4, createExt64);
        long[] create64 = Nat256.create64();
        SecT233Field.reduce(createExt64, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        return multiply(eCFieldElement.invert());
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement negate() {
        return this;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement square() {
        long[] create64 = Nat256.create64();
        SecT233Field.square(this.f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return squarePlusProduct(eCFieldElement, eCFieldElement2);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        long[] jArr = this.f755x;
        long[] jArr2 = ((SecT233FieldElement) eCFieldElement).f755x;
        long[] jArr3 = ((SecT233FieldElement) eCFieldElement2).f755x;
        long[] createExt64 = Nat256.createExt64();
        SecT233Field.squareAddToExt(jArr, createExt64);
        SecT233Field.multiplyAddToExt(jArr2, jArr3, createExt64);
        long[] create64 = Nat256.create64();
        SecT233Field.reduce(createExt64, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squarePow(int i) {
        if (i < 1) {
            return this;
        }
        long[] create64 = Nat256.create64();
        SecT233Field.squareN(this.f755x, i, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] create64 = Nat256.create64();
        SecT233Field.halfTrace(this.f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT233Field.trace(this.f755x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement invert() {
        long[] create64 = Nat256.create64();
        SecT233Field.invert(this.f755x, create64);
        return new SecT233FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] create64 = Nat256.create64();
        SecT233Field.sqrt(this.f755x, create64);
        return new SecT233FieldElement(create64);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 233;
    }

    public int getK1() {
        return 74;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecT233FieldElement) {
            return Nat256.eq64(this.f755x, ((SecT233FieldElement) obj).f755x);
        }
        return false;
    }

    public int hashCode() {
        return 2330074 ^ Arrays.hashCode(this.f755x, 0, 4);
    }
}