package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import javassist.bytecode.Opcode;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT163FieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT163FieldElement.class */
public class SecT163FieldElement extends ECFieldElement.AbstractF2m {

    /* renamed from: x */
    protected long[] f753x;

    public SecT163FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > 163) {
            throw new IllegalArgumentException("x value invalid for SecT163FieldElement");
        }
        this.f753x = SecT163Field.fromBigInteger(bigInteger);
    }

    public SecT163FieldElement() {
        this.f753x = Nat192.create64();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecT163FieldElement(long[] jArr) {
        this.f753x = jArr;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isOne() {
        return Nat192.isOne64(this.f753x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isZero() {
        return Nat192.isZero64(this.f753x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean testBitZero() {
        return (this.f753x[0] & 1) != 0;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat192.toBigInteger64(this.f753x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public String getFieldName() {
        return "SecT163Field";
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public int getFieldSize() {
        return Opcode.IF_ICMPGT;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        long[] create64 = Nat192.create64();
        SecT163Field.add(this.f753x, ((SecT163FieldElement) eCFieldElement).f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] create64 = Nat192.create64();
        SecT163Field.addOne(this.f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        return add(eCFieldElement);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        long[] create64 = Nat192.create64();
        SecT163Field.multiply(this.f753x, ((SecT163FieldElement) eCFieldElement).f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        long[] jArr = this.f753x;
        long[] jArr2 = ((SecT163FieldElement) eCFieldElement).f753x;
        long[] jArr3 = ((SecT163FieldElement) eCFieldElement2).f753x;
        long[] jArr4 = ((SecT163FieldElement) eCFieldElement3).f753x;
        long[] createExt64 = Nat192.createExt64();
        SecT163Field.multiplyAddToExt(jArr, jArr2, createExt64);
        SecT163Field.multiplyAddToExt(jArr3, jArr4, createExt64);
        long[] create64 = Nat192.create64();
        SecT163Field.reduce(createExt64, create64);
        return new SecT163FieldElement(create64);
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
        long[] create64 = Nat192.create64();
        SecT163Field.square(this.f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return squarePlusProduct(eCFieldElement, eCFieldElement2);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        long[] jArr = this.f753x;
        long[] jArr2 = ((SecT163FieldElement) eCFieldElement).f753x;
        long[] jArr3 = ((SecT163FieldElement) eCFieldElement2).f753x;
        long[] createExt64 = Nat192.createExt64();
        SecT163Field.squareAddToExt(jArr, createExt64);
        SecT163Field.multiplyAddToExt(jArr2, jArr3, createExt64);
        long[] create64 = Nat192.create64();
        SecT163Field.reduce(createExt64, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement squarePow(int i) {
        if (i < 1) {
            return this;
        }
        long[] create64 = Nat192.create64();
        SecT163Field.squareN(this.f753x, i, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] create64 = Nat192.create64();
        SecT163Field.halfTrace(this.f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT163Field.trace(this.f753x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement invert() {
        long[] create64 = Nat192.create64();
        SecT163Field.invert(this.f753x, create64);
        return new SecT163FieldElement(create64);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] create64 = Nat192.create64();
        SecT163Field.sqrt(this.f753x, create64);
        return new SecT163FieldElement(create64);
    }

    public int getRepresentation() {
        return 3;
    }

    public int getM() {
        return Opcode.IF_ICMPGT;
    }

    public int getK1() {
        return 3;
    }

    public int getK2() {
        return 6;
    }

    public int getK3() {
        return 7;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecT163FieldElement) {
            return Nat192.eq64(this.f753x, ((SecT163FieldElement) obj).f753x);
        }
        return false;
    }

    public int hashCode() {
        return 163763 ^ Arrays.hashCode(this.f753x, 0, 3);
    }
}