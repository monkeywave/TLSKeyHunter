package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP256R1FieldElement.class */
public class SecP256R1FieldElement extends ECFieldElement.AbstractFp {

    /* renamed from: Q */
    public static final BigInteger f740Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));

    /* renamed from: x */
    protected int[] f741x;

    public SecP256R1FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.compareTo(f740Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP256R1FieldElement");
        }
        this.f741x = SecP256R1Field.fromBigInteger(bigInteger);
    }

    public SecP256R1FieldElement() {
        this.f741x = Nat256.create();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecP256R1FieldElement(int[] iArr) {
        this.f741x = iArr;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero(this.f741x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne(this.f741x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean testBitZero() {
        return Nat256.getBit(this.f741x, 0) == 1;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger(this.f741x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public String getFieldName() {
        return "SecP256R1Field";
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public int getFieldSize() {
        return f740Q.bitLength();
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.add(this.f741x, ((SecP256R1FieldElement) eCFieldElement).f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] create = Nat256.create();
        SecP256R1Field.addOne(this.f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.subtract(this.f741x, ((SecP256R1FieldElement) eCFieldElement).f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.multiply(this.f741x, ((SecP256R1FieldElement) eCFieldElement).f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.inv(((SecP256R1FieldElement) eCFieldElement).f741x, create);
        SecP256R1Field.multiply(create, this.f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement negate() {
        int[] create = Nat256.create();
        SecP256R1Field.negate(this.f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement square() {
        int[] create = Nat256.create();
        SecP256R1Field.square(this.f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement invert() {
        int[] create = Nat256.create();
        SecP256R1Field.inv(this.f741x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] iArr = this.f741x;
        if (Nat256.isZero(iArr) || Nat256.isOne(iArr)) {
            return this;
        }
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        SecP256R1Field.square(iArr, create);
        SecP256R1Field.multiply(create, iArr, create);
        SecP256R1Field.squareN(create, 2, create2);
        SecP256R1Field.multiply(create2, create, create2);
        SecP256R1Field.squareN(create2, 4, create);
        SecP256R1Field.multiply(create, create2, create);
        SecP256R1Field.squareN(create, 8, create2);
        SecP256R1Field.multiply(create2, create, create2);
        SecP256R1Field.squareN(create2, 16, create);
        SecP256R1Field.multiply(create, create2, create);
        SecP256R1Field.squareN(create, 32, create);
        SecP256R1Field.multiply(create, iArr, create);
        SecP256R1Field.squareN(create, 96, create);
        SecP256R1Field.multiply(create, iArr, create);
        SecP256R1Field.squareN(create, 94, create);
        SecP256R1Field.square(create, create2);
        if (Nat256.m14eq(iArr, create2)) {
            return new SecP256R1FieldElement(create);
        }
        return null;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecP256R1FieldElement) {
            return Nat256.m14eq(this.f741x, ((SecP256R1FieldElement) obj).f741x);
        }
        return false;
    }

    public int hashCode() {
        return f740Q.hashCode() ^ Arrays.hashCode(this.f741x, 0, 8);
    }
}