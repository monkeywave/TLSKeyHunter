package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP256K1FieldElement.class */
public class SecP256K1FieldElement extends ECFieldElement.AbstractFp {

    /* renamed from: Q */
    public static final BigInteger f734Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));

    /* renamed from: x */
    protected int[] f735x;

    public SecP256K1FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.compareTo(f734Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP256K1FieldElement");
        }
        this.f735x = SecP256K1Field.fromBigInteger(bigInteger);
    }

    public SecP256K1FieldElement() {
        this.f735x = Nat256.create();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecP256K1FieldElement(int[] iArr) {
        this.f735x = iArr;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero(this.f735x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne(this.f735x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public boolean testBitZero() {
        return Nat256.getBit(this.f735x, 0) == 1;
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger(this.f735x);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public String getFieldName() {
        return "SecP256K1Field";
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public int getFieldSize() {
        return f734Q.bitLength();
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256K1Field.add(this.f735x, ((SecP256K1FieldElement) eCFieldElement).f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] create = Nat256.create();
        SecP256K1Field.addOne(this.f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256K1Field.subtract(this.f735x, ((SecP256K1FieldElement) eCFieldElement).f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256K1Field.multiply(this.f735x, ((SecP256K1FieldElement) eCFieldElement).f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256K1Field.inv(((SecP256K1FieldElement) eCFieldElement).f735x, create);
        SecP256K1Field.multiply(create, this.f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement negate() {
        int[] create = Nat256.create();
        SecP256K1Field.negate(this.f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement square() {
        int[] create = Nat256.create();
        SecP256K1Field.square(this.f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement invert() {
        int[] create = Nat256.create();
        SecP256K1Field.inv(this.f735x, create);
        return new SecP256K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] iArr = this.f735x;
        if (Nat256.isZero(iArr) || Nat256.isOne(iArr)) {
            return this;
        }
        int[] create = Nat256.create();
        SecP256K1Field.square(iArr, create);
        SecP256K1Field.multiply(create, iArr, create);
        int[] create2 = Nat256.create();
        SecP256K1Field.square(create, create2);
        SecP256K1Field.multiply(create2, iArr, create2);
        int[] create3 = Nat256.create();
        SecP256K1Field.squareN(create2, 3, create3);
        SecP256K1Field.multiply(create3, create2, create3);
        SecP256K1Field.squareN(create3, 3, create3);
        SecP256K1Field.multiply(create3, create2, create3);
        SecP256K1Field.squareN(create3, 2, create3);
        SecP256K1Field.multiply(create3, create, create3);
        int[] create4 = Nat256.create();
        SecP256K1Field.squareN(create3, 11, create4);
        SecP256K1Field.multiply(create4, create3, create4);
        SecP256K1Field.squareN(create4, 22, create3);
        SecP256K1Field.multiply(create3, create4, create3);
        int[] create5 = Nat256.create();
        SecP256K1Field.squareN(create3, 44, create5);
        SecP256K1Field.multiply(create5, create3, create5);
        int[] create6 = Nat256.create();
        SecP256K1Field.squareN(create5, 88, create6);
        SecP256K1Field.multiply(create6, create5, create6);
        SecP256K1Field.squareN(create6, 44, create5);
        SecP256K1Field.multiply(create5, create3, create5);
        SecP256K1Field.squareN(create5, 3, create3);
        SecP256K1Field.multiply(create3, create2, create3);
        SecP256K1Field.squareN(create3, 23, create3);
        SecP256K1Field.multiply(create3, create4, create3);
        SecP256K1Field.squareN(create3, 6, create3);
        SecP256K1Field.multiply(create3, create, create3);
        SecP256K1Field.squareN(create3, 2, create3);
        SecP256K1Field.square(create3, create);
        if (Nat256.m14eq(iArr, create)) {
            return new SecP256K1FieldElement(create3);
        }
        return null;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecP256K1FieldElement) {
            return Nat256.m14eq(this.f735x, ((SecP256K1FieldElement) obj).f735x);
        }
        return false;
    }

    public int hashCode() {
        return f734Q.hashCode() ^ Arrays.hashCode(this.f735x, 0, 8);
    }
}