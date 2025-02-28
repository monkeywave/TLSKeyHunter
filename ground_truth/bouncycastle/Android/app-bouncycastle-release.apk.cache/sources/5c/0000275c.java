package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP384R1FieldElement */
/* loaded from: classes2.dex */
public class SecP384R1FieldElement extends ECFieldElement.AbstractFp {

    /* renamed from: Q */
    public static final BigInteger f1084Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"));

    /* renamed from: x */
    protected int[] f1085x;

    public SecP384R1FieldElement() {
        this.f1085x = Nat.create(12);
    }

    public SecP384R1FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.compareTo(f1084Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP384R1FieldElement");
        }
        this.f1085x = SecP384R1Field.fromBigInteger(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecP384R1FieldElement(int[] iArr) {
        this.f1085x = iArr;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        int[] create = Nat.create(12);
        SecP384R1Field.add(this.f1085x, ((SecP384R1FieldElement) eCFieldElement).f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] create = Nat.create(12);
        SecP384R1Field.addOne(this.f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        int[] create = Nat.create(12);
        SecP384R1Field.inv(((SecP384R1FieldElement) eCFieldElement).f1085x, create);
        SecP384R1Field.multiply(create, this.f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecP384R1FieldElement) {
            return Nat.m35eq(12, this.f1085x, ((SecP384R1FieldElement) obj).f1085x);
        }
        return false;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public String getFieldName() {
        return "SecP384R1Field";
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public int getFieldSize() {
        return f1084Q.bitLength();
    }

    public int hashCode() {
        return f1084Q.hashCode() ^ Arrays.hashCode(this.f1085x, 0, 12);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement invert() {
        int[] create = Nat.create(12);
        SecP384R1Field.inv(this.f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isOne() {
        return Nat.isOne(12, this.f1085x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isZero() {
        return Nat.isZero(12, this.f1085x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        int[] create = Nat.create(12);
        SecP384R1Field.multiply(this.f1085x, ((SecP384R1FieldElement) eCFieldElement).f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement negate() {
        int[] create = Nat.create(12);
        SecP384R1Field.negate(this.f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] iArr = this.f1085x;
        if (Nat.isZero(12, iArr) || Nat.isOne(12, iArr)) {
            return this;
        }
        int[] create = Nat.create(24);
        int[] create2 = Nat.create(12);
        int[] create3 = Nat.create(12);
        int[] create4 = Nat.create(12);
        int[] create5 = Nat.create(12);
        SecP384R1Field.square(iArr, create2, create);
        SecP384R1Field.multiply(create2, iArr, create2, create);
        SecP384R1Field.squareN(create2, 2, create3, create);
        SecP384R1Field.multiply(create3, create2, create3, create);
        SecP384R1Field.square(create3, create3, create);
        SecP384R1Field.multiply(create3, iArr, create3, create);
        SecP384R1Field.squareN(create3, 5, create4, create);
        SecP384R1Field.multiply(create4, create3, create4, create);
        SecP384R1Field.squareN(create4, 5, create5, create);
        SecP384R1Field.multiply(create5, create3, create5, create);
        SecP384R1Field.squareN(create5, 15, create3, create);
        SecP384R1Field.multiply(create3, create5, create3, create);
        SecP384R1Field.squareN(create3, 2, create4, create);
        SecP384R1Field.multiply(create2, create4, create2, create);
        SecP384R1Field.squareN(create4, 28, create4, create);
        SecP384R1Field.multiply(create3, create4, create3, create);
        SecP384R1Field.squareN(create3, 60, create4, create);
        SecP384R1Field.multiply(create4, create3, create4, create);
        SecP384R1Field.squareN(create4, 120, create3, create);
        SecP384R1Field.multiply(create3, create4, create3, create);
        SecP384R1Field.squareN(create3, 15, create3, create);
        SecP384R1Field.multiply(create3, create5, create3, create);
        SecP384R1Field.squareN(create3, 33, create3, create);
        SecP384R1Field.multiply(create3, create2, create3, create);
        SecP384R1Field.squareN(create3, 64, create3, create);
        SecP384R1Field.multiply(create3, iArr, create3, create);
        SecP384R1Field.squareN(create3, 30, create2, create);
        SecP384R1Field.square(create2, create3, create);
        if (Nat.m35eq(12, iArr, create3)) {
            return new SecP384R1FieldElement(create2);
        }
        return null;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement square() {
        int[] create = Nat.create(12);
        SecP384R1Field.square(this.f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        int[] create = Nat.create(12);
        SecP384R1Field.subtract(this.f1085x, ((SecP384R1FieldElement) eCFieldElement).f1085x, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean testBitZero() {
        return Nat.getBit(this.f1085x, 0) == 1;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat.toBigInteger(12, this.f1085x);
    }
}