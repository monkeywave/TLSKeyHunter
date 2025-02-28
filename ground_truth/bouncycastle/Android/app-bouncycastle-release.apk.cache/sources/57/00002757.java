package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement */
/* loaded from: classes2.dex */
public class SecP256R1FieldElement extends ECFieldElement.AbstractFp {

    /* renamed from: Q */
    public static final BigInteger f1079Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));

    /* renamed from: x */
    protected int[] f1080x;

    public SecP256R1FieldElement() {
        this.f1080x = Nat256.create();
    }

    public SecP256R1FieldElement(BigInteger bigInteger) {
        if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.compareTo(f1079Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP256R1FieldElement");
        }
        this.f1080x = SecP256R1Field.fromBigInteger(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SecP256R1FieldElement(int[] iArr) {
        this.f1080x = iArr;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement add(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.add(this.f1080x, ((SecP256R1FieldElement) eCFieldElement).f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] create = Nat256.create();
        SecP256R1Field.addOne(this.f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.inv(((SecP256R1FieldElement) eCFieldElement).f1080x, create);
        SecP256R1Field.multiply(create, this.f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SecP256R1FieldElement) {
            return Nat256.m30eq(this.f1080x, ((SecP256R1FieldElement) obj).f1080x);
        }
        return false;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public String getFieldName() {
        return "SecP256R1Field";
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public int getFieldSize() {
        return f1079Q.bitLength();
    }

    public int hashCode() {
        return f1079Q.hashCode() ^ Arrays.hashCode(this.f1080x, 0, 8);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement invert() {
        int[] create = Nat256.create();
        SecP256R1Field.inv(this.f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne(this.f1080x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero(this.f1080x);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.multiply(this.f1080x, ((SecP256R1FieldElement) eCFieldElement).f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement negate() {
        int[] create = Nat256.create();
        SecP256R1Field.negate(this.f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] iArr = this.f1080x;
        if (Nat256.isZero(iArr) || Nat256.isOne(iArr)) {
            return this;
        }
        int[] createExt = Nat256.createExt();
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        SecP256R1Field.square(iArr, create, createExt);
        SecP256R1Field.multiply(create, iArr, create, createExt);
        SecP256R1Field.squareN(create, 2, create2, createExt);
        SecP256R1Field.multiply(create2, create, create2, createExt);
        SecP256R1Field.squareN(create2, 4, create, createExt);
        SecP256R1Field.multiply(create, create2, create, createExt);
        SecP256R1Field.squareN(create, 8, create2, createExt);
        SecP256R1Field.multiply(create2, create, create2, createExt);
        SecP256R1Field.squareN(create2, 16, create, createExt);
        SecP256R1Field.multiply(create, create2, create, createExt);
        SecP256R1Field.squareN(create, 32, create, createExt);
        SecP256R1Field.multiply(create, iArr, create, createExt);
        SecP256R1Field.squareN(create, 96, create, createExt);
        SecP256R1Field.multiply(create, iArr, create, createExt);
        SecP256R1Field.squareN(create, 94, create, createExt);
        SecP256R1Field.square(create, create2, createExt);
        if (Nat256.m30eq(iArr, create2)) {
            return new SecP256R1FieldElement(create);
        }
        return null;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement square() {
        int[] create = Nat256.create();
        SecP256R1Field.square(this.f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement eCFieldElement) {
        int[] create = Nat256.create();
        SecP256R1Field.subtract(this.f1080x, ((SecP256R1FieldElement) eCFieldElement).f1080x, create);
        return new SecP256R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public boolean testBitZero() {
        return Nat256.getBit(this.f1080x, 0) == 1;
    }

    @Override // org.bouncycastle.math.p016ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger(this.f1080x);
    }
}