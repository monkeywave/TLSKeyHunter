package org.bouncycastle.asn1.p009x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.p016ec.ECFieldElement;

/* renamed from: org.bouncycastle.asn1.x9.X9FieldElement */
/* loaded from: classes.dex */
public class X9FieldElement extends ASN1Object {
    private static X9IntegerConverter converter = new X9IntegerConverter();

    /* renamed from: f */
    protected ECFieldElement f334f;

    public X9FieldElement(ECFieldElement eCFieldElement) {
        this.f334f = eCFieldElement;
    }

    public ECFieldElement getValue() {
        return this.f334f;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(converter.integerToBytes(this.f334f.toBigInteger(), converter.getByteLength(this.f334f)));
    }
}