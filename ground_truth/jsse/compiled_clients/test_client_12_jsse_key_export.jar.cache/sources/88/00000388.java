package org.bouncycastle.asn1.p003x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.p010ec.ECFieldElement;

/* renamed from: org.bouncycastle.asn1.x9.X9FieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x9/X9FieldElement.class */
public class X9FieldElement extends ASN1Object {

    /* renamed from: f */
    protected ECFieldElement f90f;
    private static X9IntegerConverter converter = new X9IntegerConverter();

    public X9FieldElement(ECFieldElement eCFieldElement) {
        this.f90f = eCFieldElement;
    }

    public ECFieldElement getValue() {
        return this.f90f;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(converter.integerToBytes(this.f90f.toBigInteger(), converter.getByteLength(this.f90f)));
    }
}