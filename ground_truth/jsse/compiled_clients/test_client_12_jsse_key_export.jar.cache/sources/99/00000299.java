package org.bouncycastle.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/oiw/ElGamalParameter.class */
public class ElGamalParameter extends ASN1Object {

    /* renamed from: p */
    ASN1Integer f25p;

    /* renamed from: g */
    ASN1Integer f26g;

    public ElGamalParameter(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f25p = new ASN1Integer(bigInteger);
        this.f26g = new ASN1Integer(bigInteger2);
    }

    private ElGamalParameter(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f25p = (ASN1Integer) objects.nextElement();
        this.f26g = (ASN1Integer) objects.nextElement();
    }

    public static ElGamalParameter getInstance(Object obj) {
        if (obj instanceof ElGamalParameter) {
            return (ElGamalParameter) obj;
        }
        if (obj != null) {
            return new ElGamalParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public BigInteger getP() {
        return this.f25p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f26g.getPositiveValue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.f25p);
        aSN1EncodableVector.add(this.f26g);
        return new DERSequence(aSN1EncodableVector);
    }
}