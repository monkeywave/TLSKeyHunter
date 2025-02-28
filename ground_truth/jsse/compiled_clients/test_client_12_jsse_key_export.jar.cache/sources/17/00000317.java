package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x509/DSAParameter.class */
public class DSAParameter extends ASN1Object {

    /* renamed from: p */
    ASN1Integer f61p;

    /* renamed from: q */
    ASN1Integer f62q;

    /* renamed from: g */
    ASN1Integer f63g;

    public static DSAParameter getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public static DSAParameter getInstance(Object obj) {
        if (obj instanceof DSAParameter) {
            return (DSAParameter) obj;
        }
        if (obj != null) {
            return new DSAParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSAParameter(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f61p = new ASN1Integer(bigInteger);
        this.f62q = new ASN1Integer(bigInteger2);
        this.f63g = new ASN1Integer(bigInteger3);
    }

    private DSAParameter(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.f61p = ASN1Integer.getInstance(objects.nextElement());
        this.f62q = ASN1Integer.getInstance(objects.nextElement());
        this.f63g = ASN1Integer.getInstance(objects.nextElement());
    }

    public BigInteger getP() {
        return this.f61p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f62q.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f63g.getPositiveValue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        aSN1EncodableVector.add(this.f61p);
        aSN1EncodableVector.add(this.f62q);
        aSN1EncodableVector.add(this.f63g);
        return new DERSequence(aSN1EncodableVector);
    }
}