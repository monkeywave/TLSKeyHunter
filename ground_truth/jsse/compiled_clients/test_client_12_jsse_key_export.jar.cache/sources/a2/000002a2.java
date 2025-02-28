package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/pkcs/DHParameter.class */
public class DHParameter extends ASN1Object {

    /* renamed from: p */
    ASN1Integer f27p;

    /* renamed from: g */
    ASN1Integer f28g;

    /* renamed from: l */
    ASN1Integer f29l;

    public DHParameter(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        this.f27p = new ASN1Integer(bigInteger);
        this.f28g = new ASN1Integer(bigInteger2);
        if (i != 0) {
            this.f29l = new ASN1Integer(i);
        } else {
            this.f29l = null;
        }
    }

    public static DHParameter getInstance(Object obj) {
        if (obj instanceof DHParameter) {
            return (DHParameter) obj;
        }
        if (obj != null) {
            return new DHParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private DHParameter(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f27p = ASN1Integer.getInstance(objects.nextElement());
        this.f28g = ASN1Integer.getInstance(objects.nextElement());
        if (objects.hasMoreElements()) {
            this.f29l = (ASN1Integer) objects.nextElement();
        } else {
            this.f29l = null;
        }
    }

    public BigInteger getP() {
        return this.f27p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f28g.getPositiveValue();
    }

    public BigInteger getL() {
        if (this.f29l == null) {
            return null;
        }
        return this.f29l.getPositiveValue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        aSN1EncodableVector.add(this.f27p);
        aSN1EncodableVector.add(this.f28g);
        if (getL() != null) {
            aSN1EncodableVector.add(this.f29l);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}