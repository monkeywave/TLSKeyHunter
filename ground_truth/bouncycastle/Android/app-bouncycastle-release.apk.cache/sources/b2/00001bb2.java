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

/* loaded from: classes.dex */
public class DSAParameter extends ASN1Object {

    /* renamed from: g */
    ASN1Integer f305g;

    /* renamed from: p */
    ASN1Integer f306p;

    /* renamed from: q */
    ASN1Integer f307q;

    public DSAParameter(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f306p = new ASN1Integer(bigInteger);
        this.f307q = new ASN1Integer(bigInteger2);
        this.f305g = new ASN1Integer(bigInteger3);
    }

    private DSAParameter(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.f306p = ASN1Integer.getInstance(objects.nextElement());
        this.f307q = ASN1Integer.getInstance(objects.nextElement());
        this.f305g = ASN1Integer.getInstance(objects.nextElement());
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

    public static DSAParameter getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public BigInteger getG() {
        return this.f305g.getPositiveValue();
    }

    public BigInteger getP() {
        return this.f306p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f307q.getPositiveValue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        aSN1EncodableVector.add(this.f306p);
        aSN1EncodableVector.add(this.f307q);
        aSN1EncodableVector.add(this.f305g);
        return new DERSequence(aSN1EncodableVector);
    }
}