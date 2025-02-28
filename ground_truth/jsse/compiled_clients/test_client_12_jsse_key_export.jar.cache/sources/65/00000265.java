package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/cryptopro/ECGOST3410ParamSetParameters.class */
public class ECGOST3410ParamSetParameters extends ASN1Object {

    /* renamed from: p */
    ASN1Integer f11p;

    /* renamed from: q */
    ASN1Integer f12q;

    /* renamed from: a */
    ASN1Integer f13a;

    /* renamed from: b */
    ASN1Integer f14b;

    /* renamed from: x */
    ASN1Integer f15x;

    /* renamed from: y */
    ASN1Integer f16y;

    public static ECGOST3410ParamSetParameters getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public static ECGOST3410ParamSetParameters getInstance(Object obj) {
        if (obj == null || (obj instanceof ECGOST3410ParamSetParameters)) {
            return (ECGOST3410ParamSetParameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ECGOST3410ParamSetParameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public ECGOST3410ParamSetParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, int i, BigInteger bigInteger5) {
        this.f13a = new ASN1Integer(bigInteger);
        this.f14b = new ASN1Integer(bigInteger2);
        this.f11p = new ASN1Integer(bigInteger3);
        this.f12q = new ASN1Integer(bigInteger4);
        this.f15x = new ASN1Integer(i);
        this.f16y = new ASN1Integer(bigInteger5);
    }

    public ECGOST3410ParamSetParameters(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f13a = (ASN1Integer) objects.nextElement();
        this.f14b = (ASN1Integer) objects.nextElement();
        this.f11p = (ASN1Integer) objects.nextElement();
        this.f12q = (ASN1Integer) objects.nextElement();
        this.f15x = (ASN1Integer) objects.nextElement();
        this.f16y = (ASN1Integer) objects.nextElement();
    }

    public BigInteger getP() {
        return this.f11p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f12q.getPositiveValue();
    }

    public BigInteger getA() {
        return this.f13a.getPositiveValue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(6);
        aSN1EncodableVector.add(this.f13a);
        aSN1EncodableVector.add(this.f14b);
        aSN1EncodableVector.add(this.f11p);
        aSN1EncodableVector.add(this.f12q);
        aSN1EncodableVector.add(this.f15x);
        aSN1EncodableVector.add(this.f16y);
        return new DERSequence(aSN1EncodableVector);
    }
}