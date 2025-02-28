package org.bouncycastle.asn1.p003x9;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* renamed from: org.bouncycastle.asn1.x9.DomainParameters */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x9/DomainParameters.class */
public class DomainParameters extends ASN1Object {

    /* renamed from: p */
    private final ASN1Integer f81p;

    /* renamed from: g */
    private final ASN1Integer f82g;

    /* renamed from: q */
    private final ASN1Integer f83q;

    /* renamed from: j */
    private final ASN1Integer f84j;
    private final ValidationParams validationParams;

    public static DomainParameters getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public static DomainParameters getInstance(Object obj) {
        if (obj instanceof DomainParameters) {
            return (DomainParameters) obj;
        }
        if (obj != null) {
            return new DomainParameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DomainParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, ValidationParams validationParams) {
        if (bigInteger == null) {
            throw new IllegalArgumentException("'p' cannot be null");
        }
        if (bigInteger2 == null) {
            throw new IllegalArgumentException("'g' cannot be null");
        }
        if (bigInteger3 == null) {
            throw new IllegalArgumentException("'q' cannot be null");
        }
        this.f81p = new ASN1Integer(bigInteger);
        this.f82g = new ASN1Integer(bigInteger2);
        this.f83q = new ASN1Integer(bigInteger3);
        if (bigInteger4 != null) {
            this.f84j = new ASN1Integer(bigInteger4);
        } else {
            this.f84j = null;
        }
        this.validationParams = validationParams;
    }

    private DomainParameters(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() < 3 || aSN1Sequence.size() > 5) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.f81p = ASN1Integer.getInstance(objects.nextElement());
        this.f82g = ASN1Integer.getInstance(objects.nextElement());
        this.f83q = ASN1Integer.getInstance(objects.nextElement());
        ASN1Encodable next = getNext(objects);
        if (next == null || !(next instanceof ASN1Integer)) {
            this.f84j = null;
        } else {
            this.f84j = ASN1Integer.getInstance(next);
            next = getNext(objects);
        }
        if (next != null) {
            this.validationParams = ValidationParams.getInstance(next.toASN1Primitive());
        } else {
            this.validationParams = null;
        }
    }

    private static ASN1Encodable getNext(Enumeration enumeration) {
        if (enumeration.hasMoreElements()) {
            return (ASN1Encodable) enumeration.nextElement();
        }
        return null;
    }

    public BigInteger getP() {
        return this.f81p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f82g.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f83q.getPositiveValue();
    }

    public BigInteger getJ() {
        if (this.f84j == null) {
            return null;
        }
        return this.f84j.getPositiveValue();
    }

    public ValidationParams getValidationParams() {
        return this.validationParams;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(5);
        aSN1EncodableVector.add(this.f81p);
        aSN1EncodableVector.add(this.f82g);
        aSN1EncodableVector.add(this.f83q);
        if (this.f84j != null) {
            aSN1EncodableVector.add(this.f84j);
        }
        if (this.validationParams != null) {
            aSN1EncodableVector.add(this.validationParams);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}