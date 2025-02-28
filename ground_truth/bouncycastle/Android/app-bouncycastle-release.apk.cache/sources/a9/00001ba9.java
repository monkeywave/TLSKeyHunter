package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes.dex */
public class BasicConstraints extends ASN1Object {

    /* renamed from: cA */
    ASN1Boolean f303cA;
    ASN1Integer pathLenConstraint;

    public BasicConstraints(int i) {
        this.f303cA = ASN1Boolean.getInstance(false);
        this.pathLenConstraint = null;
        this.f303cA = ASN1Boolean.getInstance(true);
        this.pathLenConstraint = new ASN1Integer(i);
    }

    private BasicConstraints(ASN1Sequence aSN1Sequence) {
        this.f303cA = ASN1Boolean.getInstance(false);
        this.pathLenConstraint = null;
        if (aSN1Sequence.size() == 0) {
            this.f303cA = null;
            this.pathLenConstraint = null;
            return;
        }
        if (aSN1Sequence.getObjectAt(0) instanceof ASN1Boolean) {
            this.f303cA = ASN1Boolean.getInstance(aSN1Sequence.getObjectAt(0));
        } else {
            this.f303cA = null;
            this.pathLenConstraint = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0));
        }
        if (aSN1Sequence.size() > 1) {
            if (this.f303cA == null) {
                throw new IllegalArgumentException("wrong sequence in constructor");
            }
            this.pathLenConstraint = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(1));
        }
    }

    public BasicConstraints(boolean z) {
        this.f303cA = ASN1Boolean.getInstance(false);
        this.pathLenConstraint = null;
        if (z) {
            this.f303cA = ASN1Boolean.getInstance(true);
        } else {
            this.f303cA = null;
        }
        this.pathLenConstraint = null;
    }

    public static BasicConstraints fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.basicConstraints));
    }

    public static BasicConstraints getInstance(Object obj) {
        if (obj instanceof BasicConstraints) {
            return (BasicConstraints) obj;
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        if (obj != null) {
            return new BasicConstraints(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static BasicConstraints getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public BigInteger getPathLenConstraint() {
        ASN1Integer aSN1Integer = this.pathLenConstraint;
        if (aSN1Integer != null) {
            return aSN1Integer.getValue();
        }
        return null;
    }

    public ASN1Integer getPathLenConstraintInteger() {
        return this.pathLenConstraint;
    }

    public boolean isCA() {
        ASN1Boolean aSN1Boolean = this.f303cA;
        return aSN1Boolean != null && aSN1Boolean.isTrue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        ASN1Boolean aSN1Boolean = this.f303cA;
        if (aSN1Boolean != null) {
            aSN1EncodableVector.add(aSN1Boolean);
        }
        ASN1Integer aSN1Integer = this.pathLenConstraint;
        if (aSN1Integer != null) {
            aSN1EncodableVector.add(aSN1Integer);
        }
        return new DERSequence(aSN1EncodableVector);
    }

    public String toString() {
        return (this.pathLenConstraint == null ? new StringBuilder("BasicConstraints: isCa(").append(isCA()).append(")") : new StringBuilder("BasicConstraints: isCa(").append(isCA()).append("), pathLenConstraint = ").append(this.pathLenConstraint.getValue())).toString();
    }
}