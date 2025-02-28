package org.bouncycastle.asn1.p009x9;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* renamed from: org.bouncycastle.asn1.x9.DHValidationParms */
/* loaded from: classes.dex */
public class DHValidationParms extends ASN1Object {
    private ASN1Integer pgenCounter;
    private ASN1BitString seed;

    public DHValidationParms(ASN1BitString aSN1BitString, ASN1Integer aSN1Integer) {
        if (aSN1BitString == null) {
            throw new IllegalArgumentException("'seed' cannot be null");
        }
        if (aSN1Integer == null) {
            throw new IllegalArgumentException("'pgenCounter' cannot be null");
        }
        this.seed = aSN1BitString;
        this.pgenCounter = aSN1Integer;
    }

    private DHValidationParms(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        this.seed = ASN1BitString.getInstance(aSN1Sequence.getObjectAt(0));
        this.pgenCounter = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public static DHValidationParms getInstance(Object obj) {
        if (obj instanceof DHValidationParms) {
            return (DHValidationParms) obj;
        }
        if (obj != null) {
            return new DHValidationParms(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static DHValidationParms getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public ASN1Integer getPgenCounter() {
        return this.pgenCounter;
    }

    public ASN1BitString getSeed() {
        return this.seed;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.seed);
        aSN1EncodableVector.add(this.pgenCounter);
        return new DERSequence(aSN1EncodableVector);
    }
}