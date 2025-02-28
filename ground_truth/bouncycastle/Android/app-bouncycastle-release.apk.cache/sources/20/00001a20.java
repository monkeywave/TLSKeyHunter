package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes.dex */
public class InfoTypeAndValue extends ASN1Object {
    private final ASN1ObjectIdentifier infoType;
    private final ASN1Encodable infoValue;

    public InfoTypeAndValue(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this(aSN1ObjectIdentifier, null);
    }

    public InfoTypeAndValue(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1Encodable aSN1Encodable) {
        if (aSN1ObjectIdentifier == null) {
            throw new NullPointerException("'infoType' cannot be null");
        }
        this.infoType = aSN1ObjectIdentifier;
        this.infoValue = aSN1Encodable;
    }

    private InfoTypeAndValue(ASN1Sequence aSN1Sequence) {
        this.infoType = ASN1ObjectIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
        this.infoValue = aSN1Sequence.size() > 1 ? aSN1Sequence.getObjectAt(1) : null;
    }

    public static InfoTypeAndValue getInstance(Object obj) {
        if (obj instanceof InfoTypeAndValue) {
            return (InfoTypeAndValue) obj;
        }
        if (obj != null) {
            return new InfoTypeAndValue(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1ObjectIdentifier getInfoType() {
        return this.infoType;
    }

    public ASN1Encodable getInfoValue() {
        return this.infoValue;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.infoType);
        ASN1Encodable aSN1Encodable = this.infoValue;
        if (aSN1Encodable != null) {
            aSN1EncodableVector.add(aSN1Encodable);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}