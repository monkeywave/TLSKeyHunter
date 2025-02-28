package org.bouncycastle.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes.dex */
public class ECPrivateKeyStructure extends ASN1Object {
    private ASN1Sequence seq;

    public ECPrivateKeyStructure(BigInteger bigInteger) {
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(new ASN1Integer(1L));
        aSN1EncodableVector.add(new DEROctetString(asUnsignedByteArray));
        this.seq = new DERSequence(aSN1EncodableVector);
    }

    public ECPrivateKeyStructure(BigInteger bigInteger, ASN1BitString aSN1BitString, ASN1Encodable aSN1Encodable) {
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
        aSN1EncodableVector.add(new ASN1Integer(1L));
        aSN1EncodableVector.add(new DEROctetString(asUnsignedByteArray));
        if (aSN1Encodable != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 0, aSN1Encodable));
        }
        if (aSN1BitString != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 1, (ASN1Encodable) aSN1BitString));
        }
        this.seq = new DERSequence(aSN1EncodableVector);
    }

    public ECPrivateKeyStructure(BigInteger bigInteger, ASN1Encodable aSN1Encodable) {
        this(bigInteger, null, aSN1Encodable);
    }

    public ECPrivateKeyStructure(ASN1Sequence aSN1Sequence) {
        this.seq = aSN1Sequence;
    }

    private ASN1Primitive getObjectInTag(int i) {
        Enumeration objects = this.seq.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Encodable aSN1Encodable = (ASN1Encodable) objects.nextElement();
            if (aSN1Encodable instanceof ASN1TaggedObject) {
                ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) aSN1Encodable;
                if (aSN1TaggedObject.getTagNo() == i) {
                    return aSN1TaggedObject.getExplicitBaseObject().toASN1Primitive();
                }
            }
        }
        return null;
    }

    public BigInteger getKey() {
        return new BigInteger(1, ((ASN1OctetString) this.seq.getObjectAt(1)).getOctets());
    }

    public ASN1Primitive getParameters() {
        return getObjectInTag(0);
    }

    public ASN1BitString getPublicKey() {
        return (ASN1BitString) getObjectInTag(1);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }
}