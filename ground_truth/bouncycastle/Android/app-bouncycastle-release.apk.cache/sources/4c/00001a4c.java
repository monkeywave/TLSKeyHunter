package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

/* loaded from: classes.dex */
public class ContentInfo extends ASN1Object implements CMSObjectIdentifiers {
    private final ASN1Encodable content;
    private final ASN1ObjectIdentifier contentType;
    private final boolean isDefiniteLength;

    public ContentInfo(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1Encodable aSN1Encodable) {
        this.contentType = aSN1ObjectIdentifier;
        this.content = aSN1Encodable;
        boolean z = true;
        if (aSN1Encodable != null) {
            ASN1Primitive aSN1Primitive = aSN1Encodable.toASN1Primitive();
            if (!(aSN1Primitive instanceof DEROctetString) && !(aSN1Primitive instanceof DLSequence) && !(aSN1Primitive instanceof DERSequence)) {
                z = false;
            }
        }
        this.isDefiniteLength = z;
    }

    private ContentInfo(ASN1Sequence aSN1Sequence) {
        ASN1Object aSN1Object;
        if (aSN1Sequence.size() < 1 || aSN1Sequence.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        this.contentType = (ASN1ObjectIdentifier) aSN1Sequence.getObjectAt(0);
        if (aSN1Sequence.size() > 1) {
            ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(aSN1Sequence.getObjectAt(1), 128);
            if (!aSN1TaggedObject.isExplicit() || aSN1TaggedObject.getTagNo() != 0) {
                throw new IllegalArgumentException("Bad tag for 'content'");
            }
            aSN1Object = aSN1TaggedObject.getExplicitBaseObject();
        } else {
            aSN1Object = null;
        }
        this.content = aSN1Object;
        this.isDefiniteLength = !(aSN1Sequence instanceof BERSequence);
    }

    public static ContentInfo getInstance(Object obj) {
        if (obj instanceof ContentInfo) {
            return (ContentInfo) obj;
        }
        if (obj != null) {
            return new ContentInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static ContentInfo getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public ASN1Encodable getContent() {
        return this.content;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public boolean isDefiniteLength() {
        return this.isDefiniteLength;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.contentType);
        if (this.content != null) {
            aSN1EncodableVector.add(this.isDefiniteLength ? new DLTaggedObject(0, this.content) : new BERTaggedObject(0, this.content));
        }
        return this.isDefiniteLength ? new DLSequence(aSN1EncodableVector) : new BERSequence(aSN1EncodableVector);
    }
}