package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/* loaded from: classes.dex */
public class ContentHints extends ASN1Object {
    private ASN1UTF8String contentDescription;
    private ASN1ObjectIdentifier contentType;

    public ContentHints(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.contentType = aSN1ObjectIdentifier;
        this.contentDescription = null;
    }

    public ContentHints(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1UTF8String aSN1UTF8String) {
        this.contentType = aSN1ObjectIdentifier;
        this.contentDescription = aSN1UTF8String;
    }

    private ContentHints(ASN1Sequence aSN1Sequence) {
        int i = 0;
        ASN1Encodable objectAt = aSN1Sequence.getObjectAt(0);
        if (objectAt.toASN1Primitive() instanceof ASN1UTF8String) {
            this.contentDescription = ASN1UTF8String.getInstance(objectAt);
            i = 1;
        }
        this.contentType = ASN1ObjectIdentifier.getInstance(aSN1Sequence.getObjectAt(i));
    }

    public static ContentHints getInstance(Object obj) {
        if (obj instanceof ContentHints) {
            return (ContentHints) obj;
        }
        if (obj != null) {
            return new ContentHints(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DERUTF8String getContentDescription() {
        ASN1UTF8String aSN1UTF8String = this.contentDescription;
        return (aSN1UTF8String == null || (aSN1UTF8String instanceof DERUTF8String)) ? (DERUTF8String) aSN1UTF8String : new DERUTF8String(this.contentDescription.getString());
    }

    public ASN1UTF8String getContentDescriptionUTF8() {
        return this.contentDescription;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        ASN1UTF8String aSN1UTF8String = this.contentDescription;
        if (aSN1UTF8String != null) {
            aSN1EncodableVector.add(aSN1UTF8String);
        }
        aSN1EncodableVector.add(this.contentType);
        return new DERSequence(aSN1EncodableVector);
    }
}