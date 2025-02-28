package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/* loaded from: classes.dex */
public class MetaData extends ASN1Object {
    private ASN1UTF8String fileName;
    private ASN1Boolean hashProtected;
    private ASN1IA5String mediaType;
    private Attributes otherMetaData;

    public MetaData(ASN1Boolean aSN1Boolean, ASN1UTF8String aSN1UTF8String, ASN1IA5String aSN1IA5String, Attributes attributes) {
        this.hashProtected = aSN1Boolean;
        this.fileName = aSN1UTF8String;
        this.mediaType = aSN1IA5String;
        this.otherMetaData = attributes;
    }

    private MetaData(ASN1Sequence aSN1Sequence) {
        this.hashProtected = ASN1Boolean.getInstance(aSN1Sequence.getObjectAt(0));
        int i = 1;
        if (1 < aSN1Sequence.size() && (aSN1Sequence.getObjectAt(1) instanceof ASN1UTF8String)) {
            this.fileName = ASN1UTF8String.getInstance(aSN1Sequence.getObjectAt(1));
            i = 2;
        }
        if (i < aSN1Sequence.size() && (aSN1Sequence.getObjectAt(i) instanceof ASN1IA5String)) {
            this.mediaType = ASN1IA5String.getInstance(aSN1Sequence.getObjectAt(i));
            i++;
        }
        if (i < aSN1Sequence.size()) {
            this.otherMetaData = Attributes.getInstance(aSN1Sequence.getObjectAt(i));
        }
    }

    public static MetaData getInstance(Object obj) {
        if (obj instanceof MetaData) {
            return (MetaData) obj;
        }
        if (obj != null) {
            return new MetaData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DERUTF8String getFileName() {
        ASN1UTF8String aSN1UTF8String = this.fileName;
        return (aSN1UTF8String == null || (aSN1UTF8String instanceof DERUTF8String)) ? (DERUTF8String) aSN1UTF8String : new DERUTF8String(this.fileName.getString());
    }

    public ASN1UTF8String getFileNameUTF8() {
        return this.fileName;
    }

    public DERIA5String getMediaType() {
        ASN1IA5String aSN1IA5String = this.mediaType;
        return (aSN1IA5String == null || (aSN1IA5String instanceof DERIA5String)) ? (DERIA5String) aSN1IA5String : new DERIA5String(this.mediaType.getString(), false);
    }

    public ASN1IA5String getMediaTypeIA5() {
        return this.mediaType;
    }

    public Attributes getOtherMetaData() {
        return this.otherMetaData;
    }

    public boolean isHashProtected() {
        return this.hashProtected.isTrue();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
        aSN1EncodableVector.add(this.hashProtected);
        ASN1UTF8String aSN1UTF8String = this.fileName;
        if (aSN1UTF8String != null) {
            aSN1EncodableVector.add(aSN1UTF8String);
        }
        ASN1IA5String aSN1IA5String = this.mediaType;
        if (aSN1IA5String != null) {
            aSN1EncodableVector.add(aSN1IA5String);
        }
        Attributes attributes = this.otherMetaData;
        if (attributes != null) {
            aSN1EncodableVector.add(attributes);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}