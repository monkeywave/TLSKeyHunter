package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes2.dex */
public class RecipientInfo extends ASN1Object implements ASN1Choice {
    public static final int certRecipInfo = 2;
    public static final int pskRecipInfo = 0;
    public static final int rekRecipInfo = 4;
    public static final int signedDataRecipInfo = 3;
    public static final int symmRecipInfo = 1;
    private final int choice;
    private final ASN1Encodable recipientInfo;

    public RecipientInfo(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.recipientInfo = aSN1Encodable;
    }

    private RecipientInfo(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable preSharedKeyRecipientInfo;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.choice = tagNo;
        if (tagNo == 0) {
            preSharedKeyRecipientInfo = PreSharedKeyRecipientInfo.getInstance((Object) aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo == 1) {
            preSharedKeyRecipientInfo = SymmRecipientInfo.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo != 2 && tagNo != 3 && tagNo != 4) {
            throw new IllegalArgumentException("invalid choice value " + tagNo);
        } else {
            preSharedKeyRecipientInfo = PKRecipientInfo.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        }
        this.recipientInfo = preSharedKeyRecipientInfo;
    }

    public static RecipientInfo certRecipInfo(PKRecipientInfo pKRecipientInfo) {
        return new RecipientInfo(2, pKRecipientInfo);
    }

    public static RecipientInfo getInstance(Object obj) {
        if (obj instanceof RecipientInfo) {
            return (RecipientInfo) obj;
        }
        if (obj != null) {
            return new RecipientInfo(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public static RecipientInfo pskRecipInfo(PreSharedKeyRecipientInfo preSharedKeyRecipientInfo) {
        return new RecipientInfo(0, preSharedKeyRecipientInfo);
    }

    public static RecipientInfo rekRecipInfo(PKRecipientInfo pKRecipientInfo) {
        return new RecipientInfo(4, pKRecipientInfo);
    }

    public static RecipientInfo signedDataRecipInfo(PKRecipientInfo pKRecipientInfo) {
        return new RecipientInfo(3, pKRecipientInfo);
    }

    public static RecipientInfo symmRecipInfo(SymmRecipientInfo symmRecipientInfo) {
        return new RecipientInfo(1, symmRecipientInfo);
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getRecipientInfo() {
        return this.recipientInfo;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.recipientInfo);
    }
}