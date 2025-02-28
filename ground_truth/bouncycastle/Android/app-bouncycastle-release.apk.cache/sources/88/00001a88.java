package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EnvelopedData;

/* loaded from: classes.dex */
public class POPOPrivKey extends ASN1Object implements ASN1Choice {
    public static final int agreeMAC = 3;
    public static final int dhMAC = 2;
    public static final int encryptedKey = 4;
    public static final int subsequentMessage = 1;
    public static final int thisMessage = 0;
    private ASN1Encodable obj;
    private int tagNo;

    private POPOPrivKey(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable aSN1BitString;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.tagNo = tagNo;
        if (tagNo != 0) {
            if (tagNo == 1) {
                aSN1BitString = SubsequentMessage.valueOf(ASN1Integer.getInstance(aSN1TaggedObject, false).intValueExact());
            } else if (tagNo != 2) {
                if (tagNo == 3) {
                    aSN1BitString = PKMACValue.getInstance(aSN1TaggedObject, false);
                } else if (tagNo != 4) {
                    throw new IllegalArgumentException("unknown tag in POPOPrivKey");
                } else {
                    aSN1BitString = EnvelopedData.getInstance(aSN1TaggedObject, false);
                }
            }
            this.obj = aSN1BitString;
        }
        aSN1BitString = ASN1BitString.getInstance(aSN1TaggedObject, false);
        this.obj = aSN1BitString;
    }

    public POPOPrivKey(PKMACValue pKMACValue) {
        this.tagNo = 3;
        this.obj = pKMACValue;
    }

    public POPOPrivKey(SubsequentMessage subsequentMessage2) {
        this.tagNo = 1;
        this.obj = subsequentMessage2;
    }

    public static POPOPrivKey getInstance(Object obj) {
        if (obj instanceof POPOPrivKey) {
            return (POPOPrivKey) obj;
        }
        if (obj != null) {
            return new POPOPrivKey(ASN1TaggedObject.getInstance(obj));
        }
        return null;
    }

    public static POPOPrivKey getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1TaggedObject.getInstance(aSN1TaggedObject, true));
    }

    public int getType() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.obj;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, this.tagNo, this.obj);
    }
}