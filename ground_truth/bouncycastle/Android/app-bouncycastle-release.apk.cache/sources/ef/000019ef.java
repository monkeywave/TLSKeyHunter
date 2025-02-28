package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/* loaded from: classes.dex */
public class CMCStatusInfoV2 extends ASN1Object {
    private final ASN1Sequence bodyList;
    private final CMCStatus cMCStatus;
    private final OtherStatusInfo otherStatusInfo;
    private final ASN1UTF8String statusString;

    private CMCStatusInfoV2(ASN1Sequence aSN1Sequence) {
        ASN1Encodable objectAt;
        if (aSN1Sequence.size() < 2 || aSN1Sequence.size() > 4) {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.cMCStatus = CMCStatus.getInstance(aSN1Sequence.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(1));
        if (aSN1Sequence.size() > 2) {
            if (aSN1Sequence.size() == 4) {
                this.statusString = ASN1UTF8String.getInstance(aSN1Sequence.getObjectAt(2));
                objectAt = aSN1Sequence.getObjectAt(3);
            } else if (aSN1Sequence.getObjectAt(2) instanceof ASN1UTF8String) {
                this.statusString = ASN1UTF8String.getInstance(aSN1Sequence.getObjectAt(2));
            } else {
                this.statusString = null;
                objectAt = aSN1Sequence.getObjectAt(2);
            }
            this.otherStatusInfo = OtherStatusInfo.getInstance(objectAt);
            return;
        }
        this.statusString = null;
        this.otherStatusInfo = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CMCStatusInfoV2(CMCStatus cMCStatus, ASN1Sequence aSN1Sequence, ASN1UTF8String aSN1UTF8String, OtherStatusInfo otherStatusInfo) {
        this.cMCStatus = cMCStatus;
        this.bodyList = aSN1Sequence;
        this.statusString = aSN1UTF8String;
        this.otherStatusInfo = otherStatusInfo;
    }

    public static CMCStatusInfoV2 getInstance(Object obj) {
        if (obj instanceof CMCStatusInfoV2) {
            return (CMCStatusInfoV2) obj;
        }
        if (obj != null) {
            return new CMCStatusInfoV2(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public BodyPartID[] getBodyList() {
        return Utils.toBodyPartIDArray(this.bodyList);
    }

    public CMCStatus getCMCStatus() {
        return this.cMCStatus;
    }

    public OtherStatusInfo getOtherStatusInfo() {
        return this.otherStatusInfo;
    }

    public DERUTF8String getStatusString() {
        ASN1UTF8String aSN1UTF8String = this.statusString;
        return (aSN1UTF8String == null || (aSN1UTF8String instanceof DERUTF8String)) ? (DERUTF8String) aSN1UTF8String : new DERUTF8String(this.statusString.getString());
    }

    public ASN1UTF8String getStatusStringUTF8() {
        return this.statusString;
    }

    public CMCStatus getcMCStatus() {
        return this.cMCStatus;
    }

    public boolean hasOtherInfo() {
        return this.otherStatusInfo != null;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
        aSN1EncodableVector.add(this.cMCStatus);
        aSN1EncodableVector.add(this.bodyList);
        ASN1UTF8String aSN1UTF8String = this.statusString;
        if (aSN1UTF8String != null) {
            aSN1EncodableVector.add(aSN1UTF8String);
        }
        OtherStatusInfo otherStatusInfo = this.otherStatusInfo;
        if (otherStatusInfo != null) {
            aSN1EncodableVector.add(otherStatusInfo);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}