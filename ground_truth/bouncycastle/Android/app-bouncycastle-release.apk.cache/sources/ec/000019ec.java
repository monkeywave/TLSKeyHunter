package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/* loaded from: classes.dex */
public class CMCStatusInfo extends ASN1Object {
    private final ASN1Sequence bodyList;
    private final CMCStatus cMCStatus;
    private final OtherInfo otherInfo;
    private final ASN1UTF8String statusString;

    /* loaded from: classes.dex */
    public static class OtherInfo extends ASN1Object implements ASN1Choice {
        private final CMCFailInfo failInfo;
        private final PendInfo pendInfo;

        /* JADX INFO: Access modifiers changed from: package-private */
        public OtherInfo(CMCFailInfo cMCFailInfo) {
            this(cMCFailInfo, null);
        }

        private OtherInfo(CMCFailInfo cMCFailInfo, PendInfo pendInfo) {
            this.failInfo = cMCFailInfo;
            this.pendInfo = pendInfo;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public OtherInfo(PendInfo pendInfo) {
            this(null, pendInfo);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static OtherInfo getInstance(Object obj) {
            if (obj instanceof OtherInfo) {
                return (OtherInfo) obj;
            }
            if (obj instanceof ASN1Encodable) {
                ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
                if (aSN1Primitive instanceof ASN1Integer) {
                    return new OtherInfo(CMCFailInfo.getInstance(aSN1Primitive));
                }
                if (aSN1Primitive instanceof ASN1Sequence) {
                    return new OtherInfo(PendInfo.getInstance(aSN1Primitive));
                }
            }
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }

        public boolean isFailInfo() {
            return this.failInfo != null;
        }

        @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
        public ASN1Primitive toASN1Primitive() {
            PendInfo pendInfo = this.pendInfo;
            return pendInfo != null ? pendInfo.toASN1Primitive() : this.failInfo.toASN1Primitive();
        }
    }

    private CMCStatusInfo(ASN1Sequence aSN1Sequence) {
        ASN1Encodable objectAt;
        if (aSN1Sequence.size() < 2 || aSN1Sequence.size() > 4) {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.cMCStatus = CMCStatus.getInstance(aSN1Sequence.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(1));
        if (aSN1Sequence.size() <= 3) {
            if (aSN1Sequence.size() <= 2) {
                this.statusString = null;
            } else if (aSN1Sequence.getObjectAt(2) instanceof ASN1UTF8String) {
                this.statusString = ASN1UTF8String.getInstance(aSN1Sequence.getObjectAt(2));
            } else {
                this.statusString = null;
                objectAt = aSN1Sequence.getObjectAt(2);
            }
            this.otherInfo = null;
            return;
        }
        this.statusString = ASN1UTF8String.getInstance(aSN1Sequence.getObjectAt(2));
        objectAt = aSN1Sequence.getObjectAt(3);
        this.otherInfo = OtherInfo.getInstance(objectAt);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence aSN1Sequence, ASN1UTF8String aSN1UTF8String, OtherInfo otherInfo) {
        this.cMCStatus = cMCStatus;
        this.bodyList = aSN1Sequence;
        this.statusString = aSN1UTF8String;
        this.otherInfo = otherInfo;
    }

    public static CMCStatusInfo getInstance(Object obj) {
        if (obj instanceof CMCStatusInfo) {
            return (CMCStatusInfo) obj;
        }
        if (obj != null) {
            return new CMCStatusInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public BodyPartID[] getBodyList() {
        return Utils.toBodyPartIDArray(this.bodyList);
    }

    public CMCStatus getCMCStatus() {
        return this.cMCStatus;
    }

    public OtherInfo getOtherInfo() {
        return this.otherInfo;
    }

    public DERUTF8String getStatusString() {
        ASN1UTF8String aSN1UTF8String = this.statusString;
        return (aSN1UTF8String == null || (aSN1UTF8String instanceof DERUTF8String)) ? (DERUTF8String) aSN1UTF8String : new DERUTF8String(this.statusString.getString());
    }

    public ASN1UTF8String getStatusStringUTF8() {
        return this.statusString;
    }

    public boolean hasOtherInfo() {
        return this.otherInfo != null;
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
        OtherInfo otherInfo = this.otherInfo;
        if (otherInfo != null) {
            aSN1EncodableVector.add(otherInfo);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}