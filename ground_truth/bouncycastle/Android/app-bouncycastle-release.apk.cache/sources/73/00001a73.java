package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERIA5String;

/* loaded from: classes.dex */
public class TimeStampedData extends ASN1Object {
    private ASN1OctetString content;
    private ASN1IA5String dataUri;
    private MetaData metaData;
    private Evidence temporalEvidence;
    private ASN1Integer version;

    public TimeStampedData(ASN1IA5String aSN1IA5String, MetaData metaData, ASN1OctetString aSN1OctetString, Evidence evidence) {
        this.version = new ASN1Integer(1L);
        this.dataUri = aSN1IA5String;
        this.metaData = metaData;
        this.content = aSN1OctetString;
        this.temporalEvidence = evidence;
    }

    private TimeStampedData(ASN1Sequence aSN1Sequence) {
        this.version = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0));
        int i = 1;
        if (aSN1Sequence.getObjectAt(1) instanceof ASN1IA5String) {
            this.dataUri = ASN1IA5String.getInstance(aSN1Sequence.getObjectAt(1));
            i = 2;
        }
        if ((aSN1Sequence.getObjectAt(i) instanceof MetaData) || (aSN1Sequence.getObjectAt(i) instanceof ASN1Sequence)) {
            this.metaData = MetaData.getInstance(aSN1Sequence.getObjectAt(i));
            i++;
        }
        if (aSN1Sequence.getObjectAt(i) instanceof ASN1OctetString) {
            this.content = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i));
            i++;
        }
        this.temporalEvidence = Evidence.getInstance(aSN1Sequence.getObjectAt(i));
    }

    public static TimeStampedData getInstance(Object obj) {
        return (obj == null || (obj instanceof TimeStampedData)) ? (TimeStampedData) obj : new TimeStampedData(ASN1Sequence.getInstance(obj));
    }

    public ASN1OctetString getContent() {
        return this.content;
    }

    public DERIA5String getDataUri() {
        ASN1IA5String aSN1IA5String = this.dataUri;
        return (aSN1IA5String == null || (aSN1IA5String instanceof DERIA5String)) ? (DERIA5String) aSN1IA5String : new DERIA5String(this.dataUri.getString(), false);
    }

    public ASN1IA5String getDataUriIA5() {
        return this.dataUri;
    }

    public MetaData getMetaData() {
        return this.metaData;
    }

    public Evidence getTemporalEvidence() {
        return this.temporalEvidence;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(5);
        aSN1EncodableVector.add(this.version);
        ASN1IA5String aSN1IA5String = this.dataUri;
        if (aSN1IA5String != null) {
            aSN1EncodableVector.add(aSN1IA5String);
        }
        MetaData metaData = this.metaData;
        if (metaData != null) {
            aSN1EncodableVector.add(metaData);
        }
        ASN1OctetString aSN1OctetString = this.content;
        if (aSN1OctetString != null) {
            aSN1EncodableVector.add(aSN1OctetString);
        }
        aSN1EncodableVector.add(this.temporalEvidence);
        return new BERSequence(aSN1EncodableVector);
    }
}