package org.bouncycastle.asn1.tsp;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes.dex */
public class ArchiveTimeStampChain extends ASN1Object {
    private ASN1Sequence archiveTimeStamps;

    private ArchiveTimeStampChain(ASN1Sequence aSN1Sequence) {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(aSN1Sequence.size());
        Enumeration objects = aSN1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            aSN1EncodableVector.add(ArchiveTimeStamp.getInstance(objects.nextElement()));
        }
        this.archiveTimeStamps = new DERSequence(aSN1EncodableVector);
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp archiveTimeStamp) {
        this.archiveTimeStamps = new DERSequence(archiveTimeStamp);
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp[] archiveTimeStampArr) {
        this.archiveTimeStamps = new DERSequence(archiveTimeStampArr);
    }

    public static ArchiveTimeStampChain getInstance(Object obj) {
        if (obj instanceof ArchiveTimeStampChain) {
            return (ArchiveTimeStampChain) obj;
        }
        if (obj != null) {
            return new ArchiveTimeStampChain(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ArchiveTimeStampChain append(ArchiveTimeStamp archiveTimeStamp) {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(this.archiveTimeStamps.size() + 1);
        for (int i = 0; i != this.archiveTimeStamps.size(); i++) {
            aSN1EncodableVector.add(this.archiveTimeStamps.getObjectAt(i));
        }
        aSN1EncodableVector.add(archiveTimeStamp);
        return new ArchiveTimeStampChain(new DERSequence(aSN1EncodableVector));
    }

    public ArchiveTimeStamp[] getArchiveTimestamps() {
        int size = this.archiveTimeStamps.size();
        ArchiveTimeStamp[] archiveTimeStampArr = new ArchiveTimeStamp[size];
        for (int i = 0; i != size; i++) {
            archiveTimeStampArr[i] = ArchiveTimeStamp.getInstance(this.archiveTimeStamps.getObjectAt(i));
        }
        return archiveTimeStampArr;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.archiveTimeStamps;
    }
}