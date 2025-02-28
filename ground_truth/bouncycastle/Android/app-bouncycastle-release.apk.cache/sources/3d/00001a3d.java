package org.bouncycastle.asn1.cmp;

import java.util.Iterator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes.dex */
public class RootCaKeyUpdateContent extends ASN1Object {
    private final CMPCertificate newWithNew;
    private final CMPCertificate newWithOld;
    private final CMPCertificate oldWithNew;

    private RootCaKeyUpdateContent(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() < 1 || aSN1Sequence.size() > 3) {
            throw new IllegalArgumentException("expected sequence of 1 to 3 elements only");
        }
        Iterator<ASN1Encodable> it = aSN1Sequence.iterator();
        CMPCertificate cMPCertificate = CMPCertificate.getInstance(it.next());
        CMPCertificate cMPCertificate2 = null;
        CMPCertificate cMPCertificate3 = null;
        while (it.hasNext()) {
            ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(it.next());
            if (aSN1TaggedObject.hasContextTag(0)) {
                cMPCertificate2 = CMPCertificate.getInstance(aSN1TaggedObject, true);
            } else if (aSN1TaggedObject.hasContextTag(1)) {
                cMPCertificate3 = CMPCertificate.getInstance(aSN1TaggedObject, true);
            }
        }
        this.newWithNew = cMPCertificate;
        this.newWithOld = cMPCertificate2;
        this.oldWithNew = cMPCertificate3;
    }

    public RootCaKeyUpdateContent(CMPCertificate cMPCertificate, CMPCertificate cMPCertificate2, CMPCertificate cMPCertificate3) {
        if (cMPCertificate == null) {
            throw new NullPointerException("'newWithNew' cannot be null");
        }
        this.newWithNew = cMPCertificate;
        this.newWithOld = cMPCertificate2;
        this.oldWithNew = cMPCertificate3;
    }

    public static RootCaKeyUpdateContent getInstance(Object obj) {
        if (obj instanceof RootCaKeyUpdateContent) {
            return (RootCaKeyUpdateContent) obj;
        }
        if (obj != null) {
            return new RootCaKeyUpdateContent(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public CMPCertificate getNewWithNew() {
        return this.newWithNew;
    }

    public CMPCertificate getNewWithOld() {
        return this.newWithOld;
    }

    public CMPCertificate getOldWithNew() {
        return this.oldWithNew;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        aSN1EncodableVector.add(this.newWithNew);
        if (this.newWithOld != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.newWithOld));
        }
        if (this.oldWithNew != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 1, (ASN1Encodable) this.oldWithNew));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}