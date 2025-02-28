package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes.dex */
public class EnvelopedData extends ASN1Object {
    private EncryptedContentInfo encryptedContentInfo;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private ASN1Set unprotectedAttrs;
    private ASN1Integer version;

    private EnvelopedData(ASN1Sequence aSN1Sequence) {
        this.version = (ASN1Integer) aSN1Sequence.getObjectAt(0);
        ASN1Encodable objectAt = aSN1Sequence.getObjectAt(1);
        int i = 2;
        if (objectAt instanceof ASN1TaggedObject) {
            this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject) objectAt, false);
            objectAt = aSN1Sequence.getObjectAt(2);
            i = 3;
        }
        this.recipientInfos = ASN1Set.getInstance(objectAt);
        int i2 = i + 1;
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(aSN1Sequence.getObjectAt(i));
        if (aSN1Sequence.size() > i2) {
            this.unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject) aSN1Sequence.getObjectAt(i2), false);
        }
    }

    public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set aSN1Set, EncryptedContentInfo encryptedContentInfo, ASN1Set aSN1Set2) {
        this.version = new ASN1Integer(calculateVersion(originatorInfo, aSN1Set, aSN1Set2));
        this.originatorInfo = originatorInfo;
        this.recipientInfos = aSN1Set;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = aSN1Set2;
    }

    public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set aSN1Set, EncryptedContentInfo encryptedContentInfo, Attributes attributes) {
        this.version = new ASN1Integer(calculateVersion(originatorInfo, aSN1Set, ASN1Set.getInstance(attributes)));
        this.originatorInfo = originatorInfo;
        this.recipientInfos = aSN1Set;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = ASN1Set.getInstance(attributes);
    }

    public static int calculateVersion(OriginatorInfo originatorInfo, ASN1Set aSN1Set, ASN1Set aSN1Set2) {
        if (originatorInfo != null) {
            ASN1Set cRLs = originatorInfo.getCRLs();
            if (cRLs != null) {
                int size = cRLs.size();
                for (int i = 0; i < size; i++) {
                    ASN1Encodable objectAt = cRLs.getObjectAt(i);
                    if ((objectAt instanceof ASN1TaggedObject) && ((ASN1TaggedObject) objectAt).hasContextTag(1)) {
                        return 4;
                    }
                }
            }
            ASN1Set certificates = originatorInfo.getCertificates();
            if (certificates != null) {
                int size2 = certificates.size();
                boolean z = false;
                for (int i2 = 0; i2 < size2; i2++) {
                    ASN1Encodable objectAt2 = certificates.getObjectAt(i2);
                    if (objectAt2 instanceof ASN1TaggedObject) {
                        ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) objectAt2;
                        if (aSN1TaggedObject.hasContextTag(3)) {
                            return 4;
                        }
                        z = z || aSN1TaggedObject.hasContextTag(2);
                    }
                }
                if (z) {
                    return 3;
                }
            }
        }
        int size3 = aSN1Set.size();
        boolean z2 = true;
        for (int i3 = 0; i3 < size3; i3++) {
            RecipientInfo recipientInfo = RecipientInfo.getInstance(aSN1Set.getObjectAt(i3));
            if (recipientInfo.isPasswordOrOther()) {
                return 3;
            }
            z2 = z2 && recipientInfo.isKeyTransV0();
        }
        return (originatorInfo == null && aSN1Set2 == null && z2) ? 0 : 2;
    }

    public static EnvelopedData getInstance(Object obj) {
        if (obj instanceof EnvelopedData) {
            return (EnvelopedData) obj;
        }
        if (obj != null) {
            return new EnvelopedData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static EnvelopedData getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return this.encryptedContentInfo;
    }

    public OriginatorInfo getOriginatorInfo() {
        return this.originatorInfo;
    }

    public ASN1Set getRecipientInfos() {
        return this.recipientInfos;
    }

    public ASN1Set getUnprotectedAttrs() {
        return this.unprotectedAttrs;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(5);
        aSN1EncodableVector.add(this.version);
        if (this.originatorInfo != null) {
            aSN1EncodableVector.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.originatorInfo));
        }
        aSN1EncodableVector.add(this.recipientInfos);
        aSN1EncodableVector.add(this.encryptedContentInfo);
        if (this.unprotectedAttrs != null) {
            aSN1EncodableVector.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.unprotectedAttrs));
        }
        return new BERSequence(aSN1EncodableVector);
    }
}