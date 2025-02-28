package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/* loaded from: classes.dex */
public class DeltaCertificateDescriptor extends ASN1Object {
    private Extensions extensions;
    private X500Name issuer;
    private final ASN1Integer serialNumber;
    private AlgorithmIdentifier signature;
    private final ASN1BitString signatureValue;
    private X500Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private ASN1Sequence validity;

    private DeltaCertificateDescriptor(ASN1Sequence aSN1Sequence) {
        this.serialNumber = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0));
        ASN1Encodable objectAt = aSN1Sequence.getObjectAt(1);
        int i = 2;
        while (objectAt instanceof ASN1TaggedObject) {
            ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(objectAt);
            int tagNo = aSN1TaggedObject.getTagNo();
            if (tagNo == 0) {
                this.signature = AlgorithmIdentifier.getInstance(aSN1TaggedObject, true);
            } else if (tagNo == 1) {
                this.issuer = X500Name.getInstance(aSN1TaggedObject, true);
            } else if (tagNo == 2) {
                this.validity = ASN1Sequence.getInstance(aSN1TaggedObject, true);
            } else if (tagNo == 3) {
                this.subject = X500Name.getInstance(aSN1TaggedObject, true);
            }
            int i2 = i + 1;
            ASN1Encodable objectAt2 = aSN1Sequence.getObjectAt(i);
            i = i2;
            objectAt = objectAt2;
        }
        this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(objectAt);
        ASN1Encodable objectAt3 = aSN1Sequence.getObjectAt(i);
        while (objectAt3 instanceof ASN1TaggedObject) {
            ASN1TaggedObject aSN1TaggedObject2 = ASN1TaggedObject.getInstance(objectAt3);
            if (aSN1TaggedObject2.getTagNo() == 4) {
                this.extensions = Extensions.getInstance(aSN1TaggedObject2, true);
            }
            ASN1Encodable objectAt4 = aSN1Sequence.getObjectAt(i);
            i++;
            objectAt3 = objectAt4;
        }
        this.signatureValue = ASN1BitString.getInstance(objectAt3);
    }

    private void addOptional(ASN1EncodableVector aSN1EncodableVector, int i, boolean z, ASN1Object aSN1Object) {
        if (aSN1Object != null) {
            aSN1EncodableVector.add(new DERTaggedObject(z, i, aSN1Object));
        }
    }

    public static DeltaCertificateDescriptor fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.deltaCertificateDescriptor));
    }

    public static DeltaCertificateDescriptor getInstance(Object obj) {
        if (obj instanceof DeltaCertificateDescriptor) {
            return (DeltaCertificateDescriptor) obj;
        }
        if (obj != null) {
            return new DeltaCertificateDescriptor(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public X500Name getIssuer() {
        return this.issuer;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public AlgorithmIdentifier getSignature() {
        return this.signature;
    }

    public ASN1BitString getSignatureValue() {
        return this.signatureValue;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.subjectPublicKeyInfo;
    }

    public ASN1Sequence getValidity() {
        return this.validity;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(7);
        aSN1EncodableVector.add(this.serialNumber);
        addOptional(aSN1EncodableVector, 0, true, this.signature);
        addOptional(aSN1EncodableVector, 1, true, this.issuer);
        addOptional(aSN1EncodableVector, 2, true, this.validity);
        addOptional(aSN1EncodableVector, 3, true, this.subject);
        aSN1EncodableVector.add(this.subjectPublicKeyInfo);
        addOptional(aSN1EncodableVector, 4, true, this.extensions);
        aSN1EncodableVector.add(this.signatureValue);
        return new DERSequence(aSN1EncodableVector);
    }

    public DeltaCertificateDescriptor trimTo(TBSCertificate tBSCertificate, Extensions extensions) {
        AlgorithmIdentifier algorithmIdentifier = tBSCertificate.signature;
        X500Name x500Name = tBSCertificate.issuer;
        DERSequence dERSequence = new DERSequence(new ASN1Encodable[]{tBSCertificate.startDate, tBSCertificate.endDate});
        X500Name x500Name2 = tBSCertificate.subject;
        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(toASN1Primitive());
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        Enumeration objects = aSN1Sequence.getObjects();
        ASN1Encodable aSN1Encodable = (ASN1Encodable) objects.nextElement();
        loop0: while (true) {
            aSN1EncodableVector.add(aSN1Encodable);
            while (true) {
                aSN1Encodable = (ASN1Encodable) objects.nextElement();
                if (!(aSN1Encodable instanceof ASN1TaggedObject)) {
                    break loop0;
                }
                ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(aSN1Encodable);
                int tagNo = aSN1TaggedObject.getTagNo();
                if (tagNo != 0) {
                    if (tagNo != 1) {
                        if (tagNo != 2) {
                            if (tagNo == 3 && !X500Name.getInstance(aSN1TaggedObject, true).equals(x500Name2)) {
                                break;
                            }
                        } else if (!ASN1Sequence.getInstance(aSN1TaggedObject, true).equals((ASN1Primitive) dERSequence)) {
                            break;
                        }
                    } else if (!X500Name.getInstance(aSN1TaggedObject, true).equals(x500Name)) {
                        break;
                    }
                } else if (!AlgorithmIdentifier.getInstance(aSN1TaggedObject, true).equals(algorithmIdentifier)) {
                    break;
                }
            }
        }
        aSN1EncodableVector.add(aSN1Encodable);
        while (true) {
            ASN1Encodable aSN1Encodable2 = (ASN1Encodable) objects.nextElement();
            if (!(aSN1Encodable2 instanceof ASN1TaggedObject)) {
                aSN1EncodableVector.add(aSN1Encodable2);
                return new DeltaCertificateDescriptor(new DERSequence(aSN1EncodableVector));
            }
            ASN1TaggedObject aSN1TaggedObject2 = ASN1TaggedObject.getInstance(aSN1Encodable2);
            if (aSN1TaggedObject2.getTagNo() == 4) {
                Extensions extensions2 = Extensions.getInstance(aSN1TaggedObject2, true);
                ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
                Enumeration oids = extensions2.oids();
                while (oids.hasMoreElements()) {
                    Extension extension = extensions2.getExtension((ASN1ObjectIdentifier) oids.nextElement());
                    Extension extension2 = extensions.getExtension(extension.getExtnId());
                    if (extension2 != null && !extension.equals(extension2)) {
                        extensionsGenerator.addExtension(extension);
                    }
                }
                if (!extensionsGenerator.isEmpty()) {
                    aSN1EncodableVector.add(new DERTaggedObject(true, 4, (ASN1Encodable) extensionsGenerator.generate()));
                }
            }
        }
    }
}