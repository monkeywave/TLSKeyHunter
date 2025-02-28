package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/* loaded from: classes.dex */
public class CertID extends ASN1Object {
    AlgorithmIdentifier hashAlgorithm;
    ASN1OctetString issuerKeyHash;
    ASN1OctetString issuerNameHash;
    ASN1Integer serialNumber;

    private CertID(ASN1Sequence aSN1Sequence) {
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
        this.issuerNameHash = (ASN1OctetString) aSN1Sequence.getObjectAt(1);
        this.issuerKeyHash = (ASN1OctetString) aSN1Sequence.getObjectAt(2);
        this.serialNumber = (ASN1Integer) aSN1Sequence.getObjectAt(3);
    }

    public CertID(AlgorithmIdentifier algorithmIdentifier, ASN1OctetString aSN1OctetString, ASN1OctetString aSN1OctetString2, ASN1Integer aSN1Integer) {
        this.hashAlgorithm = algorithmIdentifier;
        this.issuerNameHash = aSN1OctetString;
        this.issuerKeyHash = aSN1OctetString2;
        this.serialNumber = aSN1Integer;
    }

    public static CertID getInstance(Object obj) {
        if (obj instanceof CertID) {
            return (CertID) obj;
        }
        if (obj != null) {
            return new CertID(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static CertID getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    private boolean isEqual(ASN1Encodable aSN1Encodable, ASN1Encodable aSN1Encodable2) {
        if (aSN1Encodable == aSN1Encodable2) {
            return true;
        }
        if (aSN1Encodable == null) {
            return DERNull.INSTANCE.equals(aSN1Encodable2);
        }
        if (DERNull.INSTANCE.equals(aSN1Encodable) && aSN1Encodable2 == null) {
            return true;
        }
        return aSN1Encodable.equals(aSN1Encodable2);
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof ASN1Encodable) {
            try {
                CertID certID = getInstance(obj);
                if (this.hashAlgorithm.getAlgorithm().equals((ASN1Primitive) certID.hashAlgorithm.getAlgorithm()) && isEqual(this.hashAlgorithm.getParameters(), certID.hashAlgorithm.getParameters())) {
                    if (this.issuerNameHash.equals((ASN1Primitive) certID.issuerNameHash) && this.issuerKeyHash.equals((ASN1Primitive) certID.issuerKeyHash)) {
                        if (this.serialNumber.equals((ASN1Primitive) certID.serialNumber)) {
                            return true;
                        }
                    }
                    return false;
                }
                return false;
            } catch (Exception unused) {
            }
        }
        return false;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getIssuerKeyHash() {
        return this.issuerKeyHash;
    }

    public ASN1OctetString getIssuerNameHash() {
        return this.issuerNameHash;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        ASN1Encodable parameters = this.hashAlgorithm.getParameters();
        return ((parameters == null || DERNull.INSTANCE.equals(parameters)) ? 0 : parameters.hashCode()) + ((this.hashAlgorithm.getAlgorithm().hashCode() + ((this.issuerNameHash.hashCode() + ((this.issuerKeyHash.hashCode() + (this.serialNumber.hashCode() * 7)) * 7)) * 7)) * 7);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
        aSN1EncodableVector.add(this.hashAlgorithm);
        aSN1EncodableVector.add(this.issuerNameHash);
        aSN1EncodableVector.add(this.issuerKeyHash);
        aSN1EncodableVector.add(this.serialNumber);
        return new DERSequence(aSN1EncodableVector);
    }
}