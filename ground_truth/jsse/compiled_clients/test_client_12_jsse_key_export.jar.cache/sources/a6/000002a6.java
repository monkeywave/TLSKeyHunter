package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/pkcs/IssuerAndSerialNumber.class */
public class IssuerAndSerialNumber extends ASN1Object {
    X500Name name;
    ASN1Integer certSerialNumber;

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) obj;
        }
        if (obj != null) {
            return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private IssuerAndSerialNumber(ASN1Sequence aSN1Sequence) {
        this.name = X500Name.getInstance(aSN1Sequence.getObjectAt(0));
        this.certSerialNumber = (ASN1Integer) aSN1Sequence.getObjectAt(1);
    }

    public IssuerAndSerialNumber(X509Name x509Name, BigInteger bigInteger) {
        this.name = X500Name.getInstance(x509Name.toASN1Primitive());
        this.certSerialNumber = new ASN1Integer(bigInteger);
    }

    public IssuerAndSerialNumber(X509Name x509Name, ASN1Integer aSN1Integer) {
        this.name = X500Name.getInstance(x509Name.toASN1Primitive());
        this.certSerialNumber = aSN1Integer;
    }

    public IssuerAndSerialNumber(X500Name x500Name, BigInteger bigInteger) {
        this.name = x500Name;
        this.certSerialNumber = new ASN1Integer(bigInteger);
    }

    public X500Name getName() {
        return this.name;
    }

    public ASN1Integer getCertificateSerialNumber() {
        return this.certSerialNumber;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.name);
        aSN1EncodableVector.add(this.certSerialNumber);
        return new DERSequence(aSN1EncodableVector);
    }
}