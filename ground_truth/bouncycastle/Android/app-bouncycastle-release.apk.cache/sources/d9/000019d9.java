package org.bouncycastle.asn1.p006bc;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.bc.ExternalValue */
/* loaded from: classes.dex */
public class ExternalValue extends ASN1Object {
    private final AlgorithmIdentifier hashAlg;
    private final byte[] hashValue;
    private final GeneralNames location;

    private ExternalValue(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("unknown sequence");
        }
        this.location = GeneralNames.getInstance(aSN1Sequence.getObjectAt(0));
        this.hashAlg = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(1));
        boolean z = aSN1Sequence.getObjectAt(2) instanceof ASN1BitString;
        ASN1Encodable objectAt = aSN1Sequence.getObjectAt(2);
        if (z) {
            this.hashValue = ASN1BitString.getInstance(objectAt).getOctets();
        } else {
            this.hashValue = ASN1OctetString.getInstance(objectAt).getOctets();
        }
    }

    public ExternalValue(GeneralName generalName, AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        this.location = new GeneralNames(generalName);
        this.hashAlg = algorithmIdentifier;
        this.hashValue = Arrays.clone(bArr);
    }

    public static ExternalValue getInstance(Object obj) {
        if (obj instanceof ExternalValue) {
            return (ExternalValue) obj;
        }
        if (obj != null) {
            return new ExternalValue(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public AlgorithmIdentifier getHashAlg() {
        return this.hashAlg;
    }

    public ASN1BitString getHashVal() {
        return new DERBitString(this.hashValue);
    }

    public byte[] getHashValue() {
        return Arrays.clone(this.hashValue);
    }

    public GeneralName getLocation() {
        return this.location.getNames()[0];
    }

    public GeneralName[] getLocations() {
        return this.location.getNames();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.location);
        aSN1EncodableVector.add(this.hashAlg);
        aSN1EncodableVector.add(new DEROctetString(this.hashValue));
        return new DERSequence(aSN1EncodableVector);
    }
}