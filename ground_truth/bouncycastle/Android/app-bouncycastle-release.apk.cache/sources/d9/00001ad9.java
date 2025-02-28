package org.bouncycastle.asn1.esf;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;

/* loaded from: classes.dex */
public class SignerLocation extends ASN1Object {
    private DirectoryString countryName;
    private DirectoryString localityName;
    private ASN1Sequence postalAddress;

    private SignerLocation(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(objects.nextElement(), 128);
            int tagNo = aSN1TaggedObject.getTagNo();
            if (tagNo == 0) {
                this.countryName = DirectoryString.getInstance(aSN1TaggedObject, true);
            } else if (tagNo == 1) {
                this.localityName = DirectoryString.getInstance(aSN1TaggedObject, true);
            } else if (tagNo != 2) {
                throw new IllegalArgumentException("illegal tag");
            } else {
                this.postalAddress = aSN1TaggedObject.isExplicit() ? ASN1Sequence.getInstance(aSN1TaggedObject, true) : ASN1Sequence.getInstance(aSN1TaggedObject, false);
                ASN1Sequence aSN1Sequence2 = this.postalAddress;
                if (aSN1Sequence2 != null && aSN1Sequence2.size() > 6) {
                    throw new IllegalArgumentException("postal address must contain less than 6 strings");
                }
            }
        }
    }

    public SignerLocation(ASN1UTF8String aSN1UTF8String, ASN1UTF8String aSN1UTF8String2, ASN1Sequence aSN1Sequence) {
        this(DirectoryString.getInstance(aSN1UTF8String), DirectoryString.getInstance(aSN1UTF8String2), aSN1Sequence);
    }

    private SignerLocation(DirectoryString directoryString, DirectoryString directoryString2, ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence != null && aSN1Sequence.size() > 6) {
            throw new IllegalArgumentException("postal address must contain less than 6 strings");
        }
        this.countryName = directoryString;
        this.localityName = directoryString2;
        this.postalAddress = aSN1Sequence;
    }

    public SignerLocation(DirectoryString directoryString, DirectoryString directoryString2, DirectoryString[] directoryStringArr) {
        this(directoryString, directoryString2, new DERSequence(directoryStringArr));
    }

    public static SignerLocation getInstance(Object obj) {
        return (obj == null || (obj instanceof SignerLocation)) ? (SignerLocation) obj : new SignerLocation(ASN1Sequence.getInstance(obj));
    }

    public DirectoryString getCountry() {
        return this.countryName;
    }

    public DERUTF8String getCountryName() {
        if (this.countryName == null) {
            return null;
        }
        return new DERUTF8String(getCountry().getString());
    }

    public DirectoryString getLocality() {
        return this.localityName;
    }

    public DERUTF8String getLocalityName() {
        if (this.localityName == null) {
            return null;
        }
        return new DERUTF8String(getLocality().getString());
    }

    public DirectoryString[] getPostal() {
        ASN1Sequence aSN1Sequence = this.postalAddress;
        if (aSN1Sequence == null) {
            return null;
        }
        int size = aSN1Sequence.size();
        DirectoryString[] directoryStringArr = new DirectoryString[size];
        for (int i = 0; i != size; i++) {
            directoryStringArr[i] = DirectoryString.getInstance(this.postalAddress.getObjectAt(i));
        }
        return directoryStringArr;
    }

    public ASN1Sequence getPostalAddress() {
        return this.postalAddress;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        if (this.countryName != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.countryName));
        }
        if (this.localityName != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 1, (ASN1Encodable) this.localityName));
        }
        if (this.postalAddress != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 2, (ASN1Encodable) this.postalAddress));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}