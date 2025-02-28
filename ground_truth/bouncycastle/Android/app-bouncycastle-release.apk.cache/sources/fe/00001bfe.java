package org.bouncycastle.asn1.x509.sigi;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

/* loaded from: classes.dex */
public class PersonalData extends ASN1Object {
    private ASN1GeneralizedTime dateOfBirth;
    private String gender;
    private BigInteger nameDistinguisher;
    private NameOrPseudonym nameOrPseudonym;
    private DirectoryString placeOfBirth;
    private DirectoryString postalAddress;

    private PersonalData(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() < 1) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.nameOrPseudonym = NameOrPseudonym.getInstance(objects.nextElement());
        while (objects.hasMoreElements()) {
            ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(objects.nextElement());
            int tagNo = aSN1TaggedObject.getTagNo();
            if (tagNo == 0) {
                this.nameDistinguisher = ASN1Integer.getInstance(aSN1TaggedObject, false).getValue();
            } else if (tagNo == 1) {
                this.dateOfBirth = ASN1GeneralizedTime.getInstance(aSN1TaggedObject, false);
            } else if (tagNo == 2) {
                this.placeOfBirth = DirectoryString.getInstance(aSN1TaggedObject, true);
            } else if (tagNo == 3) {
                this.gender = ASN1PrintableString.getInstance(aSN1TaggedObject, false).getString();
            } else if (tagNo != 4) {
                throw new IllegalArgumentException("Bad tag number: " + aSN1TaggedObject.getTagNo());
            } else {
                this.postalAddress = DirectoryString.getInstance(aSN1TaggedObject, true);
            }
        }
    }

    public PersonalData(NameOrPseudonym nameOrPseudonym, BigInteger bigInteger, ASN1GeneralizedTime aSN1GeneralizedTime, DirectoryString directoryString, String str, DirectoryString directoryString2) {
        this.nameOrPseudonym = nameOrPseudonym;
        this.dateOfBirth = aSN1GeneralizedTime;
        this.gender = str;
        this.nameDistinguisher = bigInteger;
        this.postalAddress = directoryString2;
        this.placeOfBirth = directoryString;
    }

    public static PersonalData getInstance(Object obj) {
        if (obj == null || (obj instanceof PersonalData)) {
            return (PersonalData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PersonalData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public ASN1GeneralizedTime getDateOfBirth() {
        return this.dateOfBirth;
    }

    public String getGender() {
        return this.gender;
    }

    public BigInteger getNameDistinguisher() {
        return this.nameDistinguisher;
    }

    public NameOrPseudonym getNameOrPseudonym() {
        return this.nameOrPseudonym;
    }

    public DirectoryString getPlaceOfBirth() {
        return this.placeOfBirth;
    }

    public DirectoryString getPostalAddress() {
        return this.postalAddress;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(6);
        aSN1EncodableVector.add(this.nameOrPseudonym);
        if (this.nameDistinguisher != null) {
            aSN1EncodableVector.add(new DERTaggedObject(false, 0, (ASN1Encodable) new ASN1Integer(this.nameDistinguisher)));
        }
        if (this.dateOfBirth != null) {
            aSN1EncodableVector.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.dateOfBirth));
        }
        if (this.placeOfBirth != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 2, (ASN1Encodable) this.placeOfBirth));
        }
        if (this.gender != null) {
            aSN1EncodableVector.add(new DERTaggedObject(false, 3, (ASN1Encodable) new DERPrintableString(this.gender, true)));
        }
        if (this.postalAddress != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 4, (ASN1Encodable) this.postalAddress));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}