package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class Ieee1609Dot2Content extends ASN1Object implements ASN1Choice {
    public static final int encryptedData = 2;
    public static final int signedCertificateRequest = 3;
    public static final int signedData = 1;
    public static final int unsecuredData = 0;
    private final int choice;
    private final ASN1Encodable ieee1609Dot2Content;

    public Ieee1609Dot2Content(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.ieee1609Dot2Content = aSN1Encodable;
    }

    private Ieee1609Dot2Content(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable opaque;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.choice = tagNo;
        if (tagNo != 0) {
            if (tagNo == 1) {
                opaque = SignedData.getInstance(aSN1TaggedObject.getExplicitBaseObject());
            } else if (tagNo == 2) {
                opaque = EncryptedData.getInstance(aSN1TaggedObject.getExplicitBaseObject());
            } else if (tagNo != 3) {
                throw new IllegalArgumentException("invalid choice value " + aSN1TaggedObject.getTagNo());
            }
            this.ieee1609Dot2Content = opaque;
        }
        opaque = Opaque.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        this.ieee1609Dot2Content = opaque;
    }

    public static Ieee1609Dot2Content encryptedData(EncryptedData encryptedData2) {
        return new Ieee1609Dot2Content(2, encryptedData2);
    }

    public static Ieee1609Dot2Content getInstance(Object obj) {
        if (obj instanceof Ieee1609Dot2Content) {
            return (Ieee1609Dot2Content) obj;
        }
        if (obj != null) {
            return new Ieee1609Dot2Content(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public static Ieee1609Dot2Content signedCertificateRequest(Opaque opaque) {
        return new Ieee1609Dot2Content(3, opaque);
    }

    public static Ieee1609Dot2Content signedCertificateRequest(byte[] bArr) {
        return new Ieee1609Dot2Content(3, new DEROctetString(Arrays.clone(bArr)));
    }

    public static Ieee1609Dot2Content signedData(SignedData signedData2) {
        return new Ieee1609Dot2Content(1, signedData2);
    }

    public static Ieee1609Dot2Content unsecuredData(Opaque opaque) {
        return new Ieee1609Dot2Content(0, opaque);
    }

    public static Ieee1609Dot2Content unsecuredData(byte[] bArr) {
        return new Ieee1609Dot2Content(0, new DEROctetString(Arrays.clone(bArr)));
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getIeee1609Dot2Content() {
        return this.ieee1609Dot2Content;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.ieee1609Dot2Content);
    }
}