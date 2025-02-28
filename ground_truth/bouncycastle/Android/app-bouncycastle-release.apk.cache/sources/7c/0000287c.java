package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class HashedData extends ASN1Object implements ASN1Choice {
    public static final int reserved = 2;
    public static final int sha256HashedData = 0;
    public static final int sha384HashedData = 1;
    private final int choice;
    private final ASN1Encodable hashedData;

    public HashedData(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.hashedData = aSN1Encodable;
    }

    private HashedData(ASN1TaggedObject aSN1TaggedObject) {
        int tagNo = aSN1TaggedObject.getTagNo();
        if (tagNo != 0 && tagNo != 1 && tagNo != 2) {
            throw new IllegalArgumentException("invalid choice value " + aSN1TaggedObject.getTagNo());
        }
        this.choice = aSN1TaggedObject.getTagNo();
        this.hashedData = DEROctetString.getInstance(aSN1TaggedObject.getExplicitBaseObject());
    }

    public static HashedData getInstance(Object obj) {
        if (obj instanceof HashedData) {
            return (HashedData) obj;
        }
        if (obj != null) {
            return new HashedData(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public static HashedData reserved(ASN1OctetString aSN1OctetString) {
        return new HashedData(2, aSN1OctetString);
    }

    public static HashedData reserved(byte[] bArr) {
        return new HashedData(2, new DEROctetString(Arrays.clone(bArr)));
    }

    public static HashedData sha256HashedData(ASN1OctetString aSN1OctetString) {
        return new HashedData(0, aSN1OctetString);
    }

    public static HashedData sha256HashedData(byte[] bArr) {
        return new HashedData(0, new DEROctetString(Arrays.clone(bArr)));
    }

    public static HashedData sha384HashedData(ASN1OctetString aSN1OctetString) {
        return new HashedData(1, aSN1OctetString);
    }

    public static HashedData sha384HashedData(byte[] bArr) {
        return new HashedData(1, new DEROctetString(Arrays.clone(bArr)));
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getHashedData() {
        return this.hashedData;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.hashedData);
    }
}