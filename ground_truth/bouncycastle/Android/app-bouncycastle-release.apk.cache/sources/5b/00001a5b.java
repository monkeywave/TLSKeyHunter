package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes.dex */
public class KeyAgreeRecipientIdentifier extends ASN1Object implements ASN1Choice {
    private IssuerAndSerialNumber issuerSerial;
    private RecipientKeyIdentifier rKeyID;

    public KeyAgreeRecipientIdentifier(IssuerAndSerialNumber issuerAndSerialNumber) {
        this.issuerSerial = issuerAndSerialNumber;
        this.rKeyID = null;
    }

    public KeyAgreeRecipientIdentifier(RecipientKeyIdentifier recipientKeyIdentifier) {
        this.issuerSerial = null;
        this.rKeyID = recipientKeyIdentifier;
    }

    public static KeyAgreeRecipientIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof KeyAgreeRecipientIdentifier)) {
            return (KeyAgreeRecipientIdentifier) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) obj;
            if (aSN1TaggedObject.hasContextTag(0)) {
                return new KeyAgreeRecipientIdentifier(RecipientKeyIdentifier.getInstance(aSN1TaggedObject, false));
            }
            throw new IllegalArgumentException("Invalid KeyAgreeRecipientIdentifier tag: " + ASN1Util.getTagText(aSN1TaggedObject));
        }
        return new KeyAgreeRecipientIdentifier(IssuerAndSerialNumber.getInstance(obj));
    }

    public static KeyAgreeRecipientIdentifier getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        if (z) {
            return getInstance(aSN1TaggedObject.getExplicitBaseObject());
        }
        throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return this.issuerSerial;
    }

    public RecipientKeyIdentifier getRKeyID() {
        return this.rKeyID;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        IssuerAndSerialNumber issuerAndSerialNumber = this.issuerSerial;
        return issuerAndSerialNumber != null ? issuerAndSerialNumber.toASN1Primitive() : new DERTaggedObject(false, 0, (ASN1Encodable) this.rKeyID);
    }
}