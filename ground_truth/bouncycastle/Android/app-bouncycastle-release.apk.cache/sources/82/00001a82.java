package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EnvelopedData;

/* loaded from: classes.dex */
public class EncryptedKey extends ASN1Object implements ASN1Choice {
    private EncryptedValue encryptedValue;
    private EnvelopedData envelopedData;

    public EncryptedKey(EnvelopedData envelopedData) {
        this.envelopedData = envelopedData;
    }

    public EncryptedKey(EncryptedValue encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    public static EncryptedKey getInstance(Object obj) {
        return obj instanceof EncryptedKey ? (EncryptedKey) obj : obj instanceof ASN1TaggedObject ? new EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject) obj, false)) : new EncryptedKey(EncryptedValue.getInstance(obj));
    }

    public ASN1Encodable getValue() {
        EncryptedValue encryptedValue = this.encryptedValue;
        return encryptedValue != null ? encryptedValue : this.envelopedData;
    }

    public boolean isEncryptedValue() {
        return this.encryptedValue != null;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        EncryptedValue encryptedValue = this.encryptedValue;
        return encryptedValue != null ? encryptedValue.toASN1Primitive() : new DERTaggedObject(false, 0, (ASN1Encodable) this.envelopedData);
    }
}