package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EciesP256EncryptedKey;

/* loaded from: classes2.dex */
public class EncryptedDataEncryptionKey extends ASN1Object implements ASN1Choice {
    public static final int eciesBrainpoolP256r1 = 1;
    public static final int eciesNistP256 = 0;
    private final int choice;
    private final ASN1Encodable encryptedDataEncryptionKey;

    public EncryptedDataEncryptionKey(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.encryptedDataEncryptionKey = aSN1Encodable;
    }

    private EncryptedDataEncryptionKey(ASN1TaggedObject aSN1TaggedObject) {
        this.choice = aSN1TaggedObject.getTagNo();
        int tagNo = aSN1TaggedObject.getTagNo();
        if (tagNo != 0 && tagNo != 1) {
            throw new IllegalArgumentException("invalid choice value " + aSN1TaggedObject.getTagNo());
        }
        this.encryptedDataEncryptionKey = EciesP256EncryptedKey.getInstance(aSN1TaggedObject.getExplicitBaseObject());
    }

    public static EncryptedDataEncryptionKey eciesBrainpoolP256r1(EciesP256EncryptedKey eciesP256EncryptedKey) {
        return new EncryptedDataEncryptionKey(1, eciesP256EncryptedKey);
    }

    public static EncryptedDataEncryptionKey eciesNistP256(EciesP256EncryptedKey eciesP256EncryptedKey) {
        return new EncryptedDataEncryptionKey(0, eciesP256EncryptedKey);
    }

    public static EncryptedDataEncryptionKey getInstance(Object obj) {
        if (obj instanceof EncryptedDataEncryptionKey) {
            return (EncryptedDataEncryptionKey) obj;
        }
        if (obj != null) {
            return new EncryptedDataEncryptionKey(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getEncryptedDataEncryptionKey() {
        return this.encryptedDataEncryptionKey;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.encryptedDataEncryptionKey);
    }
}