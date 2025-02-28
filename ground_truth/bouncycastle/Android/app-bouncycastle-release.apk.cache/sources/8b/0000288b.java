package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/* loaded from: classes2.dex */
public class PKRecipientInfo extends ASN1Object {
    private final EncryptedDataEncryptionKey encKey;
    private final HashedId8 recipientId;

    /* loaded from: classes2.dex */
    public static class Builder {
        private EncryptedDataEncryptionKey encKey;
        private HashedId8 recipientId;

        public PKRecipientInfo createPKRecipientInfo() {
            return new PKRecipientInfo(this.recipientId, this.encKey);
        }

        public Builder setEncKey(EncryptedDataEncryptionKey encryptedDataEncryptionKey) {
            this.encKey = encryptedDataEncryptionKey;
            return this;
        }

        public Builder setRecipientId(HashedId8 hashedId8) {
            this.recipientId = hashedId8;
            return this;
        }
    }

    private PKRecipientInfo(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.recipientId = HashedId8.getInstance(aSN1Sequence.getObjectAt(0));
        this.encKey = EncryptedDataEncryptionKey.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public PKRecipientInfo(HashedId8 hashedId8, EncryptedDataEncryptionKey encryptedDataEncryptionKey) {
        this.recipientId = hashedId8;
        this.encKey = encryptedDataEncryptionKey;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static PKRecipientInfo getInstance(Object obj) {
        if (obj instanceof PKRecipientInfo) {
            return (PKRecipientInfo) obj;
        }
        if (obj != null) {
            return new PKRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public EncryptedDataEncryptionKey getEncKey() {
        return this.encKey;
    }

    public HashedId getRecipientId() {
        return this.recipientId;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.recipientId, this.encKey);
    }
}