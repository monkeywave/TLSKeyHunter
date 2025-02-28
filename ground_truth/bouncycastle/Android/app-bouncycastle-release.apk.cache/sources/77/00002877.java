package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/* loaded from: classes2.dex */
public class EncryptedData extends ASN1Object {
    private final SymmetricCiphertext ciphertext;
    private final SequenceOfRecipientInfo recipients;

    /* loaded from: classes2.dex */
    public static class Builder {
        private SymmetricCiphertext ciphertext;
        private SequenceOfRecipientInfo recipients;

        public EncryptedData createEncryptedData() {
            return new EncryptedData(this.recipients, this.ciphertext);
        }

        public Builder setCiphertext(SymmetricCiphertext symmetricCiphertext) {
            this.ciphertext = symmetricCiphertext;
            return this;
        }

        public Builder setRecipients(SequenceOfRecipientInfo sequenceOfRecipientInfo) {
            this.recipients = sequenceOfRecipientInfo;
            return this;
        }
    }

    private EncryptedData(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.recipients = SequenceOfRecipientInfo.getInstance(aSN1Sequence.getObjectAt(0));
        this.ciphertext = SymmetricCiphertext.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public EncryptedData(SequenceOfRecipientInfo sequenceOfRecipientInfo, SymmetricCiphertext symmetricCiphertext) {
        this.recipients = sequenceOfRecipientInfo;
        this.ciphertext = symmetricCiphertext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EncryptedData getInstance(Object obj) {
        if (obj instanceof EncryptedData) {
            return (EncryptedData) obj;
        }
        if (obj != null) {
            return new EncryptedData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SymmetricCiphertext getCiphertext() {
        return this.ciphertext;
    }

    public SequenceOfRecipientInfo getRecipients() {
        return this.recipients;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.recipients, this.ciphertext);
    }
}