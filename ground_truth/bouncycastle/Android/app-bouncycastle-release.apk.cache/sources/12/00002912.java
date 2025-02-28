package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;

/* loaded from: classes2.dex */
public class ButterflyParamsOriginal extends ASN1Object {
    private final ButterflyExpansion encryptionExpansion;
    private final PublicEncryptionKey encryptionKey;
    private final ButterflyExpansion signingExpansion;

    /* loaded from: classes2.dex */
    public static class Builder {
        private ButterflyExpansion encryptionExpansion;
        private PublicEncryptionKey encryptionKey;
        private ButterflyExpansion signingExpansion;

        public ButterflyParamsOriginal createButterflyParamsOriginal() {
            return new ButterflyParamsOriginal(this.signingExpansion, this.encryptionKey, this.encryptionExpansion);
        }

        public Builder setEncryptionExpansion(ButterflyExpansion butterflyExpansion) {
            this.encryptionExpansion = butterflyExpansion;
            return this;
        }

        public Builder setEncryptionKey(PublicEncryptionKey publicEncryptionKey) {
            this.encryptionKey = publicEncryptionKey;
            return this;
        }

        public Builder setSigningExpansion(ButterflyExpansion butterflyExpansion) {
            this.signingExpansion = butterflyExpansion;
            return this;
        }
    }

    private ButterflyParamsOriginal(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        this.signingExpansion = ButterflyExpansion.getInstance(aSN1Sequence.getObjectAt(0));
        this.encryptionKey = PublicEncryptionKey.getInstance(aSN1Sequence.getObjectAt(1));
        this.encryptionExpansion = ButterflyExpansion.getInstance(aSN1Sequence.getObjectAt(2));
    }

    public ButterflyParamsOriginal(ButterflyExpansion butterflyExpansion, PublicEncryptionKey publicEncryptionKey, ButterflyExpansion butterflyExpansion2) {
        this.signingExpansion = butterflyExpansion;
        this.encryptionKey = publicEncryptionKey;
        this.encryptionExpansion = butterflyExpansion2;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ButterflyParamsOriginal getInstance(Object obj) {
        if (obj instanceof ButterflyParamsOriginal) {
            return (ButterflyParamsOriginal) obj;
        }
        if (obj != null) {
            return new ButterflyParamsOriginal(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ButterflyExpansion getEncryptionExpansion() {
        return this.encryptionExpansion;
    }

    public PublicEncryptionKey getEncryptionKey() {
        return this.encryptionKey;
    }

    public ButterflyExpansion getSigningExpansion() {
        return this.signingExpansion;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.signingExpansion, this.encryptionKey, this.encryptionExpansion});
    }
}