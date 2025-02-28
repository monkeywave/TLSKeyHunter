package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;

/* loaded from: classes2.dex */
public class SignedDataPayload extends ASN1Object {
    private final Ieee1609Dot2Data data;
    private final HashedData extDataHash;

    /* loaded from: classes2.dex */
    public static class Builder {
        private Ieee1609Dot2Data data;
        private HashedData extDataHash;

        public SignedDataPayload createSignedDataPayload() {
            return new SignedDataPayload(this.data, this.extDataHash);
        }

        public Builder setData(Ieee1609Dot2Data ieee1609Dot2Data) {
            this.data = ieee1609Dot2Data;
            return this;
        }

        public Builder setExtDataHash(HashedData hashedData) {
            this.extDataHash = hashedData;
            return this;
        }
    }

    private SignedDataPayload(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.data = (Ieee1609Dot2Data) OEROptional.getValue(Ieee1609Dot2Data.class, aSN1Sequence.getObjectAt(0));
        this.extDataHash = (HashedData) OEROptional.getValue(HashedData.class, aSN1Sequence.getObjectAt(1));
    }

    public SignedDataPayload(Ieee1609Dot2Data ieee1609Dot2Data, HashedData hashedData) {
        this.data = ieee1609Dot2Data;
        this.extDataHash = hashedData;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static SignedDataPayload getInstance(Object obj) {
        if (obj instanceof SignedDataPayload) {
            return (SignedDataPayload) obj;
        }
        if (obj != null) {
            return new SignedDataPayload(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Ieee1609Dot2Data getData() {
        return this.data;
    }

    public HashedData getExtDataHash() {
        return this.extDataHash;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{OEROptional.getInstance(this.data), OEROptional.getInstance(this.extDataHash)});
    }
}