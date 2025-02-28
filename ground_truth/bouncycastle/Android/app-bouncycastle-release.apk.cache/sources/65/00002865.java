package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

/* loaded from: classes2.dex */
public class EtsiTs102941CrlRequest extends ASN1Object {
    private final HashedId8 issuerId;
    private final Time32 lastKnownUpdate;

    /* loaded from: classes2.dex */
    public static class Builder {
        private HashedId8 issuerId;
        private Time32 lastKnownUpdate;

        public EtsiTs102941CrlRequest createEtsiTs102941CrlRequest() {
            return new EtsiTs102941CrlRequest(this.issuerId, this.lastKnownUpdate);
        }

        public Builder setIssuerId(HashedId8 hashedId8) {
            this.issuerId = hashedId8;
            return this;
        }

        public Builder setLastKnownUpdate(Time32 time32) {
            this.lastKnownUpdate = time32;
            return this;
        }
    }

    private EtsiTs102941CrlRequest(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.issuerId = HashedId8.getInstance(aSN1Sequence.getObjectAt(0));
        this.lastKnownUpdate = aSN1Sequence.size() > 1 ? (Time32) OEROptional.getValue(Time32.class, aSN1Sequence.getObjectAt(1)) : null;
    }

    public EtsiTs102941CrlRequest(HashedId8 hashedId8, Time32 time32) {
        this.issuerId = hashedId8;
        this.lastKnownUpdate = time32;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EtsiTs102941CrlRequest getInstance(Object obj) {
        if (obj instanceof EtsiTs102941CrlRequest) {
            return (EtsiTs102941CrlRequest) obj;
        }
        if (obj != null) {
            return new EtsiTs102941CrlRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public HashedId8 getIssuerId() {
        return this.issuerId;
    }

    public Time32 getLastKnownUpdate() {
        return this.lastKnownUpdate;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.issuerId, OEROptional.getInstance(this.lastKnownUpdate)});
    }
}