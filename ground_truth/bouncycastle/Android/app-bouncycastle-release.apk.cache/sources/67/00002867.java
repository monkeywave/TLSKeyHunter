package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/* loaded from: classes2.dex */
public class EtsiTs102941CtlRequest extends ASN1Object {
    private final HashedId8 issuerId;
    private final ASN1Integer lastKnownCtlSequence;

    /* loaded from: classes2.dex */
    public static class Builder {
        private HashedId8 issuerId;
        private ASN1Integer lastKnownCtlSequence;

        public EtsiTs102941CtlRequest createEtsiTs102941CtlRequest() {
            return new EtsiTs102941CtlRequest(this.issuerId, this.lastKnownCtlSequence);
        }

        public EtsiTs102941DeltaCtlRequest createEtsiTs102941DeltaCtlRequest() {
            return new EtsiTs102941DeltaCtlRequest(this.issuerId, this.lastKnownCtlSequence);
        }

        public Builder setIssuerId(HashedId8 hashedId8) {
            this.issuerId = hashedId8;
            return this;
        }

        public Builder setLastKnownCtlSequence(ASN1Integer aSN1Integer) {
            this.lastKnownCtlSequence = aSN1Integer;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public EtsiTs102941CtlRequest(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.issuerId = HashedId8.getInstance(aSN1Sequence.getObjectAt(0));
        this.lastKnownCtlSequence = aSN1Sequence.size() == 2 ? (ASN1Integer) OEROptional.getValue(ASN1Integer.class, aSN1Sequence.getObjectAt(1)) : null;
    }

    public EtsiTs102941CtlRequest(HashedId8 hashedId8, ASN1Integer aSN1Integer) {
        this.issuerId = hashedId8;
        this.lastKnownCtlSequence = aSN1Integer;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EtsiTs102941CtlRequest getInstance(Object obj) {
        if (obj instanceof EtsiTs102941CtlRequest) {
            return (EtsiTs102941CtlRequest) obj;
        }
        if (obj != null) {
            return new EtsiTs102941CtlRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public HashedId8 getIssuerId() {
        return this.issuerId;
    }

    public ASN1Integer getLastKnownCtlSequence() {
        return this.lastKnownCtlSequence;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.issuerId, OEROptional.getInstance(this.lastKnownCtlSequence)});
    }
}