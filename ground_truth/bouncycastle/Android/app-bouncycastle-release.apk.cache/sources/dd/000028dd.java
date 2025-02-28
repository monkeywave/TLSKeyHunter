package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;

/* loaded from: classes2.dex */
public class PsidSspRange extends ASN1Object {
    private final Psid psid;
    private final SspRange sspRange;

    /* loaded from: classes2.dex */
    public static class Builder {
        private Psid psid;
        private SspRange sspRange;

        public PsidSspRange createPsidSspRange() {
            return new PsidSspRange(this.psid, this.sspRange);
        }

        public Builder setPsid(long j) {
            this.psid = new Psid(j);
            return this;
        }

        public Builder setPsid(Psid psid) {
            this.psid = psid;
            return this;
        }

        public Builder setSspRange(SspRange sspRange) {
            this.sspRange = sspRange;
            return this;
        }
    }

    private PsidSspRange(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.psid = Psid.getInstance(aSN1Sequence.getObjectAt(0));
        this.sspRange = (SspRange) OEROptional.getValue(SspRange.class, aSN1Sequence.getObjectAt(1));
    }

    public PsidSspRange(Psid psid, SspRange sspRange) {
        this.psid = psid;
        this.sspRange = sspRange;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static PsidSspRange getInstance(Object obj) {
        if (obj instanceof PsidSspRange) {
            return (PsidSspRange) obj;
        }
        if (obj != null) {
            return new PsidSspRange(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Psid getPsid() {
        return this.psid;
    }

    public SspRange getSspRange() {
        return this.sspRange;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.psid, OEROptional.getInstance(this.sspRange)});
    }
}