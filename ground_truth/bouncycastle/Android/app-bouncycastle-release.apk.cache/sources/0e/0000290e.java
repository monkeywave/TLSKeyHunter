package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes2.dex */
public class ValidityPeriod extends ASN1Object {
    private final Duration duration;
    private final Time32 start;

    /* loaded from: classes2.dex */
    public static class Builder {
        private Duration duration;
        private Time32 start;

        public ValidityPeriod createValidityPeriod() {
            return new ValidityPeriod(this.start, this.duration);
        }

        public Builder setDuration(Duration duration) {
            this.duration = duration;
            return this;
        }

        public Builder setStart(Time32 time32) {
            this.start = time32;
            return this;
        }
    }

    private ValidityPeriod(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.start = Time32.getInstance((Object) aSN1Sequence.getObjectAt(0));
        this.duration = Duration.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public ValidityPeriod(Time32 time32, Duration duration) {
        this.start = time32;
        this.duration = duration;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ValidityPeriod getInstance(Object obj) {
        if (obj instanceof ValidityPeriod) {
            return (ValidityPeriod) obj;
        }
        if (obj != null) {
            return new ValidityPeriod(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Duration getDuration() {
        return this.duration;
    }

    public Time32 getStart() {
        return this.start;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.start, this.duration});
    }

    public String toString() {
        return "ValidityPeriod[" + this.start + " " + this.duration + "]";
    }
}