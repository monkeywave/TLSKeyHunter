package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

/* loaded from: classes2.dex */
public class ToBeSignedCrl extends ASN1Object {
    private final SequenceOfCrlEntry entries;
    private final Time32 nextUpdate;
    private final Time32 thisUpdate;
    private final Version version;

    /* loaded from: classes2.dex */
    public static class Builder {
        private SequenceOfCrlEntry entries;
        private Time32 nextUpdate;
        private Time32 thisUpdate;
        private Version version;

        public ToBeSignedCrl createToBeSignedCrl() {
            return new ToBeSignedCrl(this.version, this.thisUpdate, this.nextUpdate, this.entries);
        }

        public Builder setEntries(SequenceOfCrlEntry sequenceOfCrlEntry) {
            this.entries = sequenceOfCrlEntry;
            return this;
        }

        public Builder setNextUpdate(Time32 time32) {
            this.nextUpdate = time32;
            return this;
        }

        public Builder setThisUpdate(Time32 time32) {
            this.thisUpdate = time32;
            return this;
        }

        public Builder setVersion(Version version) {
            this.version = version;
            return this;
        }
    }

    private ToBeSignedCrl(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 4) {
            throw new IllegalArgumentException("expected sequence size of 4");
        }
        this.version = Version.getInstance(aSN1Sequence.getObjectAt(0));
        this.thisUpdate = Time32.getInstance((Object) aSN1Sequence.getObjectAt(1));
        this.nextUpdate = Time32.getInstance((Object) aSN1Sequence.getObjectAt(2));
        this.entries = SequenceOfCrlEntry.getInstance(aSN1Sequence.getObjectAt(3));
    }

    public ToBeSignedCrl(Version version, Time32 time32, Time32 time322, SequenceOfCrlEntry sequenceOfCrlEntry) {
        this.version = version;
        this.thisUpdate = time32;
        this.nextUpdate = time322;
        this.entries = sequenceOfCrlEntry;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ToBeSignedCrl getInstance(Object obj) {
        if (obj instanceof ToBeSignedCrl) {
            return (ToBeSignedCrl) obj;
        }
        if (obj != null) {
            return new ToBeSignedCrl(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SequenceOfCrlEntry getEntries() {
        return this.entries;
    }

    public Time32 getNextUpdate() {
        return this.nextUpdate;
    }

    public Time32 getThisUpdate() {
        return this.thisUpdate;
    }

    public Version getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.version, this.thisUpdate, this.nextUpdate, this.entries});
    }
}